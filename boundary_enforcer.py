"""
Boundary Enforcer — Live Path Validation
==========================================
Wraps every adapter entry and exit point with schema validation.
Rule: invalid adapter payload never reaches decide().

Enforcement points:
  1. PRE-ROUTE: validate contract before sending to any adapter
  2. POST-ADAPTER: validate specialist output before it enters decide()
  3. PRE-RESPONSE: validate final decision before it reaches the operator

On validation failure:
  - Security/mixed job → ESCALATE (REQUIRE_APPROVAL)
  - Execution-bearing trading job → NO_ACTION + REQUIRE_APPROVAL
  - Read-only trading job → degrade gracefully with warning
  - Structured audit event emitted for every failure
  - Original invalid payload is NEVER forwarded
"""

from __future__ import annotations

import logging
from typing import Any

from contracts import (
    JobContract, JobType, Sensitivity, ActionClass, GateDecision,
    SecurityVerdict, SecurityOutput, TradingOutput, TradingVerdict,
    FinalDecision, FinalDisposition,
)
from schema_validation import (
    validate_job_contract, validate_security_output, validate_trading_output,
    validate_final_decision, validate_route_metadata, validate_adapter_response_dict,
    ValidationResult,
)
from policy_engine import log_audit, decide, content_hash

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# ENFORCEMENT RESULTS
# ═══════════════════════════════════════════════════════════════════════════

class EnforcementResult:
    """Wraps an object with its validation status.
    If invalid, carries the safe fallback."""

    def __init__(
        self,
        valid: bool,
        value: Any = None,
        errors: list[str] | None = None,
        fallback_decision: FinalDecision | None = None,
    ):
        self.valid = valid
        self.value = value
        self.errors = errors or []
        self.fallback_decision = fallback_decision

    def __repr__(self):
        if self.valid:
            return f"EnforcementResult(OK, {type(self.value).__name__})"
        return f"EnforcementResult(FAILED, {len(self.errors)} errors)"


# ═══════════════════════════════════════════════════════════════════════════
# 1. PRE-ROUTE: Validate contract before adapter dispatch
# ═══════════════════════════════════════════════════════════════════════════

def enforce_pre_route(contract: JobContract) -> EnforcementResult:
    """
    Validate a contract before it is dispatched to any adapter.
    If invalid, returns a safe fallback decision.
    """
    contract_v = validate_job_contract(contract)
    route_v = validate_route_metadata(contract)

    errors = contract_v.errors + route_v.errors

    if errors:
        logger.error(f"PRE-ROUTE validation failed for job {contract.job_id}: {errors}")

        fallback = FinalDecision(
            job_id=contract.job_id,
            disposition=FinalDisposition.BLOCKED_POLICY,
            gate_decision=GateDecision.DENY,
            gate_reason=f"Pre-route validation failed: {'; '.join(errors[:3])}",
            security_summary="BLOCKED — contract failed schema validation",
        )

        # Audit the failure
        log_audit(
            contract, fallback,
            execution_action=f"VALIDATION_FAILURE:PRE_ROUTE:{len(errors)}_errors",
        )

        return EnforcementResult(
            valid=False, value=contract, errors=errors,
            fallback_decision=fallback,
        )

    return EnforcementResult(valid=True, value=contract)


# ═══════════════════════════════════════════════════════════════════════════
# 2. POST-ADAPTER: Validate specialist output before decide()
# ═══════════════════════════════════════════════════════════════════════════

def enforce_post_adapter_security(
    output: SecurityOutput | None,
    contract: JobContract,
) -> EnforcementResult:
    """
    Validate security output at the adapter boundary.
    If invalid or None on a security/mixed job → ESCALATE.
    """
    # Missing security output on security/mixed jobs
    if output is None:
        if contract.job_type in (JobType.SECURITY, JobType.MIXED):
            fallback = _make_escalate_decision(
                contract,
                reason="Missing security adapter output",
                audit_action="VALIDATION_FAILURE:MISSING_SECURITY",
            )
            return EnforcementResult(
                valid=False, errors=["missing security output"],
                fallback_decision=fallback,
            )
        # Trading/general jobs don't need security output
        return EnforcementResult(valid=True, value=None)

    # Validate structure
    v = validate_security_output(output)
    if not v.valid:
        logger.error(
            f"POST-ADAPTER security validation failed for job "
            f"{contract.job_id}: {v.errors}"
        )
        fallback = _make_escalate_decision(
            contract,
            reason=f"Security output failed validation: {'; '.join(v.errors[:3])}",
            audit_action=f"VALIDATION_FAILURE:SECURITY_OUTPUT:{len(v.errors)}_errors",
        )
        return EnforcementResult(
            valid=False, value=output, errors=v.errors,
            fallback_decision=fallback,
        )

    return EnforcementResult(valid=True, value=output)


def enforce_post_adapter_trading(
    output: TradingOutput | None,
    contract: JobContract,
) -> EnforcementResult:
    """
    Validate trading output at the adapter boundary.
    If invalid on execution-bearing job → NO_ACTION + REQUIRE_APPROVAL.
    """
    # Missing trading output
    if output is None:
        if contract.requires_execution and contract.job_type == JobType.TRADING:
            fallback = _make_noaction_decision(
                contract,
                reason="Missing trading adapter output on execution-bearing job",
                audit_action="VALIDATION_FAILURE:MISSING_TRADING",
            )
            return EnforcementResult(
                valid=False, errors=["missing trading output"],
                fallback_decision=fallback,
            )
        # Read-only or non-trading jobs → fine
        return EnforcementResult(valid=True, value=None)

    # Validate structure
    v = validate_trading_output(output)
    if not v.valid:
        logger.error(
            f"POST-ADAPTER trading validation failed for job "
            f"{contract.job_id}: {v.errors}"
        )

        if contract.requires_execution:
            fallback = _make_noaction_decision(
                contract,
                reason=f"Trading output failed validation: {'; '.join(v.errors[:3])}",
                audit_action=f"VALIDATION_FAILURE:TRADING_OUTPUT:{len(v.errors)}_errors",
            )
        else:
            # Read-only → degrade with warning, not block
            fallback = FinalDecision(
                job_id=contract.job_id,
                disposition=FinalDisposition.APPROVED_READ_ONLY,
                gate_decision=GateDecision.ALLOW,
                gate_reason="Trading output failed validation but job is read-only",
                trading_summary="INVALID — trading output failed schema validation",
            )
            log_audit(
                contract, fallback,
                execution_action=f"VALIDATION_WARNING:TRADING_OUTPUT:{len(v.errors)}_errors",
            )

        return EnforcementResult(
            valid=False, value=output, errors=v.errors,
            fallback_decision=fallback,
        )

    return EnforcementResult(valid=True, value=output)


def enforce_post_adapter_raw(
    raw_response: Any,
    adapter_name: str,
    contract: JobContract,
) -> EnforcementResult:
    """
    Validate a raw adapter response (string or dict) before parsing.
    Catches oversized payloads, deeply nested data, and wrong types.
    """
    v = validate_adapter_response_dict(raw_response, adapter_name)

    if not v.valid:
        logger.error(
            f"POST-ADAPTER raw validation failed for {adapter_name} "
            f"on job {contract.job_id}: {v.errors}"
        )

        if adapter_name.lower() in ("gemini", "security"):
            fallback = _make_escalate_decision(
                contract,
                reason=f"Raw {adapter_name} response failed validation: {'; '.join(v.errors[:3])}",
                audit_action=f"VALIDATION_FAILURE:RAW_{adapter_name.upper()}",
            )
        elif contract.requires_execution:
            fallback = _make_noaction_decision(
                contract,
                reason=f"Raw {adapter_name} response failed validation",
                audit_action=f"VALIDATION_FAILURE:RAW_{adapter_name.upper()}",
            )
        else:
            fallback = FinalDecision(
                job_id=contract.job_id,
                disposition=FinalDisposition.APPROVED_READ_ONLY,
                gate_decision=GateDecision.ALLOW,
                gate_reason=f"Raw {adapter_name} response invalid but job is read-only",
            )
            log_audit(
                contract, fallback,
                execution_action=f"VALIDATION_WARNING:RAW_{adapter_name.upper()}",
            )

        return EnforcementResult(
            valid=False, value=raw_response, errors=v.errors,
            fallback_decision=fallback,
        )

    return EnforcementResult(valid=True, value=raw_response)


# ═══════════════════════════════════════════════════════════════════════════
# 3. PRE-RESPONSE: Validate final decision before operator sees it
# ═══════════════════════════════════════════════════════════════════════════

def enforce_pre_response(decision: FinalDecision) -> EnforcementResult:
    """
    Validate a final decision before sending to the operator.
    If invalid, replace with a safe DENY.
    """
    v = validate_final_decision(decision)

    if not v.valid:
        logger.error(f"PRE-RESPONSE validation failed: {v.errors}")

        safe = FinalDecision(
            job_id=decision.job_id,
            disposition=FinalDisposition.BLOCKED_POLICY,
            gate_decision=GateDecision.DENY,
            gate_reason=f"Final decision failed validation: {'; '.join(v.errors[:3])}",
        )
        return EnforcementResult(
            valid=False, value=decision, errors=v.errors,
            fallback_decision=safe,
        )

    return EnforcementResult(valid=True, value=decision)


# ═══════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _make_escalate_decision(
    contract: JobContract,
    reason: str,
    audit_action: str,
) -> FinalDecision:
    """Build an ESCALATE fallback decision and log it."""
    decision = FinalDecision(
        job_id=contract.job_id,
        disposition=FinalDisposition.AWAITING_HUMAN_APPROVAL,
        gate_decision=GateDecision.REQUIRE_APPROVAL,
        gate_reason=reason,
        security_summary="VALIDATION FAILURE — escalated to human review",
        approval_prompt=f"Validation failure: {reason}\nReply 'approve' to proceed or 'deny' to cancel.",
    )
    log_audit(contract, decision, execution_action=audit_action)
    return decision


def _make_noaction_decision(
    contract: JobContract,
    reason: str,
    audit_action: str,
) -> FinalDecision:
    """Build a NO_ACTION + REQUIRE_APPROVAL fallback and log it."""
    decision = FinalDecision(
        job_id=contract.job_id,
        disposition=FinalDisposition.AWAITING_HUMAN_APPROVAL,
        gate_decision=GateDecision.REQUIRE_APPROVAL,
        gate_reason=reason,
        trading_summary="VALIDATION FAILURE — defaulted to NO_ACTION",
        approval_prompt=f"Trading validation failure: {reason}\nReply 'approve' to proceed or 'deny' to cancel.",
    )
    log_audit(contract, decision, execution_action=audit_action)
    return decision
