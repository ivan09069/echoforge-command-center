"""
tests/test_live_boundary_enforcement.py
=========================================
Proves the boundary enforcer blocks invalid data in the live path.

Must prove:
  1. Invalid adapter payload never reaches decide()
  2. Validation failure creates audit entry
  3. Validation failure on security/mixed → ESCALATE
  4. Validation failure on execution-bearing trading → NO_ACTION + REQUIRE_APPROVAL
  5. Oversized payload dropped cleanly
  6. Partial valid payload still rejected, not coerced
  7. Pre-route catches bad contracts before dispatch
  8. Pre-response catches bad decisions before operator
"""

import sys
import os
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from contracts import (
    JobContract, JobType, Sensitivity, ActionClass, GateDecision,
    SecurityVerdict, SecurityOutput, TradingOutput, TradingVerdict,
    FinalDecision, FinalDisposition, ArtifactRef,
)
from policy_engine import (
    build_job_contract, decide, content_hash, get_audit_log, _audit_log,
)
from schema_validation import MAX_RAW_RESPONSE_BYTES, MAX_FINDINGS_COUNT
from boundary_enforcer import (
    enforce_pre_route, enforce_post_adapter_security,
    enforce_post_adapter_trading, enforce_post_adapter_raw,
    enforce_pre_response, EnforcementResult,
)


def _clear_audit():
    _audit_log.clear()


APPROVED_STATES = {
    FinalDisposition.APPROVED,
    FinalDisposition.APPROVED_READ_ONLY,
    FinalDisposition.APPROVED_WITH_CONDITIONS,
}


# ═══════════════════════════════════════════════════════════════════════════
# 1. INVALID PAYLOAD NEVER REACHES decide()
# ═══════════════════════════════════════════════════════════════════════════

class TestInvalidPayloadBlocked:
    """Invalid adapter output must be caught by the enforcer BEFORE decide()."""

    def setup_method(self):
        _clear_audit()

    def test_invalid_security_blocked_before_decide(self):
        """Malformed security output → enforcer returns fallback, not the output."""
        contract = JobContract(
            job_type=JobType.SECURITY,
            routes=["GEMINI"],
        )
        # Security output with too many findings (exceeds MAX_FINDINGS_COUNT)
        bad_output = SecurityOutput(
            security_verdict=SecurityVerdict.ALLOW,
            findings=["f"] * (MAX_FINDINGS_COUNT + 1),
            raw_response="VERDICT: ALLOW",
        )
        result = enforce_post_adapter_security(bad_output, contract)
        assert not result.valid
        assert result.fallback_decision is not None
        assert result.fallback_decision.gate_decision == GateDecision.REQUIRE_APPROVAL

    def test_invalid_trading_blocked_before_decide(self):
        """Malformed trading output → enforcer returns fallback."""
        contract = build_job_contract(
            "Buy $100 ETH",
            {"category": "trading", "confidence": 0.9},
        )
        bad_output = TradingOutput(
            confidence=5.0,  # Out of [0, 1] range
            raw_response="Buy now",
        )
        result = enforce_post_adapter_trading(bad_output, contract)
        assert not result.valid
        assert result.fallback_decision is not None

    def test_valid_security_passes_through(self):
        contract = JobContract(
            job_type=JobType.SECURITY,
            routes=["GEMINI"],
        )
        good_output = SecurityOutput(
            security_verdict=SecurityVerdict.ALLOW,
            findings=["All clear"],
            raw_response="VERDICT: ALLOW",
        )
        result = enforce_post_adapter_security(good_output, contract)
        assert result.valid
        assert result.value is good_output

    def test_valid_trading_passes_through(self):
        contract = build_job_contract(
            "ETH price?",
            {"category": "trading", "confidence": 0.9},
        )
        good_output = TradingOutput(
            confidence=0.85,
            raw_response="ETH is $3,520",
        )
        result = enforce_post_adapter_trading(good_output, contract)
        assert result.valid
        assert result.value is good_output


# ═══════════════════════════════════════════════════════════════════════════
# 2. VALIDATION FAILURE CREATES AUDIT ENTRY
# ═══════════════════════════════════════════════════════════════════════════

class TestValidationFailureAudit:

    def setup_method(self):
        _clear_audit()

    def test_security_failure_audited(self):
        contract = JobContract(
            job_type=JobType.SECURITY, routes=["GEMINI"],
            job_id="sec-test1",
        )
        bad = SecurityOutput(
            findings=["f"] * (MAX_FINDINGS_COUNT + 1),
            raw_response="bad",
        )
        enforce_post_adapter_security(bad, contract)
        log = get_audit_log()
        assert len(log) >= 1
        assert any("VALIDATION_FAILURE" in e.get("execution_action", "") for e in log)

    def test_trading_failure_audited(self):
        contract = build_job_contract(
            "Buy $100 ETH", {"category": "trading", "confidence": 0.9},
        )
        bad = TradingOutput(confidence=99.0, raw_response="bad")
        enforce_post_adapter_trading(bad, contract)
        log = get_audit_log()
        assert any("VALIDATION_FAILURE" in e.get("execution_action", "") for e in log)

    def test_pre_route_failure_audited(self):
        contract = JobContract(
            job_id="",  # Invalid
            routes=["CLAUDE"],
        )
        enforce_pre_route(contract)
        log = get_audit_log()
        assert any("PRE_ROUTE" in e.get("execution_action", "") for e in log)

    def test_raw_response_failure_audited(self):
        contract = JobContract(
            job_type=JobType.SECURITY, routes=["GEMINI"],
        )
        enforce_post_adapter_raw(None, "gemini", contract)
        log = get_audit_log()
        assert any("RAW_GEMINI" in e.get("execution_action", "") for e in log)

    def test_audit_contains_error_count(self):
        contract = JobContract(
            job_id="",  # Invalid
            timestamp="",  # Also invalid
            routes=["UNKNOWN"],  # Also invalid
        )
        enforce_pre_route(contract)
        log = get_audit_log()
        # Action should contain error count
        actions = [e["execution_action"] for e in log if "VALIDATION_FAILURE" in e.get("execution_action", "")]
        assert len(actions) > 0
        assert any("errors" in a for a in actions)


# ═══════════════════════════════════════════════════════════════════════════
# 3. SECURITY/MIXED VALIDATION FAILURE → ESCALATE
# ═══════════════════════════════════════════════════════════════════════════

class TestSecurityMixedFailureEscalates:

    def setup_method(self):
        _clear_audit()

    def test_missing_security_on_security_job_escalates(self):
        contract = JobContract(job_type=JobType.SECURITY, routes=["GEMINI"])
        result = enforce_post_adapter_security(None, contract)
        assert not result.valid
        assert result.fallback_decision.gate_decision == GateDecision.REQUIRE_APPROVAL
        assert result.fallback_decision.disposition == FinalDisposition.AWAITING_HUMAN_APPROVAL

    def test_missing_security_on_mixed_job_escalates(self):
        contract = JobContract(job_type=JobType.MIXED, routes=["CLAUDE", "GEMINI"])
        result = enforce_post_adapter_security(None, contract)
        assert not result.valid
        assert result.fallback_decision.gate_decision == GateDecision.REQUIRE_APPROVAL

    def test_invalid_security_on_security_job_escalates(self):
        contract = JobContract(job_type=JobType.SECURITY, routes=["GEMINI"])
        bad = SecurityOutput(
            findings=["f"] * (MAX_FINDINGS_COUNT + 1),
            raw_response="too many findings",
        )
        result = enforce_post_adapter_security(bad, contract)
        assert not result.valid
        assert result.fallback_decision.gate_decision == GateDecision.REQUIRE_APPROVAL

    def test_missing_security_on_trading_job_is_fine(self):
        """TRADING jobs don't need security output — missing is OK."""
        contract = JobContract(job_type=JobType.TRADING, routes=["CLAUDE"])
        result = enforce_post_adapter_security(None, contract)
        assert result.valid

    def test_missing_security_on_general_job_is_fine(self):
        contract = JobContract(job_type=JobType.GENERAL, routes=["GPT"])
        result = enforce_post_adapter_security(None, contract)
        assert result.valid

    def test_raw_gemini_failure_escalates(self):
        contract = JobContract(job_type=JobType.SECURITY, routes=["GEMINI"])
        result = enforce_post_adapter_raw(None, "gemini", contract)
        assert not result.valid
        assert result.fallback_decision.gate_decision == GateDecision.REQUIRE_APPROVAL

    def test_raw_security_failure_escalates(self):
        contract = JobContract(job_type=JobType.SECURITY, routes=["GEMINI"])
        result = enforce_post_adapter_raw(None, "security", contract)
        assert not result.valid
        assert result.fallback_decision.gate_decision == GateDecision.REQUIRE_APPROVAL

    def test_escalate_fallback_never_approved(self):
        """Fallback for security failure must NEVER be in an approved state."""
        contract = JobContract(job_type=JobType.SECURITY, routes=["GEMINI"])
        result = enforce_post_adapter_security(None, contract)
        assert result.fallback_decision.disposition not in APPROVED_STATES


# ═══════════════════════════════════════════════════════════════════════════
# 4. EXECUTION-BEARING TRADING FAILURE → NO_ACTION + REQUIRE_APPROVAL
# ═══════════════════════════════════════════════════════════════════════════

class TestExecutionTradingFailureNoAction:

    def setup_method(self):
        _clear_audit()

    def test_missing_trading_on_execution_job(self):
        contract = build_job_contract(
            "Buy $100 ETH", {"category": "trading", "confidence": 0.9},
        )
        result = enforce_post_adapter_trading(None, contract)
        assert not result.valid
        assert result.fallback_decision.gate_decision == GateDecision.REQUIRE_APPROVAL
        assert "NO_ACTION" in result.fallback_decision.trading_summary

    def test_invalid_trading_on_execution_job(self):
        contract = build_job_contract(
            "Sell 0.5 ETH", {"category": "trading", "confidence": 0.9},
        )
        bad = TradingOutput(confidence=2.0, raw_response="sell")
        result = enforce_post_adapter_trading(bad, contract)
        assert not result.valid
        assert result.fallback_decision.gate_decision == GateDecision.REQUIRE_APPROVAL

    def test_invalid_trading_on_read_only_degrades_gracefully(self):
        """Read-only job with bad trading output → warning, not block."""
        contract = build_job_contract(
            "ETH price?", {"category": "trading", "confidence": 0.9},
        )
        bad = TradingOutput(confidence=-1.0, raw_response="price")
        result = enforce_post_adapter_trading(bad, contract)
        assert not result.valid
        # Read-only → graceful degradation, not full block
        assert result.fallback_decision.gate_decision == GateDecision.ALLOW

    def test_missing_trading_on_read_only_is_fine(self):
        contract = build_job_contract(
            "What's the gas price?", {"category": "trading", "confidence": 0.9},
        )
        result = enforce_post_adapter_trading(None, contract)
        assert result.valid

    def test_raw_claude_failure_on_execution_job(self):
        contract = build_job_contract(
            "Buy $100 ETH", {"category": "trading", "confidence": 0.9},
        )
        result = enforce_post_adapter_raw(None, "claude", contract)
        assert not result.valid
        assert result.fallback_decision.gate_decision == GateDecision.REQUIRE_APPROVAL

    def test_noaction_fallback_never_auto_approved(self):
        contract = build_job_contract(
            "Buy $100 ETH", {"category": "trading", "confidence": 0.9},
        )
        result = enforce_post_adapter_trading(None, contract)
        assert result.fallback_decision.disposition not in APPROVED_STATES


# ═══════════════════════════════════════════════════════════════════════════
# 5. OVERSIZED PAYLOAD DROPPED CLEANLY
# ═══════════════════════════════════════════════════════════════════════════

class TestOversizedPayloadDropped:

    def setup_method(self):
        _clear_audit()

    def test_oversized_security_response_dropped(self):
        contract = JobContract(job_type=JobType.SECURITY, routes=["GEMINI"])
        huge = SecurityOutput(
            raw_response="X" * (MAX_RAW_RESPONSE_BYTES + 1),
        )
        result = enforce_post_adapter_security(huge, contract)
        assert not result.valid
        assert any("exceeds" in e for e in result.errors)

    def test_oversized_trading_response_dropped(self):
        contract = build_job_contract(
            "ETH price?", {"category": "trading", "confidence": 0.9},
        )
        huge = TradingOutput(
            raw_response="Y" * (MAX_RAW_RESPONSE_BYTES + 1),
        )
        result = enforce_post_adapter_trading(huge, contract)
        assert not result.valid

    def test_oversized_raw_string_dropped(self):
        contract = JobContract(job_type=JobType.TRADING, routes=["CLAUDE"])
        result = enforce_post_adapter_raw(
            "Z" * (MAX_RAW_RESPONSE_BYTES + 1), "claude", contract,
        )
        assert not result.valid

    def test_oversized_findings_list_dropped(self):
        contract = JobContract(job_type=JobType.SECURITY, routes=["GEMINI"])
        huge = SecurityOutput(
            findings=["finding"] * (MAX_FINDINGS_COUNT + 1),
            raw_response="VERDICT: ALLOW",
        )
        result = enforce_post_adapter_security(huge, contract)
        assert not result.valid

    def test_exact_limit_passes(self):
        contract = JobContract(job_type=JobType.SECURITY, routes=["GEMINI"])
        exact = SecurityOutput(
            findings=["f"] * MAX_FINDINGS_COUNT,
            raw_response="A" * (MAX_RAW_RESPONSE_BYTES),
        )
        result = enforce_post_adapter_security(exact, contract)
        # Should pass — at limit, not over
        assert result.valid, f"Exact-limit payload rejected: {result.errors}"


# ═══════════════════════════════════════════════════════════════════════════
# 6. PARTIAL VALID PAYLOAD STILL REJECTED
# ═══════════════════════════════════════════════════════════════════════════

class TestPartialPayloadRejected:
    """An object with some valid and some invalid fields must be fully
    rejected, not partially coerced."""

    def setup_method(self):
        _clear_audit()

    def test_security_valid_verdict_invalid_findings_rejected(self):
        """Valid verdict but invalid findings type → full rejection."""
        contract = JobContract(job_type=JobType.SECURITY, routes=["GEMINI"])
        mixed = SecurityOutput(
            security_verdict=SecurityVerdict.ALLOW,  # Valid
            findings=[42, None, True],  # Invalid — not strings
            raw_response="VERDICT: ALLOW",
        )
        result = enforce_post_adapter_security(mixed, contract)
        assert not result.valid

    def test_trading_valid_verdict_invalid_confidence_rejected(self):
        """Valid verdict but confidence out of bounds → full rejection."""
        contract = build_job_contract(
            "Buy $100 ETH", {"category": "trading", "confidence": 0.9},
        )
        mixed = TradingOutput(
            trading_verdict=TradingVerdict.PROPOSE,  # Valid
            confidence=1.5,  # Invalid
            raw_response="Good setup",
        )
        result = enforce_post_adapter_trading(mixed, contract)
        assert not result.valid

    def test_contract_valid_fields_invalid_route_rejected(self):
        """Contract with valid fields but bad route → rejected at pre-route."""
        contract = build_job_contract(
            "ETH price?", {"category": "trading", "confidence": 0.9},
        )
        contract.routes = ["DEEPSEEK"]  # Invalid route
        result = enforce_pre_route(contract)
        assert not result.valid

    def test_artifact_valid_type_invalid_hash_rejected(self):
        """Artifact with valid type but malformed hash → parent contract rejected."""
        contract = build_job_contract(
            "Check status", {"category": "trading", "confidence": 0.9},
        )
        contract.artifacts = [
            ArtifactRef(type="script", hash="not-hex-at-all!!")
        ]
        result = enforce_pre_route(contract)
        assert not result.valid
        assert any("hash" in e.lower() or "hex" in e.lower() for e in result.errors)

    def test_partially_valid_never_reaches_decide(self):
        """The full flow: build contract, corrupt it, enforce, check blocked."""
        contract = build_job_contract(
            "Buy $100 ETH", {"category": "trading", "confidence": 0.9},
        )
        # Corrupt one field
        contract.routes = ["INVALID_AGENT"]

        result = enforce_pre_route(contract)
        assert not result.valid
        assert result.fallback_decision.gate_decision == GateDecision.DENY

        # The fallback should be used instead of calling decide()
        # Prove the fallback is safe
        assert result.fallback_decision.disposition == FinalDisposition.BLOCKED_POLICY


# ═══════════════════════════════════════════════════════════════════════════
# 7. PRE-ROUTE CATCHES BAD CONTRACTS
# ═══════════════════════════════════════════════════════════════════════════

class TestPreRouteCatchesBadContracts:

    def setup_method(self):
        _clear_audit()

    def test_empty_job_id_blocked(self):
        contract = _make_contract(job_id="")
        result = enforce_pre_route(contract)
        assert not result.valid
        assert result.fallback_decision.disposition == FinalDisposition.BLOCKED_POLICY

    def test_high_to_claude_blocked(self):
        contract = _make_contract(
            sensitivity=Sensitivity.HIGH,
            routes=["CLAUDE"],
            constraints=["no-secrets-in-payload", "local-only", "do-not-export"],
        )
        result = enforce_pre_route(contract)
        assert not result.valid

    def test_missing_no_secrets_constraint_blocked(self):
        contract = _make_contract(constraints=[])
        result = enforce_pre_route(contract)
        assert not result.valid

    def test_valid_pipeline_contract_passes(self):
        contract = build_job_contract(
            "ETH price?", {"category": "trading", "confidence": 0.9},
        )
        result = enforce_pre_route(contract)
        assert result.valid, f"Valid contract blocked: {result.errors}"

    def test_all_pipeline_messages_pass_pre_route(self):
        """Every contract the pipeline builds must pass pre-route."""
        messages = [
            ("ETH price?", "trading"),
            ("Decrypt keystore", "security"),
            ("Check safety then portfolio", "mixed"),
            ("Hello", "general"),
            ("Buy $100 ETH", "trading"),
        ]
        for msg, cat in messages:
            contract = build_job_contract(msg, {"category": cat, "confidence": 0.9})
            result = enforce_pre_route(contract)
            assert result.valid, f"Pipeline contract for '{msg}' failed pre-route: {result.errors}"


# ═══════════════════════════════════════════════════════════════════════════
# 8. PRE-RESPONSE CATCHES BAD DECISIONS
# ═══════════════════════════════════════════════════════════════════════════

class TestPreResponseCatchesBadDecisions:

    def test_deny_without_reason_caught(self):
        decision = FinalDecision(
            gate_decision=GateDecision.DENY,
            gate_reason="",  # Missing
        )
        result = enforce_pre_response(decision)
        assert not result.valid
        assert result.fallback_decision.gate_decision == GateDecision.DENY

    def test_require_approval_without_reason_caught(self):
        decision = FinalDecision(
            gate_decision=GateDecision.REQUIRE_APPROVAL,
            gate_reason="",
        )
        result = enforce_pre_response(decision)
        assert not result.valid

    def test_valid_decision_passes(self):
        contract = build_job_contract(
            "ETH price?", {"category": "trading", "confidence": 0.9},
        )
        decision = decide(contract)
        result = enforce_pre_response(decision)
        assert result.valid, f"Valid decision failed: {result.errors}"

    def test_all_pipeline_decisions_pass_pre_response(self):
        """Every decision the pipeline produces must pass pre-response."""
        messages = [
            ("ETH price?", "trading"),
            ("Decrypt keystore", "security"),
            ("Buy $100 ETH", "trading"),
        ]
        for msg, cat in messages:
            contract = build_job_contract(msg, {"category": cat, "confidence": 0.9})
            decision = decide(contract)
            result = enforce_pre_response(decision)
            assert result.valid, f"Pipeline decision for '{msg}' failed: {result.errors}"


# ═══════════════════════════════════════════════════════════════════════════
# FULL ENFORCEMENT CHAIN
# ═══════════════════════════════════════════════════════════════════════════

class TestFullEnforcementChain:
    """End-to-end: contract → pre-route → adapter → post-adapter → decide → pre-response."""

    def setup_method(self):
        _clear_audit()

    def test_happy_path_all_valid(self):
        contract = build_job_contract(
            "ETH price?", {"category": "trading", "confidence": 0.9},
        )
        # Pre-route
        r1 = enforce_pre_route(contract)
        assert r1.valid

        # Post-adapter (trading)
        trading = TradingOutput(confidence=0.8, raw_response="$3,520")
        r2 = enforce_post_adapter_trading(trading, contract)
        assert r2.valid

        # decide()
        decision = decide(contract, trading)

        # Pre-response
        r3 = enforce_pre_response(decision)
        assert r3.valid

    def test_failure_at_pre_route_stops_chain(self):
        contract = _make_contract(routes=["INVALID"])
        r1 = enforce_pre_route(contract)
        assert not r1.valid
        # Chain stops — fallback used, adapter never called
        assert r1.fallback_decision is not None

    def test_failure_at_post_adapter_stops_chain(self):
        contract = build_job_contract(
            "Buy $100 ETH", {"category": "trading", "confidence": 0.9},
        )
        r1 = enforce_pre_route(contract)
        assert r1.valid

        bad_trading = TradingOutput(confidence=5.0, raw_response="bad")
        r2 = enforce_post_adapter_trading(bad_trading, contract)
        assert not r2.valid
        # Chain stops — fallback used, decide() never called with bad data
        assert r2.fallback_decision is not None

    def test_all_failures_produce_audit_entries(self):
        """Every failure point in the chain must audit."""
        # Failure 1: pre-route
        c1 = _make_contract(routes=["BAD"])
        enforce_pre_route(c1)

        # Failure 2: post-adapter security
        c2 = JobContract(job_type=JobType.SECURITY, routes=["GEMINI"])
        enforce_post_adapter_security(None, c2)

        # Failure 3: post-adapter trading
        c3 = build_job_contract("Buy $100 ETH", {"category": "trading", "confidence": 0.9})
        enforce_post_adapter_trading(None, c3)

        log = get_audit_log()
        assert len(log) >= 3
        actions = [e["execution_action"] for e in log]
        assert any("PRE_ROUTE" in a for a in actions)
        assert any("MISSING_SECURITY" in a for a in actions)
        assert any("MISSING_TRADING" in a for a in actions)


# ═══════════════════════════════════════════════════════════════════════════
# ENFORCEMENT RESULT CORRECTNESS
# ═══════════════════════════════════════════════════════════════════════════

class TestEnforcementResultBehavior:

    def test_valid_result(self):
        r = EnforcementResult(valid=True, value="data")
        assert r.valid
        assert r.value == "data"
        assert r.fallback_decision is None

    def test_invalid_result(self):
        fallback = FinalDecision(gate_decision=GateDecision.DENY, gate_reason="bad")
        r = EnforcementResult(
            valid=False, errors=["error1"], fallback_decision=fallback,
        )
        assert not r.valid
        assert len(r.errors) == 1
        assert r.fallback_decision is not None


# ═══════════════════════════════════════════════════════════════════════════
# HELPER
# ═══════════════════════════════════════════════════════════════════════════

def _make_contract(**overrides) -> JobContract:
    c = build_job_contract("ETH price?", {"category": "trading", "confidence": 0.9})
    for k, v in overrides.items():
        setattr(c, k, v)
    return c
