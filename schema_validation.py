"""
Schema Boundary Validation
============================
Strict validation at every adapter boundary.
Rule: any adapter response that fails schema validation = ESCALATE, never coerce.

Validates:
  - JobContract required fields and enum values
  - SecurityOutput verdict enum, severity, findings structure
  - TradingOutput verdict enum, confidence bounds, changes structure
  - ArtifactRef hash format, sensitivity, location
  - Route metadata consistency
  - Payload size limits
  - No unexpected nested fields that could smuggle data
"""

from __future__ import annotations

import json
import logging
from dataclasses import fields as dataclass_fields
from typing import Any

from contracts import (
    JobContract, JobType, Sensitivity, ActionClass, GateDecision,
    SecurityVerdict, SecurityOutput, TradingOutput, TradingVerdict,
    FinalDecision, FinalDisposition, ArtifactRef,
)

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# LIMITS
# ═══════════════════════════════════════════════════════════════════════════

MAX_CONTEXT_SUMMARY_BYTES = 50_000      # 50 KB
MAX_RAW_RESPONSE_BYTES = 500_000        # 500 KB
MAX_FINDINGS_COUNT = 100
MAX_CONDITIONS_COUNT = 50
MAX_RECOMMENDED_CHANGES = 50
MAX_ARTIFACTS = 20
MAX_ROUTES = 5
MAX_CONSTRAINTS = 30
HASH_LENGTH = 16                        # SHA-256 truncated to 16 hex chars
JOB_ID_LENGTH = 8


# ═══════════════════════════════════════════════════════════════════════════
# Validation Result
# ═══════════════════════════════════════════════════════════════════════════

class ValidationResult:
    """Accumulates validation errors. Any error = invalid."""

    def __init__(self, subject: str):
        self.subject = subject
        self.errors: list[str] = []

    def fail(self, msg: str):
        self.errors.append(f"{self.subject}: {msg}")
        logger.warning(f"Schema validation failed — {self.subject}: {msg}")

    @property
    def valid(self) -> bool:
        return len(self.errors) == 0

    def __repr__(self):
        if self.valid:
            return f"ValidationResult({self.subject}: OK)"
        return f"ValidationResult({self.subject}: {len(self.errors)} errors)"


# ═══════════════════════════════════════════════════════════════════════════
# ENUM VALIDATORS
# ═══════════════════════════════════════════════════════════════════════════

VALID_JOB_TYPES = {e.value for e in JobType}
VALID_SENSITIVITIES = {e.value for e in Sensitivity}
VALID_ACTION_CLASSES = {e.value for e in ActionClass}
VALID_GATE_DECISIONS = {e.value for e in GateDecision}
VALID_SECURITY_VERDICTS = {e.value for e in SecurityVerdict}
VALID_TRADING_VERDICTS = {e.value for e in TradingVerdict}
VALID_DISPOSITIONS = {e.value for e in FinalDisposition}
VALID_ROUTES = {"CLAUDE", "GEMINI", "GPT", "BOTH", "NONE"}


# ═══════════════════════════════════════════════════════════════════════════
# CONTRACT VALIDATION
# ═══════════════════════════════════════════════════════════════════════════

def validate_job_contract(contract: JobContract) -> ValidationResult:
    """Validate a JobContract at the boundary."""
    v = ValidationResult("JobContract")

    # Required fields present and typed
    if not contract.job_id or not isinstance(contract.job_id, str):
        v.fail("job_id missing or not a string")
    elif len(contract.job_id) != JOB_ID_LENGTH:
        v.fail(f"job_id length {len(contract.job_id)} != expected {JOB_ID_LENGTH}")

    # Enum values
    if contract.job_type.value not in VALID_JOB_TYPES:
        v.fail(f"invalid job_type: {contract.job_type}")
    if contract.sensitivity.value not in VALID_SENSITIVITIES:
        v.fail(f"invalid sensitivity: {contract.sensitivity}")
    if contract.action_class.value not in VALID_ACTION_CLASSES:
        v.fail(f"invalid action_class: {contract.action_class}")

    # Context summary size
    if len(contract.context_summary.encode("utf-8")) > MAX_CONTEXT_SUMMARY_BYTES:
        v.fail(f"context_summary exceeds {MAX_CONTEXT_SUMMARY_BYTES} bytes")

    # Routes
    if len(contract.routes) > MAX_ROUTES:
        v.fail(f"too many routes: {len(contract.routes)} > {MAX_ROUTES}")
    for route in contract.routes:
        if route not in VALID_ROUTES:
            v.fail(f"unknown route: {route}")

    # Constraints size
    if len(contract.constraints) > MAX_CONSTRAINTS:
        v.fail(f"too many constraints: {len(contract.constraints)}")

    # Artifacts
    if len(contract.artifacts) > MAX_ARTIFACTS:
        v.fail(f"too many artifacts: {len(contract.artifacts)}")
    for i, art in enumerate(contract.artifacts):
        art_v = validate_artifact_ref(art)
        if not art_v.valid:
            for e in art_v.errors:
                v.fail(f"artifact[{i}]: {e}")

    # Boolean fields are booleans
    if not isinstance(contract.requires_execution, bool):
        v.fail(f"requires_execution is not bool: {type(contract.requires_execution)}")
    if not isinstance(contract.approval_required, bool):
        v.fail(f"approval_required is not bool: {type(contract.approval_required)}")

    # Sensitivity/route consistency
    if contract.sensitivity == Sensitivity.HIGH and "CLAUDE" in contract.routes:
        v.fail("HIGH sensitivity contract routes to CLAUDE — trust boundary violation")

    # Timestamp present
    if not contract.timestamp:
        v.fail("missing timestamp")

    return v


# ═══════════════════════════════════════════════════════════════════════════
# SECURITY OUTPUT VALIDATION
# ═══════════════════════════════════════════════════════════════════════════

def validate_security_output(output: SecurityOutput) -> ValidationResult:
    """Validate a SecurityOutput at the adapter boundary."""
    v = ValidationResult("SecurityOutput")

    # Verdict enum
    if output.security_verdict.value not in VALID_SECURITY_VERDICTS:
        v.fail(f"invalid security_verdict: {output.security_verdict}")

    # Severity enum
    if output.severity.value not in VALID_SENSITIVITIES:
        v.fail(f"invalid severity: {output.severity}")

    # Findings list
    if not isinstance(output.findings, list):
        v.fail("findings is not a list")
    elif len(output.findings) > MAX_FINDINGS_COUNT:
        v.fail(f"too many findings: {len(output.findings)}")
    else:
        for i, f in enumerate(output.findings):
            if not isinstance(f, str):
                v.fail(f"finding[{i}] is not a string: {type(f)}")

    # Conditions list
    if not isinstance(output.conditions, list):
        v.fail("conditions is not a list")
    elif len(output.conditions) > MAX_CONDITIONS_COUNT:
        v.fail(f"too many conditions: {len(output.conditions)}")

    # Raw response size
    if len(output.raw_response.encode("utf-8")) > MAX_RAW_RESPONSE_BYTES:
        v.fail(f"raw_response exceeds {MAX_RAW_RESPONSE_BYTES} bytes")

    return v


# ═══════════════════════════════════════════════════════════════════════════
# TRADING OUTPUT VALIDATION
# ═══════════════════════════════════════════════════════════════════════════

def validate_trading_output(output: TradingOutput) -> ValidationResult:
    """Validate a TradingOutput at the adapter boundary."""
    v = ValidationResult("TradingOutput")

    # Verdict enum
    if output.trading_verdict.value not in VALID_TRADING_VERDICTS:
        v.fail(f"invalid trading_verdict: {output.trading_verdict}")

    # Confidence bounds
    if not isinstance(output.confidence, (int, float)):
        v.fail(f"confidence is not a number: {type(output.confidence)}")
    elif not (0.0 <= output.confidence <= 1.0):
        v.fail(f"confidence out of range [0,1]: {output.confidence}")

    # Recommended changes
    if not isinstance(output.recommended_changes, list):
        v.fail("recommended_changes is not a list")
    elif len(output.recommended_changes) > MAX_RECOMMENDED_CHANGES:
        v.fail(f"too many recommended_changes: {len(output.recommended_changes)}")

    # Execution request must be bool
    if not isinstance(output.execution_request, bool):
        v.fail(f"execution_request is not bool: {type(output.execution_request)}")

    # Raw response size
    if len(output.raw_response.encode("utf-8")) > MAX_RAW_RESPONSE_BYTES:
        v.fail(f"raw_response exceeds {MAX_RAW_RESPONSE_BYTES} bytes")

    return v


# ═══════════════════════════════════════════════════════════════════════════
# ARTIFACT REF VALIDATION
# ═══════════════════════════════════════════════════════════════════════════

def validate_artifact_ref(ref: ArtifactRef) -> ValidationResult:
    """Validate an ArtifactRef — must be reference only, no raw content."""
    v = ValidationResult("ArtifactRef")

    if not ref.type:
        v.fail("missing artifact type")

    if ref.sensitivity.value not in VALID_SENSITIVITIES:
        v.fail(f"invalid sensitivity: {ref.sensitivity}")

    # HIGH sensitivity must be local-only
    if ref.sensitivity == Sensitivity.HIGH and ref.location != "local_ref_only":
        v.fail(f"HIGH sensitivity artifact has non-local location: {ref.location}")

    # Hash format
    if ref.hash:
        if len(ref.hash) != HASH_LENGTH:
            v.fail(f"hash length {len(ref.hash)} != expected {HASH_LENGTH}")
        if not all(c in "0123456789abcdef" for c in ref.hash):
            v.fail(f"hash contains non-hex characters")

    # Must not contain raw content fields
    ref_dict = ref.to_dict()
    forbidden_fields = {"content", "data", "raw", "payload", "body", "key", "secret"}
    present_forbidden = set(ref_dict.keys()) & forbidden_fields
    if present_forbidden:
        v.fail(f"artifact contains forbidden fields: {present_forbidden}")

    return v


# ═══════════════════════════════════════════════════════════════════════════
# FINAL DECISION VALIDATION
# ═══════════════════════════════════════════════════════════════════════════

def validate_final_decision(decision: FinalDecision) -> ValidationResult:
    """Validate a FinalDecision before it reaches the operator."""
    v = ValidationResult("FinalDecision")

    if decision.disposition.value not in VALID_DISPOSITIONS:
        v.fail(f"invalid disposition: {decision.disposition}")

    if decision.gate_decision.value not in VALID_GATE_DECISIONS:
        v.fail(f"invalid gate_decision: {decision.gate_decision}")

    # If REQUIRE_APPROVAL, must have a reason
    if decision.gate_decision == GateDecision.REQUIRE_APPROVAL:
        if not decision.gate_reason:
            v.fail("REQUIRE_APPROVAL without gate_reason")

    # If DENY, must have a reason
    if decision.gate_decision == GateDecision.DENY:
        if not decision.gate_reason:
            v.fail("DENY without gate_reason")

    return v


# ═══════════════════════════════════════════════════════════════════════════
# RAW DICT VALIDATION — for adapter responses before parsing
# ═══════════════════════════════════════════════════════════════════════════

def validate_adapter_response_dict(data: Any, adapter_name: str) -> ValidationResult:
    """Validate a raw dict from an adapter before parsing into dataclass.
    This catches malformed JSON at the boundary before it enters the system."""
    v = ValidationResult(f"AdapterResponse:{adapter_name}")

    if data is None:
        v.fail("response is None")
        return v

    if not isinstance(data, (dict, str)):
        v.fail(f"response is not dict or str: {type(data)}")
        return v

    # If string, check size limit
    if isinstance(data, str):
        if len(data.encode("utf-8")) > MAX_RAW_RESPONSE_BYTES:
            v.fail(f"response exceeds {MAX_RAW_RESPONSE_BYTES} bytes")
        return v

    # Dict: check for unexpected nested depth
    def check_depth(obj, depth=0, max_depth=10):
        if depth > max_depth:
            v.fail(f"response nested depth exceeds {max_depth}")
            return
        if isinstance(obj, dict):
            for val in obj.values():
                check_depth(val, depth + 1, max_depth)
        elif isinstance(obj, list):
            for item in obj:
                check_depth(item, depth + 1, max_depth)

    check_depth(data)

    return v


# ═══════════════════════════════════════════════════════════════════════════
# ROUTE METADATA VALIDATION
# ═══════════════════════════════════════════════════════════════════════════

def validate_route_metadata(contract: JobContract) -> ValidationResult:
    """Validate route metadata consistency with contract constraints."""
    v = ValidationResult("RouteMetadata")

    # HIGH + CLAUDE = trust boundary violation
    if contract.sensitivity == Sensitivity.HIGH:
        if "CLAUDE" in contract.routes:
            v.fail("HIGH sensitivity routed to CLAUDE (cloud)")
        if "local-only" not in contract.constraints:
            v.fail("HIGH sensitivity missing local-only constraint")
        if "do-not-export" not in contract.constraints:
            v.fail("HIGH sensitivity missing do-not-export constraint")

    # MIXED must have security-veto-is-binding
    if contract.job_type == JobType.MIXED:
        if "security-veto-is-binding" not in contract.constraints:
            v.fail("MIXED job missing security-veto-is-binding constraint")

    # VALUE_MOVING must have execution-gate-required
    if contract.action_class == ActionClass.VALUE_MOVING:
        if "execution-gate-required" not in contract.constraints:
            v.fail("VALUE_MOVING missing execution-gate-required constraint")

    # Every contract must have no-secrets-in-payload
    if "no-secrets-in-payload" not in contract.constraints:
        v.fail("missing no-secrets-in-payload constraint")

    # Routes must not be empty for non-GENERAL jobs
    if contract.job_type != JobType.GENERAL and len(contract.routes) == 0:
        v.fail("non-GENERAL job has empty routes")

    return v
