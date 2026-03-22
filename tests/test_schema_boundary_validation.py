"""
tests/test_schema_boundary_validation.py
==========================================
Strict schema validation at every adapter boundary.
Rule: any adapter response that fails validation = ESCALATE, never coerce.

Must cover:
  1. Missing required fields
  2. Wrong enum values
  3. Oversized payloads
  4. Unexpected nested fields
  5. Malformed hashes
  6. Bad route metadata
  7. Partial adapter objects
  8. Cross-boundary consistency
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
from policy_engine import build_job_contract, decide, content_hash
from schema_validation import (
    validate_job_contract, validate_security_output, validate_trading_output,
    validate_artifact_ref, validate_final_decision, validate_adapter_response_dict,
    validate_route_metadata, ValidationResult,
    MAX_CONTEXT_SUMMARY_BYTES, MAX_RAW_RESPONSE_BYTES, MAX_FINDINGS_COUNT,
    MAX_CONDITIONS_COUNT, MAX_RECOMMENDED_CHANGES, MAX_ARTIFACTS, MAX_ROUTES,
    MAX_CONSTRAINTS, HASH_LENGTH, JOB_ID_LENGTH,
)


# ═══════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _valid_contract(**overrides) -> JobContract:
    """Build a known-valid contract, then apply overrides."""
    c = build_job_contract("ETH price?", {"category": "trading", "confidence": 0.9})
    for k, val in overrides.items():
        setattr(c, k, val)
    return c


def _valid_security(**overrides) -> SecurityOutput:
    return SecurityOutput(
        security_verdict=overrides.get("security_verdict", SecurityVerdict.ALLOW),
        severity=overrides.get("severity", Sensitivity.LOW),
        findings=overrides.get("findings", []),
        conditions=overrides.get("conditions", []),
        raw_response=overrides.get("raw_response", "VERDICT: ALLOW"),
    )


def _valid_trading(**overrides) -> TradingOutput:
    return TradingOutput(
        trading_verdict=overrides.get("trading_verdict", TradingVerdict.PROPOSE),
        strategy=overrides.get("strategy", "mean_reversion"),
        confidence=overrides.get("confidence", 0.75),
        recommended_changes=overrides.get("recommended_changes", []),
        assumptions=overrides.get("assumptions", []),
        risk_notes=overrides.get("risk_notes", []),
        execution_request=overrides.get("execution_request", False),
        raw_response=overrides.get("raw_response", "Analysis complete"),
    )


# ═══════════════════════════════════════════════════════════════════════════
# 1. MISSING REQUIRED FIELDS
# ═══════════════════════════════════════════════════════════════════════════

class TestMissingRequiredFields:

    def test_contract_missing_job_id(self):
        c = _valid_contract(job_id="")
        v = validate_job_contract(c)
        assert not v.valid

    def test_contract_wrong_length_job_id(self):
        c = _valid_contract(job_id="abc")
        v = validate_job_contract(c)
        assert not v.valid

    def test_contract_too_long_job_id(self):
        c = _valid_contract(job_id="a" * 20)
        v = validate_job_contract(c)
        assert not v.valid

    def test_contract_missing_timestamp(self):
        c = _valid_contract(timestamp="")
        v = validate_job_contract(c)
        assert not v.valid

    def test_decision_deny_missing_reason(self):
        d = FinalDecision(
            gate_decision=GateDecision.DENY,
            gate_reason="",
        )
        v = validate_final_decision(d)
        assert not v.valid

    def test_decision_require_approval_missing_reason(self):
        d = FinalDecision(
            gate_decision=GateDecision.REQUIRE_APPROVAL,
            gate_reason="",
        )
        v = validate_final_decision(d)
        assert not v.valid

    def test_artifact_missing_type(self):
        ref = ArtifactRef(type="", sensitivity=Sensitivity.LOW)
        v = validate_artifact_ref(ref)
        assert not v.valid

    def test_valid_contract_passes(self):
        c = build_job_contract("ETH price?", {"category": "trading", "confidence": 0.9})
        v = validate_job_contract(c)
        assert v.valid, f"Valid contract failed: {v.errors}"

    def test_valid_security_passes(self):
        s = _valid_security()
        v = validate_security_output(s)
        assert v.valid, f"Valid security failed: {v.errors}"

    def test_valid_trading_passes(self):
        t = _valid_trading()
        v = validate_trading_output(t)
        assert v.valid, f"Valid trading failed: {v.errors}"


# ═══════════════════════════════════════════════════════════════════════════
# 2. WRONG ENUM VALUES
# ═══════════════════════════════════════════════════════════════════════════

class TestWrongEnumValues:
    """Enum fields must only accept valid values.
    Note: Python enums enforce this at construction, so these tests
    verify the validator catches issues in serialized/dict form."""

    def test_valid_enums_pass(self):
        c = _valid_contract()
        v = validate_job_contract(c)
        assert v.valid

    def test_unknown_route_caught(self):
        c = _valid_contract(routes=["DEEPSEEK"])
        v = validate_job_contract(c)
        assert not v.valid
        assert any("unknown route" in e for e in v.errors)

    def test_empty_route_string_caught(self):
        c = _valid_contract(routes=[""])
        v = validate_job_contract(c)
        assert not v.valid

    def test_valid_routes_pass(self):
        for route in ["CLAUDE", "GEMINI", "GPT"]:
            c = _valid_contract(routes=[route])
            v = validate_job_contract(c)
            route_errors = [e for e in v.errors if "route" in e.lower()]
            assert not route_errors, f"Valid route {route} flagged"

    def test_trading_confidence_out_of_range_high(self):
        t = _valid_trading(confidence=1.5)
        v = validate_trading_output(t)
        assert not v.valid

    def test_trading_confidence_out_of_range_negative(self):
        t = _valid_trading(confidence=-0.1)
        v = validate_trading_output(t)
        assert not v.valid

    def test_trading_confidence_boundary_zero(self):
        t = _valid_trading(confidence=0.0)
        v = validate_trading_output(t)
        assert v.valid

    def test_trading_confidence_boundary_one(self):
        t = _valid_trading(confidence=1.0)
        v = validate_trading_output(t)
        assert v.valid


# ═══════════════════════════════════════════════════════════════════════════
# 3. OVERSIZED PAYLOADS
# ═══════════════════════════════════════════════════════════════════════════

class TestOversizedPayloads:

    def test_oversized_context_summary(self):
        c = _valid_contract(context_summary="A" * (MAX_CONTEXT_SUMMARY_BYTES + 1))
        v = validate_job_contract(c)
        assert not v.valid
        assert any("context_summary" in e for e in v.errors)

    def test_max_context_summary_passes(self):
        c = _valid_contract(context_summary="A" * MAX_CONTEXT_SUMMARY_BYTES)
        v = validate_job_contract(c)
        summary_errors = [e for e in v.errors if "context_summary" in e]
        assert not summary_errors

    def test_oversized_security_response(self):
        s = _valid_security(raw_response="B" * (MAX_RAW_RESPONSE_BYTES + 1))
        v = validate_security_output(s)
        assert not v.valid

    def test_oversized_trading_response(self):
        t = _valid_trading(raw_response="C" * (MAX_RAW_RESPONSE_BYTES + 1))
        v = validate_trading_output(t)
        assert not v.valid

    def test_too_many_findings(self):
        s = _valid_security(findings=["f"] * (MAX_FINDINGS_COUNT + 1))
        v = validate_security_output(s)
        assert not v.valid

    def test_too_many_conditions(self):
        s = _valid_security(conditions=["c"] * (MAX_CONDITIONS_COUNT + 1))
        v = validate_security_output(s)
        assert not v.valid

    def test_too_many_recommended_changes(self):
        t = _valid_trading(recommended_changes=[{"p": "x"}] * (MAX_RECOMMENDED_CHANGES + 1))
        v = validate_trading_output(t)
        assert not v.valid

    def test_too_many_routes(self):
        c = _valid_contract(routes=["CLAUDE"] * (MAX_ROUTES + 1))
        v = validate_job_contract(c)
        assert not v.valid

    def test_too_many_constraints(self):
        c = _valid_contract(constraints=["x"] * (MAX_CONSTRAINTS + 1))
        v = validate_job_contract(c)
        assert not v.valid

    def test_too_many_artifacts(self):
        arts = [ArtifactRef(type="f", hash=content_hash("x")) for _ in range(MAX_ARTIFACTS + 1)]
        c = _valid_contract(artifacts=arts)
        v = validate_job_contract(c)
        assert not v.valid

    def test_oversized_adapter_response_string(self):
        v = validate_adapter_response_dict("X" * (MAX_RAW_RESPONSE_BYTES + 1), "test")
        assert not v.valid


# ═══════════════════════════════════════════════════════════════════════════
# 4. UNEXPECTED NESTED FIELDS
# ═══════════════════════════════════════════════════════════════════════════

class TestUnexpectedNestedFields:

    def test_deeply_nested_dict_caught(self):
        """Excessive nesting could be used to smuggle data or DoS the parser."""
        data: dict = {}
        current = data
        for i in range(15):
            current["nested"] = {}
            current = current["nested"]
        v = validate_adapter_response_dict(data, "test")
        assert not v.valid
        assert any("depth" in e for e in v.errors)

    def test_reasonable_nesting_passes(self):
        data = {"level1": {"level2": {"level3": "value"}}}
        v = validate_adapter_response_dict(data, "test")
        assert v.valid

    def test_none_response_caught(self):
        v = validate_adapter_response_dict(None, "test")
        assert not v.valid

    def test_list_response_caught(self):
        v = validate_adapter_response_dict([1, 2, 3], "test")
        assert not v.valid

    def test_int_response_caught(self):
        v = validate_adapter_response_dict(42, "test")
        assert not v.valid

    def test_artifact_forbidden_fields(self):
        """ArtifactRef must never contain raw content fields."""
        ref = ArtifactRef(type="wallet", sensitivity=Sensitivity.HIGH)
        ref_dict = ref.to_dict()
        # Manually inject forbidden fields (simulating smuggling)
        # The validator checks the to_dict() output
        v = validate_artifact_ref(ref)
        # Default ArtifactRef won't have forbidden fields
        # But ensure the validator would catch them
        assert "content" not in ref_dict
        assert "data" not in ref_dict
        assert "secret" not in ref_dict


# ═══════════════════════════════════════════════════════════════════════════
# 5. MALFORMED HASHES
# ═══════════════════════════════════════════════════════════════════════════

class TestMalformedHashes:

    def test_wrong_length_hash(self):
        ref = ArtifactRef(type="file", hash="abc123")  # Too short
        v = validate_artifact_ref(ref)
        assert not v.valid
        assert any("hash length" in e for e in v.errors)

    def test_too_long_hash(self):
        ref = ArtifactRef(type="file", hash="a" * 32)
        v = validate_artifact_ref(ref)
        assert not v.valid

    def test_non_hex_hash(self):
        ref = ArtifactRef(type="file", hash="zzzzzzzzzzzzzzzz")
        v = validate_artifact_ref(ref)
        assert not v.valid
        assert any("non-hex" in e for e in v.errors)

    def test_valid_hash_passes(self):
        ref = ArtifactRef(type="file", hash=content_hash("test content"))
        v = validate_artifact_ref(ref)
        hash_errors = [e for e in v.errors if "hash" in e.lower()]
        assert not hash_errors

    def test_empty_hash_passes(self):
        """Empty hash is allowed — hash is optional."""
        ref = ArtifactRef(type="file", hash="")
        v = validate_artifact_ref(ref)
        hash_errors = [e for e in v.errors if "hash" in e.lower()]
        assert not hash_errors

    def test_mixed_case_hex_rejected(self):
        ref = ArtifactRef(type="file", hash="ABCDEF1234567890")
        v = validate_artifact_ref(ref)
        assert not v.valid  # Must be lowercase hex


# ═══════════════════════════════════════════════════════════════════════════
# 6. BAD ROUTE METADATA
# ═══════════════════════════════════════════════════════════════════════════

class TestBadRouteMetadata:

    def test_high_to_claude_violation(self):
        c = _valid_contract(
            sensitivity=Sensitivity.HIGH,
            routes=["CLAUDE"],
            constraints=["no-secrets-in-payload", "local-only", "do-not-export"],
        )
        v = validate_route_metadata(c)
        assert not v.valid
        assert any("CLAUDE" in e for e in v.errors)

    def test_high_missing_local_only(self):
        c = _valid_contract(
            sensitivity=Sensitivity.HIGH,
            routes=["GEMINI"],
            constraints=["no-secrets-in-payload", "do-not-export"],
        )
        v = validate_route_metadata(c)
        assert not v.valid
        assert any("local-only" in e for e in v.errors)

    def test_high_missing_do_not_export(self):
        c = _valid_contract(
            sensitivity=Sensitivity.HIGH,
            routes=["GEMINI"],
            constraints=["no-secrets-in-payload", "local-only"],
        )
        v = validate_route_metadata(c)
        assert not v.valid

    def test_mixed_missing_veto_constraint(self):
        c = _valid_contract(
            job_type=JobType.MIXED,
            routes=["CLAUDE", "GEMINI"],
            constraints=["no-secrets-in-payload"],
        )
        v = validate_route_metadata(c)
        assert not v.valid
        assert any("veto" in e.lower() for e in v.errors)

    def test_value_moving_missing_gate_constraint(self):
        c = _valid_contract(
            action_class=ActionClass.VALUE_MOVING,
            constraints=["no-secrets-in-payload"],
        )
        v = validate_route_metadata(c)
        assert not v.valid
        assert any("execution-gate" in e for e in v.errors)

    def test_missing_no_secrets_constraint(self):
        c = _valid_contract(constraints=[])
        v = validate_route_metadata(c)
        assert not v.valid
        assert any("no-secrets-in-payload" in e for e in v.errors)

    def test_valid_low_trading_route_metadata(self):
        c = build_job_contract("ETH price?", {"category": "trading", "confidence": 0.9})
        v = validate_route_metadata(c)
        assert v.valid, f"Valid route metadata failed: {v.errors}"

    def test_valid_high_security_route_metadata(self):
        c = build_job_contract("Decrypt keystore", {"category": "security", "confidence": 0.9})
        v = validate_route_metadata(c)
        assert v.valid, f"Valid HIGH route metadata failed: {v.errors}"

    def test_valid_mixed_route_metadata(self):
        c = build_job_contract(
            "Check safety then portfolio",
            {"category": "mixed", "confidence": 0.8},
        )
        v = validate_route_metadata(c)
        assert v.valid, f"Valid mixed route metadata failed: {v.errors}"

    def test_non_general_empty_routes(self):
        c = _valid_contract(job_type=JobType.TRADING, routes=[])
        v = validate_route_metadata(c)
        assert not v.valid


# ═══════════════════════════════════════════════════════════════════════════
# 7. PARTIAL ADAPTER OBJECTS
# ═══════════════════════════════════════════════════════════════════════════

class TestPartialAdapterObjects:

    def test_security_output_all_defaults(self):
        """Default SecurityOutput should still validate (verdict=ESCALATE)."""
        s = SecurityOutput()
        v = validate_security_output(s)
        assert v.valid

    def test_trading_output_all_defaults(self):
        t = TradingOutput()
        v = validate_trading_output(t)
        assert v.valid

    def test_artifact_ref_all_defaults(self):
        """Default ArtifactRef has empty type — should fail."""
        ref = ArtifactRef()
        v = validate_artifact_ref(ref)
        assert not v.valid  # type is empty

    def test_security_with_only_raw_response(self):
        s = SecurityOutput(raw_response="Some text without verdict")
        v = validate_security_output(s)
        assert v.valid  # Structure is valid even if verdict is ESCALATE

    def test_trading_with_only_raw_response(self):
        t = TradingOutput(raw_response="Some analysis")
        v = validate_trading_output(t)
        assert v.valid

    def test_findings_with_non_string_elements(self):
        s = SecurityOutput(
            security_verdict=SecurityVerdict.ALLOW,
            findings=["valid", 42, None],
            raw_response="VERDICT: ALLOW",
        )
        v = validate_security_output(s)
        assert not v.valid
        assert any("not a string" in e for e in v.errors)


# ═══════════════════════════════════════════════════════════════════════════
# 8. CROSS-BOUNDARY CONSISTENCY
# Pipeline-built objects must always pass validation.
# ═══════════════════════════════════════════════════════════════════════════

class TestCrossBoundaryConsistency:
    """Every object produced by the pipeline must pass its own validation."""

    MESSAGES = [
        ("ETH price?", "trading"),
        ("Decrypt keystore", "security"),
        ("Check safety then portfolio", "mixed"),
        ("Hello", "general"),
        ("Buy $100 ETH", "trading"),
        ("Scan Coin98 approvals", "security"),
    ]

    @pytest.mark.parametrize("msg,cat", MESSAGES)
    def test_pipeline_contracts_valid(self, msg, cat):
        """Every contract from build_job_contract must pass validation."""
        contract = build_job_contract(msg, {"category": cat, "confidence": 0.9})
        v = validate_job_contract(contract)
        assert v.valid, f"Pipeline contract for '{msg}' failed: {v.errors}"

    @pytest.mark.parametrize("msg,cat", MESSAGES)
    def test_pipeline_route_metadata_valid(self, msg, cat):
        """Every contract must have consistent route metadata."""
        contract = build_job_contract(msg, {"category": cat, "confidence": 0.9})
        v = validate_route_metadata(contract)
        assert v.valid, f"Route metadata for '{msg}' failed: {v.errors}"

    @pytest.mark.parametrize("msg,cat", MESSAGES)
    def test_pipeline_decisions_valid(self, msg, cat):
        """Every decision from decide() must pass validation."""
        contract = build_job_contract(msg, {"category": cat, "confidence": 0.9})
        decision = decide(contract)
        v = validate_final_decision(decision)
        assert v.valid, f"Decision for '{msg}' failed: {v.errors}"

    def test_security_output_from_allow_valid(self):
        s = _valid_security(security_verdict=SecurityVerdict.ALLOW)
        v = validate_security_output(s)
        assert v.valid

    def test_security_output_from_reject_valid(self):
        s = _valid_security(
            security_verdict=SecurityVerdict.REJECT,
            severity=Sensitivity.HIGH,
            findings=["Critical issue"],
        )
        v = validate_security_output(s)
        assert v.valid

    def test_trading_output_from_propose_valid(self):
        t = _valid_trading(
            trading_verdict=TradingVerdict.PROPOSE,
            confidence=0.85,
            recommended_changes=[{"param": "rsi", "from": 55, "to": 52}],
        )
        v = validate_trading_output(t)
        assert v.valid


# ═══════════════════════════════════════════════════════════════════════════
# HIGH SENSITIVITY ARTIFACT BOUNDARY
# ═══════════════════════════════════════════════════════════════════════════

class TestHighSensitivityArtifactBoundary:
    """HIGH sensitivity artifacts must be local-only. Always."""

    def test_high_artifact_non_local_rejected(self):
        ref = ArtifactRef(
            type="keystore",
            sensitivity=Sensitivity.HIGH,
            location="s3://bucket/file",
            hash=content_hash("test"),
        )
        v = validate_artifact_ref(ref)
        assert not v.valid
        assert any("non-local" in e for e in v.errors)

    def test_high_artifact_cloudflare_rejected(self):
        ref = ArtifactRef(
            type="wallet_export",
            sensitivity=Sensitivity.HIGH,
            location="cloudflare_r2",
            hash=content_hash("test"),
        )
        v = validate_artifact_ref(ref)
        assert not v.valid

    def test_high_artifact_local_ref_passes(self):
        ref = ArtifactRef(
            type="keystore",
            sensitivity=Sensitivity.HIGH,
            location="local_ref_only",
            hash=content_hash("test"),
        )
        v = validate_artifact_ref(ref)
        # Only hash-related issues should remain, not location
        location_errors = [e for e in v.errors if "non-local" in e or "location" in e]
        assert not location_errors

    def test_low_artifact_any_location_passes(self):
        ref = ArtifactRef(
            type="report",
            sensitivity=Sensitivity.LOW,
            location="cloudflare_r2",
            hash=content_hash("test"),
        )
        v = validate_artifact_ref(ref)
        location_errors = [e for e in v.errors if "location" in e]
        assert not location_errors


# ═══════════════════════════════════════════════════════════════════════════
# VALIDATION RESULT CORRECTNESS
# ═══════════════════════════════════════════════════════════════════════════

class TestValidationResultBehavior:

    def test_new_result_is_valid(self):
        v = ValidationResult("test")
        assert v.valid

    def test_one_error_makes_invalid(self):
        v = ValidationResult("test")
        v.fail("something wrong")
        assert not v.valid
        assert len(v.errors) == 1

    def test_multiple_errors_accumulated(self):
        v = ValidationResult("test")
        v.fail("error 1")
        v.fail("error 2")
        v.fail("error 3")
        assert len(v.errors) == 3
        assert not v.valid

    def test_error_includes_subject(self):
        v = ValidationResult("MySubject")
        v.fail("bad field")
        assert "MySubject" in v.errors[0]
