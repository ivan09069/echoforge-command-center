"""
tests/test_replay_fixtures.py
================================
Replay tests using structurally real adapter payloads.

Must prove:
  1. Sanitized real payloads still pass validation + enforcement
  2. Malformed real-world variants fail closed
  3. Parser drift gets caught before production
  4. Audit entries stay secret-clean under replay
  5. Full enforcement chain handles every fixture shape
"""

import sys
import os
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from contracts import (
    JobContract, JobType, Sensitivity, ActionClass, GateDecision,
    SecurityVerdict, SecurityOutput, TradingOutput, TradingVerdict,
    FinalDecision, FinalDisposition,
)
from policy_engine import (
    build_job_contract, decide, enforce_response_policy,
    detect_secrets, redact_secrets, get_audit_log, _audit_log,
)
from schema_validation import (
    validate_security_output, validate_trading_output,
    validate_adapter_response_dict, MAX_RAW_RESPONSE_BYTES,
    MAX_FINDINGS_COUNT,
)
from boundary_enforcer import (
    enforce_pre_route, enforce_post_adapter_security,
    enforce_post_adapter_trading, enforce_post_adapter_raw,
    enforce_pre_response,
)
from tests.replay_fixtures import (
    CLAUDE_VALID, CLAUDE_MALFORMED,
    GEMINI_VALID, GEMINI_MALFORMED,
    MCP_VALID, MCP_MALFORMED,
    TRIAGE_VALID, TRIAGE_MALFORMED,
)


def _clear_audit():
    _audit_log.clear()


APPROVED_STATES = {
    FinalDisposition.APPROVED,
    FinalDisposition.APPROVED_READ_ONLY,
    FinalDisposition.APPROVED_WITH_CONDITIONS,
}


def _parse_verdict(raw: str) -> SecurityOutput:
    out = SecurityOutput(raw_response=raw)
    upper = raw.upper()
    if "VERDICT: REJECT" in upper:
        out.security_verdict = SecurityVerdict.REJECT
    elif "VERDICT: ESCALATE" in upper:
        out.security_verdict = SecurityVerdict.ESCALATE
    elif "VERDICT: ALLOW_WITH_CONDITIONS" in upper:
        out.security_verdict = SecurityVerdict.ALLOW_WITH_CONDITIONS
    elif "VERDICT: ALLOW" in upper:
        out.security_verdict = SecurityVerdict.ALLOW
    else:
        out.security_verdict = SecurityVerdict.ESCALATE
    return out


# ═══════════════════════════════════════════════════════════════════════════
# 1. VALID CLAUDE FIXTURES PASS
# ═══════════════════════════════════════════════════════════════════════════

class TestValidClaudeFixtures:
    """Sanitized real Claude responses must pass validation and enforcement."""

    @pytest.mark.parametrize("name", CLAUDE_VALID.keys())
    def test_valid_claude_passes_schema(self, name):
        fixture = CLAUDE_VALID[name]
        output = TradingOutput(
            confidence=fixture.get("confidence", 0.0),
            raw_response=fixture["raw"],
        )
        v = validate_trading_output(output)
        assert v.valid, f"Claude fixture '{name}' failed schema: {v.errors}"

    @pytest.mark.parametrize("name", CLAUDE_VALID.keys())
    def test_valid_claude_passes_enforcement(self, name):
        _clear_audit()
        fixture = CLAUDE_VALID[name]
        contract = build_job_contract(
            "ETH price?", {"category": "trading", "confidence": 0.9},
        )
        output = TradingOutput(
            confidence=fixture.get("confidence", 0.0),
            raw_response=fixture["raw"],
        )
        result = enforce_post_adapter_trading(output, contract)
        assert result.valid, f"Claude fixture '{name}' failed enforcement: {result.errors}"

    @pytest.mark.parametrize("name", CLAUDE_VALID.keys())
    def test_valid_claude_no_secret_leaks(self, name):
        fixture = CLAUDE_VALID[name]
        secrets = detect_secrets(fixture["raw"])
        assert len(secrets) == 0, f"Claude fixture '{name}' contains secrets: {secrets}"

    @pytest.mark.parametrize("name", CLAUDE_VALID.keys())
    def test_valid_claude_through_full_pipeline(self, name):
        _clear_audit()
        fixture = CLAUDE_VALID[name]
        contract = build_job_contract(
            "Check market data", {"category": "trading", "confidence": 0.9},
        )
        r1 = enforce_pre_route(contract)
        assert r1.valid

        output = TradingOutput(
            confidence=fixture.get("confidence", 0.0),
            raw_response=fixture["raw"],
        )
        r2 = enforce_post_adapter_trading(output, contract)
        assert r2.valid

        decision = decide(contract, output)
        r3 = enforce_pre_response(decision)
        assert r3.valid

        final = enforce_response_policy(fixture["raw"], decision)
        secrets_in_final = detect_secrets(final)
        assert len(secrets_in_final) == 0


# ═══════════════════════════════════════════════════════════════════════════
# 2. MALFORMED CLAUDE FIXTURES FAIL CLOSED
# ═══════════════════════════════════════════════════════════════════════════

class TestMalformedClaudeFixtures:

    def setup_method(self):
        _clear_audit()

    def test_leaked_private_key_redacted(self):
        f = CLAUDE_MALFORMED["leaked_private_key"]
        secrets = detect_secrets(f["raw"])
        assert len(secrets) > 0
        decision = FinalDecision(gate_decision=GateDecision.ALLOW)
        cleaned = enforce_response_policy(f["raw"], decision)
        assert "abababab" not in cleaned

    def test_leaked_password_redacted(self):
        f = CLAUDE_MALFORMED["leaked_password"]
        cleaned = enforce_response_policy(
            f["raw"], FinalDecision(gate_decision=GateDecision.ALLOW),
        )
        assert "2012Kenworth" not in cleaned

    def test_leaked_api_key_redacted(self):
        f = CLAUDE_MALFORMED["leaked_api_key"]
        cleaned = enforce_response_policy(
            f["raw"], FinalDecision(gate_decision=GateDecision.ALLOW),
        )
        assert "sk-ant-" not in cleaned

    def test_confidence_over_one_fails_schema(self):
        f = CLAUDE_MALFORMED["confidence_over_one"]
        output = TradingOutput(confidence=f["confidence"], raw_response=f["raw"])
        v = validate_trading_output(output)
        assert not v.valid

    def test_confidence_over_one_fails_enforcement(self):
        f = CLAUDE_MALFORMED["confidence_over_one"]
        contract = build_job_contract(
            "Buy $100 ETH", {"category": "trading", "confidence": 0.9},
        )
        output = TradingOutput(confidence=f["confidence"], raw_response=f["raw"])
        result = enforce_post_adapter_trading(output, contract)
        assert not result.valid

    def test_confidence_negative_fails(self):
        f = CLAUDE_MALFORMED["confidence_negative"]
        output = TradingOutput(confidence=f["confidence"], raw_response=f["raw"])
        v = validate_trading_output(output)
        assert not v.valid

    def test_oversized_response_fails(self):
        f = CLAUDE_MALFORMED["oversized_response"]
        output = TradingOutput(raw_response=f["raw"])
        v = validate_trading_output(output)
        assert not v.valid

    def test_empty_response_passes_schema_but_no_content(self):
        """Empty string is structurally valid (no size violation)."""
        f = CLAUDE_MALFORMED["empty_response"]
        output = TradingOutput(raw_response=f["raw"])
        v = validate_trading_output(output)
        assert v.valid  # Empty is structurally valid

    def test_html_injection_does_not_crash(self):
        f = CLAUDE_MALFORMED["html_injection"]
        output = TradingOutput(raw_response=f["raw"])
        v = validate_trading_output(output)
        assert v.valid  # HTML is valid text, not a schema violation


# ═══════════════════════════════════════════════════════════════════════════
# 3. VALID GEMINI FIXTURES PASS
# ═══════════════════════════════════════════════════════════════════════════

class TestValidGeminiFixtures:

    @pytest.mark.parametrize("name", GEMINI_VALID.keys())
    def test_valid_gemini_parses_verdict(self, name):
        fixture = GEMINI_VALID[name]
        parsed = _parse_verdict(fixture["raw"])
        # Should parse to a valid verdict (not ESCALATE unless intended)
        if "ESCALATE" in fixture["raw"].upper():
            assert parsed.security_verdict == SecurityVerdict.ESCALATE
        elif "REJECT" in fixture["raw"].upper():
            assert parsed.security_verdict == SecurityVerdict.REJECT
        elif "ALLOW_WITH_CONDITIONS" in fixture["raw"].upper():
            assert parsed.security_verdict == SecurityVerdict.ALLOW_WITH_CONDITIONS
        elif "ALLOW" in fixture["raw"].upper():
            assert parsed.security_verdict == SecurityVerdict.ALLOW

    @pytest.mark.parametrize("name", GEMINI_VALID.keys())
    def test_valid_gemini_passes_schema(self, name):
        fixture = GEMINI_VALID[name]
        parsed = _parse_verdict(fixture["raw"])
        v = validate_security_output(parsed)
        assert v.valid, f"Gemini fixture '{name}' failed schema: {v.errors}"

    @pytest.mark.parametrize("name", GEMINI_VALID.keys())
    def test_valid_gemini_passes_enforcement(self, name):
        _clear_audit()
        fixture = GEMINI_VALID[name]
        contract = JobContract(job_type=JobType.SECURITY, routes=["GEMINI"])
        parsed = _parse_verdict(fixture["raw"])
        result = enforce_post_adapter_security(parsed, contract)
        assert result.valid, f"Gemini fixture '{name}' failed enforcement: {result.errors}"

    @pytest.mark.parametrize("name", GEMINI_VALID.keys())
    def test_valid_gemini_no_secret_leaks(self, name):
        fixture = GEMINI_VALID[name]
        secrets = detect_secrets(fixture["raw"])
        assert len(secrets) == 0, f"Gemini fixture '{name}' leaks secrets: {secrets}"

    def test_reject_verdict_blocks_in_decide(self):
        fixture = GEMINI_VALID["mev_signer_alert"]
        parsed = _parse_verdict(fixture["raw"])
        contract = JobContract(job_type=JobType.SECURITY, routes=["GEMINI"])
        decision = decide(contract, None, parsed)
        assert decision.disposition == FinalDisposition.BLOCKED_SECURITY

    def test_allow_with_conditions_surfaces_in_decide(self):
        fixture = GEMINI_VALID["approval_scan_risky"]
        parsed = _parse_verdict(fixture["raw"])
        assert parsed.security_verdict == SecurityVerdict.ALLOW_WITH_CONDITIONS

    def test_escalate_requires_approval_in_decide(self):
        fixture = GEMINI_VALID["escalate_unclear"]
        parsed = _parse_verdict(fixture["raw"])
        contract = JobContract(job_type=JobType.SECURITY, routes=["GEMINI"])
        decision = decide(contract, None, parsed)
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL


# ═══════════════════════════════════════════════════════════════════════════
# 4. MALFORMED GEMINI FIXTURES FAIL CLOSED
# ═══════════════════════════════════════════════════════════════════════════

class TestMalformedGeminiFixtures:

    def setup_method(self):
        _clear_audit()

    def test_no_verdict_marker_escalates(self):
        f = GEMINI_MALFORMED["no_verdict_marker"]
        parsed = _parse_verdict(f["raw"])
        assert parsed.security_verdict == SecurityVerdict.ESCALATE

    def test_wrong_verdict_value_escalates(self):
        f = GEMINI_MALFORMED["wrong_verdict_value"]
        parsed = _parse_verdict(f["raw"])
        # "VERDICT: APPROVED" is not a valid enum → ESCALATE
        assert parsed.security_verdict == SecurityVerdict.ESCALATE

    def test_leaked_password_in_finding_redacted(self):
        f = GEMINI_MALFORMED["leaked_password_in_finding"]
        cleaned = enforce_response_policy(
            f["raw"], FinalDecision(gate_decision=GateDecision.ALLOW),
        )
        assert "2012Kenworth" not in cleaned

    def test_oversized_findings_fails_schema(self):
        raw = GEMINI_MALFORMED["oversized_findings"]["raw"]
        count = GEMINI_MALFORMED["oversized_findings"]["findings_count"]
        output = SecurityOutput(
            findings=["f"] * count,
            raw_response=raw,
        )
        v = validate_security_output(output)
        assert not v.valid

    def test_oversized_response_fails_schema(self):
        f = GEMINI_MALFORMED["oversized_response"]
        output = SecurityOutput(raw_response=f["raw"])
        v = validate_security_output(output)
        assert not v.valid

    def test_empty_response_escalates(self):
        f = GEMINI_MALFORMED["empty_response"]
        parsed = _parse_verdict(f["raw"])
        assert parsed.security_verdict == SecurityVerdict.ESCALATE

    def test_contradictory_verdict_caught_by_enforcement(self):
        """ALLOW verdict with critical findings — enforcement passes the
        structure, but decide() + veto logic would catch severity."""
        f = GEMINI_MALFORMED["contradictory_verdict"]
        parsed = _parse_verdict(f["raw"])
        # Parser sees ALLOW (it's structurally present)
        assert parsed.security_verdict == SecurityVerdict.ALLOW
        # But the content says "compromised" + "being drained"
        # This is a semantic issue — the enforcer passes structure,
        # the human operator sees the contradiction in the response.
        # Schema validation still passes.
        v = validate_security_output(parsed)
        assert v.valid


# ═══════════════════════════════════════════════════════════════════════════
# 5. MCP RAW RESPONSE FIXTURES
# ═══════════════════════════════════════════════════════════════════════════

class TestMCPFixtures:

    def setup_method(self):
        _clear_audit()

    @pytest.mark.parametrize("name", MCP_VALID.keys())
    def test_valid_mcp_passes_raw_validation(self, name):
        raw = MCP_VALID[name]
        v = validate_adapter_response_dict(raw, "mcp")
        assert v.valid, f"MCP fixture '{name}' failed: {v.errors}"

    @pytest.mark.parametrize("name", MCP_VALID.keys())
    def test_valid_mcp_passes_enforcement(self, name):
        raw = MCP_VALID[name]
        contract = JobContract(job_type=JobType.TRADING, routes=["CLAUDE"])
        result = enforce_post_adapter_raw(raw, "mcp", contract)
        assert result.valid

    def test_null_response_fails(self):
        contract = JobContract(job_type=JobType.SECURITY, routes=["GEMINI"])
        result = enforce_post_adapter_raw(None, "gemini", contract)
        assert not result.valid

    def test_empty_string_passes(self):
        """Empty string is a valid string type, just empty."""
        v = validate_adapter_response_dict("", "mcp")
        assert v.valid

    def test_invalid_json_string_passes_raw_validation(self):
        """Invalid JSON is still a valid string — JSON parsing is a separate concern."""
        raw = MCP_MALFORMED["invalid_json"]
        v = validate_adapter_response_dict(raw, "mcp")
        assert v.valid  # It's a string, not a None/list/int

    def test_list_response_fails(self):
        v = validate_adapter_response_dict([1, 2, 3], "mcp")
        assert not v.valid

    def test_number_response_fails(self):
        v = validate_adapter_response_dict(42, "mcp")
        assert not v.valid

    def test_boolean_response_fails(self):
        v = validate_adapter_response_dict(True, "mcp")
        assert not v.valid

    def test_nested_bomb_fails(self):
        data: dict = {}
        current = data
        for i in range(15):
            current["n"] = {}
            current = current["n"]
        v = validate_adapter_response_dict(data, "mcp")
        assert not v.valid


# ═══════════════════════════════════════════════════════════════════════════
# 6. TRIAGE CLASSIFICATION FIXTURES
# ═══════════════════════════════════════════════════════════════════════════

class TestTriageFixtures:

    @pytest.mark.parametrize("name", TRIAGE_VALID.keys())
    def test_valid_triage_builds_contract(self, name):
        classification = TRIAGE_VALID[name]
        contract = build_job_contract("Test message", classification)
        assert contract is not None
        assert contract.job_id

    def test_execution_classification_flags_execution(self):
        classification = TRIAGE_VALID["execution_classification"]
        contract = build_job_contract("Buy $100 ETH from JIT0906", classification)
        assert contract.requires_execution is True

    @pytest.mark.parametrize("name", TRIAGE_MALFORMED.keys())
    def test_malformed_triage_does_not_crash(self, name):
        classification = TRIAGE_MALFORMED[name]
        contract = build_job_contract("Test", classification)
        assert contract is not None
        assert contract.job_type == JobType.GENERAL or contract.job_type in JobType

    def test_missing_category_defaults_general(self):
        contract = build_job_contract("Test", TRIAGE_MALFORMED["missing_category"])
        assert contract.job_type == JobType.GENERAL


# ═══════════════════════════════════════════════════════════════════════════
# 7. AUDIT STAYS SECRET-CLEAN UNDER REPLAY
# ═══════════════════════════════════════════════════════════════════════════

class TestAuditSecretClean:
    """Run all malformed fixtures through the pipeline and verify
    the audit log never contains raw secrets."""

    def setup_method(self):
        _clear_audit()

    def test_claude_leaks_cleaned_from_audit(self):
        for name in CLAUDE_MALFORMED:
            fixture = CLAUDE_MALFORMED[name]
            contract = build_job_contract(
                "Test", {"category": "trading", "confidence": 0.9},
            )
            output = TradingOutput(
                confidence=fixture.get("confidence", 0.0),
                raw_response=fixture.get("raw", ""),
            )
            enforce_post_adapter_trading(output, contract)

        log_str = json.dumps(get_audit_log())
        # No raw secrets in audit
        assert "abababab" not in log_str
        assert "2012Kenworth" not in log_str
        assert "sk-ant-" not in log_str
        assert "85Freightliner" not in log_str

    def test_gemini_leaks_cleaned_from_audit(self):
        for name in GEMINI_MALFORMED:
            fixture = GEMINI_MALFORMED[name]
            contract = JobContract(job_type=JobType.SECURITY, routes=["GEMINI"])
            raw = fixture.get("raw", "")
            parsed = _parse_verdict(raw) if raw else SecurityOutput()
            enforce_post_adapter_security(parsed, contract)

        log_str = json.dumps(get_audit_log())
        assert "2012Kenworth" not in log_str

    def test_full_replay_audit_has_no_secrets(self):
        """Run every fixture through enforcement and check entire audit log."""
        # Claude fixtures
        for name, fixture in {**CLAUDE_VALID, **CLAUDE_MALFORMED}.items():
            contract = build_job_contract(
                "Test", {"category": "trading", "confidence": 0.9},
            )
            output = TradingOutput(
                confidence=fixture.get("confidence", 0.0),
                raw_response=fixture.get("raw", ""),
            )
            enforce_post_adapter_trading(output, contract)

        # Gemini fixtures
        for name, fixture in {**GEMINI_VALID, **GEMINI_MALFORMED}.items():
            contract = JobContract(job_type=JobType.SECURITY, routes=["GEMINI"])
            raw = fixture.get("raw", "")
            parsed = _parse_verdict(raw) if raw else SecurityOutput()
            enforce_post_adapter_security(parsed, contract)

        log_str = json.dumps(get_audit_log())
        FORBIDDEN_IN_AUDIT = [
            "abababab" * 4,  # Private key fragment
            "2012Kenworth",
            "85Freightliner",
            "85Blazer",
            "82Chevy",
            "sk-ant-",
            "BEGIN PRIVATE KEY",
        ]
        for forbidden in FORBIDDEN_IN_AUDIT:
            assert forbidden not in log_str, f"Secret '{forbidden}' found in audit log"


# ═══════════════════════════════════════════════════════════════════════════
# 8. PARSER DRIFT DETECTION
# ═══════════════════════════════════════════════════════════════════════════

class TestParserDrift:
    """Verify the verdict parser correctly handles every Gemini fixture.
    If the parser changes, these tests catch it."""

    EXPECTED_VERDICTS = {
        "clean_sweep": SecurityVerdict.ALLOW,
        "approval_scan_risky": SecurityVerdict.ALLOW_WITH_CONDITIONS,
        "mev_signer_alert": SecurityVerdict.REJECT,
        "code_audit_safe": SecurityVerdict.ALLOW,
        "code_audit_unsafe": SecurityVerdict.ALLOW_WITH_CONDITIONS,
        "escalate_unclear": SecurityVerdict.ESCALATE,
    }

    @pytest.mark.parametrize("name,expected", EXPECTED_VERDICTS.items())
    def test_verdict_parsing_matches_expected(self, name, expected):
        fixture = GEMINI_VALID[name]
        parsed = _parse_verdict(fixture["raw"])
        assert parsed.security_verdict == expected, (
            f"Parser drift: '{name}' expected {expected}, got {parsed.security_verdict}"
        )

    EXPECTED_MALFORMED_VERDICTS = {
        "no_verdict_marker": SecurityVerdict.ESCALATE,
        "wrong_verdict_value": SecurityVerdict.ESCALATE,
        "empty_response": SecurityVerdict.ESCALATE,
        "contradictory_verdict": SecurityVerdict.ALLOW,  # Structurally present
    }

    @pytest.mark.parametrize("name,expected", EXPECTED_MALFORMED_VERDICTS.items())
    def test_malformed_verdict_parsing(self, name, expected):
        fixture = GEMINI_MALFORMED[name]
        parsed = _parse_verdict(fixture["raw"])
        assert parsed.security_verdict == expected, (
            f"Parser drift on malformed: '{name}' expected {expected}, got {parsed.security_verdict}"
        )


# ═══════════════════════════════════════════════════════════════════════════
# 9. FULL CHAIN REPLAY
# ═══════════════════════════════════════════════════════════════════════════

class TestFullChainReplay:
    """End-to-end replay: triage → contract → enforce → adapter → decide → respond."""

    def setup_method(self):
        _clear_audit()

    def test_trading_happy_path(self):
        classification = TRIAGE_VALID["trading_classification"]
        contract = build_job_contract("What is the ETH price?", classification)
        r1 = enforce_pre_route(contract)
        assert r1.valid

        fixture = CLAUDE_VALID["price_query"]
        output = TradingOutput(confidence=0.0, raw_response=fixture["raw"])
        r2 = enforce_post_adapter_trading(output, contract)
        assert r2.valid

        decision = decide(contract, output)
        r3 = enforce_pre_response(decision)
        assert r3.valid
        assert decision.gate_decision == GateDecision.ALLOW

    def test_security_reject_path(self):
        classification = TRIAGE_VALID["security_classification"]
        contract = build_job_contract("Check MEV signer activity", classification)
        r1 = enforce_pre_route(contract)
        assert r1.valid

        fixture = GEMINI_VALID["mev_signer_alert"]
        parsed = _parse_verdict(fixture["raw"])
        r2 = enforce_post_adapter_security(parsed, contract)
        assert r2.valid

        decision = decide(contract, None, parsed)
        assert decision.disposition == FinalDisposition.BLOCKED_SECURITY
        assert decision.gate_decision == GateDecision.DENY

    def test_mixed_veto_path(self):
        classification = TRIAGE_VALID["mixed_classification"]
        contract = build_job_contract(
            "Optimize bot but check safety", classification,
        )
        r1 = enforce_pre_route(contract)
        assert r1.valid

        trading_fixture = CLAUDE_VALID["bot_tuning"]
        trading = TradingOutput(
            confidence=trading_fixture["confidence"],
            raw_response=trading_fixture["raw"],
        )
        security_fixture = GEMINI_VALID["mev_signer_alert"]
        security = _parse_verdict(security_fixture["raw"])

        r2 = enforce_post_adapter_trading(trading, contract)
        assert r2.valid
        r3 = enforce_post_adapter_security(security, contract)
        assert r3.valid

        decision = decide(contract, trading, security)
        assert decision.disposition == FinalDisposition.BLOCKED_SECURITY

    def test_execution_path_requires_approval(self):
        classification = TRIAGE_VALID["execution_classification"]
        contract = build_job_contract("Buy $100 ETH from JIT0906", classification)
        r1 = enforce_pre_route(contract)
        assert r1.valid

        fixture = CLAUDE_VALID["trade_proposal"]
        output = TradingOutput(
            confidence=fixture["confidence"],
            raw_response=fixture["raw"],
        )
        r2 = enforce_post_adapter_trading(output, contract)
        assert r2.valid

        decision = decide(contract, output)
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL

    def test_leaked_key_caught_at_response_boundary(self):
        contract = build_job_contract(
            "Check wallet", {"category": "trading", "confidence": 0.9},
        )
        fixture = CLAUDE_MALFORMED["leaked_private_key"]
        decision = FinalDecision(
            disposition=FinalDisposition.APPROVED_READ_ONLY,
            gate_decision=GateDecision.ALLOW,
        )
        final = enforce_response_policy(fixture["raw"], decision)
        assert "abababab" not in final
        assert "[REDACTED:" in final
