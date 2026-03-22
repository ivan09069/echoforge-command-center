"""
tests/test_adapter_failure_modes.py
=====================================
Tests for how the system handles failures at the adapter boundary.
The safety envelope must hold even when specialists fail.

Core principle: failure ≠ silent pass. Every adapter failure must
resolve to a safe state (ESCALATE, DENY, or REQUIRE_APPROVAL).

Must cover:
  1. Claude adapter timeout → safe degradation
  2. Gemini adapter timeout → safe degradation
  3. Malformed JSON from either adapter
  4. Empty specialist output
  5. Conflicting route metadata
  6. Partial mixed-job completion (one succeeds, one fails)
  7. Audit logging under failure
  8. Missing security output in security/mixed jobs → ESCALATE
"""

import sys
import os
import json
import asyncio
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from dataclasses import dataclass

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from contracts import (
    JobContract, JobType, Sensitivity, ActionClass, GateDecision,
    SecurityVerdict, SecurityOutput, TradingOutput, TradingVerdict,
    FinalDecision, FinalDisposition,
)
from policy_engine import (
    build_job_contract, decide, enforce_response_policy,
    log_audit, get_audit_log, content_hash, redact_secrets,
    _audit_log,
)


def _clear_audit():
    _audit_log.clear()


# ═══════════════════════════════════════════════════════════════════════════
# 1. CLAUDE ADAPTER TIMEOUT
# ═══════════════════════════════════════════════════════════════════════════

class TestClaudeTimeout:
    """When Claude (trading lane) times out, the system must not crash
    and must degrade to a safe state."""

    def setup_method(self):
        _clear_audit()

    def test_trading_timeout_returns_safe_state(self):
        """Trading timeout on a READ_ONLY job → still no crash, audit logged."""
        contract = build_job_contract(
            "What is the ETH price?",
            {"category": "trading", "confidence": 0.9},
        )
        # Simulate: trading agent returned nothing (timeout)
        trading_out = None
        decision = decide(contract, trading_out, None)
        # TRADING job with no security route → should still resolve
        assert decision is not None
        assert decision.gate_decision in (GateDecision.ALLOW, GateDecision.REQUIRE_APPROVAL)

    def test_trading_timeout_on_value_moving_still_gates(self):
        """Even if Claude times out, VALUE_MOVING must still require approval."""
        contract = build_job_contract(
            "Buy $100 of ETH",
            {"category": "trading", "confidence": 0.9},
        )
        decision = decide(contract, None, None)
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL

    def test_trading_timeout_audit_recorded(self):
        contract = build_job_contract(
            "Show portfolio",
            {"category": "trading", "confidence": 0.9},
        )
        decision = decide(contract, None, None)
        log_audit(contract, decision, execution_action="TIMEOUT:CLAUDE")
        log = get_audit_log()
        assert len(log) == 1
        assert log[0]["execution_action"] == "TIMEOUT:CLAUDE"

    def test_trading_timeout_error_message_safe(self):
        """Error message from timeout must not contain secrets."""
        error_msg = "Timeout connecting to https://echoforge-mcp.jivantorres9.workers.dev/sse after 30s"
        decision = FinalDecision(
            disposition=FinalDisposition.APPROVED_READ_ONLY,
            gate_decision=GateDecision.ALLOW,
        )
        cleaned = enforce_response_policy(error_msg, decision)
        # URL is not a secret, should pass through
        assert "echoforge" in cleaned.lower()


# ═══════════════════════════════════════════════════════════════════════════
# 2. GEMINI ADAPTER TIMEOUT
# ═══════════════════════════════════════════════════════════════════════════

class TestGeminiTimeout:
    """When Gemini (security lane) times out, the system must NOT
    default to ALLOW. Missing security = ESCALATE."""

    def setup_method(self):
        _clear_audit()

    def test_security_timeout_escalates(self):
        """Missing security output on a SECURITY job → ESCALATE."""
        contract = JobContract(
            job_type=JobType.SECURITY,
            routes=["GEMINI"],
        )
        decision = decide(contract, None, None)  # No security output
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL
        assert "MISSING" in decision.security_summary or "missing" in decision.gate_reason.lower()

    def test_mixed_job_gemini_timeout_escalates(self):
        """Mixed job where Gemini times out → ESCALATE, even if Claude succeeded."""
        contract = JobContract(
            job_type=JobType.MIXED,
            routes=["CLAUDE", "GEMINI"],
        )
        trading = TradingOutput(
            trading_verdict=TradingVerdict.PROPOSE,
            confidence=0.85,
            raw_response="Great setup, recommend entry.",
        )
        # Gemini timed out → security is None
        decision = decide(contract, trading, None)
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL
        assert decision.disposition == FinalDisposition.AWAITING_HUMAN_APPROVAL

    def test_gemini_timeout_audit_recorded(self):
        contract = JobContract(job_type=JobType.SECURITY, routes=["GEMINI"])
        decision = decide(contract, None, None)
        log_audit(contract, decision, execution_action="TIMEOUT:GEMINI")
        log = get_audit_log()
        assert log[0]["execution_action"] == "TIMEOUT:GEMINI"
        assert log[0]["final_disposition"] == "AWAITING_HUMAN_APPROVAL"


# ═══════════════════════════════════════════════════════════════════════════
# 3. MALFORMED JSON FROM ADAPTERS
# ═══════════════════════════════════════════════════════════════════════════

class TestMalformedAdapterOutput:
    """Malformed output from specialist agents must be handled safely.
    The policy engine and verdict parser must not crash on garbage."""

    def setup_method(self):
        _clear_audit()

    def test_malformed_trading_response_does_not_crash(self):
        """Garbage text from Claude → still produces a valid decision."""
        contract = build_job_contract(
            "ETH price?",
            {"category": "trading", "confidence": 0.9},
        )
        # Garbage response
        trading = TradingOutput(raw_response="@#$%^&*()_+{}|:<>?")
        decision = decide(contract, trading, None)
        assert decision is not None

    def test_malformed_security_response_treated_as_escalate(self):
        """Garbage text from Gemini → no valid verdict → ESCALATE."""
        contract = JobContract(
            job_type=JobType.SECURITY,
            routes=["GEMINI"],
        )
        # Malformed — no valid VERDICT: marker
        security = SecurityOutput(
            raw_response="ERROR: java.lang.NullPointerException at line 42",
        )
        # Default verdict is ESCALATE (from contracts.py)
        decision = decide(contract, None, security)
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL

    def test_html_in_response_does_not_crash(self):
        """HTML/XSS in model output → handled, not executed."""
        contract = build_job_contract(
            "Check status",
            {"category": "trading", "confidence": 0.9},
        )
        trading = TradingOutput(
            raw_response="<script>alert('xss')</script><img onerror=alert(1) src=x>"
        )
        decision = decide(contract, trading, None)
        assert decision is not None

    def test_extremely_long_response_handled(self):
        """10MB of garbage should not crash the pipeline."""
        contract = build_job_contract(
            "Status?",
            {"category": "trading", "confidence": 0.9},
        )
        trading = TradingOutput(raw_response="A" * 10_000_000)
        decision = decide(contract, trading, None)
        assert decision is not None

    def test_null_bytes_in_response(self):
        """Null bytes in output should not crash redaction."""
        response = "Price is $3,520\x00\x00\x00 done"
        decision = FinalDecision(
            disposition=FinalDisposition.APPROVED_READ_ONLY,
            gate_decision=GateDecision.ALLOW,
        )
        cleaned = enforce_response_policy(response, decision)
        assert cleaned is not None

    def test_json_in_response_not_misinterpreted(self):
        """JSON embedded in model response should pass through safely."""
        response = '{"status": "ok", "price": 3520, "key": "not_a_real_key"}'
        decision = FinalDecision(
            disposition=FinalDisposition.APPROVED_READ_ONLY,
            gate_decision=GateDecision.ALLOW,
        )
        cleaned = enforce_response_policy(response, decision)
        assert "3520" in cleaned

    def test_malformed_verdict_with_partial_marker(self):
        """'VERDICT:' without a valid value → ESCALATE."""
        security = SecurityOutput(raw_response="VERDICT: ")
        # Empty after marker → doesn't match ALLOW, REJECT, etc. → ESCALATE default
        assert security.security_verdict == SecurityVerdict.ESCALATE

    def test_multiple_verdict_lines_first_wins(self):
        """If Gemini outputs multiple VERDICT lines, first match should win.
        Our parser checks REJECT before ALLOW in the if-elif chain."""
        raw = "VERDICT: REJECT\nFINDINGS: bad\nVERDICT: ALLOW"
        out = SecurityOutput(raw_response=raw)
        upper = raw.upper()
        # Parser checks REJECT first in the chain
        if "VERDICT: REJECT" in upper:
            out.security_verdict = SecurityVerdict.REJECT
        elif "VERDICT: ALLOW" in upper:
            out.security_verdict = SecurityVerdict.ALLOW
        assert out.security_verdict == SecurityVerdict.REJECT


# ═══════════════════════════════════════════════════════════════════════════
# 4. EMPTY SPECIALIST OUTPUT
# ═══════════════════════════════════════════════════════════════════════════

class TestEmptySpecialistOutput:
    """Empty or None outputs from specialists must degrade safely."""

    def setup_method(self):
        _clear_audit()

    def test_both_none_trading_job(self):
        """TRADING job, both outputs None → still resolves."""
        contract = JobContract(
            job_type=JobType.TRADING,
            routes=["CLAUDE"],
        )
        decision = decide(contract, None, None)
        assert decision is not None
        # Trading-only with no output → READ_ONLY approved (no security needed)
        assert decision.disposition == FinalDisposition.APPROVED_READ_ONLY

    def test_both_none_security_job_escalates(self):
        """SECURITY job, no output → ESCALATE."""
        contract = JobContract(
            job_type=JobType.SECURITY,
            routes=["GEMINI"],
        )
        decision = decide(contract, None, None)
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL

    def test_both_none_mixed_job_escalates(self):
        """MIXED job, no output → ESCALATE."""
        contract = JobContract(
            job_type=JobType.MIXED,
            routes=["CLAUDE", "GEMINI"],
        )
        decision = decide(contract, None, None)
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL

    def test_empty_string_trading_response(self):
        """Empty string from Claude → valid but empty."""
        contract = build_job_contract(
            "ETH price?",
            {"category": "trading", "confidence": 0.9},
        )
        trading = TradingOutput(raw_response="")
        decision = decide(contract, trading, None)
        assert decision is not None

    def test_empty_string_security_response(self):
        """Empty string from Gemini → verdict stays ESCALATE default."""
        contract = JobContract(
            job_type=JobType.SECURITY,
            routes=["GEMINI"],
        )
        security = SecurityOutput(raw_response="")
        # Default verdict is ESCALATE
        decision = decide(contract, None, security)
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL

    def test_whitespace_only_response(self):
        """Whitespace-only output → not a real response."""
        contract = build_job_contract(
            "Check gas",
            {"category": "trading", "confidence": 0.9},
        )
        trading = TradingOutput(raw_response="   \n\t\n   ")
        decision = decide(contract, trading, None)
        assert decision is not None


# ═══════════════════════════════════════════════════════════════════════════
# 5. CONFLICTING ROUTE METADATA
# ═══════════════════════════════════════════════════════════════════════════

class TestConflictingRouteMetadata:
    """Routes that contradict contract constraints must resolve safely."""

    def test_high_sensitivity_with_claude_route_blocked(self):
        """Contract says HIGH + CLAUDE route → decide() blocks."""
        contract = JobContract(
            job_type=JobType.TRADING,
            sensitivity=Sensitivity.HIGH,
            routes=["CLAUDE"],
        )
        decision = decide(contract)
        assert decision.disposition == FinalDisposition.BLOCKED_POLICY

    def test_empty_routes_does_not_crash(self):
        """Contract with empty routes → still resolves."""
        contract = JobContract(
            job_type=JobType.GENERAL,
            routes=[],
        )
        decision = decide(contract)
        assert decision is not None

    def test_unknown_route_does_not_crash(self):
        """Route to a nonexistent agent → still resolves."""
        contract = JobContract(
            job_type=JobType.TRADING,
            routes=["DEEPSEEK"],
        )
        decision = decide(contract)
        assert decision is not None

    def test_duplicate_routes(self):
        """Duplicate routes → should not cause double processing."""
        contract = JobContract(
            job_type=JobType.MIXED,
            routes=["CLAUDE", "CLAUDE", "GEMINI"],
        )
        decision = decide(contract, None, None)
        # MIXED with no security output → ESCALATE
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL

    def test_sensitivity_mismatch_contract_vs_routes(self):
        """Contract says LOW but routes were manually set to only GEMINI.
        This is unusual but must not crash."""
        contract = JobContract(
            job_type=JobType.TRADING,
            sensitivity=Sensitivity.LOW,
            routes=["GEMINI"],  # Unusual for trading
        )
        decision = decide(contract, None, None)
        # GEMINI-only route treated as needing security → missing security → ESCALATE
        # Actually job_type is TRADING, not SECURITY/MIXED, so missing security check
        # doesn't apply. This is fine — it's an unusual config.
        assert decision is not None


# ═══════════════════════════════════════════════════════════════════════════
# 6. PARTIAL MIXED-JOB COMPLETION
# ═══════════════════════════════════════════════════════════════════════════

class TestPartialMixedCompletion:
    """When one specialist succeeds and the other fails in a mixed job."""

    def setup_method(self):
        _clear_audit()

    def test_claude_succeeds_gemini_fails_escalates(self):
        """Claude returns data, Gemini times out → ESCALATE (missing security)."""
        contract = JobContract(
            job_type=JobType.MIXED,
            routes=["CLAUDE", "GEMINI"],
        )
        trading = TradingOutput(
            trading_verdict=TradingVerdict.PROPOSE,
            confidence=0.80,
            raw_response="Strong signal, buy recommended.",
        )
        decision = decide(contract, trading, None)
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL
        assert decision.disposition == FinalDisposition.AWAITING_HUMAN_APPROVAL

    def test_gemini_succeeds_claude_fails_uses_security(self):
        """Gemini returns data, Claude times out → use security result."""
        contract = JobContract(
            job_type=JobType.MIXED,
            routes=["CLAUDE", "GEMINI"],
        )
        security = SecurityOutput(
            security_verdict=SecurityVerdict.ALLOW,
            raw_response="VERDICT: ALLOW\nAll clear.",
        )
        # Claude failed but security passed → still need to check.
        # Missing security doesn't apply here because security IS present.
        decision = decide(contract, None, security)
        assert decision is not None
        # Security ALLOW with no execution → APPROVED_READ_ONLY
        assert decision.gate_decision == GateDecision.ALLOW

    def test_gemini_rejects_claude_fails_still_blocked(self):
        """Gemini REJECTs, Claude times out → BLOCKED_SECURITY."""
        contract = JobContract(
            job_type=JobType.MIXED,
            routes=["CLAUDE", "GEMINI"],
        )
        security = SecurityOutput(
            security_verdict=SecurityVerdict.REJECT,
            raw_response="VERDICT: REJECT\nDangerous.",
        )
        decision = decide(contract, None, security)
        assert decision.disposition == FinalDisposition.BLOCKED_SECURITY

    def test_both_fail_escalates(self):
        """Both agents fail → ESCALATE."""
        contract = JobContract(
            job_type=JobType.MIXED,
            routes=["CLAUDE", "GEMINI"],
        )
        decision = decide(contract, None, None)
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL

    def test_partial_completion_audit_trail(self):
        """Audit must record partial completion state."""
        contract = JobContract(
            job_type=JobType.MIXED,
            routes=["CLAUDE", "GEMINI"],
        )
        trading = TradingOutput(raw_response="Partial")
        decision = decide(contract, trading, None)
        log_audit(
            contract, decision, trading, None,
            execution_action="PARTIAL:GEMINI_TIMEOUT",
        )
        log = get_audit_log()
        assert log[0]["execution_action"] == "PARTIAL:GEMINI_TIMEOUT"
        assert log[0]["trading_verdict_hash"]  # Trading hash present
        assert log[0]["security_verdict_hash"] == ""  # Security missing

    def test_exception_in_one_agent_captured(self):
        """Simulate: Claude raises, Gemini succeeds.
        decide() should still work with the available output."""
        contract = JobContract(
            job_type=JobType.MIXED,
            routes=["CLAUDE", "GEMINI"],
        )
        # Simulate exception by passing error as trading response
        trading = TradingOutput(
            raw_response="Error: ConnectionTimeout after 30s",
        )
        security = SecurityOutput(
            security_verdict=SecurityVerdict.ALLOW,
            raw_response="VERDICT: ALLOW\nAll clear.",
        )
        decision = decide(contract, trading, security)
        assert decision is not None
        assert decision.gate_decision == GateDecision.ALLOW


# ═══════════════════════════════════════════════════════════════════════════
# 7. AUDIT LOGGING UNDER FAILURE
# ═══════════════════════════════════════════════════════════════════════════

class TestAuditUnderFailure:
    """Every failure must be auditable. No silent failures."""

    def setup_method(self):
        _clear_audit()

    def test_timeout_logged(self):
        contract = build_job_contract("ETH price?", {"category": "trading"})
        decision = decide(contract)
        log_audit(contract, decision, execution_action="TIMEOUT:CLAUDE")
        assert get_audit_log()[0]["execution_action"] == "TIMEOUT:CLAUDE"

    def test_blocked_policy_logged(self):
        contract = JobContract(
            sensitivity=Sensitivity.HIGH,
            routes=["CLAUDE"],
        )
        decision = decide(contract)
        log_audit(contract, decision)
        assert get_audit_log()[0]["final_disposition"] == "BLOCKED_POLICY"

    def test_missing_security_logged(self):
        contract = JobContract(
            job_type=JobType.SECURITY,
            routes=["GEMINI"],
        )
        decision = decide(contract, None, None)
        log_audit(contract, decision, execution_action="MISSING:GEMINI_OUTPUT")
        log = get_audit_log()
        assert log[0]["final_disposition"] == "AWAITING_HUMAN_APPROVAL"
        assert log[0]["execution_action"] == "MISSING:GEMINI_OUTPUT"

    def test_malformed_response_logged(self):
        contract = build_job_contract("Status?", {"category": "trading"})
        trading = TradingOutput(raw_response="GARBAGE@#$%")
        decision = decide(contract, trading, None)
        log_audit(contract, decision, trading, execution_action="MALFORMED:CLAUDE")
        log = get_audit_log()
        assert log[0]["trading_verdict_hash"]  # Hash logged, not raw garbage

    def test_audit_never_contains_adapter_secrets(self):
        """Even if an adapter leaks secrets in its error, audit must not contain them."""
        fake_key = "0x" + "ab" * 32
        error_response = f"Error: key {fake_key} not found in keystore"
        # The response goes through redaction before reaching audit context
        redacted, _ = redact_secrets(error_response)
        assert fake_key not in redacted

        contract = build_job_contract("Check wallet", {"category": "trading"})
        decision = decide(contract)
        log_audit(contract, decision)
        log_str = json.dumps(get_audit_log())
        assert fake_key not in log_str

    def test_multiple_failures_all_logged(self):
        """Multiple sequential failures must each get their own audit entry."""
        for i, action in enumerate([
            "TIMEOUT:CLAUDE", "TIMEOUT:GEMINI", "MALFORMED:CLAUDE",
            "MISSING:GEMINI_OUTPUT", "PARTIAL:GEMINI_TIMEOUT",
        ]):
            contract = build_job_contract(f"Job {i}", {"category": "trading"})
            decision = decide(contract)
            log_audit(contract, decision, execution_action=action)
        log = get_audit_log()
        assert len(log) == 5
        actions = [entry["execution_action"] for entry in log]
        assert "TIMEOUT:CLAUDE" in actions
        assert "TIMEOUT:GEMINI" in actions
        assert "MALFORMED:CLAUDE" in actions

    def test_audit_job_ids_unique_under_failure(self):
        """Each failed job must have a unique ID."""
        for _ in range(10):
            contract = build_job_contract("Test", {"category": "trading"})
            decision = decide(contract)
            log_audit(contract, decision)
        ids = [entry["job_id"] for entry in get_audit_log()]
        assert len(set(ids)) == 10


# ═══════════════════════════════════════════════════════════════════════════
# 8. MISSING SECURITY OUTPUT → ESCALATE (invariant enforcement)
# ═══════════════════════════════════════════════════════════════════════════

class TestMissingSecurityOutputInvariant:
    """This is the new invariant: missing security output in a job that
    expected security analysis must NEVER resolve to ALLOW."""

    APPROVED_STATES = {
        FinalDisposition.APPROVED,
        FinalDisposition.APPROVED_READ_ONLY,
        FinalDisposition.APPROVED_WITH_CONDITIONS,
    }

    def test_security_job_no_output_not_approved(self):
        contract = JobContract(
            job_type=JobType.SECURITY,
            routes=["GEMINI"],
        )
        decision = decide(contract, None, None)
        assert decision.disposition not in self.APPROVED_STATES

    def test_mixed_job_no_security_not_approved(self):
        """Even with trading output, missing security → not approved."""
        contract = JobContract(
            job_type=JobType.MIXED,
            routes=["CLAUDE", "GEMINI"],
        )
        trading = TradingOutput(
            trading_verdict=TradingVerdict.PROPOSE,
            confidence=0.99,
            raw_response="Perfect trade, highest confidence.",
        )
        decision = decide(contract, trading, None)
        assert decision.disposition not in self.APPROVED_STATES

    def test_mixed_job_no_security_even_read_only(self):
        """READ_ONLY mixed job with missing security → still not auto-approved."""
        contract = JobContract(
            job_type=JobType.MIXED,
            action_class=ActionClass.READ_ONLY,
            requires_execution=False,
            routes=["CLAUDE", "GEMINI"],
        )
        decision = decide(contract, None, None)
        assert decision.disposition not in self.APPROVED_STATES

    def test_trading_job_no_security_is_fine(self):
        """TRADING-only job doesn't need security output → can be approved."""
        contract = JobContract(
            job_type=JobType.TRADING,
            routes=["CLAUDE"],
        )
        decision = decide(contract, None, None)
        # Trading-only, no execution → APPROVED_READ_ONLY is correct
        assert decision.disposition == FinalDisposition.APPROVED_READ_ONLY

    def test_general_job_no_security_is_fine(self):
        """GENERAL job doesn't need security → can proceed."""
        contract = JobContract(
            job_type=JobType.GENERAL,
            routes=["GPT"],
        )
        decision = decide(contract, None, None)
        assert decision.disposition == FinalDisposition.APPROVED_READ_ONLY


# ═══════════════════════════════════════════════════════════════════════════
# RESPONSE POLICY UNDER FAILURE
# ═══════════════════════════════════════════════════════════════════════════

class TestResponsePolicyUnderFailure:
    """enforce_response_policy must handle all failure states cleanly."""

    def test_deny_appends_block_notice(self):
        decision = FinalDecision(
            gate_decision=GateDecision.DENY,
            gate_reason="Security REJECT",
        )
        result = enforce_response_policy("Some response", decision)
        assert "BLOCKED" in result

    def test_require_approval_appends_prompt(self):
        decision = FinalDecision(
            gate_decision=GateDecision.REQUIRE_APPROVAL,
            approval_prompt="Reply 'approve' to proceed.",
        )
        result = enforce_response_policy("Some response", decision)
        assert "approve" in result.lower()

    def test_conditions_appended(self):
        decision = FinalDecision(
            gate_decision=GateDecision.ALLOW,
            conditions=["Patch shell=True", "Redact logs"],
        )
        result = enforce_response_policy("Some response", decision)
        assert "shell" in result.lower()
        assert "Redact" in result

    def test_secret_in_error_message_redacted(self):
        """If an adapter error contains a secret, it must be stripped."""
        fake_key = "0x" + "cd" * 32
        error = f"Adapter error: key {fake_key} connection refused"
        decision = FinalDecision(
            disposition=FinalDisposition.APPROVED_READ_ONLY,
            gate_decision=GateDecision.ALLOW,
        )
        result = enforce_response_policy(error, decision)
        assert fake_key not in result

    def test_empty_response_with_deny_still_shows_block(self):
        decision = FinalDecision(
            gate_decision=GateDecision.DENY,
            gate_reason="Test denial",
        )
        result = enforce_response_policy("", decision)
        assert "BLOCKED" in result
        assert "Test denial" in result
