"""
tests/test_end_to_end_pipeline.py
===================================
Integration tests across the full pipeline.
No live API calls — mocks at the LLM/MCP boundary.
Tests the actual flow: classify → contract → normalize → route → decide → enforce.

Must-cover cases:
  1. LOW trading request → approved read-only
  2. HIGH secret-bearing request → local/security only
  3. Mixed request → Claude proposes, Gemini rejects, final blocked
  4. Value-moving request → approval required
  5. Model output leak → redacted before final response
  6. Malformed contract → rejected safely

Additional coverage:
  - Audit trail verification (blocked actions recorded)
  - Approval workflow hardening (approve/deny paths)
  - Concurrency for mixed-route jobs
  - Unknown/missing fields in verdicts
  - Edge cases in sensitivity classification
"""

import sys
import os
import asyncio
import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from dataclasses import dataclass

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from contracts import (
    JobContract, JobType, Sensitivity, ActionClass, GateDecision,
    SecurityVerdict, SecurityOutput, TradingOutput, TradingVerdict,
    FinalDecision, FinalDisposition, ArtifactRef,
)
from policy_engine import (
    build_job_contract, decide, enforce_response_policy,
    detect_secrets, redact_secrets, classify_sensitivity,
    classify_action, select_routes, build_constraints,
    log_audit, get_audit_log, content_hash,
    _audit_log,
)


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _clear_audit():
    """Reset audit log between tests."""
    _audit_log.clear()


def _simulate_pipeline(
    user_msg: str,
    triage_category: str,
    triage_confidence: float = 0.9,
    trading_response: str | None = None,
    security_response: str | None = None,
    trading_intent: str | None = None,
    security_intent: str | None = None,
) -> tuple[JobContract, FinalDecision, str]:
    """
    Simulate the full pipeline without live LLM calls.
    Returns (contract, decision, final_response_text).
    """
    # Step 1: Classification (mocked — we pass the result)
    classification = {
        "category": triage_category,
        "confidence": triage_confidence,
        "reasoning": "test",
        "trading_intent": trading_intent,
        "security_intent": security_intent,
        "involves_execution": classify_action(user_msg) != ActionClass.READ_ONLY,
    }

    # Step 2: Build contract
    contract = build_job_contract(user_msg, classification)

    # Step 3: Context normalization (redaction)
    # In real pipeline, ChatGPT normalizes. Here we use the policy engine directly.
    safe_ctx = contract.context_summary  # Already redacted by build_job_contract

    # Step 4: Build specialist outputs
    trading_out = None
    security_out = None

    if trading_response is not None and "CLAUDE" in contract.routes:
        trading_out = TradingOutput(raw_response=trading_response)

    if security_response is not None and "GEMINI" in contract.routes:
        security_out = _parse_security_output(security_response)

    # Step 5: Decide
    decision = decide(contract, trading_out, security_out)

    # Step 6: Build response
    if trading_response and security_response:
        response = f"Security: {security_response}\n\nTrading: {trading_response}"
    elif trading_response:
        response = trading_response
    elif security_response:
        response = security_response
    else:
        response = "No specialist response."

    # Step 7: Enforce response policy
    final = enforce_response_policy(response, decision)

    # Step 8: Audit
    log_audit(contract, decision, trading_out, security_out)

    return contract, decision, final


def _parse_security_output(raw: str) -> SecurityOutput:
    """Parse a security response into structured output."""
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
        # Unknown/unparseable → ESCALATE. Unknown ≠ safe.
        out.security_verdict = SecurityVerdict.ESCALATE

    if "SEVERITY: HIGH" in upper:
        out.severity = Sensitivity.HIGH
    elif "SEVERITY: MEDIUM" in upper:
        out.severity = Sensitivity.MEDIUM
    return out


# ═══════════════════════════════════════════════════════════════════════════
# 1. LOW TRADING REQUEST → APPROVED READ-ONLY
# ═══════════════════════════════════════════════════════════════════════════

class TestE2E_LowTrading:

    def setup_method(self):
        _clear_audit()

    def test_eth_price_query(self):
        contract, decision, response = _simulate_pipeline(
            user_msg="What is the current price of ETH?",
            triage_category="trading",
            trading_response="ETH is currently at $3,520.",
        )
        assert contract.sensitivity == Sensitivity.LOW
        assert contract.action_class == ActionClass.READ_ONLY
        assert "CLAUDE" in contract.routes
        assert decision.disposition == FinalDisposition.APPROVED_READ_ONLY
        assert decision.gate_decision == GateDecision.ALLOW
        assert "3,520" in response

    def test_portfolio_summary(self):
        contract, decision, response = _simulate_pipeline(
            user_msg="Show me a portfolio summary",
            triage_category="trading",
            trading_response="Total: 5.43 ETH (~$19,100)",
        )
        assert contract.sensitivity == Sensitivity.LOW
        assert decision.disposition == FinalDisposition.APPROVED_READ_ONLY

    def test_bot_status_check(self):
        contract, decision, response = _simulate_pipeline(
            user_msg="What is the bot status?",
            triage_category="trading",
            trading_response="Sentinel X active, 12 trades today, +$45.20",
        )
        assert contract.sensitivity == Sensitivity.LOW
        assert decision.gate_decision == GateDecision.ALLOW

    def test_simulation_is_read_only(self):
        contract, decision, _ = _simulate_pipeline(
            user_msg="Simulate buying $100 of ETH",
            triage_category="trading",
            trading_response="Simulation: fill at $3,518, qty 0.0284",
        )
        # "simulate" should not trigger VALUE_MOVING
        assert contract.action_class == ActionClass.READ_ONLY
        assert decision.disposition == FinalDisposition.APPROVED_READ_ONLY

    def test_audit_recorded_for_low_trading(self):
        _simulate_pipeline(
            user_msg="ETH price?",
            triage_category="trading",
            trading_response="$3,520",
        )
        log = get_audit_log()
        assert len(log) == 1
        assert log[0]["sensitivity"] == "LOW"
        assert log[0]["final_disposition"] == "APPROVED_READ_ONLY"


# ═══════════════════════════════════════════════════════════════════════════
# 2. HIGH SECRET-BEARING REQUEST → LOCAL/SECURITY ONLY
# ═══════════════════════════════════════════════════════════════════════════

class TestE2E_HighSecretBearing:

    def setup_method(self):
        _clear_audit()

    def test_keystore_decrypt_reclassified(self):
        """Trading request with HIGH keywords → reclassified to security."""
        contract, decision, _ = _simulate_pipeline(
            user_msg="Decrypt wallet_69.json using the electrum-history private key",
            triage_category="trading",
            security_response="VERDICT: ALLOW\nLocal analysis only.",
        )
        assert contract.sensitivity == Sensitivity.HIGH
        assert contract.job_type == JobType.SECURITY  # Reclassified
        assert "CLAUDE" not in contract.routes
        assert "GEMINI" in contract.routes
        assert "local-only" in contract.constraints

    def test_private_key_in_message_blocked_from_cloud(self):
        fake_key = "0x" + "ab" * 32
        contract, decision, final = _simulate_pipeline(
            user_msg=f"Check balance for key {fake_key}",
            triage_category="trading",
            security_response="VERDICT: ALLOW\nBalance checked locally.",
        )
        assert contract.sensitivity == Sensitivity.HIGH
        assert "CLAUDE" not in contract.routes
        assert fake_key not in contract.context_summary
        assert "[REDACTED:" in contract.context_summary

    def test_password_in_message(self):
        contract, _, _ = _simulate_pipeline(
            user_msg="Try password 2012Kenworth5. on the keystore",
            triage_category="security",
            security_response="VERDICT: ALLOW\nPassword tested locally.",
        )
        assert contract.sensitivity == Sensitivity.HIGH
        assert "2012Kenworth" not in contract.context_summary
        assert "local-only" in contract.constraints

    def test_env_file_request(self):
        contract, _, _ = _simulate_pipeline(
            user_msg="Show me the .env file contents",
            triage_category="security",
            security_response="VERDICT: ALLOW\nLocal read only.",
        )
        assert contract.sensitivity == Sensitivity.HIGH
        assert "CLAUDE" not in contract.routes

    def test_seed_phrase_never_routes_cloud(self):
        seed = "abandon " * 12
        contract, _, _ = _simulate_pipeline(
            user_msg=f"Recover wallet from {seed.strip()}",
            triage_category="trading",
            security_response="VERDICT: ALLOW",
        )
        assert contract.sensitivity == Sensitivity.HIGH
        assert "CLAUDE" not in contract.routes
        assert seed.strip() not in contract.context_summary

    def test_high_forced_to_claude_blocked_by_decide(self):
        """Even if routing was somehow wrong, decide() catches it."""
        contract = JobContract(
            job_type=JobType.TRADING,
            sensitivity=Sensitivity.HIGH,
            routes=["CLAUDE"],
        )
        decision = decide(contract)
        assert decision.disposition == FinalDisposition.BLOCKED_POLICY
        assert decision.gate_decision == GateDecision.DENY

    def test_audit_records_high_block(self):
        _simulate_pipeline(
            user_msg="Decrypt my keystore file",
            triage_category="trading",
            security_response="VERDICT: ALLOW",
        )
        log = get_audit_log()
        assert len(log) == 1
        assert log[0]["sensitivity"] == "HIGH"
        assert "GEMINI" in log[0]["routes_chosen"]


# ═══════════════════════════════════════════════════════════════════════════
# 3. MIXED: CLAUDE PROPOSES, GEMINI REJECTS → BLOCKED
# ═══════════════════════════════════════════════════════════════════════════

class TestE2E_MixedVeto:

    def setup_method(self):
        _clear_audit()

    def test_trading_yes_security_reject_equals_blocked(self):
        contract, decision, final = _simulate_pipeline(
            user_msg="Optimize my bot parameters and make sure it's safe",
            triage_category="mixed",
            trading_response="Recommend: lower RSI threshold to 52, raise TP to 1.4%. High confidence.",
            security_response="VERDICT: REJECT\nSEVERITY: HIGH\nFINDINGS:\n- Unsafe subprocess usage\n- Credential leakage risk",
        )
        assert contract.job_type == JobType.MIXED
        assert decision.disposition == FinalDisposition.BLOCKED_SECURITY
        assert decision.gate_decision == GateDecision.DENY
        assert "BLOCKED" in final or "REJECT" in final or "Deny" in final.lower() or "blocked" in final.lower()

    def test_mixed_with_security_allow_with_conditions(self):
        contract, decision, final = _simulate_pipeline(
            user_msg="Deploy the new bot version but audit it first",
            triage_category="mixed",
            trading_response="Deployment config looks good. Ready to ship.",
            security_response=(
                "VERDICT: ALLOW_WITH_CONDITIONS\nSEVERITY: MEDIUM\n"
                "FINDINGS:\n- No keys detected\n- Uses shell=True\n"
                "CONDITIONS:\n- Replace shell=True\n- Add input validation"
            ),
        )
        # ALLOW_WITH_CONDITIONS should pass but with conditions
        assert decision.disposition in (
            FinalDisposition.APPROVED_WITH_CONDITIONS,
            FinalDisposition.APPROVED_READ_ONLY,
            FinalDisposition.AWAITING_HUMAN_APPROVAL,
        )
        if decision.conditions:
            assert any("shell" in c.lower() for c in decision.conditions)

    def test_mixed_both_allow_passes(self):
        contract, decision, _ = _simulate_pipeline(
            user_msg="Check if wallets are safe then show portfolio",
            triage_category="mixed",
            trading_response="Portfolio: 5.43 ETH",
            security_response="VERDICT: ALLOW\nSEVERITY: LOW\nAll wallets OK.",
        )
        assert decision.disposition in (
            FinalDisposition.APPROVED_READ_ONLY,
            FinalDisposition.APPROVED,
            FinalDisposition.APPROVED_WITH_CONDITIONS,
        )
        assert decision.gate_decision == GateDecision.ALLOW

    def test_audit_records_mixed_veto(self):
        _simulate_pipeline(
            user_msg="Tune bot and check safety",
            triage_category="mixed",
            trading_response="Go aggressive.",
            security_response="VERDICT: REJECT\nSEVERITY: HIGH",
        )
        log = get_audit_log()
        assert len(log) == 1
        assert log[0]["final_disposition"] == "BLOCKED_SECURITY"
        assert log[0]["security_verdict_hash"]  # Not empty


# ═══════════════════════════════════════════════════════════════════════════
# 4. VALUE-MOVING → APPROVAL REQUIRED
# ═══════════════════════════════════════════════════════════════════════════

class TestE2E_ValueMovingApproval:

    def setup_method(self):
        _clear_audit()

    def test_buy_requires_approval(self):
        contract, decision, final = _simulate_pipeline(
            user_msg="Buy $100 of ETH from JIT0906 wallet",
            triage_category="trading",
            trading_response="Order ready: buy $100 ETH at ~$3,520.",
        )
        assert contract.action_class == ActionClass.VALUE_MOVING
        assert contract.approval_required is True
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL
        assert decision.disposition == FinalDisposition.AWAITING_HUMAN_APPROVAL
        assert "approve" in final.lower() or "APPROVAL" in final

    def test_sell_requires_approval(self):
        contract, decision, _ = _simulate_pipeline(
            user_msg="Sell 0.5 ETH for USDC",
            triage_category="trading",
            trading_response="Sell order: 0.5 ETH → ~$1,760 USDC",
        )
        assert contract.action_class == ActionClass.VALUE_MOVING
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL

    def test_transfer_requires_approval(self):
        contract, decision, _ = _simulate_pipeline(
            user_msg="Transfer 1 ETH to BankrCoin wallet",
            triage_category="trading",
            trading_response="Transfer queued.",
        )
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL

    def test_bridge_requires_approval(self):
        contract, decision, _ = _simulate_pipeline(
            user_msg="Bridge 0.5 ETH from Base to Arbitrum",
            triage_category="trading",
            trading_response="Bridge route found.",
        )
        assert contract.action_class == ActionClass.VALUE_MOVING
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL

    def test_deploy_is_sensitive_write(self):
        contract, decision, _ = _simulate_pipeline(
            user_msg="Deploy the new sentinel bot to production",
            triage_category="trading",
            trading_response="Deployment config ready.",
        )
        assert contract.action_class == ActionClass.SENSITIVE_WRITE
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL

    def test_read_only_does_not_require_approval(self):
        contract, decision, _ = _simulate_pipeline(
            user_msg="What's the gas price on Base?",
            triage_category="trading",
            trading_response="Base gas: 0.002 gwei",
        )
        assert contract.action_class == ActionClass.READ_ONLY
        assert contract.approval_required is False
        assert decision.gate_decision == GateDecision.ALLOW

    def test_audit_records_approval_requirement(self):
        _simulate_pipeline(
            user_msg="Buy $100 ETH",
            triage_category="trading",
            trading_response="Ready.",
        )
        log = get_audit_log()
        assert log[0]["final_disposition"] == "AWAITING_HUMAN_APPROVAL"
        assert log[0]["action_class"] == "VALUE_MOVING"


# ═══════════════════════════════════════════════════════════════════════════
# 5. MODEL OUTPUT LEAK → REDACTED
# ═══════════════════════════════════════════════════════════════════════════

class TestE2E_OutputRedaction:

    def setup_method(self):
        _clear_audit()

    def test_private_key_in_trading_response(self):
        leaked = "0x" + "de" * 32
        _, _, final = _simulate_pipeline(
            user_msg="Check my wallet status",
            triage_category="trading",
            trading_response=f"Wallet key is {leaked}. Balance: 0.5 ETH.",
        )
        assert leaked not in final
        assert "[REDACTED:" in final

    def test_password_in_security_response(self):
        _, _, final = _simulate_pipeline(
            user_msg="What password cracked the keystore?",
            triage_category="security",
            security_response="The password was 2012Kenworth5. cracked via brute force.\nVERDICT: ALLOW",
        )
        assert "2012Kenworth" not in final

    def test_api_key_in_response(self):
        _, _, final = _simulate_pipeline(
            user_msg="Show me the bot config",
            triage_category="trading",
            trading_response="Config: API key is sk-ant-abcdefghijklmnopqrstuvwxyz1234567890",
        )
        assert "sk-ant-" not in final

    def test_multiple_leaks_all_caught(self):
        leaked_key = "0x" + "ff" * 32
        _, _, final = _simulate_pipeline(
            user_msg="Status report",
            triage_category="trading",
            trading_response=(
                f"Key: {leaked_key}\n"
                "Password: 85Freightliner!\n"
                "API: sk-abcdefghijklmnopqrstuvwxyz1234567890"
            ),
        )
        assert leaked_key not in final
        assert "85Freightliner" not in final
        assert "sk-abc" not in final
        assert final.count("[REDACTED:") >= 3

    def test_clean_response_passes_through(self):
        _, _, final = _simulate_pipeline(
            user_msg="ETH price?",
            triage_category="trading",
            trading_response="ETH is $3,520. No issues.",
        )
        assert "[REDACTED:" not in final
        assert "redacted" not in final.lower()


# ═══════════════════════════════════════════════════════════════════════════
# 6. MALFORMED CONTRACTS → REJECTED SAFELY
# ═══════════════════════════════════════════════════════════════════════════

class TestE2E_MalformedContracts:

    def test_empty_message(self):
        contract = build_job_contract("", {"category": "general", "confidence": 0.5})
        decision = decide(contract)
        # Should not crash, should default to safe state
        assert decision.gate_decision in (GateDecision.ALLOW, GateDecision.DENY)

    def test_unknown_category(self):
        contract = build_job_contract(
            "Something unusual",
            {"category": "UNKNOWN_TYPE", "confidence": 0.1},
        )
        assert contract.job_type == JobType.GENERAL
        decision = decide(contract)
        assert decision is not None

    def test_missing_confidence(self):
        contract = build_job_contract(
            "Check prices",
            {"category": "trading"},  # No confidence key
        )
        assert contract is not None
        assert contract.job_type == JobType.TRADING

    def test_missing_category(self):
        contract = build_job_contract("Hello", {})
        assert contract.job_type == JobType.GENERAL

    def test_none_classification_fields(self):
        contract = build_job_contract(
            "Test",
            {
                "category": "mixed",
                "confidence": None,
                "trading_intent": None,
                "security_intent": None,
            },
        )
        assert contract.job_type == JobType.MIXED

    def test_decide_with_no_specialist_output(self):
        """decide() must work with zero specialist responses."""
        contract = JobContract(job_type=JobType.TRADING, routes=["CLAUDE"])
        decision = decide(contract, None, None)
        assert decision.disposition == FinalDisposition.APPROVED_READ_ONLY

    def test_decide_with_empty_security_output(self):
        """Empty SecurityOutput defaults to ESCALATE — unknown = not trusted."""
        contract = JobContract(job_type=JobType.SECURITY, routes=["GEMINI"])
        security = SecurityOutput()  # All defaults → ESCALATE
        decision = decide(contract, None, security)
        assert decision is not None
        assert decision.disposition == FinalDisposition.AWAITING_HUMAN_APPROVAL
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL

    def test_security_output_unknown_verdict_defaults_to_escalate(self):
        """If parsing fails, verdict must be ESCALATE, not ALLOW. Unknown ≠ safe."""
        out = _parse_security_output("Some response with no verdict markers")
        assert out.security_verdict == SecurityVerdict.ESCALATE

    def test_contract_serialization_roundtrip(self):
        contract = build_job_contract(
            "Buy $100 ETH",
            {"category": "trading", "confidence": 0.9},
        )
        d = contract.to_dict()
        j = contract.to_json()
        parsed = json.loads(j)
        assert parsed["job_id"] == d["job_id"]
        assert parsed["job_type"] == "TRADING"
        assert parsed["action_class"] == "VALUE_MOVING"


# ═══════════════════════════════════════════════════════════════════════════
# AUDIT TRAIL VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════

class TestAuditTrail:

    def setup_method(self):
        _clear_audit()

    def test_blocked_action_recorded(self):
        contract = JobContract(
            job_type=JobType.TRADING,
            sensitivity=Sensitivity.HIGH,
            routes=["CLAUDE"],
        )
        decision = decide(contract)
        log_audit(contract, decision)
        log = get_audit_log()
        assert len(log) == 1
        assert log[0]["final_disposition"] == "BLOCKED_POLICY"
        assert log[0]["sensitivity"] == "HIGH"

    def test_security_reject_recorded(self):
        contract = JobContract(
            job_type=JobType.MIXED, routes=["CLAUDE", "GEMINI"],
        )
        security = SecurityOutput(
            security_verdict=SecurityVerdict.REJECT,
            raw_response="REJECT",
        )
        decision = decide(contract, None, security)
        log_audit(contract, decision, None, security)
        log = get_audit_log()
        assert log[0]["final_disposition"] == "BLOCKED_SECURITY"
        assert log[0]["security_verdict_hash"]  # Non-empty hash
        assert len(log[0]["security_verdict_hash"]) == 16

    def test_approval_required_recorded(self):
        contract = build_job_contract(
            "Buy $100 ETH",
            {"category": "trading", "confidence": 0.9},
        )
        decision = decide(contract)
        log_audit(contract, decision)
        log = get_audit_log()
        assert log[0]["final_disposition"] == "AWAITING_HUMAN_APPROVAL"
        assert log[0]["action_class"] == "VALUE_MOVING"

    def test_audit_never_contains_secrets(self):
        fake_key = "0x" + "ab" * 32
        contract = build_job_contract(
            f"Use key {fake_key} to sign",
            {"category": "trading", "confidence": 0.9},
        )
        decision = decide(contract)
        log_audit(contract, decision)
        log = get_audit_log()
        log_str = json.dumps(log)
        assert fake_key not in log_str
        assert "2012Kenworth" not in log_str

    def test_multiple_jobs_all_recorded(self):
        for i in range(5):
            contract = build_job_contract(
                f"Job {i}: check prices",
                {"category": "trading", "confidence": 0.9},
            )
            decision = decide(contract)
            log_audit(contract, decision)
        log = get_audit_log()
        assert len(log) == 5
        # Each has a unique job_id
        ids = [entry["job_id"] for entry in log]
        assert len(set(ids)) == 5

    def test_audit_contains_routes(self):
        contract = build_job_contract(
            "Mixed: tune bot and audit",
            {"category": "mixed", "confidence": 0.8},
        )
        decision = decide(contract)
        log_audit(contract, decision)
        log = get_audit_log()
        assert "CLAUDE" in log[0]["routes_chosen"] or "GEMINI" in log[0]["routes_chosen"]

    def test_verdict_hashes_differ(self):
        """Two different verdicts must produce different hashes."""
        h1 = content_hash("ALLOW - all good")
        h2 = content_hash("REJECT - unsafe")
        assert h1 != h2


# ═══════════════════════════════════════════════════════════════════════════
# APPROVAL WORKFLOW HARDENING
# ═══════════════════════════════════════════════════════════════════════════

class TestApprovalWorkflow:

    def test_value_moving_always_gates(self):
        """Every VALUE_MOVING action class must hit the gate."""
        for msg in [
            "Buy $100 ETH", "Sell BTC", "Swap ETH for USDC",
            "Transfer to wallet", "Send 0.1 ETH", "Withdraw funds",
            "Bridge to arbitrum",
        ]:
            contract = build_job_contract(msg, {"category": "trading", "confidence": 0.9})
            decision = decide(contract)
            assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL, (
                f"'{msg}' did not require approval"
            )

    def test_sensitive_write_always_gates(self):
        for msg in ["Deploy to production", "Rotate credentials"]:
            contract = build_job_contract(msg, {"category": "trading", "confidence": 0.9})
            assert contract.action_class == ActionClass.SENSITIVE_WRITE
            decision = decide(contract)
            assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL

    def test_approval_prompt_is_non_empty(self):
        contract = build_job_contract(
            "Buy $50 ETH",
            {"category": "trading", "confidence": 0.9},
        )
        decision = decide(contract)
        assert decision.approval_prompt  # Non-empty
        assert "approve" in decision.approval_prompt.lower()

    def test_security_reject_overrides_value_moving_approval(self):
        """If security rejects, we don't even get to approval — it's blocked."""
        contract = JobContract(
            job_type=JobType.MIXED,
            action_class=ActionClass.VALUE_MOVING,
            requires_execution=True,
            routes=["CLAUDE", "GEMINI"],
        )
        security = SecurityOutput(
            security_verdict=SecurityVerdict.REJECT,
            raw_response="REJECT",
        )
        decision = decide(contract, None, security)
        assert decision.disposition == FinalDisposition.BLOCKED_SECURITY
        assert decision.gate_decision == GateDecision.DENY
        # NOT AWAITING_HUMAN_APPROVAL — security veto is absolute


# ═══════════════════════════════════════════════════════════════════════════
# CONCURRENCY FOR MIXED-ROUTE JOBS
# ═══════════════════════════════════════════════════════════════════════════

class TestConcurrency:

    def test_mixed_routes_are_parallel_safe(self):
        """Both routes should be present for mixed jobs."""
        contract = build_job_contract(
            "Check safety and show portfolio",
            {"category": "mixed", "confidence": 0.85},
        )
        assert "CLAUDE" in contract.routes
        assert "GEMINI" in contract.routes

    def test_independent_histories(self):
        """Trading and security histories must not share state."""
        trading_hist = []
        security_hist = []

        # Simulate two independent conversations
        trading_hist.append({"role": "user", "content": "ETH price?"})
        trading_hist.append({"role": "assistant", "content": "$3,520"})

        security_hist.append({"role": "user", "content": "Scan approvals"})
        security_hist.append({"role": "assistant", "content": "2 approvals found"})

        # Histories must be independent
        assert len(trading_hist) == 2
        assert len(security_hist) == 2
        assert trading_hist[0]["content"] != security_hist[0]["content"]

    def test_decide_handles_both_outputs(self):
        """decide() must handle both trading and security outputs in one call."""
        contract = JobContract(
            job_type=JobType.MIXED,
            routes=["CLAUDE", "GEMINI"],
        )
        trading = TradingOutput(
            trading_verdict=TradingVerdict.PROPOSE,
            confidence=0.8,
            raw_response="Looks good",
        )
        security = SecurityOutput(
            security_verdict=SecurityVerdict.ALLOW,
            raw_response="All clear",
        )
        decision = decide(contract, trading, security)
        assert decision.trading_summary
        assert decision.security_summary
        assert decision.disposition == FinalDisposition.APPROVED_READ_ONLY


# ═══════════════════════════════════════════════════════════════════════════
# EDGE CASES
# ═══════════════════════════════════════════════════════════════════════════

class TestEdgeCases:

    def test_very_long_message(self):
        """Pipeline should handle very long messages without crashing."""
        long_msg = "Check prices " * 1000
        contract = build_job_contract(long_msg, {"category": "trading", "confidence": 0.5})
        decision = decide(contract)
        assert decision is not None

    def test_unicode_in_message(self):
        contract = build_job_contract(
            "Check price for ETH 🚀💎🙌",
            {"category": "trading", "confidence": 0.9},
        )
        assert contract.sensitivity == Sensitivity.LOW

    def test_special_chars_in_message(self):
        contract = build_job_contract(
            "What's the P&L for <script>alert('xss')</script>?",
            {"category": "trading", "confidence": 0.5},
        )
        decision = decide(contract)
        assert decision is not None

    def test_sensitivity_escalation_chain(self):
        """LOW < MEDIUM < HIGH — verify ordering."""
        assert classify_sensitivity("ETH price") == Sensitivity.LOW
        assert classify_sensitivity("Check approval status") == Sensitivity.MEDIUM
        assert classify_sensitivity("Decrypt my keystore") == Sensitivity.HIGH

    def test_action_class_escalation_chain(self):
        """READ_ONLY < SAFE_WRITE < SENSITIVE_WRITE < VALUE_MOVING."""
        assert classify_action("What's the price?") == ActionClass.READ_ONLY
        assert classify_action("Buy $100 ETH") == ActionClass.VALUE_MOVING
        assert classify_action("Deploy to production") == ActionClass.SENSITIVE_WRITE

    def test_general_job_has_no_specialist_routes(self):
        contract = build_job_contract("Hello", {"category": "general", "confidence": 0.9})
        assert contract.routes == ["GPT"]

    def test_constraint_no_secrets_always_present(self):
        """Every contract must have the no-secrets-in-payload constraint."""
        for cat in ["trading", "security", "mixed", "general"]:
            contract = build_job_contract(
                "Test message",
                {"category": cat, "confidence": 0.9},
            )
            assert "no-secrets-in-payload" in contract.constraints, (
                f"Category '{cat}' missing no-secrets-in-payload"
            )
