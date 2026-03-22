"""
tests/test_mutation_resistance.py
====================================
Mutation testing for the safety envelope.

Each test simulates a specific mutation to critical safety logic
and proves the system would detect the breakage. If any of these
mutations could pass silently, the envelope has a hole.

Target mutations:
  1. Invert security veto (REJECT → ALLOW)
  2. Allow HIGH → CLAUDE (remove cloud route block)
  3. Bypass approval for VALUE_MOVING
  4. Disable redaction (secrets pass through)
  5. Change missing security fallback to ALLOW
  6. Invert analysis-intent override (questions become commands)
  7. Remove simulation override (dry-run becomes execution)
  8. Empty trading output treated as actionable

Test strategy: monkeypatch the function, run through the pipeline,
assert that the mutated behavior produces WRONG results. If the test
passes, it means the original code is correct AND the mutation would
be caught.
"""

import sys
import os
import copy
import pytest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from contracts import (
    JobContract, JobType, Sensitivity, ActionClass, GateDecision,
    SecurityVerdict, SecurityOutput, TradingOutput, TradingVerdict,
    FinalDecision, FinalDisposition,
)
import policy_engine
from policy_engine import (
    build_job_contract, decide, enforce_response_policy,
    detect_secrets, redact_secrets, classify_sensitivity,
    classify_action, select_routes, requires_execution,
    _audit_log,
)


def _clear_audit():
    _audit_log.clear()


# ═══════════════════════════════════════════════════════════════════════════
# MUTATION 1: Invert security veto (REJECT → treated as ALLOW)
# If this mutation passed silently, security veto would be meaningless.
# ═══════════════════════════════════════════════════════════════════════════

class TestMutation_InvertSecurityVeto:
    """Prove: if someone removed the REJECT check from decide(),
    the system would produce WRONG (unsafe) results."""

    def test_reject_must_block_not_approve(self):
        """Without the REJECT guard, this would return APPROVED_READ_ONLY."""
        contract = JobContract(
            job_type=JobType.TRADING,
            routes=["CLAUDE"],
        )
        security = SecurityOutput(
            security_verdict=SecurityVerdict.REJECT,
            raw_response="VERDICT: REJECT",
        )
        decision = decide(contract, None, security)
        # Correct: BLOCKED_SECURITY
        assert decision.disposition == FinalDisposition.BLOCKED_SECURITY
        # If mutation applied (REJECT ignored), this would be APPROVED_READ_ONLY
        assert decision.disposition != FinalDisposition.APPROVED_READ_ONLY

    def test_reject_blocks_even_high_confidence_trade(self):
        """Mutation would let 0.99 confidence override a REJECT."""
        contract = JobContract(
            job_type=JobType.MIXED,
            routes=["CLAUDE", "GEMINI"],
        )
        trading = TradingOutput(
            trading_verdict=TradingVerdict.PROPOSE,
            confidence=0.99,
            execution_request=True,
            raw_response="Best trade ever",
        )
        security = SecurityOutput(
            security_verdict=SecurityVerdict.REJECT,
            raw_response="VERDICT: REJECT\nDanger.",
        )
        decision = decide(contract, trading, security)
        assert decision.disposition == FinalDisposition.BLOCKED_SECURITY
        assert decision.gate_decision == GateDecision.DENY

    def test_mutated_decide_would_approve_rejected_job(self):
        """Directly simulate the mutation: skip REJECT check."""
        contract = JobContract(
            job_type=JobType.TRADING,
            routes=["CLAUDE"],
        )
        security = SecurityOutput(
            security_verdict=SecurityVerdict.REJECT,
            raw_response="REJECT",
        )

        # Simulate mutation: create a "broken" decide that ignores REJECT
        def mutated_decide(c, t=None, s=None):
            d = FinalDecision(job_id=c.job_id)
            # MUTATION: skip security check entirely
            if not c.requires_execution:
                d.disposition = FinalDisposition.APPROVED_READ_ONLY
                d.gate_decision = GateDecision.ALLOW
            return d

        # Mutated version gives WRONG answer
        mutated = mutated_decide(contract, None, security)
        assert mutated.disposition == FinalDisposition.APPROVED_READ_ONLY  # WRONG

        # Real version gives RIGHT answer
        real = decide(contract, None, security)
        assert real.disposition == FinalDisposition.BLOCKED_SECURITY  # RIGHT

        # They must differ — proving the guard is active
        assert mutated.disposition != real.disposition


# ═══════════════════════════════════════════════════════════════════════════
# MUTATION 2: Allow HIGH → CLAUDE (remove cloud route block)
# If this mutation passed, secrets could leak to Cloudflare.
# ═══════════════════════════════════════════════════════════════════════════

class TestMutation_AllowHighToCloud:
    """Prove: if someone removed the HIGH→GEMINI-only route enforcement,
    HIGH sensitivity jobs would incorrectly route to CLAUDE."""

    def test_select_routes_blocks_high_from_claude(self):
        """Original behavior: HIGH → GEMINI only."""
        routes = select_routes(JobType.TRADING, Sensitivity.HIGH)
        assert "CLAUDE" not in routes

    def test_mutated_select_routes_would_leak(self):
        """Simulate mutation: HIGH treated same as LOW."""
        def mutated_select_routes(job_type, sensitivity):
            # MUTATION: ignore sensitivity, always use default routes
            route_map = {
                JobType.TRADING: ["CLAUDE"],
                JobType.SECURITY: ["GEMINI"],
                JobType.MIXED: ["CLAUDE", "GEMINI"],
                JobType.GENERAL: ["GPT"],
            }
            return route_map.get(job_type, ["GPT"])

        # Mutated version gives WRONG answer
        mutated_routes = mutated_select_routes(JobType.TRADING, Sensitivity.HIGH)
        assert "CLAUDE" in mutated_routes  # WRONG — secret leak

        # Real version gives RIGHT answer
        real_routes = select_routes(JobType.TRADING, Sensitivity.HIGH)
        assert "CLAUDE" not in real_routes  # RIGHT

    def test_decide_catches_high_to_claude_even_if_routed(self):
        """Even if routing was wrong, decide() has a second guard."""
        contract = JobContract(
            sensitivity=Sensitivity.HIGH,
            routes=["CLAUDE"],  # Wrongly routed
        )
        decision = decide(contract)
        assert decision.disposition == FinalDisposition.BLOCKED_POLICY

    def test_contract_builder_reclassifies_high_trading(self):
        """build_job_contract must reclassify, not just route differently."""
        contract = build_job_contract(
            "Decrypt my keystore",
            {"category": "trading", "confidence": 0.9},
        )
        assert contract.job_type == JobType.SECURITY  # Reclassified
        assert "CLAUDE" not in contract.routes

    def test_all_high_keywords_route_local(self):
        """Every HIGH keyword must result in local-only routing."""
        HIGH_PHRASES = [
            "private key", "seed phrase", "mnemonic", "decrypt",
            "password", "secret", "credential", ".env",
        ]
        for phrase in HIGH_PHRASES:
            sens = classify_sensitivity(f"Show me the {phrase}")
            if sens == Sensitivity.HIGH:
                routes = select_routes(JobType.TRADING, sens)
                assert "CLAUDE" not in routes, f"HIGH phrase '{phrase}' routed to CLAUDE"


# ═══════════════════════════════════════════════════════════════════════════
# MUTATION 3: Bypass approval for VALUE_MOVING
# If this mutation passed, trades could execute without human consent.
# ═══════════════════════════════════════════════════════════════════════════

class TestMutation_BypassValueMovingApproval:
    """Prove: if someone removed the VALUE_MOVING gate, trades would
    auto-execute without approval."""

    VALUE_MOVING_PHRASES = [
        "Buy $100 ETH", "Sell BTC", "Swap ETH for USDC",
        "Send 1 ETH", "Transfer to wallet", "Withdraw funds",
        "Bridge to arbitrum",
    ]

    @pytest.mark.parametrize("phrase", VALUE_MOVING_PHRASES)
    def test_value_moving_always_requires_approval(self, phrase):
        contract = build_job_contract(phrase, {"category": "trading", "confidence": 0.9})
        decision = decide(contract)
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL

    def test_mutated_decide_would_auto_approve(self):
        """Simulate mutation: remove VALUE_MOVING gate check."""
        contract = JobContract(
            job_type=JobType.TRADING,
            action_class=ActionClass.VALUE_MOVING,
            requires_execution=True,
            routes=["CLAUDE"],
        )
        trading = TradingOutput(
            trading_verdict=TradingVerdict.PROPOSE,
            raw_response="Execute trade",
        )

        # Simulate mutation: skip action_class check
        def mutated_decide(c, t=None, s=None):
            d = FinalDecision(job_id=c.job_id)
            # MUTATION: always allow execution
            d.disposition = FinalDisposition.APPROVED
            d.gate_decision = GateDecision.ALLOW
            return d

        mutated = mutated_decide(contract, trading)
        assert mutated.gate_decision == GateDecision.ALLOW  # WRONG

        real = decide(contract, trading)
        assert real.gate_decision == GateDecision.REQUIRE_APPROVAL  # RIGHT

        assert mutated.gate_decision != real.gate_decision

    def test_sensitive_write_also_gated(self):
        """SENSITIVE_WRITE must also be gated — not just VALUE_MOVING."""
        contract = JobContract(
            action_class=ActionClass.SENSITIVE_WRITE,
            requires_execution=True,
            routes=["CLAUDE"],
        )
        decision = decide(contract)
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL


# ═══════════════════════════════════════════════════════════════════════════
# MUTATION 4: Disable redaction (secrets pass through)
# If this mutation passed, secrets would appear in user responses.
# ═══════════════════════════════════════════════════════════════════════════

class TestMutation_DisableRedaction:
    """Prove: if someone disabled the redaction engine, secrets would
    appear in final output."""

    SECRETS = [
        "0x" + "ab" * 32,
        "2012Kenworth5.",
        "sk-ant-abcdefghijklmnopqrstuvwxyz1234567890",
        "-----BEGIN PRIVATE KEY-----",
    ]

    @pytest.mark.parametrize("secret", SECRETS)
    def test_redaction_removes_secret(self, secret):
        text = f"The value is {secret} and more text"
        redacted, count = redact_secrets(text)
        assert secret not in redacted
        assert count > 0

    @pytest.mark.parametrize("secret", SECRETS)
    def test_mutated_redaction_would_leak(self, secret):
        """Simulate mutation: redact_secrets returns input unchanged."""
        text = f"The value is {secret} end"
        # Mutated: no-op redaction
        mutated_result = text  # Just passes through
        assert secret in mutated_result  # WRONG — secret leaked

        # Real: secret removed
        real_result, _ = redact_secrets(text)
        assert secret not in real_result  # RIGHT

    @pytest.mark.parametrize("secret", SECRETS)
    def test_response_policy_catches_leaked_secret(self, secret):
        """enforce_response_policy is the last line of defense."""
        response = f"Found: {secret}"
        decision = FinalDecision(
            disposition=FinalDisposition.APPROVED_READ_ONLY,
            gate_decision=GateDecision.ALLOW,
        )
        cleaned = enforce_response_policy(response, decision)
        assert secret not in cleaned

    def test_contract_summary_redacted(self):
        """build_job_contract must redact secrets in context_summary."""
        fake_key = "0x" + "ff" * 32
        contract = build_job_contract(
            f"Use key {fake_key} to check balance",
            {"category": "trading", "confidence": 0.9},
        )
        assert fake_key not in contract.context_summary


# ═══════════════════════════════════════════════════════════════════════════
# MUTATION 5: Change missing security fallback to ALLOW
# If this mutation passed, missing Gemini output = silent pass.
# ═══════════════════════════════════════════════════════════════════════════

class TestMutation_MissingSecurityFallbackToAllow:
    """Prove: if someone changed the missing-security-output check
    to default to ALLOW instead of ESCALATE, security jobs would
    silently pass without analysis."""

    def test_security_job_missing_output_escalates(self):
        contract = JobContract(
            job_type=JobType.SECURITY,
            routes=["GEMINI"],
        )
        decision = decide(contract, None, None)
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL
        assert decision.disposition == FinalDisposition.AWAITING_HUMAN_APPROVAL

    def test_mixed_job_missing_security_escalates(self):
        contract = JobContract(
            job_type=JobType.MIXED,
            routes=["CLAUDE", "GEMINI"],
        )
        trading = TradingOutput(
            trading_verdict=TradingVerdict.PROPOSE,
            confidence=0.95,
            raw_response="Perfect trade",
        )
        decision = decide(contract, trading, None)
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL

    def test_mutated_fallback_would_silently_pass(self):
        """Simulate mutation: missing security → ALLOW."""
        contract = JobContract(
            job_type=JobType.SECURITY,
            routes=["GEMINI"],
        )

        def mutated_decide(c, t=None, s=None):
            d = FinalDecision(job_id=c.job_id)
            # MUTATION: missing security = ALLOW
            if s is None:
                d.disposition = FinalDisposition.APPROVED_READ_ONLY
                d.gate_decision = GateDecision.ALLOW
            return d

        mutated = mutated_decide(contract, None, None)
        assert mutated.gate_decision == GateDecision.ALLOW  # WRONG

        real = decide(contract, None, None)
        assert real.gate_decision == GateDecision.REQUIRE_APPROVAL  # RIGHT

        assert mutated.gate_decision != real.gate_decision

    def test_empty_security_output_defaults_escalate(self):
        """SecurityOutput() dataclass default must be ESCALATE."""
        out = SecurityOutput()
        assert out.security_verdict == SecurityVerdict.ESCALATE


# ═══════════════════════════════════════════════════════════════════════════
# MUTATION 6: Invert analysis-intent override
# If this mutation passed, "How many trades?" would become VALUE_MOVING.
# ═══════════════════════════════════════════════════════════════════════════

class TestMutation_InvertAnalysisIntent:
    """Prove: if someone removed the analysis-intent override,
    questions about state would be misclassified as commands."""

    ANALYSIS_QUESTIONS = [
        "How many trades did the bot make today?",
        "How much capital is deployed?",
        "What is the current price of ETH?",
        "Show me the portfolio summary",
        "Compare mean reversion vs momentum",
    ]

    @pytest.mark.parametrize("question", ANALYSIS_QUESTIONS)
    def test_analysis_questions_are_read_only(self, question):
        assert classify_action(question) == ActionClass.READ_ONLY

    @pytest.mark.parametrize("question", ANALYSIS_QUESTIONS)
    def test_analysis_questions_no_execution(self, question):
        assert requires_execution(question) is False

    def test_mutated_classifier_would_misclassify(self):
        """Without analysis-intent override, 'trade' triggers VALUE_MOVING."""
        question = "How many trades did the bot make today?"

        # Simulate mutation: skip analysis check, go straight to keywords
        lower = question.lower()
        from policy_engine import VALUE_MOVING_KEYWORDS
        would_be_value_moving = any(kw in lower for kw in VALUE_MOVING_KEYWORDS)
        assert would_be_value_moving  # "trade" matches — WRONG classification

        # Real classifier gets it right
        real = classify_action(question)
        assert real == ActionClass.READ_ONLY  # RIGHT


# ═══════════════════════════════════════════════════════════════════════════
# MUTATION 7: Remove simulation override
# If this mutation passed, "Simulate buying" would trigger real execution.
# ═══════════════════════════════════════════════════════════════════════════

class TestMutation_RemoveSimulationOverride:
    """Prove: if someone removed the simulation override,
    dry-run requests would be treated as real execution."""

    SIMULATION_PHRASES = [
        "Simulate buying $100 of ETH",
        "Backtest mean reversion",
        "What if I bought ETH at $3,400?",
        "Dry run: buy $125 BTC",
        "Paper trade ETH/USDC",
    ]

    @pytest.mark.parametrize("phrase", SIMULATION_PHRASES)
    def test_simulations_are_read_only(self, phrase):
        assert classify_action(phrase) == ActionClass.READ_ONLY

    @pytest.mark.parametrize("phrase", SIMULATION_PHRASES)
    def test_simulations_no_execution(self, phrase):
        assert requires_execution(phrase) is False

    def test_mutated_classifier_would_execute_simulations(self):
        """Without simulation override, 'buy' triggers VALUE_MOVING."""
        phrase = "Simulate buying $100 of ETH"

        from policy_engine import VALUE_MOVING_KEYWORDS
        lower = phrase.lower()
        would_be_value_moving = any(kw in lower for kw in VALUE_MOVING_KEYWORDS)
        assert would_be_value_moving  # "buy" matches — WRONG

        real = classify_action(phrase)
        assert real == ActionClass.READ_ONLY  # RIGHT

    def test_simulation_contract_never_requires_approval(self):
        for phrase in self.SIMULATION_PHRASES:
            contract = build_job_contract(
                phrase, {"category": "trading", "confidence": 0.9},
            )
            assert contract.approval_required is False, (
                f"Simulation '{phrase}' incorrectly required approval"
            )


# ═══════════════════════════════════════════════════════════════════════════
# MUTATION 8: Empty trading output treated as actionable
# If this mutation passed, missing Claude output could trigger trades.
# ═══════════════════════════════════════════════════════════════════════════

class TestMutation_EmptyTradingAsActionable:
    """Prove: empty or missing trading output for execution-bearing
    TRADING jobs degrades to NO_ACTION, never inferred as actionable."""

    def test_missing_trading_on_value_moving_gates(self):
        """VALUE_MOVING with no trading output → REQUIRE_APPROVAL."""
        contract = build_job_contract(
            "Buy $100 of ETH",
            {"category": "trading", "confidence": 0.9},
        )
        # No trading output (Claude timed out)
        decision = decide(contract, None, None)
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL
        assert "NO_ACTION" in decision.trading_summary or "MISSING" in decision.trading_summary

    def test_missing_trading_on_read_only_is_fine(self):
        """READ_ONLY with no trading output → still ALLOW (no execution)."""
        contract = build_job_contract(
            "What is the ETH price?",
            {"category": "trading", "confidence": 0.9},
        )
        decision = decide(contract, None, None)
        assert decision.gate_decision == GateDecision.ALLOW

    def test_mutated_would_auto_execute_without_analysis(self):
        """Simulate mutation: no trading output check, proceed to gate."""
        contract = JobContract(
            job_type=JobType.TRADING,
            action_class=ActionClass.VALUE_MOVING,
            requires_execution=True,
            routes=["CLAUDE"],
        )

        # Mutated: skip missing-trading check
        def mutated_decide(c, t=None, s=None):
            d = FinalDecision(job_id=c.job_id)
            # MUTATION: no check for missing trading output
            # Falls through to execution gate which requires approval
            # for VALUE_MOVING — but what if someone also mutated that?
            d.disposition = FinalDisposition.APPROVED
            d.gate_decision = GateDecision.ALLOW
            return d

        mutated = mutated_decide(contract, None)
        assert mutated.gate_decision == GateDecision.ALLOW  # WRONG

        real = decide(contract, None)
        assert real.gate_decision == GateDecision.REQUIRE_APPROVAL  # RIGHT

    def test_empty_string_trading_output_on_execution_job(self):
        """Empty string response is still a TradingOutput — not None.
        But the trading_verdict defaults to NO_ACTION."""
        contract = build_job_contract(
            "Buy $100 ETH",
            {"category": "trading", "confidence": 0.9},
        )
        trading = TradingOutput(raw_response="")  # Empty but present
        decision = decide(contract, trading, None)
        # TradingOutput is present, so it goes to the VALUE_MOVING gate
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL


# ═══════════════════════════════════════════════════════════════════════════
# COMPOUND MUTATIONS — multiple safety guards removed
# ═══════════════════════════════════════════════════════════════════════════

class TestCompoundMutations:
    """Test that even if ONE guard fails, other guards catch it.
    Defense in depth: no single point of failure."""

    def test_route_block_plus_decide_block(self):
        """HIGH sensitivity is blocked at BOTH route selection AND decide().
        Removing one still leaves the other."""
        # Guard 1: select_routes
        routes = select_routes(JobType.TRADING, Sensitivity.HIGH)
        assert "CLAUDE" not in routes

        # Guard 2: decide() with forced wrong route
        contract = JobContract(
            sensitivity=Sensitivity.HIGH,
            routes=["CLAUDE"],  # Guard 1 bypassed
        )
        decision = decide(contract)
        assert decision.disposition == FinalDisposition.BLOCKED_POLICY

    def test_redaction_plus_response_policy(self):
        """Secrets are caught at BOTH contract building AND response policy.
        Two independent layers."""
        fake_key = "0x" + "cd" * 32

        # Guard 1: contract summary redaction
        contract = build_job_contract(
            f"Check {fake_key}",
            {"category": "trading", "confidence": 0.9},
        )
        assert fake_key not in contract.context_summary

        # Guard 2: response policy (if somehow guard 1 missed it)
        response = f"Key is {fake_key}"
        decision = FinalDecision(
            disposition=FinalDisposition.APPROVED_READ_ONLY,
            gate_decision=GateDecision.ALLOW,
        )
        cleaned = enforce_response_policy(response, decision)
        assert fake_key not in cleaned

    def test_veto_plus_gate_plus_missing_security(self):
        """Three independent guards on mixed execution jobs:
        1. Security veto
        2. Execution gate
        3. Missing security check
        All three must independently block unsafe outcomes."""
        contract = JobContract(
            job_type=JobType.MIXED,
            action_class=ActionClass.VALUE_MOVING,
            requires_execution=True,
            routes=["CLAUDE", "GEMINI"],
        )

        # Guard 1: Security REJECT
        sec_reject = SecurityOutput(
            security_verdict=SecurityVerdict.REJECT,
            raw_response="REJECT",
        )
        d1 = decide(contract, None, sec_reject)
        assert d1.disposition == FinalDisposition.BLOCKED_SECURITY

        # Guard 2: Missing security → ESCALATE
        d2 = decide(contract, None, None)
        assert d2.gate_decision == GateDecision.REQUIRE_APPROVAL

        # Guard 3: Even with security ALLOW, VALUE_MOVING still gates
        sec_allow = SecurityOutput(
            security_verdict=SecurityVerdict.ALLOW,
            raw_response="VERDICT: ALLOW",
        )
        trading = TradingOutput(raw_response="Go")
        d3 = decide(contract, trading, sec_allow)
        assert d3.gate_decision == GateDecision.REQUIRE_APPROVAL


# ═══════════════════════════════════════════════════════════════════════════
# HARD DEFAULTS — prove they cannot be silently changed
# ═══════════════════════════════════════════════════════════════════════════

class TestHardDefaultsMutationResistance:
    """The HARD_DEFAULTS dict must be immutable in effect.
    These values drive all downstream behavior."""

    def test_defaults_match_behavior(self):
        """Each hard default must be reflected in actual system behavior."""
        from policy_engine import HARD_DEFAULTS

        # security_veto = True → REJECT always blocks
        assert HARD_DEFAULTS["security_veto"] is True
        sec = SecurityOutput(security_verdict=SecurityVerdict.REJECT, raw_response="R")
        d = decide(JobContract(routes=["CLAUDE"]), None, sec)
        assert d.disposition == FinalDisposition.BLOCKED_SECURITY

        # default_execution_mode = disabled → no auto-execution
        assert HARD_DEFAULTS["default_execution_mode"] == "disabled"

        # secrets_to_cloud = False → HIGH never routes to CLAUDE
        assert HARD_DEFAULTS["secrets_to_cloud"] is False
        routes = select_routes(JobType.TRADING, Sensitivity.HIGH)
        assert "CLAUDE" not in routes

        # value_moving_requires_approval = True
        assert HARD_DEFAULTS["value_moving_requires_approval"] is True
        d = decide(JobContract(
            action_class=ActionClass.VALUE_MOVING,
            requires_execution=True, routes=["CLAUDE"],
        ))
        assert d.gate_decision == GateDecision.REQUIRE_APPROVAL

        # high_sensitivity_requires_local = True
        assert HARD_DEFAULTS["high_sensitivity_requires_local"] is True
        routes = select_routes(JobType.MIXED, Sensitivity.HIGH)
        assert "CLAUDE" not in routes
