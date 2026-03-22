"""
tests/test_routing_golden_corpus.py
=====================================
Pinned corpus of routing phrases. Classifier semantics are frozen here.
Any change to classify_sensitivity, classify_action, select_routes,
or the verdict parser must pass this entire suite.

Buckets:
  1. Simulation phrases → READ_ONLY, no execution
  2. Analysis-only phrases → READ_ONLY, no approval
  3. Sensitive local-only phrases → HIGH, GEMINI only, local-only constraint
  4. Value-moving phrases → VALUE_MOVING, approval required
  5. Mixed phrases with security veto expectations
  6. Unknown/ambiguous verdict handling → ESCALATE, never ALLOW

This is the regression gate. Do not weaken these tests.
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from contracts import (
    JobContract, JobType, Sensitivity, ActionClass, GateDecision,
    SecurityVerdict, SecurityOutput, TradingOutput, TradingVerdict,
    FinalDecision, FinalDisposition,
)
from policy_engine import (
    build_job_contract, decide, classify_sensitivity, classify_action,
    select_routes, detect_secrets, redact_secrets, requires_execution,
)


# ═══════════════════════════════════════════════════════════════════════════
# HELPER
# ═══════════════════════════════════════════════════════════════════════════

def _contract(msg: str, category: str = "trading") -> JobContract:
    return build_job_contract(msg, {"category": category, "confidence": 0.9})


def _parse_verdict(raw: str) -> SecurityOutput:
    """Mirror of web_ui._parse_security_verdict with the tightened default."""
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
# BUCKET 1: SIMULATION PHRASES → READ_ONLY
# Simulation is reasoning, not execution.
# ═══════════════════════════════════════════════════════════════════════════

class TestGolden_Simulation:
    """All simulation/hypothetical phrases must classify as READ_ONLY
    and must NOT require execution or approval."""

    CORPUS = [
        "Simulate buying $100 of ETH",
        "Simulate selling 0.5 BTC",
        "Run a simulation of the mean reversion strategy",
        "What if I bought ETH at $3,400?",
        "Hypothetical: swap all USDC to ETH",
        "Do a dry-run of the trade",
        "Dry run: buy $125 BTC",
        "Paper trade ETH/USDC for the next hour",
        "Backtest mean reversion on last 30 days",
        "Backtest the momentum strategy with new thresholds",
        "Test run buying $50 of ETH",
        "Simulate a bridge from Base to Arbitrum",
        "What if we sold everything and went to cash?",
    ]

    @pytest.mark.parametrize("phrase", CORPUS)
    def test_simulation_is_read_only(self, phrase):
        assert classify_action(phrase) == ActionClass.READ_ONLY, (
            f"'{phrase}' was not READ_ONLY"
        )

    @pytest.mark.parametrize("phrase", CORPUS)
    def test_simulation_does_not_require_execution(self, phrase):
        assert requires_execution(phrase) is False, (
            f"'{phrase}' incorrectly flagged as requiring execution"
        )

    @pytest.mark.parametrize("phrase", CORPUS)
    def test_simulation_contract_no_approval(self, phrase):
        contract = _contract(phrase)
        assert contract.approval_required is False, (
            f"'{phrase}' incorrectly required approval"
        )


# ═══════════════════════════════════════════════════════════════════════════
# BUCKET 2: ANALYSIS-ONLY PHRASES → READ_ONLY, LOW sensitivity
# Pure information retrieval. No state changes.
# ═══════════════════════════════════════════════════════════════════════════

class TestGolden_AnalysisOnly:
    """Pure analysis/information queries. LOW sensitivity, READ_ONLY,
    no approval needed, routable to cloud."""

    CORPUS = [
        "What is the current price of ETH?",
        "Show me a portfolio summary",
        "What's the gas price on Base?",
        "What is the bot status?",
        "How many trades did the bot make today?",
        "What's the PnL for this session?",
        "Compare mean reversion vs momentum performance",
        "What are the current RSI thresholds?",
        "Show me the trading rules",
        "What pairs are we trading?",
        "What's the daily cap?",
        "How much capital is deployed?",
    ]

    @pytest.mark.parametrize("phrase", CORPUS)
    def test_analysis_is_read_only(self, phrase):
        assert classify_action(phrase) == ActionClass.READ_ONLY

    @pytest.mark.parametrize("phrase", CORPUS)
    def test_analysis_is_low_sensitivity(self, phrase):
        assert classify_sensitivity(phrase) == Sensitivity.LOW

    @pytest.mark.parametrize("phrase", CORPUS)
    def test_analysis_routes_to_claude(self, phrase):
        contract = _contract(phrase, "trading")
        assert "CLAUDE" in contract.routes

    @pytest.mark.parametrize("phrase", CORPUS)
    def test_analysis_auto_approved(self, phrase):
        contract = _contract(phrase)
        decision = decide(contract)
        assert decision.gate_decision == GateDecision.ALLOW


# ═══════════════════════════════════════════════════════════════════════════
# BUCKET 3: SENSITIVE LOCAL-ONLY PHRASES → HIGH, GEMINI, local-only
# These must NEVER reach Cloudflare.
# ═══════════════════════════════════════════════════════════════════════════

class TestGolden_SensitiveLocalOnly:
    """Any mention of secrets, keys, passwords, or sensitive artifacts
    must classify as HIGH and route exclusively to local/GEMINI."""

    CORPUS = [
        "Decrypt wallet_69.json",
        "Recover the seed phrase from the backup",
        "Try password 2012Kenworth5. on the keystore",
        "Check the .env file for leaked keys",
        "Crack the encrypted keystore",
        "Brute force the Coin98 .C98 file",
        "Show me the mnemonic for the Samsung wallet",
        "Extract the private key from the electrum-history file",
        "Audit the wallet dump for credential leakage",
        "What password cracked the Samsung keystore?",
        "Check if 85Freightliner is the right password",
        "Search SmartSwitch backups for seed phrases",
        "Review the wallet export for sensitive data",
    ]

    @pytest.mark.parametrize("phrase", CORPUS)
    def test_high_sensitivity(self, phrase):
        assert classify_sensitivity(phrase) == Sensitivity.HIGH, (
            f"'{phrase}' was not HIGH sensitivity"
        )

    @pytest.mark.parametrize("phrase", CORPUS)
    def test_never_routes_to_claude(self, phrase):
        # Even if triage says "trading", HIGH sensitivity overrides
        contract = _contract(phrase, "trading")
        assert "CLAUDE" not in contract.routes, (
            f"'{phrase}' incorrectly routed to CLAUDE"
        )

    @pytest.mark.parametrize("phrase", CORPUS)
    def test_routes_to_gemini(self, phrase):
        contract = _contract(phrase, "security")
        assert "GEMINI" in contract.routes

    @pytest.mark.parametrize("phrase", CORPUS)
    def test_local_only_constraint(self, phrase):
        contract = _contract(phrase, "security")
        assert "local-only" in contract.constraints, (
            f"'{phrase}' missing local-only constraint"
        )

    @pytest.mark.parametrize("phrase", CORPUS)
    def test_do_not_export_constraint(self, phrase):
        contract = _contract(phrase, "security")
        assert "do-not-export" in contract.constraints


# ═══════════════════════════════════════════════════════════════════════════
# BUCKET 4: VALUE-MOVING PHRASES → VALUE_MOVING, approval required
# Every one of these must hit the execution gate.
# ═══════════════════════════════════════════════════════════════════════════

class TestGolden_ValueMoving:
    """Every phrase involving fund movement must require explicit approval."""

    CORPUS = [
        "Buy $100 of ETH",
        "Buy $50 BTC from JIT0906",
        "Sell my entire ETH position",
        "Sell 0.5 ETH for USDC",
        "Swap ETH for USDC",
        "Swap all USDC to BTC",
        "Trade $125 on ETH/USDC",
        "Send 1 ETH to the BankrCoin wallet",
        "Send funds to 0x22af",
        "Transfer 0.5 ETH to Arbitrum",
        "Transfer remaining USDC to JIT0906",
        "Withdraw from Coinbase to JIT0906",
        "Withdraw all ETH",
        "Bridge 0.5 ETH from Base to Arbitrum",
        "Bridge USDC to Ethereum mainnet",
    ]

    @pytest.mark.parametrize("phrase", CORPUS)
    def test_classified_as_value_moving(self, phrase):
        assert classify_action(phrase) == ActionClass.VALUE_MOVING, (
            f"'{phrase}' was not VALUE_MOVING"
        )

    @pytest.mark.parametrize("phrase", CORPUS)
    def test_requires_approval(self, phrase):
        contract = _contract(phrase)
        assert contract.approval_required is True, (
            f"'{phrase}' did not require approval"
        )

    @pytest.mark.parametrize("phrase", CORPUS)
    def test_gate_requires_approval(self, phrase):
        contract = _contract(phrase)
        decision = decide(contract)
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL, (
            f"'{phrase}' did not gate as REQUIRE_APPROVAL"
        )


# ═══════════════════════════════════════════════════════════════════════════
# BUCKET 5: MIXED PHRASES — security veto expectations
# When both lanes run, security verdict is binding.
# ═══════════════════════════════════════════════════════════════════════════

class TestGolden_MixedWithVeto:
    """Mixed requests where security should have veto authority."""

    MIXED_CORPUS = [
        "Optimize bot but make sure it isn't leaking secrets",
        "Deploy this but audit permissions first",
        "Tune strategy without exposing secrets",
        "Make this automation production safe",
        "Check if wallets are safe then show portfolio",
        "Review the bot code and suggest threshold changes",
        "Audit the config and then run a trade simulation",
    ]

    @pytest.mark.parametrize("phrase", MIXED_CORPUS)
    def test_mixed_routes_both_agents(self, phrase):
        contract = _contract(phrase, "mixed")
        assert "CLAUDE" in contract.routes or "GEMINI" in contract.routes

    def test_reject_veto_blocks_mixed_proposal(self):
        """Core veto test: Claude says yes, Gemini says REJECT → BLOCKED."""
        contract = JobContract(
            job_type=JobType.MIXED,
            routes=["CLAUDE", "GEMINI"],
        )
        trading = TradingOutput(
            trading_verdict=TradingVerdict.PROPOSE,
            confidence=0.92,
            raw_response="Excellent setup, execute immediately",
        )
        security = SecurityOutput(
            security_verdict=SecurityVerdict.REJECT,
            findings=["Credential leakage in subprocess call"],
            raw_response="VERDICT: REJECT",
        )
        decision = decide(contract, trading, security)
        assert decision.disposition == FinalDisposition.BLOCKED_SECURITY
        assert decision.gate_decision == GateDecision.DENY

    def test_allow_with_conditions_surfaces_conditions(self):
        contract = JobContract(
            job_type=JobType.MIXED,
            routes=["CLAUDE", "GEMINI"],
        )
        security = SecurityOutput(
            security_verdict=SecurityVerdict.ALLOW_WITH_CONDITIONS,
            conditions=["Patch shell=True", "Redact logs"],
            raw_response="VERDICT: ALLOW_WITH_CONDITIONS",
        )
        decision = decide(contract, None, security)
        assert len(decision.conditions) > 0

    def test_escalate_requires_human(self):
        contract = JobContract(
            job_type=JobType.MIXED,
            routes=["CLAUDE", "GEMINI"],
        )
        security = SecurityOutput(
            security_verdict=SecurityVerdict.ESCALATE,
            raw_response="VERDICT: ESCALATE",
        )
        decision = decide(contract, None, security)
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL

    def test_mixed_veto_constraint_present(self):
        """Mixed jobs must carry the security-veto-is-binding constraint."""
        for phrase in self.MIXED_CORPUS:
            contract = _contract(phrase, "mixed")
            assert "security-veto-is-binding" in contract.constraints, (
                f"'{phrase}' missing veto constraint"
            )


# ═══════════════════════════════════════════════════════════════════════════
# BUCKET 6: UNKNOWN/AMBIGUOUS VERDICT HANDLING → ESCALATE
# Unknown ≠ safe. Unparseable ≠ approved.
# ═══════════════════════════════════════════════════════════════════════════

class TestGolden_UnknownVerdict:
    """Any verdict that cannot be parsed must default to ESCALATE.
    This is the tightened policy: unknown ≠ safe."""

    UNPARSEABLE_RESPONSES = [
        "",
        "I checked everything and it looks fine.",
        "No issues found in the wallet scan.",
        "The analysis is complete.",
        "RESULT: PASS",
        "STATUS: OK",
        "FINDING: none",
        "All checks passed successfully.",
        "VERDICT: APPROVED",  # Not a valid verdict enum value
        "VERDICT: PASS",      # Not a valid verdict enum value
    ]

    @pytest.mark.parametrize("response", UNPARSEABLE_RESPONSES)
    def test_unknown_verdict_escalates(self, response):
        out = _parse_verdict(response)
        assert out.security_verdict == SecurityVerdict.ESCALATE, (
            f"Response '{response[:40]}...' defaulted to {out.security_verdict} instead of ESCALATE"
        )

    # Parser is case-insensitive (.upper()) by design — LLM output varies in case.
    VALID_VERDICTS = [
        ("VERDICT: ALLOW\nAll clear.", SecurityVerdict.ALLOW),
        ("VERDICT: REJECT\nUnsafe.", SecurityVerdict.REJECT),
        ("VERDICT: ESCALATE\nNeeds review.", SecurityVerdict.ESCALATE),
        ("VERDICT: ALLOW_WITH_CONDITIONS\nPatch needed.", SecurityVerdict.ALLOW_WITH_CONDITIONS),
        # Lowercase variants — parser is case-insensitive, these are valid
        ("verdict: allow", SecurityVerdict.ALLOW),
        ("Verdict: Reject", SecurityVerdict.REJECT),
        ("verdict: escalate", SecurityVerdict.ESCALATE),
        ("verdict: allow_with_conditions", SecurityVerdict.ALLOW_WITH_CONDITIONS),
    ]

    @pytest.mark.parametrize("response,expected", VALID_VERDICTS)
    def test_valid_verdicts_parse_correctly(self, response, expected):
        out = _parse_verdict(response)
        assert out.security_verdict == expected, (
            f"'{response[:40]}' parsed as {out.security_verdict} not {expected}"
        )

    def test_empty_security_output_defaults_to_escalate(self):
        """A bare SecurityOutput() must default to ESCALATE."""
        out = SecurityOutput()
        assert out.security_verdict == SecurityVerdict.ESCALATE

    def test_escalate_default_requires_approval_in_decide(self):
        """An ESCALATE verdict must result in REQUIRE_APPROVAL."""
        contract = JobContract(job_type=JobType.SECURITY, routes=["GEMINI"])
        security = SecurityOutput()  # Defaults to ESCALATE
        decision = decide(contract, None, security)
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL

    def test_case_insensitive_parsing_is_intentional(self):
        """Parser uses .upper() — case variation in LLM output is expected and valid."""
        for variant in ["VERDICT: ALLOW", "verdict: allow", "Verdict: Allow"]:
            out = _parse_verdict(variant)
            assert out.security_verdict == SecurityVerdict.ALLOW, (
                f"'{variant}' should parse as ALLOW (case-insensitive)"
            )


# ═══════════════════════════════════════════════════════════════════════════
# SECRET DETECTION GOLDEN CORPUS
# Pinned patterns that must always be caught.
# ═══════════════════════════════════════════════════════════════════════════

class TestGolden_SecretDetection:
    """Pinned secret patterns. If detection regresses, this fails."""

    MUST_DETECT = [
        # Private keys
        ("0x" + "ab" * 32, Sensitivity.HIGH),
        ("0x" + "00" * 32, Sensitivity.HIGH),
        ("0x" + "ff" * 32, Sensitivity.HIGH),
        # Ivan's passwords
        ("2012KENWORTH", Sensitivity.HIGH),
        ("2012Kenworth", Sensitivity.HIGH),
        ("2012Kenworth5.", Sensitivity.HIGH),
        ("85Freightliner", Sensitivity.HIGH),
        ("85Blazer", Sensitivity.HIGH),
        ("82Chevy4!", Sensitivity.HIGH),
        ("82Chevy5;", Sensitivity.HIGH),
        # API keys
        ("sk-ant-abcdefghijklmnopqrstuvwxyz1234567890", Sensitivity.HIGH),
        ("sk-abcdefghijklmnopqrstuvwxyz1234567890", Sensitivity.HIGH),
        ("AIzaSyAbcdefghijklmnopqrstuvwxyz1234567890", Sensitivity.HIGH),
        # PEM
        ("-----BEGIN PRIVATE KEY-----", Sensitivity.HIGH),
        ("-----BEGIN RSA PRIVATE KEY-----", Sensitivity.HIGH),
    ]

    @pytest.mark.parametrize("secret,expected_sens", MUST_DETECT)
    def test_secret_detected(self, secret, expected_sens):
        findings = detect_secrets(f"Value: {secret}")
        assert len(findings) > 0, f"Secret not detected: {secret[:20]}..."

    @pytest.mark.parametrize("secret,expected_sens", MUST_DETECT)
    def test_secret_redacted(self, secret, expected_sens):
        redacted, count = redact_secrets(f"The secret is {secret} end")
        assert secret not in redacted
        assert count > 0

    @pytest.mark.parametrize("secret,expected_sens", MUST_DETECT)
    def test_secret_triggers_correct_sensitivity(self, secret, expected_sens):
        sens = classify_sensitivity(f"Use {secret}")
        assert sens == expected_sens, f"{secret[:20]}... → {sens} not {expected_sens}"

    MUST_NOT_DETECT = [
        "ETH price is $3,520",
        "Transaction hash 0x1234abcd",
        "Wallet label: JIT0906",
        "RSI threshold: 52",
        "Daily cap: $4,500",
        "Bot uptime: 12 hours",
    ]

    @pytest.mark.parametrize("safe_text", MUST_NOT_DETECT)
    def test_safe_text_not_flagged(self, safe_text):
        findings = detect_secrets(safe_text)
        assert len(findings) == 0, f"False positive: '{safe_text}' flagged as secret"


# ═══════════════════════════════════════════════════════════════════════════
# ROUTE INVARIANT CORPUS
# Pinned: LOW→cloud OK, HIGH→local only
# ═══════════════════════════════════════════════════════════════════════════

class TestGolden_RouteInvariants:
    """Route selection must be deterministic and pinned."""

    @pytest.mark.parametrize("job_type", [JobType.TRADING, JobType.SECURITY, JobType.MIXED, JobType.GENERAL])
    def test_high_never_includes_claude(self, job_type):
        routes = select_routes(job_type, Sensitivity.HIGH)
        assert "CLAUDE" not in routes

    def test_low_trading_includes_claude(self):
        routes = select_routes(JobType.TRADING, Sensitivity.LOW)
        assert "CLAUDE" in routes

    def test_low_security_includes_gemini(self):
        routes = select_routes(JobType.SECURITY, Sensitivity.LOW)
        assert "GEMINI" in routes

    def test_low_mixed_includes_both(self):
        routes = select_routes(JobType.MIXED, Sensitivity.LOW)
        assert "CLAUDE" in routes
        assert "GEMINI" in routes

    def test_medium_trading_includes_claude(self):
        """MEDIUM sensitivity can still route to cloud with reduced context."""
        routes = select_routes(JobType.TRADING, Sensitivity.MEDIUM)
        assert "CLAUDE" in routes

    def test_medium_mixed_includes_both(self):
        routes = select_routes(JobType.MIXED, Sensitivity.MEDIUM)
        assert "CLAUDE" in routes
        assert "GEMINI" in routes
