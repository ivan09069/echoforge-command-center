"""
tests/test_policy_invariants.py
================================
Five invariants to lock before adding any features.
These are the non-negotiable rules of the system.

Invariants:
  1. SECURITY_REJECT => final != APPROVED (any form)
  2. HIGH sensitivity => no cloud route (CLAUDE never receives HIGH)
  3. VALUE_MOVING => approval always required
  4. Raw secrets => never appear in final output
  5. Artifact refs => hashes only, no raw sensitive payloads

Minimum proof pack:
  A. One passing LOW + READ_ONLY trading job
  B. One HIGH job blocked from Cloudflare
  C. One mixed job where trading=yes, security=REJECT
  D. One VALUE_MOVING job halted pending approval
  E. One output-redaction test (secret in model output gets stripped)

Run: pytest tests/test_policy_invariants.py -v
"""

import sys
import os
import pytest

# Ensure project root is importable
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
    content_hash, HARD_DEFAULTS,
)


# ═══════════════════════════════════════════════════════════════════════════
# INVARIANT 1: SECURITY_REJECT => final != any APPROVED state
# ═══════════════════════════════════════════════════════════════════════════

class TestInvariant1_SecurityRejectBlocksAll:
    """If security says REJECT, no form of approval is possible."""

    APPROVED_STATES = {
        FinalDisposition.APPROVED,
        FinalDisposition.APPROVED_READ_ONLY,
        FinalDisposition.APPROVED_WITH_CONDITIONS,
    }

    def _make_reject(self, **kwargs) -> SecurityOutput:
        return SecurityOutput(
            security_verdict=SecurityVerdict.REJECT,
            severity=kwargs.get("severity", Sensitivity.HIGH),
            findings=kwargs.get("findings", ["Test rejection"]),
            raw_response="VERDICT: REJECT",
        )

    def test_reject_blocks_trading_read_only(self):
        contract = JobContract(job_type=JobType.TRADING, routes=["CLAUDE"])
        trading = TradingOutput(trading_verdict=TradingVerdict.PROPOSE, raw_response="buy")
        security = self._make_reject()
        decision = decide(contract, trading, security)
        assert decision.disposition not in self.APPROVED_STATES
        assert decision.disposition == FinalDisposition.BLOCKED_SECURITY

    def test_reject_blocks_trading_with_execution(self):
        contract = JobContract(
            job_type=JobType.TRADING, routes=["CLAUDE"],
            requires_execution=True, action_class=ActionClass.VALUE_MOVING,
        )
        trading = TradingOutput(
            trading_verdict=TradingVerdict.PROPOSE,
            confidence=0.95, execution_request=True,
            raw_response="high confidence buy",
        )
        security = self._make_reject()
        decision = decide(contract, trading, security)
        assert decision.disposition not in self.APPROVED_STATES

    def test_reject_blocks_security_job(self):
        contract = JobContract(job_type=JobType.SECURITY, routes=["GEMINI"])
        security = self._make_reject()
        decision = decide(contract, None, security)
        assert decision.disposition == FinalDisposition.BLOCKED_SECURITY

    def test_reject_blocks_mixed_job(self):
        """The critical case: Claude says yes, Gemini says REJECT."""
        contract = JobContract(
            job_type=JobType.MIXED, routes=["CLAUDE", "GEMINI"],
        )
        trading = TradingOutput(
            trading_verdict=TradingVerdict.PROPOSE,
            confidence=0.90, strategy="mean_reversion",
            raw_response="Strong signal, recommend immediate entry",
        )
        security = self._make_reject(
            findings=["Unsafe environment", "Unverified contract approval"],
        )
        decision = decide(contract, trading, security)
        assert decision.disposition == FinalDisposition.BLOCKED_SECURITY
        assert decision.gate_decision == GateDecision.DENY

    def test_reject_blocks_even_low_sensitivity(self):
        contract = JobContract(
            job_type=JobType.TRADING, sensitivity=Sensitivity.LOW,
            routes=["CLAUDE"],
        )
        security = self._make_reject(severity=Sensitivity.LOW)
        decision = decide(contract, None, security)
        assert decision.disposition not in self.APPROVED_STATES

    def test_reject_with_escalate_also_blocks(self):
        """ESCALATE should not approve either."""
        contract = JobContract(job_type=JobType.SECURITY, routes=["GEMINI"])
        security = SecurityOutput(
            security_verdict=SecurityVerdict.ESCALATE,
            raw_response="VERDICT: ESCALATE",
        )
        decision = decide(contract, None, security)
        assert decision.disposition not in self.APPROVED_STATES
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL


# ═══════════════════════════════════════════════════════════════════════════
# INVARIANT 2: HIGH sensitivity => no cloud route
# ═══════════════════════════════════════════════════════════════════════════

class TestInvariant2_HighNeverCloud:
    """HIGH sensitivity must never route to CLAUDE (Cloudflare lane)."""

    def test_high_routes_to_gemini_only(self):
        routes = select_routes(JobType.TRADING, Sensitivity.HIGH)
        assert "CLAUDE" not in routes
        assert "GEMINI" in routes

    def test_high_security_stays_local(self):
        routes = select_routes(JobType.SECURITY, Sensitivity.HIGH)
        assert "CLAUDE" not in routes

    def test_high_mixed_routes_to_gemini_only(self):
        """Even MIXED requests with HIGH sensitivity cannot reach cloud."""
        routes = select_routes(JobType.MIXED, Sensitivity.HIGH)
        assert "CLAUDE" not in routes

    def test_high_general_routes_to_gemini_only(self):
        routes = select_routes(JobType.GENERAL, Sensitivity.HIGH)
        assert "CLAUDE" not in routes

    def test_contract_builder_reclassifies_high_trading(self):
        """build_job_contract must reclassify HIGH+TRADING to SECURITY."""
        classification = {"category": "trading", "confidence": 0.9}
        # Message with HIGH keyword
        contract = build_job_contract("decrypt my keystore file", classification)
        assert contract.sensitivity == Sensitivity.HIGH
        assert "CLAUDE" not in contract.routes

    def test_contract_builder_with_private_key(self):
        """A message containing a private key must go local only."""
        fake_key = "0x" + "a1" * 32  # 64 hex chars
        contract = build_job_contract(
            f"Check this key {fake_key}",
            {"category": "trading", "confidence": 0.8},
        )
        assert contract.sensitivity == Sensitivity.HIGH
        assert "CLAUDE" not in contract.routes

    def test_decide_blocks_high_to_claude_if_somehow_routed(self):
        """Even if routes were manually set wrong, decide() must block."""
        contract = JobContract(
            job_type=JobType.TRADING,
            sensitivity=Sensitivity.HIGH,
            routes=["CLAUDE"],  # This should never happen, but test the guard
        )
        decision = decide(contract)
        assert decision.disposition == FinalDisposition.BLOCKED_POLICY
        assert decision.gate_decision == GateDecision.DENY

    def test_known_passwords_trigger_high(self):
        """Ivan's known password patterns must classify as HIGH."""
        for pw in ["2012Kenworth5.", "2012KENWORTH", "85Freightliner", "85Blazer", "82Chevy4!"]:
            sens = classify_sensitivity(f"Try password {pw}")
            assert sens == Sensitivity.HIGH, f"Password '{pw}' did not trigger HIGH"

    def test_seed_phrase_triggers_high(self):
        fake_seed = "abandon " * 12
        sens = classify_sensitivity(f"My seed is {fake_seed.strip()}")
        assert sens == Sensitivity.HIGH

    def test_api_key_triggers_high(self):
        sens = classify_sensitivity("My key is sk-ant-abcdefghijklmnopqrstuvwxyz1234567890")
        assert sens == Sensitivity.HIGH


# ═══════════════════════════════════════════════════════════════════════════
# INVARIANT 3: VALUE_MOVING => approval always required
# ═══════════════════════════════════════════════════════════════════════════

class TestInvariant3_ValueMovingRequiresApproval:
    """Any VALUE_MOVING action must require explicit human approval."""

    VALUE_PHRASES = [
        "buy $100 of ETH",
        "sell my BTC position",
        "swap ETH for USDC",
        "transfer 0.5 ETH to wallet",
        "send funds to JIT0906",
        "withdraw from exchange",
        "bridge ETH to arbitrum",
    ]

    def test_value_moving_action_class_detected(self):
        for phrase in self.VALUE_PHRASES:
            ac = classify_action(phrase)
            assert ac == ActionClass.VALUE_MOVING, f"'{phrase}' not classified as VALUE_MOVING"

    def test_value_moving_gate_requires_approval(self):
        contract = JobContract(
            job_type=JobType.TRADING,
            action_class=ActionClass.VALUE_MOVING,
            requires_execution=True,
            routes=["CLAUDE"],
        )
        decision = decide(contract)
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL
        assert decision.disposition == FinalDisposition.AWAITING_HUMAN_APPROVAL

    def test_value_moving_even_with_allow_security(self):
        """Security ALLOW does not bypass the approval requirement."""
        contract = JobContract(
            job_type=JobType.TRADING,
            action_class=ActionClass.VALUE_MOVING,
            requires_execution=True,
            routes=["CLAUDE"],
        )
        security = SecurityOutput(
            security_verdict=SecurityVerdict.ALLOW,
            raw_response="All clear",
        )
        trading = TradingOutput(
            trading_verdict=TradingVerdict.PROPOSE,
            confidence=0.99,
            raw_response="Perfect setup",
        )
        decision = decide(contract, trading, security)
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL

    def test_sensitive_write_also_requires_approval(self):
        contract = JobContract(
            job_type=JobType.SECURITY,
            action_class=ActionClass.SENSITIVE_WRITE,
            requires_execution=True,
            routes=["GEMINI"],
        )
        decision = decide(contract)
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL

    def test_contract_builder_flags_approval(self):
        contract = build_job_contract(
            "Buy $100 of ETH from JIT0906",
            {"category": "trading", "confidence": 0.95},
        )
        assert contract.approval_required is True
        assert contract.action_class == ActionClass.VALUE_MOVING

    def test_hard_default_is_set(self):
        assert HARD_DEFAULTS["value_moving_requires_approval"] is True


# ═══════════════════════════════════════════════════════════════════════════
# INVARIANT 4: Raw secrets => never appear in final output
# ═══════════════════════════════════════════════════════════════════════════

class TestInvariant4_SecretsNeverInOutput:
    """Secrets must be stripped from any response before it reaches the user."""

    SECRETS = [
        ("0x" + "ab" * 32, "PRIVATE_KEY"),
        ("2012Kenworth5.", "KNOWN_PASSWORD"),
        ("2012KENWORTH", "KNOWN_PASSWORD"),
        ("85Freightliner!", "KNOWN_PASSWORD"),
        ("85Blazer3;", "KNOWN_PASSWORD"),
        ("82Chevy4!", "KNOWN_PASSWORD"),
        ("sk-ant-abcdefghijklmnopqrstuvwxyz1234567890", "ANTHROPIC_API_KEY"),
        ("sk-abcdefghijklmnopqrstuvwxyz1234567890", "OPENAI_API_KEY"),
        ("AIzaSyAbcdefghijklmnopqrstuvwxyz1234567890", "GOOGLE_API_KEY"),
        ("-----BEGIN PRIVATE KEY-----", "PEM_KEY"),
    ]

    def test_detect_finds_all_secret_types(self):
        for secret, expected_type in self.SECRETS:
            findings = detect_secrets(f"Here is the value: {secret}")
            types_found = [f["type"] for f in findings]
            assert expected_type in types_found, (
                f"Secret type '{expected_type}' not detected for: {secret[:20]}..."
            )

    def test_redact_removes_all_secrets(self):
        for secret, _ in self.SECRETS:
            text = f"The secret is {secret} and more text"
            redacted, count = redact_secrets(text)
            assert secret not in redacted, f"Secret not redacted: {secret[:20]}..."
            assert count > 0
            assert "[REDACTED:" in redacted

    def test_enforce_response_policy_strips_secrets(self):
        """If a model accidentally outputs a secret, the response policy catches it."""
        fake_key = "0x" + "de" * 32
        response = f"The private key for this wallet is {fake_key}"
        decision = FinalDecision(
            disposition=FinalDisposition.APPROVED_READ_ONLY,
            gate_decision=GateDecision.ALLOW,
        )
        cleaned = enforce_response_policy(response, decision)
        assert fake_key not in cleaned
        assert "[REDACTED:" in cleaned

    def test_response_policy_strips_password_patterns(self):
        response = "I found the password: 2012Kenworth5. in the keystore"
        decision = FinalDecision(
            disposition=FinalDisposition.APPROVED_READ_ONLY,
            gate_decision=GateDecision.ALLOW,
        )
        cleaned = enforce_response_policy(response, decision)
        assert "2012Kenworth" not in cleaned

    def test_contract_summary_is_redacted(self):
        fake_key = "0x" + "ff" * 32
        contract = build_job_contract(
            f"Check balance for key {fake_key}",
            {"category": "trading", "confidence": 0.9},
        )
        assert fake_key not in contract.context_summary
        assert "[REDACTED:" in contract.context_summary

    def test_multiple_secrets_all_redacted(self):
        text = (
            "Key: 0x" + "ab" * 32 + " "
            "Password: 2012Kenworth5. "
            "API: sk-ant-abcdefghijklmnopqrstuvwxyz1234567890"
        )
        redacted, count = redact_secrets(text)
        assert count >= 3
        assert "0x" + "ab" * 32 not in redacted
        assert "2012Kenworth" not in redacted
        assert "sk-ant-" not in redacted


# ═══════════════════════════════════════════════════════════════════════════
# INVARIANT 5: Artifact refs => hashes only, no raw sensitive payloads
# ═══════════════════════════════════════════════════════════════════════════

class TestInvariant5_ArtifactRefsHashesOnly:
    """Artifacts must be referenced by type/hash/location, never raw content."""

    def test_artifact_ref_has_no_content_field(self):
        ref = ArtifactRef(
            type="script",
            location="local_ref_only",
            sensitivity=Sensitivity.HIGH,
            hash=content_hash("some sensitive content"),
        )
        d = ref.to_dict()
        assert "content" not in d
        assert "raw" not in d
        assert d["hash"]  # hash is present
        assert d["location"] == "local_ref_only"

    def test_artifact_hash_is_deterministic(self):
        h1 = content_hash("test content")
        h2 = content_hash("test content")
        assert h1 == h2
        assert len(h1) == 16  # Truncated SHA-256

    def test_artifact_hash_differs_for_different_content(self):
        h1 = content_hash("content A")
        h2 = content_hash("content B")
        assert h1 != h2

    def test_contract_artifacts_are_refs_not_content(self):
        contract = JobContract(
            artifacts=[
                ArtifactRef(
                    type="wallet_file",
                    location="local_ref_only",
                    sensitivity=Sensitivity.HIGH,
                    hash=content_hash("wallet data"),
                ),
            ]
        )
        d = contract.to_dict()
        for art in d["artifacts"]:
            assert "content" not in art
            assert "data" not in art
            assert art["location"] == "local_ref_only"
            assert art["hash"]

    def test_high_sensitivity_artifact_location_is_local(self):
        ref = ArtifactRef(
            type="keystore",
            sensitivity=Sensitivity.HIGH,
        )
        assert ref.location == "local_ref_only"


# ═══════════════════════════════════════════════════════════════════════════
# MINIMUM PROOF PACK
# ═══════════════════════════════════════════════════════════════════════════

class TestProofPack:
    """
    End-to-end proof that the system handles each scenario correctly.
    These are the minimum tests required before any deployment.
    """

    def test_A_low_read_only_trading_passes(self):
        """Proof A: LOW + READ_ONLY trading job passes cleanly."""
        contract = build_job_contract(
            "What is the current price of ETH?",
            {"category": "trading", "confidence": 0.95},
        )
        assert contract.sensitivity == Sensitivity.LOW
        assert contract.action_class == ActionClass.READ_ONLY
        assert "CLAUDE" in contract.routes
        assert contract.approval_required is False

        decision = decide(contract)
        assert decision.disposition == FinalDisposition.APPROVED_READ_ONLY
        assert decision.gate_decision == GateDecision.ALLOW

    def test_B_high_blocked_from_cloudflare(self):
        """Proof B: HIGH job cannot reach Claude/Cloudflare lane."""
        contract = build_job_contract(
            "Decrypt wallet_69.json using the electrum-history private key",
            {"category": "trading", "confidence": 0.7},
        )
        # Must be reclassified to security
        assert contract.sensitivity == Sensitivity.HIGH
        assert "CLAUDE" not in contract.routes
        assert "GEMINI" in contract.routes
        # Double check: if somehow forced to CLAUDE, decide() blocks it
        forced = JobContract(
            sensitivity=Sensitivity.HIGH, routes=["CLAUDE"],
        )
        decision = decide(forced)
        assert decision.disposition == FinalDisposition.BLOCKED_POLICY

    def test_C_mixed_trading_yes_security_reject(self):
        """Proof C: Trading says yes, security says REJECT → blocked."""
        contract = JobContract(
            job_type=JobType.MIXED,
            routes=["CLAUDE", "GEMINI"],
        )
        trading = TradingOutput(
            trading_verdict=TradingVerdict.PROPOSE,
            confidence=0.88,
            strategy="mean_reversion",
            execution_request=True,
            raw_response="Strong entry signal on ETH, recommend immediate buy",
        )
        security = SecurityOutput(
            security_verdict=SecurityVerdict.REJECT,
            severity=Sensitivity.HIGH,
            findings=["Wallet has unlimited approval to known drainer", "Unsafe environment"],
            raw_response="VERDICT: REJECT\nSEVERITY: HIGH\nDo not proceed.",
        )
        decision = decide(contract, trading, security)
        assert decision.disposition == FinalDisposition.BLOCKED_SECURITY
        assert decision.gate_decision == GateDecision.DENY
        # Trading confidence doesn't matter — security veto is absolute
        assert "REJECT" in decision.gate_reason or "Security" in decision.gate_reason

    def test_D_value_moving_halted_pending_approval(self):
        """Proof D: VALUE_MOVING job requires human approval."""
        contract = build_job_contract(
            "Buy $100 of ETH from JIT0906 wallet",
            {"category": "trading", "confidence": 0.95},
        )
        assert contract.action_class == ActionClass.VALUE_MOVING
        assert contract.approval_required is True

        decision = decide(contract)
        assert decision.disposition == FinalDisposition.AWAITING_HUMAN_APPROVAL
        assert decision.gate_decision == GateDecision.REQUIRE_APPROVAL
        assert decision.approval_prompt  # Non-empty prompt for user

    def test_E_output_redaction_strips_secret(self):
        """Proof E: Secret in model output gets stripped before user sees it."""
        # Simulate a model accidentally leaking a private key
        leaked_key = "0x" + "ba" * 32
        model_output = (
            f"I found the wallet. The private key is {leaked_key}. "
            "You can use this to sign transactions."
        )
        decision = FinalDecision(
            disposition=FinalDisposition.APPROVED_READ_ONLY,
            gate_decision=GateDecision.ALLOW,
        )
        final_output = enforce_response_policy(model_output, decision)

        # The secret must NOT be in the final output
        assert leaked_key not in final_output
        # The redaction marker must be present
        assert "[REDACTED:" in final_output
        # The warning must be present
        assert "redacted" in final_output.lower()


# ═══════════════════════════════════════════════════════════════════════════
# HARD DEFAULTS VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════

class TestHardDefaults:
    """Verify the non-negotiable defaults are set correctly."""

    def test_security_veto_enabled(self):
        assert HARD_DEFAULTS["security_veto"] is True

    def test_default_security_mode_read_only(self):
        assert HARD_DEFAULTS["default_security_mode"] == "read_only"

    def test_default_execution_disabled(self):
        assert HARD_DEFAULTS["default_execution_mode"] == "disabled"

    def test_secrets_to_cloud_false(self):
        assert HARD_DEFAULTS["secrets_to_cloud"] is False

    def test_value_moving_requires_approval(self):
        assert HARD_DEFAULTS["value_moving_requires_approval"] is True

    def test_high_sensitivity_requires_local(self):
        assert HARD_DEFAULTS["high_sensitivity_requires_local"] is True


# ═══════════════════════════════════════════════════════════════════════════
# CONSTRAINT BUILDER VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════

class TestConstraints:
    """Verify constraint generation enforces boundaries."""

    def test_trading_gets_no_secrets_constraint(self):
        c = build_constraints(JobType.TRADING, Sensitivity.LOW, ActionClass.READ_ONLY, ["CLAUDE"])
        assert "no-secrets" in c
        assert "cloud-safe" in c

    def test_high_gets_local_only(self):
        c = build_constraints(JobType.SECURITY, Sensitivity.HIGH, ActionClass.READ_ONLY, ["GEMINI"])
        assert "local-only" in c
        assert "do-not-export" in c

    def test_value_moving_gets_gate(self):
        c = build_constraints(JobType.TRADING, Sensitivity.LOW, ActionClass.VALUE_MOVING, ["CLAUDE"])
        assert "value-moving-requires-approval" in c
        assert "execution-gate-required" in c

    def test_mixed_gets_veto_constraint(self):
        c = build_constraints(JobType.MIXED, Sensitivity.LOW, ActionClass.READ_ONLY, ["CLAUDE", "GEMINI"])
        assert "security-veto-is-binding" in c

    def test_medium_gets_reduced_context(self):
        c = build_constraints(JobType.SECURITY, Sensitivity.MEDIUM, ActionClass.READ_ONLY, ["GEMINI"])
        assert "reduced-context-only" in c
