"""
Phase 2 — Policy Engine
=========================
The heart of the system. Every request passes through here
before and after specialist processing.

Responsibilities:
  Input policy  — classify, detect secrets, reduce context, choose path
  Routing policy — enforce trust boundaries, select local vs cloud
  Output policy  — normalize verdicts, apply veto, gate execution
  Audit          — log everything, log no secrets

Hard defaults (non-negotiable):
  security_veto = true
  default_security_mode = read_only
  default_execution_mode = disabled
  secrets_to_cloud = false
  value_moving_requires_approval = true
  high_sensitivity_requires_local = true
"""

from __future__ import annotations

import re
import hashlib
import logging
from typing import Any

from contracts import (
    JobContract, JobType, Sensitivity, ActionClass, GateDecision,
    SecurityVerdict, SecurityOutput, TradingOutput,
    FinalDecision, FinalDisposition, ArtifactRef, AuditEntry,
)

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# HARD DEFAULTS — non-negotiable
# ═══════════════════════════════════════════════════════════════════════════

HARD_DEFAULTS = {
    "security_veto": True,
    "default_security_mode": "read_only",
    "default_execution_mode": "disabled",
    "secrets_to_cloud": False,
    "value_moving_requires_approval": True,
    "high_sensitivity_requires_local": True,
}


# ═══════════════════════════════════════════════════════════════════════════
# SECRET DETECTION & REDACTION
# ═══════════════════════════════════════════════════════════════════════════

# Patterns that indicate HIGH/CRITICAL secrets
SECRET_PATTERNS: list[tuple[str, str, Sensitivity]] = [
    # Private keys (64 hex chars)
    (r"\b(0x[a-fA-F0-9]{64})\b", "PRIVATE_KEY", Sensitivity.HIGH),
    # Seed phrases (12-24 words)
    (r"(?i)((?:\b[a-z]+\b\s+){11,23}\b[a-z]+\b)", "POTENTIAL_SEED_PHRASE", Sensitivity.HIGH),
    # Ivan's known password patterns
    (r"(?i)\b2012(?:kenworth|KENWORTH)\S*\b", "KNOWN_PASSWORD", Sensitivity.HIGH),
    (r"(?i)\b85(?:freightliner|Freightliner|blazer|Blazer)\S*\b", "KNOWN_PASSWORD", Sensitivity.HIGH),
    (r"(?i)\b82(?:chevy|Chevy)\S*\b", "KNOWN_PASSWORD", Sensitivity.HIGH),
    # API keys
    (r"(?i)sk-ant-[a-zA-Z0-9\-_]{20,}", "ANTHROPIC_API_KEY", Sensitivity.HIGH),
    (r"(?i)sk-[a-zA-Z0-9]{20,}", "OPENAI_API_KEY", Sensitivity.HIGH),
    (r"(?i)AIza[a-zA-Z0-9\-_]{35}", "GOOGLE_API_KEY", Sensitivity.HIGH),
    # PEM keys
    (r"(?i)-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "PEM_KEY", Sensitivity.HIGH),
    # Wallet file references
    (r"(?i)(keystore|\.c98|wallet_\d+\.json|\.dat)\b", "WALLET_FILE_REF", Sensitivity.MEDIUM),
    # .env contents
    (r"(?i)(^|\s)([A-Z_]+)=(sk-|0x[a-f0-9]{20,}|['\"].*['\"])", "ENV_VAR_SECRET", Sensitivity.HIGH),
    # Auth tokens / cookies
    (r"(?i)(bearer\s+[a-zA-Z0-9\-_.]+)", "AUTH_TOKEN", Sensitivity.HIGH),
]


def detect_secrets(text: str) -> list[dict]:
    """Scan text for secret material. Returns list of findings with type and sensitivity."""
    findings = []
    for pattern, label, sensitivity in SECRET_PATTERNS:
        for m in re.finditer(pattern, text):
            findings.append({
                "type": label,
                "sensitivity": sensitivity.value,
                "position": m.start(),
                "length": len(m.group()),
                # Preview: first 4 chars + "..." — never full secret
                "preview": m.group()[:4] + "…" if len(m.group()) > 4 else "***",
            })
    return findings


def redact_secrets(text: str) -> tuple[str, int]:
    """Remove all detected secrets from text. Returns (redacted_text, count)."""
    redacted = text
    count = 0
    for pattern, label, _ in SECRET_PATTERNS:
        matches = list(re.finditer(pattern, redacted))
        for m in reversed(matches):
            redacted = redacted[:m.start()] + f"[REDACTED:{label}]" + redacted[m.end():]
            count += 1
    return redacted, count


def content_hash(text: str) -> str:
    """SHA-256 hash for audit trail — hash the verdict, not the secrets."""
    return hashlib.sha256(text.encode()).hexdigest()[:16]


# ═══════════════════════════════════════════════════════════════════════════
# SENSITIVITY CLASSIFIER
# ═══════════════════════════════════════════════════════════════════════════

HIGH_KEYWORDS = frozenset({
    "private key", "seed phrase", "mnemonic", "keystore", "decrypt",
    "password", "secret", "credential", "recover seed", "crack",
    "brute force", ".c98", "wallet_69", "electrum-history",
    "smartswitch backup", ".env", "wallet dump", "wallet export",
    "signing flow", "auth cookie", "raw key",
})

MEDIUM_KEYWORDS = frozenset({
    "approval", "revoke", "allowance", "spender", "contract audit",
    "exposed", "leaked", "git history", "vulnerable", "permission",
    "bot config", "account id", "deployment metadata", "model prompt",
    "private repo",
})

EXECUTION_KEYWORDS = frozenset({
    "buy", "sell", "swap", "trade", "execute", "send", "transfer",
    "revoke", "approve", "deploy", "broadcast", "sign", "bridge",
    "withdraw", "rotate", "modify", "update config", "patch",
})

VALUE_MOVING_KEYWORDS = frozenset({
    "buy", "sell", "swap", "trade", "send", "transfer", "withdraw",
    "bridge", "sign tx", "broadcast",
})

SENSITIVE_WRITE_KEYWORDS = frozenset({
    "deploy", "rotate", "modify prod", "update live", "change config",
    "alter bot", "push to production",
})


def classify_sensitivity(text: str) -> Sensitivity:
    """Classify sensitivity. Secrets detected = immediate HIGH."""
    # Secret patterns override everything
    secrets = detect_secrets(text)
    if secrets:
        max_sens = max(s["sensitivity"] for s in secrets)
        if max_sens == "HIGH":
            return Sensitivity.HIGH

    lower = text.lower()
    if any(kw in lower for kw in HIGH_KEYWORDS):
        return Sensitivity.HIGH
    if any(kw in lower for kw in MEDIUM_KEYWORDS):
        return Sensitivity.MEDIUM
    return Sensitivity.LOW


SIMULATION_KEYWORDS = frozenset({
    "simulate", "simulation", "dry-run", "dry run", "backtest",
    "what if", "hypothetical", "test run", "paper trade",
})

# Prefixes that signal a question about state, not a command to act.
# "How many trades" asks about trades (noun), not to trade (verb).
# "How much capital is deployed" asks about deployment state, not to deploy.
ANALYSIS_INTENT_PREFIXES = frozenset({
    "how many", "how much", "what is", "what are", "what's", "what was",
    "show me", "check the", "list the", "list all", "list my",
    "count", "status of", "status for",
    "is the", "are the", "was the", "were the", "did the", "does the",
    "compare", "review the", "summarize", "describe",
    "when did", "when was", "where is", "where are",
    "which", "who",
})


def _is_analysis_intent(lower: str) -> bool:
    """Check if the message is asking about state rather than commanding action."""
    return any(lower.startswith(prefix) for prefix in ANALYSIS_INTENT_PREFIXES)


def classify_action(text: str) -> ActionClass:
    """Classify what kind of action this request involves.

    Override order:
      1. Simulation/dry-run intent → READ_ONLY
      2. Analysis-intent prefix → READ_ONLY
      3. Explicit VALUE_MOVING keywords
      4. Explicit SENSITIVE_WRITE keywords
      5. Other execution keywords → SAFE_WRITE
      6. Fallback → READ_ONLY
    """
    lower = text.lower()
    # 1. Simulation intent — reasoning is not execution
    if any(kw in lower for kw in SIMULATION_KEYWORDS):
        return ActionClass.READ_ONLY
    # 2. Analysis intent — state questions are not commands
    if _is_analysis_intent(lower):
        return ActionClass.READ_ONLY
    # 3-5. Explicit execution classification
    if any(kw in lower for kw in VALUE_MOVING_KEYWORDS):
        return ActionClass.VALUE_MOVING
    if any(kw in lower for kw in SENSITIVE_WRITE_KEYWORDS):
        return ActionClass.SENSITIVE_WRITE
    if any(kw in lower for kw in EXECUTION_KEYWORDS):
        return ActionClass.SAFE_WRITE
    return ActionClass.READ_ONLY


def requires_execution(text: str) -> bool:
    """Determine if the request involves a state-changing action.
    Simulation and analysis intents override execution keywords."""
    lower = text.lower()
    if any(kw in lower for kw in SIMULATION_KEYWORDS):
        return False
    if _is_analysis_intent(lower):
        return False
    return any(kw in lower for kw in EXECUTION_KEYWORDS)


# ═══════════════════════════════════════════════════════════════════════════
# ROUTE SELECTOR — enforces trust boundaries
# ═══════════════════════════════════════════════════════════════════════════

def select_routes(job_type: JobType, sensitivity: Sensitivity) -> list[str]:
    """
    Choose routes. HIGH sensitivity always goes local/GEMINI.
    Rule: HIGH never goes to Cloudflare lane.
    """
    if sensitivity == Sensitivity.HIGH:
        # High sensitivity: security lane only, local only
        return ["GEMINI"]

    route_map = {
        JobType.TRADING: ["CLAUDE"],
        JobType.SECURITY: ["GEMINI"],
        JobType.MIXED: ["CLAUDE", "GEMINI"],
        JobType.GENERAL: ["GPT"],
    }
    return route_map.get(job_type, ["GPT"])


def build_constraints(
    job_type: JobType,
    sensitivity: Sensitivity,
    action_class: ActionClass,
    routes: list[str],
) -> list[str]:
    """Generate constraint list enforcing trust boundaries."""
    c: list[str] = []

    # Universal
    c.append("no-secrets-in-payload")

    # Sensitivity-based
    if sensitivity == Sensitivity.HIGH:
        c.append("local-only")
        c.append("do-not-export")
    elif sensitivity == Sensitivity.MEDIUM:
        c.append("reduced-context-only")

    # Route-based
    if "CLAUDE" in routes:
        c.append("no-secrets")
        c.append("cloud-safe")
    if "GEMINI" in routes and sensitivity in (Sensitivity.HIGH, Sensitivity.MEDIUM):
        c.append("security-read-only-default")

    # Action-based
    if action_class == ActionClass.READ_ONLY:
        c.append("read-only")
    elif action_class == ActionClass.VALUE_MOVING:
        c.append("value-moving-requires-approval")
        c.append("execution-gate-required")
    elif action_class == ActionClass.SENSITIVE_WRITE:
        c.append("sensitive-write-requires-approval")
        c.append("execution-gate-required")
    elif action_class == ActionClass.SAFE_WRITE:
        c.append("write-allowed-with-session-approval")

    # Mixed
    if job_type == JobType.MIXED:
        c.append("security-veto-is-binding")

    return c


# ═══════════════════════════════════════════════════════════════════════════
# JOB CONTRACT BUILDER — single point of policy decision
# ═══════════════════════════════════════════════════════════════════════════

def build_job_contract(user_message: str, classification: dict) -> JobContract:
    """
    Build a complete job contract from user message + triage classification.
    This is where all input policy decisions are made.
    """
    category = classification.get("category", "general")
    job_type_map = {
        "trading": JobType.TRADING,
        "security": JobType.SECURITY,
        "mixed": JobType.MIXED,
        "general": JobType.GENERAL,
    }
    job_type = job_type_map.get(category, JobType.GENERAL)

    sensitivity = classify_sensitivity(user_message)
    action_class = classify_action(user_message)
    needs_execution = requires_execution(user_message)

    # HARD RULE: HIGH sensitivity reclassifies trading → security
    if sensitivity == Sensitivity.HIGH and job_type == JobType.TRADING:
        job_type = JobType.SECURITY
        logger.warning(f"Reclassified TRADING→SECURITY due to HIGH sensitivity")

    routes = select_routes(job_type, sensitivity)
    constraints = build_constraints(job_type, sensitivity, action_class, routes)

    # Determine if approval is required
    approval_required = (
        action_class in (ActionClass.VALUE_MOVING, ActionClass.SENSITIVE_WRITE)
        or (needs_execution and sensitivity != Sensitivity.LOW)
    )

    # Redact secrets for context summary
    redacted_msg, redaction_count = redact_secrets(user_message)

    contract = JobContract(
        job_type=job_type,
        sensitivity=sensitivity,
        action_class=action_class,
        requires_execution=needs_execution,
        approval_required=approval_required,
        context_summary=redacted_msg if redaction_count > 0 else user_message,
        constraints=constraints,
        routes=routes,
    )

    logger.info(f"📋 Contract built: {contract.to_json()}")
    return contract


# ═══════════════════════════════════════════════════════════════════════════
# DECISION REDUCER — the canonical decide() function
# ═══════════════════════════════════════════════════════════════════════════

def decide(
    contract: JobContract,
    trading: TradingOutput | None = None,
    security: SecurityOutput | None = None,
) -> FinalDecision:
    """
    The canonical decision function. Precedence:
      1. Policy engine
      2. Security verdict
      3. Execution gate
      4. Trading recommendation
    """
    decision = FinalDecision(job_id=contract.job_id)

    # --- Policy check ---
    if contract.sensitivity == Sensitivity.HIGH and "CLAUDE" in contract.routes:
        decision.disposition = FinalDisposition.BLOCKED_POLICY
        decision.gate_decision = GateDecision.DENY
        decision.gate_reason = "HIGH sensitivity cannot route to cloud lane"
        return decision

    # --- Missing security output in security/mixed jobs → ESCALATE ---
    # If a job expected security analysis but got none, do not proceed silently.
    if security is None and contract.job_type in (JobType.SECURITY, JobType.MIXED):
        decision.disposition = FinalDisposition.AWAITING_HUMAN_APPROVAL
        decision.gate_decision = GateDecision.REQUIRE_APPROVAL
        decision.gate_reason = (
            "Missing security output for "
            f"{contract.job_type.value} job — treating as ESCALATE"
        )
        decision.security_summary = "MISSING — no security analysis received"
        return decision

    # --- Security verdict check (binding) ---
    if security:
        decision.security_summary = "; ".join(security.findings) if security.findings else "No findings"

        if security.security_verdict == SecurityVerdict.REJECT:
            decision.disposition = FinalDisposition.BLOCKED_SECURITY
            decision.gate_decision = GateDecision.DENY
            decision.gate_reason = "Security REJECT — no exceptions"
            decision.operator_message = security.raw_response
            return decision

        if security.security_verdict == SecurityVerdict.ESCALATE:
            decision.disposition = FinalDisposition.AWAITING_HUMAN_APPROVAL
            decision.gate_decision = GateDecision.REQUIRE_APPROVAL
            decision.gate_reason = "Security ESCALATE — needs human review"
            decision.conditions = security.conditions
            return decision

        if security.security_verdict == SecurityVerdict.ALLOW_WITH_CONDITIONS:
            decision.conditions = security.conditions

    # --- Trading summary ---
    if trading:
        decision.trading_summary = (
            f"{trading.trading_verdict.value}: {trading.strategy} "
            f"(conf={trading.confidence})"
        )
    elif contract.job_type == JobType.TRADING and contract.requires_execution:
        # Missing trading output on an execution-bearing TRADING job
        # → degrade to NO_ACTION. Never infer actionability from absence.
        decision.trading_summary = "MISSING — no trading analysis received, defaulting to NO_ACTION"
        decision.disposition = FinalDisposition.AWAITING_HUMAN_APPROVAL
        decision.gate_decision = GateDecision.REQUIRE_APPROVAL
        decision.gate_reason = (
            "Missing trading output for execution-bearing TRADING job — "
            "defaulting to NO_ACTION"
        )
        decision.approval_prompt = (
            "Trading analysis unavailable. Action defaulted to NO_ACTION.\n"
            "Reply 'approve' to proceed anyway or 'deny' to cancel."
        )
        return decision

    # --- Execution gate ---
    if not contract.requires_execution:
        if security and security.security_verdict == SecurityVerdict.ALLOW_WITH_CONDITIONS:
            decision.disposition = FinalDisposition.APPROVED_WITH_CONDITIONS
        else:
            decision.disposition = FinalDisposition.APPROVED_READ_ONLY
        decision.gate_decision = GateDecision.ALLOW
        decision.gate_reason = "Read-only operation"
        return decision

    if contract.action_class in (ActionClass.VALUE_MOVING, ActionClass.SENSITIVE_WRITE):
        decision.disposition = FinalDisposition.AWAITING_HUMAN_APPROVAL
        decision.gate_decision = GateDecision.REQUIRE_APPROVAL
        decision.gate_reason = (
            f"{contract.action_class.value} requires explicit approval every time"
        )
        decision.approval_prompt = (
            f"Action: {contract.action_class.value}\n"
            f"Reply 'approve' to proceed or 'deny' to cancel."
        )
        return decision

    if contract.action_class == ActionClass.SAFE_WRITE:
        if security and security.security_verdict == SecurityVerdict.ALLOW_WITH_CONDITIONS:
            decision.disposition = FinalDisposition.APPROVED_WITH_CONDITIONS
            decision.gate_decision = GateDecision.ALLOW
            decision.gate_reason = "Safe write approved with security conditions"
        else:
            decision.disposition = FinalDisposition.APPROVED
            decision.gate_decision = GateDecision.ALLOW
            decision.gate_reason = "Safe write approved"
        return decision

    # Default: approve read-only
    decision.disposition = FinalDisposition.APPROVED_READ_ONLY
    decision.gate_decision = GateDecision.ALLOW
    decision.gate_reason = "Default: approved"
    return decision


# ═══════════════════════════════════════════════════════════════════════════
# RESPONSE POLICY — applied to output before it reaches the user
# ═══════════════════════════════════════════════════════════════════════════

def enforce_response_policy(response: str, decision: FinalDecision) -> str:
    """Final policy enforcement on response text. Redact any leaked secrets."""
    # Check for secret leakage in response
    secrets = detect_secrets(response)
    if secrets:
        response, _ = redact_secrets(response)
        response += "\n\n⚠️ Sensitive data was redacted from this response."

    # Append gate status
    if decision.gate_decision == GateDecision.DENY:
        response += f"\n\n🚫 **BLOCKED**: {decision.gate_reason}"
    elif decision.gate_decision == GateDecision.REQUIRE_APPROVAL:
        response += f"\n\n⏸️ **APPROVAL REQUIRED**: {decision.approval_prompt}"

    # Append conditions if any
    if decision.conditions:
        cond_str = "\n".join(f"  • {c}" for c in decision.conditions)
        response += f"\n\n🔒 **Conditions**:\n{cond_str}"

    return response


# ═══════════════════════════════════════════════════════════════════════════
# AUDIT LOGGER — references and classifications only, no secrets
# ═══════════════════════════════════════════════════════════════════════════

_audit_log: list[dict] = []


def log_audit(
    contract: JobContract,
    decision: FinalDecision,
    trading: TradingOutput | None = None,
    security: SecurityOutput | None = None,
    execution_action: str = "",
    approval_record: str = "",
) -> AuditEntry:
    """Log an audit entry. Never logs secrets — only references, hashes, classifications."""
    entry = AuditEntry(
        job_id=contract.job_id,
        classifier_result=contract.job_type.value,
        sensitivity=contract.sensitivity.value,
        action_class=contract.action_class.value,
        routes_chosen=contract.routes,
        artifacts_touched=[a.hash for a in contract.artifacts],
        trading_verdict_hash=content_hash(trading.raw_response) if trading else "",
        security_verdict_hash=content_hash(security.raw_response) if security else "",
        final_disposition=decision.disposition.value,
        execution_action=execution_action,
        approval_record=approval_record,
    )
    _audit_log.append(entry.to_dict())
    logger.info(f"📝 Audit: job={entry.job_id} disp={entry.final_disposition} "
                f"sens={entry.sensitivity} action={entry.action_class}")
    return entry


def get_audit_log() -> list[dict]:
    return list(_audit_log)
