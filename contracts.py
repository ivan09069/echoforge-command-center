"""
Phase 1 — Contract Layer
==========================
Canonical schemas for the entire system.
Every routed request becomes a JobContract.
Every specialist emits a typed verdict.
Every action passes through a FinalDecision.

Core principles:
  - Reasoning is not execution
  - Routing is not permission
  - Security can veto trading
  - Secrets never cross the wrong boundary
"""

from __future__ import annotations

import uuid
import json
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════════════════

class JobType(str, Enum):
    TRADING = "TRADING"
    SECURITY = "SECURITY"
    MIXED = "MIXED"
    GENERAL = "GENERAL"


class Sensitivity(str, Enum):
    LOW = "LOW"         # Public market data, generic logs, strategy descriptions
    MEDIUM = "MEDIUM"   # Internal bot configs, account IDs, deployment metadata
    HIGH = "HIGH"       # .env, private keys, seeds, wallet exports, auth tokens


class ActionClass(str, Enum):
    READ_ONLY = "READ_ONLY"           # Fetch prices, inspect status, read logs, dry-run
    SAFE_WRITE = "SAFE_WRITE"         # Create draft config, save report, patch non-sensitive
    SENSITIVE_WRITE = "SENSITIVE_WRITE"  # Modify prod bot, deploy, rotate creds
    VALUE_MOVING = "VALUE_MOVING"     # Trades, withdrawals, signing, bridging, transfers


class SecurityVerdict(str, Enum):
    ALLOW = "ALLOW"
    ALLOW_WITH_CONDITIONS = "ALLOW_WITH_CONDITIONS"
    REJECT = "REJECT"
    ESCALATE = "ESCALATE"


class TradingVerdict(str, Enum):
    PROPOSE = "PROPOSE"
    HOLD = "HOLD"
    NO_ACTION = "NO_ACTION"


class FinalDisposition(str, Enum):
    APPROVED_READ_ONLY = "APPROVED_READ_ONLY"
    APPROVED = "APPROVED"
    APPROVED_WITH_CONDITIONS = "APPROVED_WITH_CONDITIONS"
    BLOCKED_POLICY = "BLOCKED_POLICY"
    BLOCKED_SECURITY = "BLOCKED_SECURITY"
    AWAITING_HUMAN_APPROVAL = "AWAITING_HUMAN_APPROVAL"


class GateDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


# ═══════════════════════════════════════════════════════════════════════════
# Artifact Reference (never the artifact itself across trust boundaries)
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ArtifactRef:
    """Reference to an artifact — never the raw content across boundaries."""
    type: str = ""             # "script", "config", "wallet_file", "log"
    location: str = "local_ref_only"
    sensitivity: Sensitivity = Sensitivity.LOW
    hash: str = ""             # Content hash for audit, not content itself

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "location": self.location,
            "sensitivity": self.sensitivity.value,
            "hash": self.hash,
        }


# ═══════════════════════════════════════════════════════════════════════════
# Job Contract — the canonical routing unit
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class JobContract:
    """Every routed request becomes one of these."""
    job_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    job_type: JobType = JobType.GENERAL
    sensitivity: Sensitivity = Sensitivity.LOW
    action_class: ActionClass = ActionClass.READ_ONLY
    requires_execution: bool = False
    approval_required: bool = False
    context_summary: str = ""
    artifacts: list[ArtifactRef] = field(default_factory=list)
    constraints: list[str] = field(default_factory=list)
    routes: list[str] = field(default_factory=list)   # ["CLAUDE"], ["GEMINI"], ["CLAUDE","GEMINI"]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "job_type": self.job_type.value,
            "sensitivity": self.sensitivity.value,
            "action_class": self.action_class.value,
            "requires_execution": self.requires_execution,
            "approval_required": self.approval_required,
            "context_summary": self.context_summary,
            "artifacts": [a.to_dict() for a in self.artifacts],
            "constraints": self.constraints,
            "routes": self.routes,
            "timestamp": self.timestamp,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# ═══════════════════════════════════════════════════════════════════════════
# Security Verdict — emitted by Gemini lane
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class SecurityOutput:
    """Structured output from the security/Gemini lane."""
    security_verdict: SecurityVerdict = SecurityVerdict.ESCALATE
    severity: Sensitivity = Sensitivity.LOW
    findings: list[str] = field(default_factory=list)
    conditions: list[str] = field(default_factory=list)
    raw_response: str = ""  # Full text for display

    def to_dict(self) -> dict:
        return {
            "security_verdict": self.security_verdict.value,
            "severity": self.severity.value,
            "findings": self.findings,
            "conditions": self.conditions,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# ═══════════════════════════════════════════════════════════════════════════
# Trading Verdict — emitted by Claude lane
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class TradingOutput:
    """Structured output from the trading/Claude lane."""
    trading_verdict: TradingVerdict = TradingVerdict.NO_ACTION
    strategy: str = ""
    confidence: float = 0.0
    recommended_changes: list[dict] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    risk_notes: list[str] = field(default_factory=list)
    execution_request: bool = False
    raw_response: str = ""  # Full text for display

    def to_dict(self) -> dict:
        return {
            "trading_verdict": self.trading_verdict.value,
            "strategy": self.strategy,
            "confidence": self.confidence,
            "recommended_changes": self.recommended_changes,
            "assumptions": self.assumptions,
            "risk_notes": self.risk_notes,
            "execution_request": self.execution_request,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# ═══════════════════════════════════════════════════════════════════════════
# Final Decision — the merged operator-facing output
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class FinalDecision:
    """The single output ChatGPT produces after merging both lanes."""
    job_id: str = ""
    disposition: FinalDisposition = FinalDisposition.APPROVED_READ_ONLY
    gate_decision: GateDecision = GateDecision.ALLOW
    gate_reason: str = ""
    trading_summary: str = ""
    security_summary: str = ""
    conditions: list[str] = field(default_factory=list)
    operator_message: str = ""  # The final text shown to user
    approval_prompt: str = ""   # Non-empty if awaiting approval
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "disposition": self.disposition.value,
            "gate_decision": self.gate_decision.value,
            "gate_reason": self.gate_reason,
            "trading_summary": self.trading_summary,
            "security_summary": self.security_summary,
            "conditions": self.conditions,
            "approval_prompt": self.approval_prompt,
            "timestamp": self.timestamp,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# ═══════════════════════════════════════════════════════════════════════════
# Audit Entry — logged for every job, never contains secrets
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class AuditEntry:
    """Immutable audit record. References and classifications only, no secrets."""
    job_id: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    classifier_result: str = ""
    sensitivity: str = ""
    action_class: str = ""
    routes_chosen: list[str] = field(default_factory=list)
    artifacts_touched: list[str] = field(default_factory=list)  # Hashes only
    trading_verdict_hash: str = ""
    security_verdict_hash: str = ""
    final_disposition: str = ""
    execution_action: str = ""
    approval_record: str = ""

    def to_dict(self) -> dict:
        return asdict(self)
