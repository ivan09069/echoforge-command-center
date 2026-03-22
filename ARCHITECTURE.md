# EchoForge Command Center — Canonical Operating Model

## Core Principles

```
Reasoning is not execution.
Routing is not permission.
Security can veto trading.
Secrets never cross the wrong boundary.
```

## Architecture

```
User (ivan0906)
  ↓
ChatGPT — Triage Router / Policy Layer / Output Merger
  ├── Claude — Trading Analyst
  │     ↓
  │   EchoForge MCP (Cloudflare, remote-safe, non-secret)
  │
  └── Gemini — Security Analyst
        ↓
      Security MCP (Local, sensitive, read-only by default)

Decision Engine
  ↓
Approve / Reject / Escalate
  ↓
Execution Gate
  ↓
Allowed Tool / Bot / Script
```

## Non-Negotiable Trust Boundaries

### 1. ChatGPT Boundary (Control Plane)
| Allowed | NOT Allowed |
|---------|-------------|
| Classify request | Hold secrets |
| Reduce context | Auto-execute trades |
| Build job contract | Override security veto |
| Route to specialists | Pass raw artifacts to cloud |
| Merge responses | |
| Enforce policy | |
| Request approval | |

### 2. Claude Boundary (Trading Intelligence)
| Allowed | NOT Allowed |
|---------|-------------|
| Signal interpretation | Direct secret access |
| Risk logic | Wallet exports |
| Sizing proposals | Local forensic artifacts |
| Threshold tuning | Unrestricted tool execution |
| Market reasoning | Final authority over execution |
| Strategy comparison | |
| Backtest analysis | |

### 3. Gemini Boundary (Security Intelligence)
| Allowed | NOT Allowed |
|---------|-------------|
| Script/code audit | Direct trade execution |
| Wallet/tooling security review | Policy override |
| Permission analysis | Send artifacts to non-local |
| Exploit/pathology detection | |
| Forensic anomaly detection | |
| Environment hardening review | |

### 4. EchoForge MCP Boundary (Cloudflare)
| Allowed | NOT Allowed |
|---------|-------------|
| Market data fetch | Seed phrases |
| Bot status | Private keys |
| Portfolio summaries (no secrets) | Wallet dumps |
| Safe remote reads | Raw auth cookies |
| Simulation I/O | Unredacted .env |
| Non-sensitive orchestration | Local forensic evidence |

### 5. Security MCP Boundary (Local)
| Allowed | Default Mode |
|---------|-------------|
| Local code scanning | **Read-only** |
| Credential leakage checks | Explicit promotion for remediation |
| File/path inspection | |
| Wallet artifact classification | |
| Script risk review | |
| Local-only correlation | |

## Routing Model

| Request Type | Route | Examples |
|---|---|---|
| TRADING | Claude → EchoForge MCP | Strategy tuning, PnL review, threshold changes, pair selection |
| SECURITY | Gemini → Security MCP | Key leakage, wallet audit, suspicious scripts, hardening |
| MIXED | Both (parallel/sequence) | "Optimize bot but check safety", "deploy but audit permissions" |
| GENERAL | GPT direct | Greetings, system questions |

**Mixed requests**: Security lane has veto authority.

## Decision Precedence (Hardcoded)

```
1. Policy engine
2. Security verdict
3. Execution gate
4. Trading recommendation
```

If Claude says "high opportunity" and Gemini says "unsafe environment" → **no execution**.

## Security Classification

| Level | Examples |
|---|---|
| **LOW** | Public market data, generic logs, strategy descriptions, thresholds |
| **MEDIUM** | Internal bot configs, account IDs, deployment metadata, private repo code |
| **HIGH** | .env, private keys, seed phrases, wallet exports, auth tokens, signing flows |

**Rule: HIGH never goes to Cloudflare lane.**

## Action Classes

| Class | Examples | Approval |
|---|---|---|
| READ_ONLY | Fetch prices, inspect status, dry-run sim | Auto-approve if low risk |
| SAFE_WRITE | Create draft config, save report | Session approval |
| SENSITIVE_WRITE | Modify prod bot, deploy, rotate creds | Explicit approval |
| VALUE_MOVING | Trades, withdrawals, signing, bridging | **Explicit approval every time** |

## Job Contract Schema

```json
{
  "job_id": "uuid",
  "job_type": "TRADING|SECURITY|MIXED|GENERAL",
  "sensitivity": "LOW|MEDIUM|HIGH",
  "action_class": "READ_ONLY|SAFE_WRITE|SENSITIVE_WRITE|VALUE_MOVING",
  "requires_execution": false,
  "approval_required": true,
  "context_summary": "Redacted summary of request",
  "artifacts": [{"type": "script", "location": "local_ref_only", "sensitivity": "HIGH"}],
  "constraints": ["no-secrets-in-payload", "local-only", "read-only"],
  "routes": ["CLAUDE", "GEMINI"]
}
```

## Security Verdict Schema

```json
{
  "security_verdict": "ALLOW|ALLOW_WITH_CONDITIONS|REJECT|ESCALATE",
  "severity": "LOW|MEDIUM|HIGH",
  "findings": ["No private keys detected", "Uses subprocess with shell=True"],
  "conditions": ["Replace shell=True", "Redact account IDs in logs"]
}
```

If verdict is **REJECT**, execution halts. No exceptions.

## Trading Verdict Schema

```json
{
  "trading_verdict": "PROPOSE|HOLD|NO_ACTION",
  "strategy": "mean_reversion",
  "confidence": 0.61,
  "recommended_changes": [{"param": "rsi_buy", "from": 55, "to": 52}],
  "assumptions": ["low slippage", "range-bound regime"],
  "risk_notes": ["Higher hold time likely"],
  "execution_request": false
}
```

## Final Disposition Values

| Disposition | Meaning |
|---|---|
| APPROVED_READ_ONLY | Safe, no execution involved |
| APPROVED | Action approved |
| APPROVED_WITH_CONDITIONS | Approved but must meet security conditions |
| BLOCKED_POLICY | Policy engine rejected (e.g., HIGH to cloud) |
| BLOCKED_SECURITY | Security REJECT — binding veto |
| AWAITING_HUMAN_APPROVAL | Needs explicit approve/deny |

## Policy Engine Rules

### Input Policy (before routing)
1. Classify job type
2. Classify sensitivity
3. Detect secrets (regex patterns)
4. Reduce context (strip irrelevant blobs)
5. Choose local vs cloud path

### Routing Policy
- LOW + non-secret + analysis → cloud-safe
- MEDIUM → reduced context only
- HIGH or secret-adjacent → **local-only security path**
- Execution intent flagged separately from reasoning

### Output Policy (before action)
1. Normalize outputs into structured verdicts
2. Compare Claude vs Gemini results
3. Apply veto logic
4. Require human approval where needed
5. Allow only whitelisted actions

## Failure Nodes Defended Against

| Failure | Defense |
|---|---|
| **Prompt bleed** — sensitive payload to cloud | Redaction engine + sensitivity classifier |
| **Execution creep** — analysis becomes action | Action class separation + execution gate |
| **Security downgrade** — findings treated as advisory | Binding veto in decision reducer |
| **Context over-sharing** — full blobs everywhere | Normalization step, minimized summaries |
| **Remote trust inflation** — Cloudflare = local | Hard constraint: `no-secrets`, `cloud-safe` |

## Hard Defaults (Non-Negotiable)

```python
security_veto = True
default_security_mode = "read_only"
default_execution_mode = "disabled"
secrets_to_cloud = False
value_moving_requires_approval = True
high_sensitivity_requires_local = True
```

## Audit Trail

Every job emits: job_id, timestamp, classifier result, sensitivity, action class,
routes chosen, artifacts touched (hashes only), trading verdict hash,
security verdict hash, final disposition, execution action, approval record.

**Never log secrets. Log references, hashes, and classifications.**

## One-Line Operating Law

> Cloud for non-secret reasoning, local for sensitive inspection,
> and nothing executes past the gate without policy + security + approval.
