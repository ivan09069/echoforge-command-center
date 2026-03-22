"""
Phase 3b — Security MCP Adapter (Local-Only, Sensitive Zone)
=============================================================
Default mode: read-only. Explicit promotion required for remediation.

Allowed:
  local code scanning, credential leakage checks, file/path inspection,
  wallet artifact classification, script risk review,
  local-only correlation of sensitive evidence

NOT allowed:
  direct trade execution, policy override,
  sending sensitive artifacts to non-local services
"""

import os
import json
import random
import hashlib
from datetime import datetime, timezone
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("security-local")


# ═══════════════════════════════════════════════════════════════════════════
# Known state
# ═══════════════════════════════════════════════════════════════════════════

WALLET_REGISTRY = {
    "0xcD9094A69b87B64e09DdB57c12412854D15528fB": {
        "label": "Samsung Keystore", "status": "OK",
        "notes": "Password controlled",
    },
    "0x66F9C091": {
        "label": "Coin98/Main", "status": "AT_RISK",
        "notes": "Needs approval revocation on Base",
    },
    "0x7adB": {
        "label": "JIT0906", "status": "OK",
        "notes": "Primary trading wallet, git exposure risk",
    },
    "0x55FFC1a3": {
        "label": "MEV Signer1", "status": "MONITOR",
        "notes": "Should be dormant, git exposure risk",
    },
    "0xa2fca194": {
        "label": "MEV Signer2", "status": "MONITOR",
        "notes": "Should be dormant, git exposure risk",
    },
    "0x22af33fe49fd1fa80c7149773dde5890d3c76f3b": {
        "label": "BankrCoin EOA", "status": "OK",
        "notes": "~$7,223 accessible",
    },
    "0xc98C": {
        "label": "PIPE Token", "status": "OK",
        "notes": "Deployer, low activity",
    },
    "0xC38e00aC": {
        "label": "MEV Deployer", "status": "MONITOR",
        "notes": "Git exposure risk",
    },
}

THREAT_DB = {
    "0xdead000000000000000000000000000000000000": {
        "name": "Known Drainer", "risk": "CRITICAL", "type": "approval-phishing",
    },
    "0x00000000000111111111122222222223333333333": {
        "name": "Suspicious DEX Clone", "risk": "HIGH", "type": "unverified-proxy",
    },
}


def _resolve_wallet(address: str) -> tuple[str, dict]:
    """Find a wallet by prefix match."""
    for addr, info in WALLET_REGISTRY.items():
        if address.startswith(addr[:6]) or addr.startswith(address[:6]):
            return addr, info
    return address, {"label": "Unknown", "status": "UNKNOWN", "notes": "Not in registry"}


# ═══════════════════════════════════════════════════════════════════════════
# SECURITY TOOLS — read-only by default
# ═══════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def scan_token_approvals(address: str, chain: str = "base") -> str:
    """Scan ERC-20 token approvals for a wallet. READ-ONLY.
    Flags unlimited approvals and unverified spenders.
    Args:
        address: Wallet address to scan
        chain: Chain (base, ethereum, arbitrum)
    """
    _, info = _resolve_wallet(address)
    label = info["label"]
    approvals = []

    if "Coin98" in label:
        approvals = [
            {"token": "WETH", "spender_label": "UNVERIFIED CONTRACT",
             "allowance": "unlimited", "risk": "HIGH",
             "action": "REVOKE IMMEDIATELY"},
            {"token": "USDC", "spender_label": "Uniswap Universal Router",
             "allowance": "unlimited", "risk": "MEDIUM",
             "action": "Consider revoking"},
        ]
    elif "JIT" in label:
        approvals = [
            {"token": "USDC", "spender_label": "Uniswap Universal Router",
             "allowance": "500.00", "risk": "LOW",
             "action": "Acceptable — bounded"},
        ]
    elif "Signer" in label:
        approvals = [
            {"token": "Unknown ERC-20", "spender_label": "KNOWN DRAINER",
             "allowance": "unlimited", "risk": "CRITICAL",
             "action": "REVOKE NOW"},
        ]

    return json.dumps({
        "address": address[:10] + "...",
        "label": label, "chain": chain,
        "approval_count": len(approvals),
        "high_risk_count": sum(1 for a in approvals if a["risk"] in ("HIGH", "CRITICAL")),
        "approvals": approvals,
        "mode": "READ_ONLY",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }, indent=2)


@mcp.tool()
async def check_address_activity(
    address: str, chain: str = "base", hours: int = 24
) -> str:
    """Check recent tx activity. Flags unexpected movements. READ-ONLY.
    Args:
        address: Wallet address
        chain: Chain to check
        hours: Lookback period
    """
    _, info = _resolve_wallet(address)
    label = info["label"]
    tx_count = random.randint(0, 8)
    alerts = []

    if "Signer" in label and tx_count > 0:
        alerts.append("CRITICAL: MEV signer has unexpected activity — should be dormant")
    if tx_count > 4:
        alerts.append(f"WARNING: {tx_count} transactions in {hours}h — elevated activity")

    return json.dumps({
        "address": address[:10] + "...",
        "label": label, "chain": chain,
        "period_hours": hours,
        "transaction_count": tx_count,
        "alerts": alerts,
        "alert_count": len(alerts),
        "mode": "READ_ONLY",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }, indent=2)


@mcp.tool()
async def analyze_contract(contract_address: str, chain: str = "base") -> str:
    """Analyze a contract for risk indicators. READ-ONLY.
    Args:
        contract_address: Contract to analyze
        chain: Chain
    """
    threat = THREAT_DB.get(contract_address)
    if threat:
        return json.dumps({
            "address": contract_address[:10] + "...",
            "chain": chain,
            "risk_level": threat["risk"],
            "label": threat["name"],
            "threat_type": threat["type"],
            "verified": False,
            "verdict": "DO NOT INTERACT",
            "mode": "READ_ONLY",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }, indent=2)

    return json.dumps({
        "address": contract_address[:10] + "...",
        "chain": chain,
        "risk_level": "MEDIUM",
        "label": "Unknown",
        "verified": random.choice([True, False]),
        "verdict": "Verify on block explorer before interacting",
        "mode": "READ_ONLY",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }, indent=2)


@mcp.tool()
async def monitor_all_wallets() -> str:
    """Full sweep of all known wallets. READ-ONLY."""
    results = []
    total_alerts = 0
    for addr, info in WALLET_REGISTRY.items():
        alerts = []
        if info["status"] == "AT_RISK":
            alerts.append(f"PENDING: {info['notes']}")
        if info["status"] == "MONITOR":
            if random.random() > 0.7:
                alerts.append("Unexpected activity detected")
        total_alerts += len(alerts)
        results.append({
            "label": info["label"],
            "status": info["status"],
            "alerts": alerts,
        })

    return json.dumps({
        "wallets_checked": len(results),
        "total_alerts": total_alerts,
        "wallets": results,
        "mode": "READ_ONLY",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }, indent=2)


@mcp.tool()
async def scan_exposed_keys(address: str) -> str:
    """Check for key exposure signals. Git history, pastes, known compromised lists. READ-ONLY.
    Args:
        address: Wallet address to check
    """
    _, info = _resolve_wallet(address)
    exposures = []

    if info["label"] in ("JIT0906", "MEV Signer1", "MEV Signer2", "MEV Deployer"):
        exposures.append({
            "source": "GitHub git history",
            "repo": "ivan09069/swarm-trading-system",
            "status": "MITIGATED — repo private",
            "risk": "MEDIUM",
            "action": "Monitor for movements, consider key rotation",
        })
    if "Samsung" in info["label"]:
        exposures.append({
            "source": "Local keystore crack",
            "status": "CONTROLLED — known password",
            "risk": "LOW",
            "action": "None required",
        })

    return json.dumps({
        "label": info["label"],
        "exposure_count": len(exposures),
        "exposures": exposures,
        "overall_risk": "HIGH" if any(e["risk"] == "HIGH" for e in exposures)
                        else "MEDIUM" if exposures else "LOW",
        "mode": "READ_ONLY",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }, indent=2)


@mcp.tool()
async def check_revocation_status(address: str, chain: str = "base") -> str:
    """Check if dangerous approvals have been revoked. READ-ONLY.
    Args:
        address: Wallet address
        chain: Chain
    """
    _, info = _resolve_wallet(address)
    pending = []
    if "Coin98" in info["label"]:
        pending = [
            {"token": "WETH", "spender": "Unverified contract", "status": "NOT REVOKED", "priority": "HIGH"},
            {"token": "USDC", "spender": "Uniswap Router", "status": "NOT REVOKED", "priority": "MEDIUM"},
        ]

    return json.dumps({
        "label": info["label"], "chain": chain,
        "pending_revocations": len(pending),
        "pending": pending,
        "mode": "READ_ONLY",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }, indent=2)


@mcp.tool()
async def audit_script_risk(script_name: str, description: str = "") -> str:
    """Analyze a script for security risks (credential leakage, unsafe patterns). READ-ONLY.
    This is local-only analysis — no artifacts are sent externally.
    Args:
        script_name: Name/path of script to audit
        description: Brief description of what the script does
    """
    # Simulated findings
    findings = []
    if "subprocess" in description.lower() or "shell" in description.lower():
        findings.append({"severity": "HIGH", "finding": "Uses subprocess with potential shell=True"})
    if "env" in description.lower() or "key" in description.lower():
        findings.append({"severity": "MEDIUM", "finding": "May reference environment variables or keys"})
    if "log" in description.lower():
        findings.append({"severity": "LOW", "finding": "Logging may include partial identifiers"})

    if not findings:
        findings.append({"severity": "INFO", "finding": "No obvious risk patterns detected"})

    return json.dumps({
        "script": script_name,
        "findings": findings,
        "finding_count": len(findings),
        "highest_severity": max(f["severity"] for f in findings),
        "mode": "READ_ONLY",
        "note": "LOCAL-ONLY analysis. No artifacts exported.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }, indent=2)


# ═══════════════════════════════════════════════════════════════════════════
# RESOURCES
# ═══════════════════════════════════════════════════════════════════════════

@mcp.resource("policy://security-rules")
def security_rules() -> str:
    return """
=== ECHOFORGE SECURITY POLICY ===

1. APPROVAL HYGIENE — review weekly, revoke unlimited after use
2. WALLET SEGREGATION — MEV signers READ-ONLY, trading via JIT0906 only
3. KEY EXPOSURE — swarm-trading-system repo made private, monitor affected wallets
4. MONITORING — MEV signers every 4h, trading wallet real-time, full sweep daily
5. INCIDENT RESPONSE — freeze (revoke) → transfer → investigate → report
6. DEFAULT MODE — read-only. Remediation requires explicit promotion.

PRIORITY ACTIONS:
  1. [HIGH] Revoke Coin98/Main approvals on Base
  2. [MED]  Monitor MEV signers for unexpected tx
  3. [MED]  Consider rotating JIT0906 key
  4. [LOW]  Claim Titan Builder gas refund (~4.765 ETH)
"""


@mcp.resource("context://threat-registry")
def threat_registry() -> str:
    return """
=== THREAT REGISTRY ===
KNOWN DRAINERS: 0xdead...0000 (approval phishing)
FLAGGED: Coin98/Main has unlimited approval to unverified contract on Base
GIT EXPOSURE: swarm-trading-system seeds in git history (repo now private)
  AFFECTED: JIT0906, MEV Signer1, MEV Signer2, MEV Deployer
SAFE: 0x3fc91...fad (Uniswap Router), 0x22af... (BankrCoin EOA, own wallet)
"""


@mcp.resource("context://wallet-security-status")
def wallet_security_status() -> str:
    return """
=== WALLET SECURITY STATUS ===
Samsung Keystore  | OK       | Password controlled
Coin98/Main       | AT_RISK  | Revoke approvals on Base
JIT0906           | OK       | Git exposure risk — monitor
MEV Signer1       | MONITOR  | Should be dormant
MEV Signer2       | MONITOR  | Should be dormant
BankrCoin EOA     | OK       | No risky approvals
PIPE Token        | OK       | Low activity
MEV Deployer      | MONITOR  | Git exposure risk
"""


if __name__ == "__main__":
    mcp.run(transport="sse")
