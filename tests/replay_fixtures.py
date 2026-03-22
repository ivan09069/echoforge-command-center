"""
Replay Fixtures — Sanitized Real-World Adapter Payloads
=========================================================
Structurally realistic payloads modeled on actual Claude, Gemini,
and MCP adapter output shapes. Secrets replaced, but structure,
nesting, field names, and edge cases preserved.

Used by test_replay_fixtures.py to prove:
  - Real payloads pass validation
  - Real-world malformations fail closed
  - Parser drift gets caught
  - Audit entries stay secret-clean
"""


# ═══════════════════════════════════════════════════════════════════════════
# CLAUDE (TRADING) ADAPTER RESPONSES
# ═══════════════════════════════════════════════════════════════════════════

CLAUDE_VALID = {
    "price_query": {
        "raw": (
            "Based on the current market data, ETH is trading at approximately $3,520. "
            "The 24-hour range has been $3,480–$3,555, with moderate volume. "
            "No significant catalysts detected in the immediate term."
        ),
        "verdict": "NO_ACTION",
        "confidence": 0.0,
    },
    "trade_proposal": {
        "raw": (
            "I recommend a mean-reversion entry on ETH/USDC.\n\n"
            "**Proposal:**\n"
            "- Pair: ETH/USDC\n"
            "- Side: Buy\n"
            "- Size: $100 (within $125 per-trade limit)\n"
            "- Entry: ~$3,518 (RSI at 48, approaching oversold)\n"
            "- Take-profit: $3,567 (+1.4%)\n"
            "- Stop-loss: $3,412 (-3%)\n\n"
            "Kelly fraction suggests 0.08 at current edge estimate. "
            "This is analysis only — execution requires your approval."
        ),
        "verdict": "PROPOSE",
        "confidence": 0.72,
        "strategy": "mean_reversion",
        "changes": [
            {"param": "entry_price", "value": 3518},
            {"param": "tp_pct", "value": 1.4},
            {"param": "sl_pct", "value": 3.0},
        ],
    },
    "bot_tuning": {
        "raw": (
            "After reviewing the last 30 days of backtest data, I suggest the following "
            "threshold adjustments for the RSI/EMA50 mean-reversion strategy:\n\n"
            "1. Lower RSI buy threshold from 55 to 52 (more selective entries)\n"
            "2. Raise take-profit from 1.1% to 1.4% (wider targets, fewer whipsaws)\n"
            "3. Keep stop-loss at 3% (adequate for current volatility regime)\n\n"
            "Expected impact: ~15% fewer trades, ~8% higher average win. "
            "Net positive expectancy improvement of approximately 0.3% per trade."
        ),
        "verdict": "PROPOSE",
        "confidence": 0.61,
        "strategy": "mean_reversion",
        "changes": [
            {"param": "rsi_buy", "from": 55, "to": 52},
            {"param": "tp_pct", "from": 1.1, "to": 1.4},
        ],
    },
    "simulation_result": {
        "raw": (
            "Simulation complete. Dry-run results for buying $100 ETH:\n"
            "- Estimated fill: $3,518.42\n"
            "- Quantity: 0.02842 ETH\n"
            "- Slippage estimate: 0.12%\n"
            "- Gas estimate: ~$0.003 on Base\n\n"
            "No real funds were moved. This is a simulation only."
        ),
        "verdict": "NO_ACTION",
        "confidence": 0.0,
    },
}

CLAUDE_MALFORMED = {
    "leaked_private_key": {
        "raw": (
            "I found the wallet details. The private key is "
            "0xabababababababababababababababababababababababababababababababab "
            "and the balance is 0.5 ETH."
        ),
    },
    "leaked_password": {
        "raw": (
            "The Samsung keystore was cracked with password 2012Kenworth5. "
            "which matches the known pattern."
        ),
    },
    "leaked_api_key": {
        "raw": (
            "Bot config loaded. Using API key sk-ant-abcdefghijklmnopqrstuvwxyz1234567890 "
            "for authentication."
        ),
    },
    "confidence_over_one": {
        "raw": "Very confident trade. ETH going up.",
        "confidence": 1.5,
    },
    "confidence_negative": {
        "raw": "Uncertain analysis.",
        "confidence": -0.3,
    },
    "oversized_response": {
        "raw": "A" * 600_000,  # Over 500KB limit
    },
    "empty_response": {
        "raw": "",
    },
    "html_injection": {
        "raw": '<script>alert("xss")</script><img onerror=alert(1) src=x>',
    },
}


# ═══════════════════════════════════════════════════════════════════════════
# GEMINI (SECURITY) ADAPTER RESPONSES
# ═══════════════════════════════════════════════════════════════════════════

GEMINI_VALID = {
    "clean_sweep": {
        "raw": (
            "Security sweep complete.\n\n"
            "Wallets checked: 8\n"
            "Alerts: 0\n\n"
            "All wallets within expected parameters. "
            "MEV signers dormant. JIT0906 active with bounded approvals. "
            "Coin98/Main still has pending revocations on Base.\n\n"
            "---\n"
            "VERDICT: ALLOW\n"
            "SEVERITY: LOW\n"
            "FINDINGS:\n"
            "- Coin98/Main approval revocation still pending\n"
            "- All other wallets within normal parameters\n"
            "CONDITIONS:\n"
        ),
    },
    "approval_scan_risky": {
        "raw": (
            "Approval scan for Coin98/Main on Base:\n\n"
            "Found 2 active approvals:\n"
            "1. WETH → UNVERIFIED CONTRACT (unlimited) — HIGH risk\n"
            "2. USDC → Uniswap Universal Router (unlimited) — MEDIUM risk\n\n"
            "Recommendation: Revoke both immediately, especially #1.\n\n"
            "---\n"
            "VERDICT: ALLOW_WITH_CONDITIONS\n"
            "SEVERITY: HIGH\n"
            "FINDINGS:\n"
            "- Unlimited approval to unverified contract on Base\n"
            "- Unlimited USDC approval to Uniswap Router\n"
            "CONDITIONS:\n"
            "- Revoke WETH approval to unverified contract immediately\n"
            "- Revoke or reduce USDC approval to Uniswap Router\n"
        ),
    },
    "mev_signer_alert": {
        "raw": (
            "CRITICAL: MEV Signer1 (0x55FF...) has unexpected outbound activity.\n"
            "3 transactions in last 4 hours. This wallet should be dormant.\n\n"
            "Transactions detected:\n"
            "- Transfer out: 0.12 ETH (2h ago)\n"
            "- Contract call: unknown target (3h ago)\n"
            "- Approval set: unlimited to unrecognized spender (4h ago)\n\n"
            "This is a potential compromise. Immediate action required.\n\n"
            "---\n"
            "VERDICT: REJECT\n"
            "SEVERITY: HIGH\n"
            "FINDINGS:\n"
            "- MEV Signer1 has unexpected outbound transactions\n"
            "- Unlimited approval set to unrecognized spender\n"
            "- Wallet should be dormant per security policy\n"
            "CONDITIONS:\n"
        ),
    },
    "code_audit_safe": {
        "raw": (
            "Script audit complete for sentinel_x_run.sh:\n\n"
            "No credential leakage detected.\n"
            "No unsafe subprocess patterns.\n"
            "Environment variables accessed via standard export.\n"
            "No hardcoded secrets or API keys found.\n\n"
            "---\n"
            "VERDICT: ALLOW\n"
            "SEVERITY: LOW\n"
            "FINDINGS:\n"
            "- No private keys or secrets detected\n"
            "- Standard environment variable usage\n"
            "- No shell=True subprocess calls\n"
            "CONDITIONS:\n"
        ),
    },
    "code_audit_unsafe": {
        "raw": (
            "Script audit for trading_bot.py:\n\n"
            "ISSUES FOUND:\n"
            "1. subprocess.call with shell=True on line 42\n"
            "2. Logging includes partial account identifiers\n"
            "3. API key loaded from hardcoded path without validation\n\n"
            "---\n"
            "VERDICT: ALLOW_WITH_CONDITIONS\n"
            "SEVERITY: MEDIUM\n"
            "FINDINGS:\n"
            "- Uses subprocess with shell=True\n"
            "- Logs contain partial account identifiers\n"
            "- API key loading path not validated\n"
            "CONDITIONS:\n"
            "- Replace shell=True with explicit command list\n"
            "- Redact account identifiers from logs\n"
            "- Add path validation for API key loading\n"
        ),
    },
    "escalate_unclear": {
        "raw": (
            "Analysis inconclusive. Unable to fully assess the security posture "
            "of the submitted artifact. Additional context needed.\n\n"
            "---\n"
            "VERDICT: ESCALATE\n"
            "SEVERITY: MEDIUM\n"
            "FINDINGS:\n"
            "- Incomplete analysis due to insufficient context\n"
            "CONDITIONS:\n"
            "- Provide full script source for complete audit\n"
        ),
    },
}

GEMINI_MALFORMED = {
    "no_verdict_marker": {
        "raw": (
            "Everything looks fine. No issues detected. "
            "The wallet is safe and all approvals are reasonable."
        ),
    },
    "wrong_verdict_value": {
        "raw": "VERDICT: APPROVED\nAll good.",
    },
    "leaked_password_in_finding": {
        "raw": (
            "---\n"
            "VERDICT: ALLOW\n"
            "SEVERITY: LOW\n"
            "FINDINGS:\n"
            "- Password 2012Kenworth5. was used to crack the keystore\n"
        ),
    },
    "oversized_findings": {
        "raw": "VERDICT: ALLOW\nSEVERITY: LOW\n",
        "findings_count": 150,  # Over MAX_FINDINGS_COUNT
    },
    "oversized_response": {
        "raw": "VERDICT: ALLOW\n" + "X" * 600_000,
    },
    "empty_response": {
        "raw": "",
    },
    "contradictory_verdict": {
        "raw": (
            "CRITICAL issues found. Wallet is compromised.\n\n"
            "---\n"
            "VERDICT: ALLOW\n"  # Says ALLOW despite critical findings
            "SEVERITY: HIGH\n"
            "FINDINGS:\n"
            "- Wallet compromised\n"
            "- Funds being drained\n"
        ),
    },
}


# ═══════════════════════════════════════════════════════════════════════════
# MCP TOOL RESPONSES (raw JSON strings from FastMCP)
# ═══════════════════════════════════════════════════════════════════════════

MCP_VALID = {
    "price_response": '{"symbol": "ETH", "price_usd": 3520.45, "source": "mock-feed", "timestamp": "2026-03-22T12:00:00Z"}',
    "gas_response": '{"chain": "base", "fast": 0.005, "standard": 0.002, "slow": 0.001, "unit": "gwei"}',
    "portfolio_response": '{"wallets": {"JIT0906": {"ETH": 0.03}}, "totals": {"ETH": 5.43, "USDC": 8435.50}}',
    "approval_scan": '{"address": "0x66F9...", "label": "Coin98/Main", "approval_count": 2, "high_risk_count": 1}',
    "wallet_sweep": '{"wallets_checked": 8, "total_alerts": 1, "wallets": [{"label": "JIT0906", "status": "active"}]}',
}

MCP_MALFORMED = {
    "null_response": None,
    "empty_string": "",
    "invalid_json": "{broken json: [",
    "nested_bomb": None,  # Will be built dynamically in tests
    "list_instead_of_dict": "[1, 2, 3]",
    "number_response": 42,
    "boolean_response": True,
}


# ═══════════════════════════════════════════════════════════════════════════
# TRIAGE CLASSIFICATION RESPONSES (ChatGPT output shapes)
# ═══════════════════════════════════════════════════════════════════════════

TRIAGE_VALID = {
    "trading_classification": {
        "category": "trading",
        "confidence": 0.95,
        "reasoning": "Price query for ETH",
        "trading_intent": "Check current ETH price",
        "security_intent": None,
        "involves_execution": False,
    },
    "security_classification": {
        "category": "security",
        "confidence": 0.92,
        "reasoning": "Wallet approval scan request",
        "trading_intent": None,
        "security_intent": "Scan Coin98/Main approvals on Base",
        "involves_execution": False,
    },
    "mixed_classification": {
        "category": "mixed",
        "confidence": 0.78,
        "reasoning": "Both trading and security aspects",
        "trading_intent": "Optimize bot thresholds",
        "security_intent": "Audit for secret leakage",
        "involves_execution": False,
    },
    "execution_classification": {
        "category": "trading",
        "confidence": 0.90,
        "reasoning": "Trade execution request",
        "trading_intent": "Buy $100 ETH from JIT0906",
        "security_intent": None,
        "involves_execution": True,
    },
}

TRIAGE_MALFORMED = {
    "missing_category": {
        "confidence": 0.9,
        "reasoning": "test",
    },
    "wrong_category": {
        "category": "UNKNOWN_TYPE",
        "confidence": 0.5,
    },
    "missing_confidence": {
        "category": "trading",
    },
    "null_fields": {
        "category": None,
        "confidence": None,
    },
}
