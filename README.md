# EchoForge Command Center

3-agent triage system with hard trust boundaries.

**ChatGPT** triages → **Claude** trades → **Gemini** guards → **Policy engine** enforces → **Execution gate** blocks or approves.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full canonical operating model.

## Quick Start

```bash
# 1. API keys
cat > .env << 'EOF'
OPENAI_API_KEY="sk-..."
ANTHROPIC_API_KEY="sk-ant-..."
GOOGLE_API_KEY="your-gemini-key"
EOF

# 2. Run
docker compose up --build

# 3. Open
# Command Center: http://localhost:8000
# Audit log:      http://localhost:8000/audit
```

### Without Docker

```bash
pip install anthropic openai google-genai "mcp[cli]" httpx fastapi uvicorn websockets

# Terminal 1 — Security MCP (local)
MCP_PORT=8002 python security_server.py

# Terminal 2 — Command Center
python web_ui.py
```

## Files

```
contracts.py        — Phase 1: Job, verdict, decision schemas
policy_engine.py    — Phase 2: Classifier, redactor, router, gate, audit
trading_server.py   — Phase 3a: EchoForge MCP adapter (remote-safe)
security_server.py  — Phase 3b: Security MCP adapter (local, read-only)
trading_agent.py    — Claude lane (MCP client)
security_agent.py   — Gemini lane (MCP client)
triage_router.py    — Phase 4: ChatGPT orchestrator
web_ui.py           — Phase 5: Operator view + execution gate
ARCHITECTURE.md     — Canonical operating model
```

## Test Prompts

| Prompt | Route | Gate |
|--------|-------|------|
| "ETH price?" | Claude | ALLOW |
| "Simulate $100 ETH trade" | Claude | ALLOW (read-only) |
| "Buy $100 ETH from JIT0906" | Claude | REQUIRE_APPROVAL |
| "Security sweep" | Gemini | ALLOW |
| "Scan Coin98 approvals" | Gemini | ALLOW |
| "Optimize bot but check safety" | Both → Merged | ALLOW (security veto enabled) |
| "Buy $500 DOGE from MEV Signer1" | Claude | REQUIRE_APPROVAL → policy violations |
| "Decrypt wallet_69.json" | Gemini (reclassified HIGH) | ALLOW (local-only) |
