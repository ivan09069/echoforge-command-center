"""
Claude Lane — Trading Analyst
================================
Connects to EchoForge MCP (Cloudflare, remote-safe).

Allowed: signal interpretation, risk logic, sizing proposals,
  threshold tuning, market reasoning, strategy comparison, backtest analysis

NOT allowed: direct secret access, wallet exports, local forensic artifacts,
  unrestricted tool execution, final authority over execution
"""

import os
import json
import logging

import anthropic
from mcp import ClientSession
from mcp.client.sse import sse_client

logger = logging.getLogger(__name__)

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
MODEL = os.getenv("MODEL", "claude-sonnet-4-20250514")
MCP_SERVER_URL = os.getenv(
    "MCP_SERVER_URL",
    "https://echoforge-mcp.jivantorres9.workers.dev/sse"
)
MAX_TURNS = 12

SYSTEM_PROMPT = """You are the Trading Analyst in the EchoForge Command Center.
You provide trading intelligence — you do NOT execute trades.

YOUR ROLE:
- Signal interpretation and market structure analysis
- Risk/reward assessment using Sentinel X v10 rules
- Position sizing proposals (Kelly Criterion, $125 max, $4,500 daily cap)
- Strategy comparison (mean reversion vs momentum)
- Threshold tuning recommendations
- Backtest interpretation

CRITICAL CONSTRAINTS:
- You are ANALYSIS ONLY. You cannot execute trades.
- You have NO access to secrets, private keys, or sensitive data.
- Your proposals go through an execution gate that requires human approval.
- If your analysis conflicts with a security verdict, security wins.
- Only BTC/USDC and ETH/USDC pairs. Only JIT0906 wallet for trading.
- MEV signer wallets are OFF LIMITS.

OUTPUT FORMAT:
When proposing trades or changes, structure your response clearly:
- What you recommend and why
- Confidence level (low/medium/high)
- Assumptions your recommendation depends on
- Risk notes
- Whether execution would be needed

You do NOT have final say. The policy engine decides."""


def _mcp_to_anthropic(tool) -> dict:
    schema = tool.inputSchema or {"type": "object", "properties": {}}
    return {
        "name": tool.name,
        "description": tool.description or "",
        "input_schema": schema,
    }


class TradingAgent:
    def __init__(self):
        self.client = anthropic.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
        self.session: ClientSession | None = None
        self.tools: list[dict] = []
        self.resource_uris: list = []
        self._streams = None

    async def connect(self):
        logger.info(f"Trading agent connecting to {MCP_SERVER_URL}")
        self._streams = sse_client(MCP_SERVER_URL)
        rs, ws = await self._streams.__aenter__()
        self.session = ClientSession(rs, ws)
        await self.session.__aenter__()
        await self.session.initialize()

        result = await self.session.list_tools()
        self.tools = [_mcp_to_anthropic(t) for t in result.tools]
        logger.info(f"Trading tools: {[t['name'] for t in self.tools]}")

        try:
            res = await self.session.list_resources()
            self.resource_uris = [r.uri for r in res.resources]
            if self.resource_uris:
                self.tools.append({
                    "name": "read_resource",
                    "description": f"Read MCP resource. URIs: {', '.join(str(u) for u in self.resource_uris)}",
                    "input_schema": {
                        "type": "object",
                        "properties": {"uri": {"type": "string"}},
                        "required": ["uri"],
                    },
                })
        except Exception:
            pass

    async def disconnect(self):
        if self.session:
            await self.session.__aexit__(None, None, None)
        if self._streams:
            await self._streams.__aexit__(None, None, None)

    async def _call_tool(self, name: str, args: dict) -> str:
        if name == "read_resource":
            r = await self.session.read_resource(args["uri"])
            return "\n".join(c.text for c in r.contents if hasattr(c, "text"))
        r = await self.session.call_tool(name, args)
        return "\n".join(c.text for c in r.content if hasattr(c, "text"))

    async def chat(self, message: str, history: list[dict] | None = None) -> str:
        messages = list(history) if history else []
        messages.append({"role": "user", "content": message})

        for _ in range(MAX_TURNS):
            resp = await self.client.messages.create(
                model=MODEL, max_tokens=4096,
                system=SYSTEM_PROMPT,
                tools=self.tools, messages=messages,
            )

            if resp.stop_reason == "end_turn":
                return "\n".join(b.text for b in resp.content if b.type == "text")

            if resp.stop_reason == "tool_use":
                messages.append({"role": "assistant", "content": resp.content})
                results = []
                for b in resp.content:
                    if b.type == "tool_use":
                        try:
                            r = await self._call_tool(b.name, b.input)
                            results.append({"type": "tool_result", "tool_use_id": b.id, "content": r})
                        except Exception as e:
                            results.append({"type": "tool_result", "tool_use_id": b.id,
                                            "content": f"Error: {e}", "is_error": True})
                messages.append({"role": "user", "content": results})
            else:
                parts = [b.text for b in resp.content if b.type == "text"]
                return "\n".join(parts) if parts else "(no response)"

        return "(max turns)"
