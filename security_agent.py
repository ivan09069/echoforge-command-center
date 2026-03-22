"""
Gemini Lane — Security Analyst
=================================
Connects to Security MCP (local-only, read-only default).

Allowed: code audit, wallet/tooling review, permission checks,
  exploit/pathology detection, forensic analysis, environment hardening

NOT allowed: direct trade execution, policy override,
  sending sensitive artifacts to non-local services

Must emit one of: ALLOW, ALLOW_WITH_CONDITIONS, REJECT, ESCALATE
"""

import os
import json
import logging

import google.genai as genai
from google.genai import types as gt
from mcp import ClientSession
from mcp.client.sse import sse_client

logger = logging.getLogger(__name__)

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
MCP_SECURITY_URL = os.getenv("MCP_SECURITY_URL", "http://localhost:8002/sse")
MAX_TURNS = 12

SYSTEM_PROMPT = """You are the Security Analyst in the EchoForge Command Center.
You protect Ivan's crypto infrastructure by identifying threats and enforcing security.

YOUR ROLE:
- Code audit and script risk review
- Wallet and tooling security review
- Permission analysis (token approvals, contract interactions)
- Exploit and pathology detection
- Forensic anomaly detection
- Environment hardening review

CRITICAL CONSTRAINTS:
- You operate in READ-ONLY mode by default.
- You NEVER execute trades or move funds.
- You NEVER send sensitive artifacts to non-local services.
- You CAN veto trading recommendations if you find security issues.
- Your verdict is BINDING — if you say REJECT, execution halts.

STANDARD PATROL (when asked for a "security sweep"):
  1. monitor_all_wallets
  2. scan_token_approvals on Coin98/Main (0x66F9C091)
  3. check_address_activity on MEV Signer1 and MEV Signer2
  4. Summarize with risk levels and next steps

OUTPUT: End every response with a clear verdict block:
---
VERDICT: ALLOW | ALLOW_WITH_CONDITIONS | REJECT | ESCALATE
SEVERITY: LOW | MEDIUM | HIGH
FINDINGS: [list key findings]
CONDITIONS: [list conditions if ALLOW_WITH_CONDITIONS]
---

KNOWN PRIORITIES:
- Coin98/Main needs approval revocations on Base (HIGH)
- MEV signer wallets should be dormant (MONITOR)
- swarm-trading-system git history exposed seeds (MEDIUM)
- Titan Builder gas refund ~4.765 ETH (LOW, pending recovery)"""


def _mcp_to_gemini(tool) -> gt.FunctionDeclaration:
    schema = tool.inputSchema or {"type": "object", "properties": {}}
    props = {}
    for k, v in schema.get("properties", {}).items():
        props[k] = {"type": v.get("type", "string").upper(), "description": v.get("description", "")}
    return gt.FunctionDeclaration(
        name=tool.name,
        description=tool.description or "",
        parameters={"type": "OBJECT", "properties": props, "required": schema.get("required", [])},
    )


class SecurityAgent:
    def __init__(self):
        self.client = genai.Client(api_key=GOOGLE_API_KEY)
        self.session: ClientSession | None = None
        self.gemini_tools: list = []
        self.resource_uris: list = []
        self._streams = None

    async def connect(self):
        logger.info(f"Security agent connecting to {MCP_SECURITY_URL}")
        self._streams = sse_client(MCP_SECURITY_URL)
        rs, ws = await self._streams.__aenter__()
        self.session = ClientSession(rs, ws)
        await self.session.__aenter__()
        await self.session.initialize()

        result = await self.session.list_tools()
        decls = [_mcp_to_gemini(t) for t in result.tools]
        logger.info(f"Security tools: {[d.name for d in decls]}")

        try:
            res = await self.session.list_resources()
            self.resource_uris = [r.uri for r in res.resources]
            if self.resource_uris:
                decls.append(gt.FunctionDeclaration(
                    name="read_resource",
                    description=f"Read MCP resource. URIs: {', '.join(str(u) for u in self.resource_uris)}",
                    parameters={"type": "OBJECT", "properties": {
                        "uri": {"type": "STRING", "description": "Resource URI"}
                    }, "required": ["uri"]},
                ))
        except Exception:
            pass

        self.gemini_tools = [gt.Tool(function_declarations=decls)]

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
        contents = []
        if history:
            for m in history:
                role = "user" if m["role"] == "user" else "model"
                contents.append(gt.Content(role=role, parts=[gt.Part(text=m["content"])]))
        contents.append(gt.Content(role="user", parts=[gt.Part(text=message)]))

        for _ in range(MAX_TURNS):
            resp = self.client.models.generate_content(
                model=GEMINI_MODEL, contents=contents,
                config=gt.GenerateContentConfig(
                    system_instruction=SYSTEM_PROMPT,
                    tools=self.gemini_tools, temperature=0.2,
                ),
            )
            candidate = resp.candidates[0]
            parts = candidate.content.parts
            fn_calls = [p for p in parts if p.function_call]
            texts = [p.text for p in parts if hasattr(p, "text") and p.text]

            if not fn_calls:
                return "\n".join(texts) if texts else "(no response)"

            contents.append(candidate.content)
            fn_responses = []
            for p in fn_calls:
                fc = p.function_call
                try:
                    r = await self._call_tool(fc.name, dict(fc.args))
                    fn_responses.append(gt.Part(
                        function_response=gt.FunctionResponse(name=fc.name, response={"result": r})
                    ))
                except Exception as e:
                    fn_responses.append(gt.Part(
                        function_response=gt.FunctionResponse(name=fc.name, response={"error": str(e)})
                    ))
            contents.append(gt.Content(role="user", parts=fn_responses))

        return "(max turns)"
