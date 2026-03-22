"""
ChatGPT — Triage Router / Policy Layer / Output Merger
========================================================
The control plane, NOT the money plane.

Allowed:
  classify, reduce context, build job contract, route,
  merge responses, enforce policy, request approval

NOT allowed:
  hold secrets, auto-execute trades, override security veto,
  pass raw sensitive artifacts to cloud systems

Decision precedence (hardcoded):
  1. Policy engine
  2. Security verdict
  3. Execution gate
  4. Trading recommendation
"""

import os
import json
import logging
from openai import AsyncOpenAI

from policy_engine import redact_secrets
from contracts import Sensitivity

logger = logging.getLogger(__name__)

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
TRIAGE_MODEL = os.getenv("TRIAGE_MODEL", "gpt-4o-mini")


# ═══════════════════════════════════════════════════════════════════════════
# Classification
# ═══════════════════════════════════════════════════════════════════════════

CLASSIFY_PROMPT = """You are the triage router for EchoForge Command Center.
Classify the user message into EXACTLY one category. Respond with ONLY valid JSON.

ROUTING TABLE:
- "trading" — strategy tuning, pnl interpretation, threshold changes, pair selection,
  signal logic, simulated optimization, prices, portfolio, bot status, buy/sell analysis
- "security" — key leakage review, wallet/tooling security, suspicious script behavior,
  audit, hardening, forensics, approvals, revocations, contract analysis, code audit
- "mixed" — examples: "optimize bot but check safety", "deploy but audit permissions",
  "tune strategy without exposing secrets", "make automation production safe"
- "general" — greetings, system questions, unclear intent

JSON format (respond with ONLY this, no markdown fences):
{
  "category": "trading|security|mixed|general",
  "confidence": 0.0-1.0,
  "reasoning": "brief explanation",
  "trading_intent": "null or trading part summary",
  "security_intent": "null or security part summary",
  "involves_execution": true/false
}"""


# ═══════════════════════════════════════════════════════════════════════════
# Context Normalization
# ═══════════════════════════════════════════════════════════════════════════

NORMALIZE_PROMPT = """You are a context normalizer for a secure AI routing system.
Given a user message, produce a MINIMAL safe summary that:
1. Preserves intent and key parameters
2. REMOVES all sensitive data (passwords, keys, seeds, .env contents)
3. Replaces addresses with labels when known
4. Stays under 200 words

Known wallet labels (use these instead of raw addresses):
- 0xcD90... = Samsung Keystore
- 0x66F9... = Coin98/Main
- 0x7adB... = JIT0906 (primary trading wallet)
- 0x55FF... = MEV Signer1 (DO NOT TRADE)
- 0xa2fc... = MEV Signer2 (DO NOT TRADE)
- 0x22af... = BankrCoin EOA
- 0xc98C... = PIPE Token

Respond with ONLY the normalized summary text. No JSON, no markdown."""


# ═══════════════════════════════════════════════════════════════════════════
# Output Merger — security veto is binding
# ═══════════════════════════════════════════════════════════════════════════

MERGE_PROMPT = """You are the output merger for EchoForge Command Center.
You received responses from the Trading Agent (Claude) and Security Agent (Gemini).
Merge them into ONE operator-facing decision.

HARDCODED PRECEDENCE:
1. Policy engine (already applied)
2. Security verdict — IF REJECT, trading is overridden. No exceptions.
3. Execution gate (already applied)
4. Trading recommendation (lowest priority)

MERGE RULES:
- If security says REJECT and trading says "high opportunity" → result = NO EXECUTION
- If security says ALLOW_WITH_CONDITIONS → list conditions prominently
- Always present security findings FIRST
- End with clear final disposition: APPROVED_READ_ONLY, APPROVED_WITH_CONDITIONS,
  BLOCKED_SECURITY, or AWAITING_HUMAN_APPROVAL
- Be concise and direct — Ivan wants answers, not essays

Trading Agent (Claude) said:
{trading_response}

Security Agent (Gemini) said:
{security_response}

Merge into a single operator response. Security veto is binding."""


# ═══════════════════════════════════════════════════════════════════════════
# General handler
# ═══════════════════════════════════════════════════════════════════════════

GENERAL_PROMPT = """You are the front-desk of EchoForge Command Center.
Two specialist agents:
1. TRADING (Claude) — prices, trades, portfolio, bot tuning, strategy
2. SECURITY (Gemini) — wallet monitoring, approvals, threats, code audit

If intent is unclear, ask whether they need trading or security help.
Keep responses under 3 sentences. No fluff. Direct."""


class TriageRouter:
    def __init__(self):
        self.client = AsyncOpenAI(api_key=OPENAI_API_KEY)

    async def classify(self, user_message: str) -> dict:
        """Classify user intent. Step 1 of the pipeline."""
        try:
            resp = await self.client.chat.completions.create(
                model=TRIAGE_MODEL,
                messages=[
                    {"role": "system", "content": CLASSIFY_PROMPT},
                    {"role": "user", "content": user_message},
                ],
                max_tokens=200,
                temperature=0,
            )
            raw = resp.choices[0].message.content.strip()
            clean = raw.replace("```json", "").replace("```", "").strip()
            result = json.loads(clean)
            logger.info(
                f"  🏷️  Triage: {result['category']} "
                f"(conf={result['confidence']}) — {result.get('reasoning', '')}"
            )
            return result
        except Exception as e:
            logger.error(f"Classification failed: {e}")
            return {
                "category": "general", "confidence": 0.5,
                "reasoning": f"error: {e}",
                "trading_intent": None, "security_intent": None,
                "involves_execution": False,
            }

    async def normalize_context(self, user_message: str, sensitivity: Sensitivity) -> str:
        """
        Reduce context before routing. Strip secrets, minimize.
        LOW sensitivity = pass through. MEDIUM/HIGH = LLM normalization + regex.
        """
        if sensitivity == Sensitivity.LOW:
            return user_message

        try:
            resp = await self.client.chat.completions.create(
                model=TRIAGE_MODEL,
                messages=[
                    {"role": "system", "content": NORMALIZE_PROMPT},
                    {"role": "user", "content": user_message},
                ],
                max_tokens=300,
                temperature=0,
            )
            normalized = resp.choices[0].message.content.strip()
            # Double-check with regex redaction
            normalized, _ = redact_secrets(normalized)
            logger.info(f"  🔒 Normalized: {normalized[:80]}...")
            return normalized
        except Exception as e:
            logger.error(f"Normalization failed: {e}")
            redacted, _ = redact_secrets(user_message)
            return redacted

    async def merge_outputs(
        self,
        trading_response: str | None,
        security_response: str | None,
    ) -> str:
        """
        Merge trading + security outputs. Security veto is binding.
        ChatGPT computes the final operator-facing disposition.
        """
        if not trading_response and not security_response:
            return "Both agents failed to produce output."
        if not trading_response:
            return security_response
        if not security_response:
            return trading_response

        try:
            prompt = MERGE_PROMPT.format(
                trading_response=trading_response,
                security_response=security_response,
            )
            resp = await self.client.chat.completions.create(
                model=TRIAGE_MODEL,
                messages=[{"role": "system", "content": prompt}],
                max_tokens=1000,
                temperature=0.2,
            )
            return resp.choices[0].message.content.strip()
        except Exception as e:
            logger.error(f"Merge failed: {e}")
            return (
                f"🛡️ Security:\n{security_response}\n\n"
                f"---\n\n📈 Trading:\n{trading_response}"
            )

    async def handle_general(self, user_message: str) -> str:
        """Handle general/unclear messages directly."""
        try:
            resp = await self.client.chat.completions.create(
                model=TRIAGE_MODEL,
                messages=[
                    {"role": "system", "content": GENERAL_PROMPT},
                    {"role": "user", "content": user_message},
                ],
                max_tokens=200,
                temperature=0.7,
            )
            return resp.choices[0].message.content.strip()
        except Exception as e:
            return f"Router error: {e}"
