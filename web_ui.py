"""
EchoForge Command Center — Operator View
==========================================
Single chat box. Invisible triage. Full pipeline:

  User → classify → build contract → normalize → route →
  specialist(s) → merge → decide → enforce → gate → respond

Approval flow: REQUIRE_APPROVAL → user types approve/deny → proceed or block.
Audit trail at /audit.
"""

import os
import json
import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse, JSONResponse

from operator_security import authorized_token, require_remote_safe
from boundary_enforcer import enforce_pre_route
from triage_router import TriageRouter
from trading_agent import TradingAgent
from security_agent import SecurityAgent
from policy_engine import (
    build_job_contract, decide, enforce_response_policy,
    log_audit, get_audit_log,
)
from contracts import (
    JobContract, JobType, GateDecision, FinalDisposition,
    SecurityOutput, SecurityVerdict, TradingOutput,
    Sensitivity,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

triage: TriageRouter | None = None
trading: TradingAgent | None = None
security: SecurityAgent | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global triage, trading, security
    triage = TriageRouter()
    trading = TradingAgent()
    security = SecurityAgent()

    for name, agent in [("Trading/Claude", trading), ("Security/Gemini", security)]:
        for attempt in range(10):
            try:
                await agent.connect()
                logger.info(f"✅ {name} connected")
                break
            except Exception as e:
                wait = min(2 ** attempt, 30)
                logger.warning(f"{name} attempt {attempt+1} failed: {e}. Retry {wait}s...")
                await asyncio.sleep(wait)
        else:
            logger.error(f"❌ {name} failed to connect")
    yield
    if trading: await trading.disconnect()
    if security: await security.disconnect()


app = FastAPI(title="EchoForge Command Center", lifespan=lifespan)


# ═══════════════════════════════════════════════════════════════════════════
# WebSocket — the single operator interface
# ═══════════════════════════════════════════════════════════════════════════

@app.websocket("/ws")
async def ws_chat(ws: WebSocket):
    if len(os.getenv('OPERATOR_TOKEN', '')) < 32:
        await ws.close(code=1008); return
    await ws.accept()
    try:
        hello_text = await asyncio.wait_for(ws.receive_text(), timeout=10)
        if len(hello_text) > 4096:
            await ws.close(code=1008); return
        hello = json.loads(hello_text)
        token = hello.get('token') if isinstance(hello, dict) else None
        if not authorized_token(token, os.getenv('OPERATOR_TOKEN', '')):
            await ws.close(code=1008); return
    except (ValueError, asyncio.TimeoutError, WebSocketDisconnect):
        await ws.close(code=1008); return
    await ws.send_json({'authenticated': True})
    trading_history: list[dict] = []
    security_history: list[dict] = []
    pending_contract: JobContract | None = None
    pending_safe_ctx: str | None = None

    try:
        while True:
            user_msg = await ws.receive_text()
            try:
                require_remote_safe(user_msg)
            except PermissionError:
                await ws.send_json({'agent': 'system', 'text': 'Content requires local review; no provider request was made.', 'contract': None, 'decision': None})
                continue

            if not all([triage, trading, security]):
                await ws.send_json({"agent": "system", "text": "Agents initializing...",
                                    "contract": None, "decision": None})
                continue

            # ── Approval gate response ──────────────────────────
            if pending_contract and pending_contract.approval_required:
                lower = user_msg.strip().lower()
                if lower in ("approve", "yes", "y", "go", "do it"):
                    # Re-run with approval
                    try:
                        resp = await trading.chat(
                            f"APPROVED for analysis only: {pending_safe_ctx}",
                            history=trading_history,
                        )
                        log_audit(pending_contract,
                                  decide(pending_contract),
                                  execution_action="ANALYSIS_ONLY_AFTER_APPROVAL",
                                  approval_record="USER_APPROVED")
                        await ws.send_json({
                            "agent": "claude", "text": f"Approved for analysis only.\n\n{resp}",
                            "contract": pending_contract.to_dict(), "decision": None,
                        })
                    except Exception as e:
                        await ws.send_json({
                            "agent": "system", "text": f"⚠️ Execution failed: {e}",
                            "contract": pending_contract.to_dict(), "decision": None,
                        })
                else:
                    log_audit(pending_contract,
                              decide(pending_contract),
                              execution_action="BLOCKED",
                              approval_record="USER_DENIED")
                    await ws.send_json({
                        "agent": "gpt", "text": "🚫 Denied. No action taken.",
                        "contract": pending_contract.to_dict(), "decision": None,
                    })
                pending_contract = None
                pending_safe_ctx = None
                continue

            # ── Full pipeline ───────────────────────────────────
            try:
                # 1. Classify
                classification = await triage.classify(user_msg)

                # 2. Build job contract (policy engine)
                contract = build_job_contract(user_msg, classification)
                preflight = enforce_pre_route(contract)
                if not preflight.valid:
                    await ws.send_json({'agent': 'system', 'text': 'Request failed policy validation.', 'contract': contract.to_dict(), 'decision': preflight.fallback_decision.to_dict()})
                    continue

                # 3. Normalize context
                safe_ctx = await triage.normalize_context(user_msg, contract.sensitivity)

                # 4. Route to specialist(s)
                trading_out: TradingOutput | None = None
                security_out: SecurityOutput | None = None
                response = ""
                agent_label = "gpt"

                if contract.routes == ["CLAUDE"]:
                    resp = await trading.chat(safe_ctx, history=trading_history)
                    trading_history.append({"role": "user", "content": safe_ctx})
                    trading_history.append({"role": "assistant", "content": resp})
                    trading_out = TradingOutput(raw_response=resp)
                    response = resp
                    agent_label = "claude"

                elif contract.routes == ["GEMINI"]:
                    resp = await security.chat(safe_ctx, history=security_history)
                    security_history.append({"role": "user", "content": safe_ctx})
                    security_history.append({"role": "assistant", "content": resp})
                    security_out = _parse_security_verdict(resp)
                    response = resp
                    agent_label = "gemini"

                elif "CLAUDE" in contract.routes and "GEMINI" in contract.routes:
                    # Parallel execution
                    t_intent = safe_ctx
                    s_intent = safe_ctx

                    t_task = asyncio.create_task(trading.chat(t_intent, history=trading_history))
                    s_task = asyncio.create_task(security.chat(s_intent, history=security_history))

                    t_resp, s_resp = await asyncio.gather(t_task, s_task, return_exceptions=True)
                    t_text = t_resp if isinstance(t_resp, str) else f"Error: {t_resp}"
                    s_text = s_resp if isinstance(s_resp, str) else f"Error: {s_resp}"

                    trading_history.append({"role": "user", "content": t_intent})
                    trading_history.append({"role": "assistant", "content": t_text})
                    security_history.append({"role": "user", "content": s_intent})
                    security_history.append({"role": "assistant", "content": s_text})

                    trading_out = TradingOutput(raw_response=t_text)
                    security_out = _parse_security_verdict(s_text)

                    # ChatGPT merges with veto logic
                    response = await triage.merge_outputs(t_text, s_text)
                    agent_label = "merged"

                else:
                    response = await triage.handle_general(user_msg)
                    agent_label = "gpt"

                # 5. Decide (policy → security → gate → trading)
                decision = decide(contract, trading_out, security_out)

                # Apply security veto for mixed requests
                if (security_out
                        and security_out.security_verdict == SecurityVerdict.REJECT
                        and contract.job_type == JobType.MIXED):
                    decision.disposition = FinalDisposition.BLOCKED_SECURITY
                    decision.gate_decision = GateDecision.DENY
                    decision.gate_reason = "Security REJECT — binding veto"

                # 6. Enforce response policy
                decision.operator_message = response
                response = enforce_response_policy(response, decision)

                # 7. Check if approval gate triggered
                if decision.gate_decision == GateDecision.REQUIRE_APPROVAL:
                    pending_contract = contract
                    pending_safe_ctx = safe_ctx

                # 8. Audit
                log_audit(contract, decision, trading_out, security_out)

                # 9. Send to operator
                await ws.send_json({
                    "agent": agent_label,
                    "text": response,
                    "contract": contract.to_dict(),
                    "decision": decision.to_dict(),
                })

            except Exception as e:
                logger.error(f"Pipeline error: {e}", exc_info=True)
                await ws.send_json({
                    "agent": "system", "text": "Pipeline failed; inspect server logs locally.",
                    "contract": None, "decision": None,
                })

    except WebSocketDisconnect:
        pass


def _parse_security_verdict(raw: str) -> SecurityOutput:
    """
    Parse Gemini's structured verdict from its response text.
    Looks for VERDICT: line in the output.
    """
    out = SecurityOutput(raw_response=raw)
    upper = raw.upper()

    if "VERDICT: REJECT" in upper:
        out.security_verdict = SecurityVerdict.REJECT
    elif "VERDICT: ESCALATE" in upper:
        out.security_verdict = SecurityVerdict.ESCALATE
    elif "VERDICT: ALLOW_WITH_CONDITIONS" in upper:
        out.security_verdict = SecurityVerdict.ALLOW_WITH_CONDITIONS
    elif "VERDICT: ALLOW" in upper:
        out.security_verdict = SecurityVerdict.ALLOW
    else:
        # CRITICAL: unknown/unparseable verdict defaults to ESCALATE, not ALLOW.
        # If we can't parse the security verdict, we do not assume safety.
        out.security_verdict = SecurityVerdict.ESCALATE

    # Extract severity
    if "SEVERITY: HIGH" in upper:
        out.severity = Sensitivity.HIGH
    elif "SEVERITY: MEDIUM" in upper:
        out.severity = Sensitivity.MEDIUM
    else:
        out.severity = Sensitivity.LOW

    # Extract findings lines
    in_findings = False
    in_conditions = False
    for line in raw.split("\n"):
        stripped = line.strip()
        if stripped.upper().startswith("FINDINGS:"):
            in_findings = True
            in_conditions = False
            rest = stripped[9:].strip().strip("[]")
            if rest:
                out.findings.append(rest)
            continue
        if stripped.upper().startswith("CONDITIONS:"):
            in_conditions = True
            in_findings = False
            rest = stripped[11:].strip().strip("[]")
            if rest:
                out.conditions.append(rest)
            continue
        if stripped.startswith("---") or stripped.upper().startswith("VERDICT:"):
            in_findings = False
            in_conditions = False
            continue
        if in_findings and stripped.startswith("-"):
            out.findings.append(stripped.lstrip("- "))
        if in_conditions and stripped.startswith("-"):
            out.conditions.append(stripped.lstrip("- "))

    return out


# ═══════════════════════════════════════════════════════════════════════════
# Audit endpoint
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/audit")
async def audit(request: Request):
    expected = os.getenv('OPERATOR_TOKEN', '')
    if len(expected) < 32: return JSONResponse({'error': 'operator_auth_not_configured'}, status_code=503)
    auth = request.headers.get('authorization', '')
    if not authorized_token(auth[7:] if auth.startswith('Bearer ') else '', expected):
        return JSONResponse({'error': 'unauthorized'}, status_code=401)
    return JSONResponse(get_audit_log(), headers={'Cache-Control': 'no-store'})


# ═══════════════════════════════════════════════════════════════════════════
# HTML
# ═══════════════════════════════════════════════════════════════════════════

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>EchoForge Command Center</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'SF Mono','Fira Code','Consolas',monospace;background:#06060c;color:#d8d8e0;height:100vh;display:flex;flex-direction:column}
header{padding:11px 20px;background:#0b0b14;border-bottom:1px solid #181828;display:flex;align-items:center;gap:8px}
header h1{font-size:13px;font-weight:700;color:#fff;letter-spacing:1.5px}
.pipe{color:#282838}
.b{font-size:8px;padding:2px 6px;border-radius:2px;font-weight:700;letter-spacing:.5px}
.b-gpt{background:#091a12;color:#6a9;border:1px solid #1a3a2a}
.b-claude{background:#1a120a;color:#c9a06a;border:1px solid #3a2a1a}
.b-gemini{background:#0a0e1e;color:#6a8af7;border:1px solid #1a2a4a}
.b-merged{background:#120a1e;color:#a07af7;border:1px solid #2a1a4a}
.b-system{background:#1e0a0a;color:#e55;border:1px solid #4a1a1a}
#status{margin-left:auto;font-size:9px;color:#383848}
#chat{flex:1;overflow-y:auto;padding:14px 20px;display:flex;flex-direction:column;gap:8px}
.msg{max-width:88%;padding:9px 13px;border-radius:5px;font-size:12px;line-height:1.6;white-space:pre-wrap;word-break:break-word}
.msg.user{align-self:flex-end;background:#0a0e1a;border:1px solid #141e38;color:#8aa4cc}
.msg.agent{align-self:flex-start;background:#09090f;border:1px solid #141420}
.mh{display:flex;align-items:center;gap:5px;margin-bottom:5px}
.meta{color:#2a2a3a;font-size:8px}
.tag{font-size:7px;padding:1px 4px;border-radius:2px;background:#0c0c14;border:1px solid #1a1a28;color:#3a3a4a}
.tag.hi{border-color:#4a3500;color:#b80}
.tag.crit{border-color:#4a0000;color:#e44}
.tag.exec{border-color:#4a3a00;color:#ea0}
.tag.gate-deny{border-color:#4a0000;color:#f44}
.tag.gate-approve{border-color:#003a00;color:#4e4}
.tag.gate-wait{border-color:#4a3a00;color:#ea0}
.thinking{align-self:flex-start;padding:5px 13px;font-size:10px}
@keyframes p{0%,100%{opacity:.15}50%{opacity:1}}
.thinking .d span{animation:p 1.4s infinite;color:#333}
.thinking .d span:nth-child(2){animation-delay:.2s}
.thinking .d span:nth-child(3){animation-delay:.4s}
.thinking .rl{color:#282838;font-size:8px}
.ex{padding:14px;display:flex;flex-wrap:wrap;gap:5px;justify-content:center}
.ex button{padding:5px 10px;background:#09090f;border:1px solid #141420;border-radius:4px;color:#484858;font-family:inherit;font-size:9px;cursor:pointer;transition:all .12s}
.ex button:hover{border-color:#444;color:#aaa}
.ex button.t:hover{border-color:#c9a06a;color:#c9a06a}
.ex button.s:hover{border-color:#6a8af7;color:#6a8af7}
.ex button.m:hover{border-color:#a07af7;color:#a07af7}
#bar{padding:10px 20px;background:#0b0b14;border-top:1px solid #181828;display:flex;gap:8px}
#bar input{flex:1;padding:9px 12px;background:#06060c;border:1px solid #181828;border-radius:4px;color:#d8d8e0;font-family:inherit;font-size:12px;outline:none}
#bar input:focus{border-color:#333}
#bar button{padding:9px 16px;background:#141420;color:#585868;border:1px solid #1e1e30;border-radius:4px;font-family:inherit;font-weight:600;cursor:pointer;font-size:11px}
#bar button:hover{background:#1e1e30;color:#ccc}
#bar button:disabled{opacity:.2;cursor:not-allowed}
</style>
</head>
<body>
<header>
  <h1>ECHOFORGE</h1><span class="pipe">|</span>
  <span class="b b-gpt">GPT</span>
  <span class="b b-claude">CLAUDE</span>
  <span class="b b-gemini">GEMINI</span>
  <span id="status">locked</span>
  <input id="operator-token" type="password" autocomplete="off" placeholder="Operator token" aria-label="Operator token"/>
  <button onclick="connect()">Connect</button>
</header>
<div id="chat">
  <div class="ex">
    <button class="t" onclick="S('What is the current price of ETH?')">ETH Price</button>
    <button class="t" onclick="S('Show portfolio summary')">Portfolio</button>
    <button class="t" onclick="S('Simulate buying $100 of ETH')">Simulate Trade</button>
    <button class="t" onclick="S('Buy $100 of ETH from JIT0906')">Trade ETH ⚠️</button>
    <button class="s" onclick="S('Run a full security sweep')">Security Sweep</button>
    <button class="s" onclick="S('Scan token approvals for Coin98/Main')">Approvals</button>
    <button class="s" onclick="S('Check MEV signers for activity')">MEV Monitor</button>
    <button class="m" onclick="S('Check wallets are safe then show portfolio')">Mixed</button>
    <button class="s" onclick="S('Audit my sentinel bot script for unsafe patterns')">Code Audit</button>
  </div>
</div>
<div id="bar">
  <input id="i" placeholder="Trading, security, or anything..." onkeydown="if(event.key==='Enter')S()" autofocus/>
  <button id="btn" onclick="S()">Send</button>
</div>
<script>
const C=document.getElementById('chat'),I=document.getElementById('i'),B=document.getElementById('btn'),
      ST=document.getElementById('status');let ws,authenticated=false;
const CL={claude:{l:'CLAUDE',c:'b-claude'},gemini:{l:'GEMINI',c:'b-gemini'},
           gpt:{l:'GPT',c:'b-gpt'},merged:{l:'MERGED',c:'b-merged'},system:{l:'SYS',c:'b-system'}};
function connect(){
  const field=document.getElementById('operator-token'),token=field.value;if(!token)return;
  if(ws)ws.close();authenticated=false;
  const p=location.protocol==='https:'?'wss':'ws';
  ws=new WebSocket(`${p}://${location.host}/ws`);
  ws.onopen=()=>{ws.send(JSON.stringify({token}));field.value='';ST.textContent='authenticating'};
  ws.onclose=()=>{authenticated=false;ST.textContent='locked';ST.style.color='#e44'};
  ws.onmessage=e=>{
    const t=document.querySelector('.thinking');if(t)t.remove();
    const d=JSON.parse(e.data);if(d.authenticated){authenticated=true;ST.textContent='live';ST.style.color='#6a9';return;}addA(d.agent,d.text,d.contract,d.decision);
    B.disabled=false;I.disabled=false;I.focus()};
}
function addU(t){const d=document.createElement('div');d.className='msg user';d.textContent=t;C.appendChild(d);C.scrollTop=C.scrollHeight}
function addA(ag,txt,con,dec){
  const d=document.createElement('div');d.className='msg agent';
  const h=document.createElement('div');h.className='mh';
  const b=document.createElement('span');const info=CL[ag]||CL.system;
  b.className='b '+info.c;b.textContent=info.l;h.appendChild(b);
  if(con){
    if(con.sensitivity&&con.sensitivity!=='LOW'){
      const t=document.createElement('span');
      t.className='tag '+(con.sensitivity==='HIGH'?'hi':'');
      t.textContent=con.sensitivity;h.appendChild(t)}
    if(con.action_class&&con.action_class!=='READ_ONLY'){
      const t=document.createElement('span');t.className='tag exec';
      t.textContent=con.action_class;h.appendChild(t)}
  }
  if(dec){
    if(dec.gate_decision==='DENY'){
      const t=document.createElement('span');t.className='tag gate-deny';t.textContent='DENIED';h.appendChild(t)}
    else if(dec.gate_decision==='REQUIRE_APPROVAL'){
      const t=document.createElement('span');t.className='tag gate-wait';t.textContent='AWAITING';h.appendChild(t)}
    else if(dec.disposition&&dec.disposition!=='APPROVED_READ_ONLY'){
      const t=document.createElement('span');t.className='tag gate-approve';t.textContent=dec.disposition;h.appendChild(t)}
  }
  if(con){const j=document.createElement('span');j.className='meta';j.textContent=con.job_id;h.appendChild(j)}
  d.appendChild(h);d.appendChild(document.createTextNode(txt));C.appendChild(d);C.scrollTop=C.scrollHeight}
function S(t){
  const m=t||I.value.trim();if(!m||!ws||!authenticated||ws.readyState!==1)return;addU(m);
  const th=document.createElement('div');th.className='thinking';
  th.innerHTML='<span class="rl">routing</span> <span class="d"><span>·</span><span>·</span><span>·</span></span>';
  C.appendChild(th);C.scrollTop=C.scrollHeight;
  ws.send(m);I.value='';B.disabled=true;I.disabled=true;
  const ex=document.querySelector('.ex');if(ex)ex.remove()}
</script>
</body>
</html>"""


@app.get("/")
async def root():
    return HTMLResponse(HTML)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
