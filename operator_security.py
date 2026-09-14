"""Enforced operator and provider boundaries; no provider calls at import time."""
import hashlib
import hmac
import json
from policy_engine import detect_secrets, classify_sensitivity
from contracts import Sensitivity

READ_ONLY_TOOLS = {
    'trading': frozenset({'check_token_price', 'check_gas_price', 'get_portfolio_summary',
                         'validate_trade_proposal', 'get_bot_status', 'simulate_trade'}),
    'security': frozenset({'scan_token_approvals', 'check_address_activity', 'analyze_contract',
                          'monitor_all_wallets', 'scan_exposed_keys', 'check_revocation_status', 'audit_script_risk'}),
}

def authorized_token(received, expected):
    if not isinstance(expected, str) or len(expected) < 32 or not isinstance(received, str):
        return False
    return hmac.compare_digest(hashlib.sha256(received.encode()).digest(), hashlib.sha256(expected.encode()).digest())

def require_remote_safe(text):
    if not isinstance(text, str) or len(text.encode('utf-8')) > 65536:
        raise PermissionError('Remote content must be bounded text')
    if detect_secrets(text) or classify_sensitivity(text) == Sensitivity.HIGH:
        raise PermissionError('Sensitive content requires local review')
    return text

async def call_readonly_tool(session, lane, name, args):
    if name not in READ_ONLY_TOOLS.get(lane, ()):
        raise PermissionError('Tool is not on the reviewed read-only allowlist')
    require_remote_safe(json.dumps(args))
    try:
        result = await session.call_tool(name, args)
    except Exception:
        raise RuntimeError('Read-only tool request failed') from None
    text = '\n'.join(part.text for part in result.content if hasattr(part, 'text'))
    return require_remote_safe(text)
