import unittest
from types import SimpleNamespace
from operator_security import authorized_token, require_remote_safe, call_readonly_tool

class OperatorSecurityTests(unittest.IsolatedAsyncioTestCase):
    def test_auth_requires_configured_token(self):
        self.assertFalse(authorized_token('', ''))
        self.assertFalse(authorized_token('short', 'short'))
        token = 'synthetic-fixture-' + 'x' * 32
        self.assertTrue(authorized_token(token, token))
        self.assertFalse(authorized_token('wrong', token))
        self.assertFalse(authorized_token('é', token))

    def test_secrets_rejected_without_returning_value(self):
        candidate = '0x' + 'a1' * 32
        with self.assertRaises(PermissionError) as result:
            require_remote_safe('private_key=' + candidate)
        self.assertNotIn(candidate, str(result.exception))

    async def test_unknown_write_and_resource_tools_never_reach_transport(self):
        calls = []
        async def call(name, args): calls.append(name)
        session = SimpleNamespace(call_tool=call)
        for lane in ['trading', 'security']:
            for name in ['execute_trade', 'read_resource', 'export_wallet', 'unknown']:
                with self.assertRaises(PermissionError):
                    await call_readonly_tool(session, lane, name, {})
        self.assertEqual(calls, [])

    async def test_allowed_tool_results_are_checked_before_provider_receives_them(self):
        candidate = '0x' + 'b2' * 32
        async def call(name, args):
            return SimpleNamespace(content=[SimpleNamespace(text='private_key=' + candidate)])
        with self.assertRaises(PermissionError) as result:
            await call_readonly_tool(SimpleNamespace(call_tool=call), 'trading', 'check_token_price', {})
        self.assertNotIn(candidate, str(result.exception))

    async def test_readonly_tool_can_return_public_analysis(self):
        async def call(name, args): return SimpleNamespace(content=[SimpleNamespace(text='Price unavailable')])
        result = await call_readonly_tool(SimpleNamespace(call_tool=call), 'trading', 'check_token_price', {})
        self.assertEqual(result, 'Price unavailable')

if __name__ == '__main__': unittest.main()
