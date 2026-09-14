import ast
import asyncio
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from operator_security import authorized_token, require_remote_safe

class Disconnected(Exception): pass
class Socket:
    def __init__(self, messages): self.messages=iter(messages);self.accepted=False;self.closed=None;self.sent=[]
    async def accept(self): self.accepted=True
    async def close(self, code): self.closed=code
    async def receive_text(self):
        try:return next(self.messages)
        except StopIteration:raise Disconnected()
    async def send_json(self, data): self.sent.append(data)

def route_functions():
    tree=ast.parse(Path(__file__).with_name('web_ui.py').read_text())
    funcs=[n for n in tree.body if isinstance(n,ast.AsyncFunctionDef) and n.name in ('ws_chat','audit')]
    for func in funcs:func.decorator_list=[]
    future=ast.ImportFrom(module='__future__',names=[ast.alias(name='annotations')],level=0)
    module=ast.fix_missing_locations(ast.Module(body=[future,*funcs],type_ignores=[]))
    def forbidden(*args,**kwargs):raise AssertionError('provider or audit accessed before authentication')
    def response(body,status_code=200,headers=None):return SimpleNamespace(body=body,status_code=status_code,headers=headers)
    namespace=dict(os=os,json=json,asyncio=asyncio,authorized_token=authorized_token,require_remote_safe=require_remote_safe,
      WebSocketDisconnect=Disconnected,triage=SimpleNamespace(classify=forbidden),trading=object(),security=object(),JSONResponse=response,get_audit_log=forbidden)
    exec(compile(module,'operator-routes','exec'),namespace)
    return namespace

class RouteTests(unittest.IsolatedAsyncioTestCase):
    async def test_missing_or_invalid_token_never_opens_provider_path(self):
        functions=route_functions()
        for expected,provided in [('', ''),('synthetic-'+ 'x'*32,'wrong')]:
            with patch.dict(os.environ,{'OPERATOR_TOKEN':expected}):
                socket=Socket([json.dumps({'token':provided})]);await functions['ws_chat'](socket)
                self.assertEqual(socket.closed,1008)

    async def test_authenticated_secret_is_rejected_before_classification(self):
        functions=route_functions();token='synthetic-'+ 'x'*32
        candidate='0x'+'a1'*32
        with patch.dict(os.environ,{'OPERATOR_TOKEN':token}):
            socket=Socket([json.dumps({'token':token}),'private_key='+candidate])
            await functions['ws_chat'](socket)
        self.assertTrue(socket.sent[0]['authenticated'])
        self.assertIn('local review',socket.sent[1]['text'])
        self.assertNotIn(candidate,json.dumps(socket.sent))

    async def test_audit_endpoint_requires_token_before_reading_audit(self):
        functions=route_functions()
        for configured,code in [('',503),('synthetic-'+ 'x'*32,401)]:
            with patch.dict(os.environ,{'OPERATOR_TOKEN':configured}):
                response=await functions['audit'](SimpleNamespace(headers={}))
                self.assertEqual(response.status_code,code)

if __name__ == '__main__':unittest.main()
