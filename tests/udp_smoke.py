#!/usr/bin/env python3
"""Live gateway UDP configuration and lifecycle checks on owned loopback sockets."""
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get('HANGANG_BINARY', ROOT/'target/debug/hangang')).resolve()


def port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(self.server.label + b':' + data, self.client_address)


class UdpGateway(unittest.TestCase):
    def test_revisioned_reload_rollback_status_and_unsupported_modes(self):
        with tempfile.TemporaryDirectory(prefix='hangang-udp-') as directory:
            root = Path(directory)
            token = secrets.token_hex(32)
            env = {k:v for k,v in os.environ.items() if not k.startswith('HANGANG_')}
            env['HANGANG_ADMIN_TOKEN'] = token
            servers = []
            clients = []
            child = None
            try:
                for label in (b'a', b'b'):
                    server = socketserver.UDPServer(('127.0.0.1', 0), Echo)
                    server.label = label
                    threading.Thread(target=server.serve_forever, daemon=True).start()
                    servers.append(server)
                listen = port(socket.SOCK_DGRAM)
                public, admin = port(), port()
                while admin == public:
                    admin = port()
                route = {'id':'udp-test','listen':f'127.0.0.1:{listen}', 'backends':[f'127.0.0.1:{s.server_address[1]}' for s in servers], 'idle_timeout_ms':5000, 'max_sessions':8, 'max_datagram_bytes':2048}
                config = {'revision':0,'http':[],'tcp':[],'udp':[route]}
                path = root/'config.json'
                path.write_text(json.dumps(config))
                args = [str(BINARY),'--config',str(path),'--listen',f'127.0.0.1:{public}','--admin',f'127.0.0.1:{admin}','--lua-workers','1','--threads','2']
                subprocess.run(args+['--check'], env=env, check=True, capture_output=True, timeout=10)
                for extra in (['--supervised','--check'], ['--database','sqlite:'+str(root/'shared.sqlite3')]):
                    probe = subprocess.run(args+extra, env=env, capture_output=True, timeout=15)
                    self.assertNotEqual(probe.returncode,0,'unsupported authority must reject UDP')
                with open(root/'gateway.log','w+') as log:
                    child = subprocess.Popen(args,env=env,stdout=log,stderr=log)
                    def request(method, resource, body=None, revision=None):
                        conn = http.client.HTTPConnection('127.0.0.1',admin,timeout=3)
                        headers={'Authorization':'Bearer '+token}
                        if revision is not None:headers['If-Match']=f'"{revision}"'
                        if body is not None:headers['Content-Type']='application/json';body=json.dumps(body)
                        try:
                            conn.request(method,resource,body,headers)
                            response=conn.getresponse(); data=response.read()
                            try: payload=json.loads(data) if data else None
                            except json.JSONDecodeError: payload=data.decode(errors='replace')
                            return response.status,payload
                        finally:conn.close()
                    for _ in range(100):
                        try:
                            if request('GET','/v1/status')[0]==200:break
                        except (OSError,http.client.HTTPException):pass
                        if child.poll() is not None:log.seek(0);self.fail(log.read())
                        time.sleep(.05)
                    else:self.fail('gateway never became ready')
                    def client():
                        c=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);c.settimeout(1);clients.append(c);return c
                    def exchange(c,message=b'hello'):
                        c.sendto(message,('127.0.0.1',listen));data,_=c.recvfrom(4096);label,payload=data.split(b':',1);self.assertEqual(payload,message);return label
                    first,second=client(),client()
                    self.assertEqual({exchange(first),exchange(second)},{b'a',b'b'})
                    first_label=exchange(first)
                    code,current=request('GET','/v1/config');self.assertEqual(code,200)
                    unchanged=dict(current);unchanged['settings']={'health_path':'/ready'}
                    code,new=request('PUT','/v1/config',unchanged,current['revision']);self.assertEqual(code,200,new)
                    self.assertEqual(exchange(first),first_label,'unrelated edits must retain flow affinity')
                    status=request('GET','/v1/status')[1]
                    self.assertEqual(status['udp_routes'],1)
                    self.assertEqual(status['udp']['routes'][0]['sessions'],2)
                    code, metrics=request('GET','/metrics')
                    self.assertEqual(code,200)
                    self.assertIn('hangang_udp_sessions{route="udp-test"} 2',metrics)
                    self.assertIn('hangang_udp_datagrams_forwarded_total{route="udp-test"}',metrics)
                    code,current=request('GET','/v1/config')
                    # A bind failure during preparation must preserve persisted and runtime revisions.
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as occupied:
                        occupied.bind(('127.0.0.1',0))
                        failed=json.loads(json.dumps(current));failed['udp'].append({**route,'id':'occupied','listen':f'127.0.0.1:{occupied.getsockname()[1]}'})
                        code,_=request('PUT','/v1/config',failed,current['revision']);self.assertGreaterEqual(code,400)
                    self.assertEqual(request('GET','/v1/config')[1]['revision'],current['revision'])
                    self.assertEqual(json.loads(path.read_text())['revision'],current['revision'])
                    self.assertEqual(exchange(first),first_label)
                    code,_=request('PUT','/v1/config',current,0);self.assertEqual(code,409)
                    # Disabled relay no longer forwards; a new listen address is really rebound.
                    current['udp'][0]['enabled']=False
                    code,_=request('PUT','/v1/config',current,current['revision']);self.assertEqual(code,200)
                    time.sleep(.1)
                    silent=client();silent.settimeout(.2);silent.sendto(b'no',('127.0.0.1',listen))
                    with self.assertRaises(TimeoutError):silent.recvfrom(100)
                    current=request('GET','/v1/config')[1]
                    current['udp'][0]['enabled']=True
                    listen=port(socket.SOCK_DGRAM);current['udp'][0]['listen']=f'127.0.0.1:{listen}'
                    code,_=request('PUT','/v1/config',current,current['revision']);self.assertEqual(code,200)
                    self.assertIn(exchange(client()),(b'a',b'b'))
                    # Plain file edits use the same preparation path and retain good state on malformed input.
                    active=request('GET','/v1/config')[1]
                    path.write_text('{invalid')
                    time.sleep(.7)
                    self.assertEqual(request('GET','/v1/config')[1]['revision'],active['revision'])
                    self.assertIn(exchange(client()),(b'a',b'b'))
                    child.terminate();child.wait(timeout=10)
                    child=None
            finally:
                if child is not None and child.poll() is None:
                    child.terminate()
                    try:child.wait(timeout=5)
                    except subprocess.TimeoutExpired:child.kill();child.wait()
                for c in clients:c.close()
                for server in servers:server.shutdown();server.server_close()


if __name__=='__main__':unittest.main(verbosity=2)
