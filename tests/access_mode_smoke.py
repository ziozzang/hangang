#!/usr/bin/env python3
"""Owned real-process access policy/CAS/concurrency fixture; no production targets."""
import base64
import concurrent.futures
import copy
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get('HANGANG_BIN', ROOT / 'target/debug/hangang'))
TOKEN = 'owned-access-mode-fixture'


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def call(port, method, path, document=None, headers=None):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
    supplied = dict(headers or {})
    if document is not None:
        supplied['Content-Type'] = 'application/json'
    try:
        connection.request(method, path, json.dumps(document) if document is not None else None, supplied)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def main():
    observations, lock = [], threading.Lock()

    class Origin(BaseHTTPRequestHandler):
        def do_GET(self):
            with lock:
                observations.append((self.path, self.headers.get('x-user'), self.headers.get('x-app'), self.headers.get('authorization')))
            body = b'owned-origin'
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    origin = ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    child = None
    try:
        with tempfile.TemporaryDirectory(prefix='hangang-access-mode-') as folder:
            path = Path(folder) / 'config.json'
            backend = f'http://127.0.0.1:{origin.server_port}'
            path.write_text(json.dumps({'http': [{'id': 'legacy', 'path_prefix': '/legacy', 'backends': [backend]}]}))
            public, admin = free_port(), free_port()
            with (Path(folder) / 'process.log').open('wb') as log:
                child = subprocess.Popen([str(BINARY), '--config', str(path), '--listen', f'127.0.0.1:{public}',
                                          '--admin', f'127.0.0.1:{admin}', '--threads', '2', '--lua-workers', '16'],
                                         env={**os.environ, 'HANGANG_ADMIN_TOKEN': TOKEN}, stdout=log, stderr=log)
                auth = {'Authorization': f'Bearer {TOKEN}'}
                for _ in range(200):
                    if child.poll() is not None:
                        raise RuntimeError('owned gateway exited before readiness')
                    try:
                        status, body = call(admin, 'GET', '/v1/config', headers=auth)
                        if status == 200:
                            document = json.loads(body)
                            break
                    except OSError:
                        pass
                    time.sleep(.05)
                else:
                    raise RuntimeError('owned gateway readiness deadline')
                assert 'access_mode' not in document['http'][0], 'legacy serialization changed'
                assert call(public, 'GET', '/legacy')[0] == 200
                salt = b'0123456789abcdef'
                credential = f'alice:{salt.hex()}:{hashlib.sha256(salt + b"secret").hexdigest()}'
                protected = {'id': 'protected', 'path_prefix': '/protected', 'backends': [backend],
                             'access_mode': 'protected', 'basic_auth': {'credentials': [credential], 'hide_credentials': True, 'identity_header': 'x-user'},
                             'lua': "hangang.set_header('x-app', 'flexible')"}
                document['http'].append(protected)
                status, body = call(admin, 'PUT', '/v1/config', document, {**auth, 'If-Match': f'"{document["revision"]}"'})
                assert status == 200, f'protected publication failed: {status}'
                committed = json.loads(body)
                revision = committed['revision']
                request_auth = {'Authorization': 'Basic ' + base64.b64encode(b'alice:secret').decode()}
                assert call(public, 'GET', '/protected')[0] == 401
                assert call(public, 'GET', '/protected', headers={'Cache-Control': 'only-if-cached'})[0] == 401
                assert call(public, 'GET', '/protected', headers={**request_auth, 'Cache-Control': 'only-if-cached'})[0] == 504
                assert call(public, 'GET', '/protected', headers=request_auth) == (200, b'owned-origin')
                invalid = copy.deepcopy(committed)
                invalid['http'][1]['basic_auth'] = None
                omitted = copy.deepcopy(invalid)
                omitted['http'][1].pop('access_mode')

                def exercise(index):
                    if index % 10 == 0:
                        result, _ = call(admin, 'PUT', '/v1/config', omitted if index % 20 == 0 else invalid, {**auth, 'If-Match': f'"{revision}"'})
                        assert result in (400, 422), f'invalid downgrade status {result}'
                    elif index % 2:
                        result = call(public, 'GET', '/protected', headers=request_auth)
                        assert result == (200, b'owned-origin'), f'authenticated response {result!r}'
                    else:
                        assert call(public, 'GET', '/protected')[0] == 401

                with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
                    list(executor.map(exercise, range(100)))
                status, body = call(admin, 'GET', '/v1/config', headers=auth)
                observed = json.loads(body)
                assert status == 200 and observed['revision'] == revision
                assert observed['http'][1]['access_mode'] == 'protected' and observed['http'][1]['basic_auth']
                stored = json.loads(path.read_text())
                assert stored['revision'] == revision and stored['http'][1]['basic_auth']
                with lock:
                    protected_seen = [row for row in observations if row[0] == '/protected']
                    assert len(protected_seen) == 51
                    assert all(row[1:] == ('alice', 'flexible', None) for row in protected_seen)
                subprocess.run(['npx', 'playwright', 'test', 'tests/access-actual.spec.js'], cwd=ROOT / 'web',
                               env={**os.environ, 'HANGANG_ACCESS_ACTUAL_BASE': f'http://127.0.0.1:{admin}',
                                    'HANGANG_ACCESS_ACTUAL_TOKEN': TOKEN,
                                    'HANGANG_ACCESS_ACTUAL_PUBLIC': f'http://127.0.0.1:{public}'}, check=True)
                with lock:
                    edited_seen = [row for row in observations if row[0] == '/protected' and row[2] == 'editor']
                    assert len(edited_seen) == 1
                    assert edited_seen[0][1:] == ('alice', 'editor', None)
                print(json.dumps({'fixture': 'owned-access-mode', 'concurrent_operations': 100,
                                  'rejected_downgrades': 10, 'authenticated_origin_requests_before_browser': 51,
                                  'unauthenticated_origin_requests': 0, 'revision_preserved': True,
                                  'legacy_preserved': True, 'lua_application_mutation_preserved': True,
                                  'editor_saved_policy_executed_at_origin': True,
                                  'performance_comparison': False}))
    finally:
        if child is not None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        origin.shutdown()
        origin.server_close()
        thread.join(timeout=5)


if __name__ == '__main__':
    main()
