#!/usr/bin/env python3
"""Disposable local gateway/UI qualification; no production targets."""
import collections
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
from access_mode_smoke import BINARY, ROOT, call, free_port


def main():
    origins = []
    threads = []
    child = None
    for tag in [b'a', b'b']:
        def handler(tag):
            class Origin(BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200)
                    self.send_header('Content-Length', '1')
                    self.end_headers()
                    self.wfile.write(tag)

                def log_message(self, *_):
                    pass
            return Origin
        origin = ThreadingHTTPServer(('127.0.0.1', 0), handler(tag))
        thread = threading.Thread(target=origin.serve_forever, daemon=True)
        thread.start()
        origins.append(origin)
        threads.append(thread)
    try:
        with tempfile.TemporaryDirectory(prefix='hangang-named-ui-') as folder:
            config_path = Path(folder) / 'config.json'
            public, admin, stream = free_port(), free_port(), free_port()
            endpoints = [f'127.0.0.1:{origin.server_port}' for origin in origins]
            config_path.write_text(json.dumps({
                'http': [{'id': 'http-named', 'backends': ['http://' + endpoint for endpoint in endpoints],
                          'balance': {'weights': [3, 1]}}],
                'tcp': [{'id': 'tcp-named', 'listen': f'127.0.0.1:{stream}', 'backends': endpoints}],
            }))
            with (Path(folder) / 'gateway.log').open('wb') as log:
                child = subprocess.Popen([
                    str(BINARY), '--config', str(config_path), '--listen', f'127.0.0.1:{public}',
                    '--admin', f'127.0.0.1:{admin}', '--threads', '2', '--lua-workers', '1',
                ], env={**os.environ, 'HANGANG_ADMIN_TOKEN': 'fixture-named-member-token'},
                    stdout=log, stderr=log)
                headers = {'Authorization': 'Bearer fixture-named-member-token'}
                deadline = time.monotonic() + 10
                while True:
                    try:
                        assert call(admin, 'GET', '/v1/status', headers=headers)[0] == 200
                        break
                    except (OSError, AssertionError):
                        assert child.poll() is None, 'owned gateway exited before readiness'
                        assert time.monotonic() < deadline, 'owned gateway startup timed out'
                        time.sleep(0.05)
                subprocess.run(['npx', 'playwright', 'test', 'tests/named-members-actual.spec.js'],
                               cwd=ROOT / 'web', env={**os.environ,
                                   'HANGANG_NAMED_ACTUAL_BASE': f'http://127.0.0.1:{admin}'}, check=True)
                persisted = json.loads(config_path.read_text())
                assert persisted['http'][0]['backends'][0]['id'] == 'blue'
                assert persisted['tcp'][0]['backends'][1]['id'] == 'green'
                http_counts = collections.Counter(call(public, 'GET', '/')[1].decode() for _ in range(50))
                assert http_counts == {'a': 30, 'b': 20}, http_counts
                tcp_counts = collections.Counter()
                for _ in range(20):
                    with socket.create_connection(('127.0.0.1', stream), timeout=3) as peer:
                        peer.sendall(b'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
                        data = b''
                        while chunk := peer.recv(4096):
                            data += chunk
                        assert b'200 OK' in data.split(b'\r\n', 1)[0]
                        tcp_counts[data.split(b'\r\n\r\n', 1)[1].decode()] += 1
                assert tcp_counts == {'a': 15, 'b': 5}, tcp_counts
                print(json.dumps({'owned_ui_passed': 1, 'http_distribution': http_counts,
                                  'tcp_distribution': tcp_counts, 'persisted_member_ids': True,
                                  'production_modified': False, 'performance_comparison': False}))
    finally:
        if child is not None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        for origin in origins:
            origin.shutdown()
            origin.server_close()
        for thread in threads:
            thread.join(timeout=5)


if __name__ == '__main__':
    main()
