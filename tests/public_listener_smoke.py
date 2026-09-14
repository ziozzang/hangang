#!/usr/bin/env python3
"""Own a loopback gateway, origin and occupied socket for the embedded public-listener UI smoke."""
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from access_mode_smoke import call, free_port

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get('HANGANG_BIN', os.environ.get('HANGANG_BINARY', ROOT / 'target/debug/hangang'))).resolve()


def main():
    if not BINARY.is_file():
        raise RuntimeError(f'Build the debug gateway first or set HANGANG_BIN: {BINARY}')

    class Origin(BaseHTTPRequestHandler):
        def do_GET(self):
            body = f'owned-public-listener-origin:{self.path}'.encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    origin = ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    origin.daemon_threads = True
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    occupied = socket.socket()
    occupied.bind(('127.0.0.1', 0))
    occupied.listen(1)
    occupied_port = occupied.getsockname()[1]
    try:
        with tempfile.TemporaryDirectory(prefix='hangang-public-listener-') as folder:
            root = Path(folder)
            state = root / 'config.json'
            backend = f'http://127.0.0.1:{origin.server_port}'
            state.write_text(json.dumps({'http': [
                {'id': 'scoped', 'path_prefix': '/scoped', 'backends': [backend]},
                {'id': 'legacy', 'path_prefix': '/legacy', 'backends': [backend]},
            ]}))
            ports = {origin.server_port, occupied_port}
            public = free_port()
            while public in ports:
                public = free_port()
            ports.add(public)
            admin = free_port()
            while admin in ports:
                admin = free_port()
            ports.add(admin)
            edge = free_port()
            while edge in ports:
                edge = free_port()
            token = secrets.token_hex(24)
            with (root / 'gateway.log').open('wb') as log:
                child = subprocess.Popen([
                    str(BINARY), '--config', str(state), '--listen', f'127.0.0.1:{public}',
                    '--admin', f'127.0.0.1:{admin}', '--threads', '2', '--lua-workers', '1',
                ], env={**os.environ, 'HANGANG_ADMIN_TOKEN': token}, stdout=log, stderr=log)
                try:
                    for _ in range(200):
                        if child.poll() is not None:
                            raise RuntimeError(f'gateway exited before readiness: {(root / "gateway.log").read_text()[-3000:]}')
                        try:
                            if call(admin, 'GET', '/v1/config', headers={'Authorization': f'Bearer {token}'})[0] == 200:
                                break
                        except OSError:
                            pass
                        time.sleep(.05)
                    else:
                        raise RuntimeError('gateway readiness deadline')
                    subprocess.run(['npx', 'playwright', 'test', 'tests/public-listener-actual.spec.js', '--workers=1', '--reporter=line'],
                                   cwd=ROOT / 'web', check=True, env={**os.environ,
                                   'HANGANG_UI_TEST_PORT': '41791',
                                   'HANGANG_PUBLIC_ACTUAL_ADMIN': f'http://127.0.0.1:{admin}',
                                   'HANGANG_PUBLIC_ACTUAL_DEFAULT': f'http://127.0.0.1:{public}',
                                   'HANGANG_PUBLIC_ACTUAL_EDGE': f'http://127.0.0.1:{edge}',
                                   'HANGANG_PUBLIC_ACTUAL_OCCUPIED': f'127.0.0.1:{occupied_port}',
                                   'HANGANG_PUBLIC_ACTUAL_TOKEN': token})
                    saved = json.loads(state.read_text())
                    assert saved['public_http'][0]['id'] == 'edge'
                    assert saved['public_http'][0]['listen'] == f'127.0.0.1:{edge}'
                    assert saved['http'][0]['listener_ids'] == ['default', 'edge']
                finally:
                    child.terminate()
                    try:
                        child.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=5)
    finally:
        occupied.close()
        origin.shutdown()
        origin.server_close()
    print('Owned embedded public listener UI and forwarding: passed')


if __name__ == '__main__':
    main()
