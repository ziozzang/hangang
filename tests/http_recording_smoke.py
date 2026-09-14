#!/usr/bin/env python3
"""Own a gateway and origin, exercise embedded HTTP recording UI, then clean up."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from access_mode_smoke import ROOT, BINARY, call, free_port


def main():
    class Origin(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'owned-http-recording-origin'
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    origin = ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    origin.daemon_threads = True
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix='hangang-http-recording-') as directory:
            root = Path(directory)
            state = root / 'config.json'
            state.write_text(json.dumps({'http': [{'id': 'owned', 'backends': [f'http://127.0.0.1:{origin.server_port}']}]}))
            public, admin = free_port(), free_port()
            while public == admin:
                admin = free_port()
            token = secrets.token_hex(24)
            with (root / 'gateway.log').open('wb') as log:
                child = subprocess.Popen([
                    str(BINARY), '--config', str(state), '--listen', f'127.0.0.1:{public}',
                    '--admin', f'127.0.0.1:{admin}', '--threads', '2', '--lua-workers', '1', '--access-log',
                ], env={**os.environ, 'HANGANG_ADMIN_TOKEN': token, 'RUST_LOG': 'hangang::access=info'}, stdout=log, stderr=log)
                try:
                    for _ in range(200):
                        if child.poll() is not None:
                            raise RuntimeError('owned gateway exited before readiness')
                        try:
                            if call(admin, 'GET', '/v1/config', headers={'Authorization': f'Bearer {token}'})[0] == 200:
                                break
                        except OSError:
                            pass
                        time.sleep(.05)
                    else:
                        raise RuntimeError('owned gateway readiness deadline')
                    subprocess.run(['npx', 'playwright', 'test', 'http-recording-actual.spec.js', '--workers=1', '--reporter=line'],
                                   cwd=ROOT / 'web', check=True, env={**os.environ,
                                   'HANGANG_RECORDING_ACTUAL_BASE': f'http://127.0.0.1:{admin}',
                                   'HANGANG_RECORDING_ACTUAL_PUBLIC': f'http://127.0.0.1:{public}',
                                   'HANGANG_RECORDING_ACTUAL_TOKEN': token})
                    saved = json.loads(state.read_text())
                    assert saved['revision'] == 2
                    assert saved.get('settings', {}).get('http_recording') is None
                finally:
                    child.terminate()
                    try:
                        child.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=5)
            trace = (root / 'gateway.log').read_text()
            assert 'hidden-recording-fixture' not in trace
            assert 'query-recording-fixture' not in trace
            assert '/keep-recording-fixture' in trace
    finally:
        origin.shutdown()
        origin.server_close()
    print('Owned embedded HTTP recording UI and both outputs: passed')


if __name__ == '__main__':
    main()
