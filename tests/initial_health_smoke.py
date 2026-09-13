#!/usr/bin/env python3
"""Owned process qualification of first-check admission; no production traffic."""
import concurrent.futures
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time

from access_mode_smoke import BINARY, ROOT, call, free_port


def main():
    lock = threading.Lock()
    state = {"healthy": False, "probes": 0, "requests": 0}

    class Origin(BaseHTTPRequestHandler):
        def do_GET(self):
            with lock:
                if self.path == '/health':
                    state['probes'] += 1
                    status = 200 if state['healthy'] else 503
                else:
                    state['requests'] += 1
                    status = 200
            self.send_response(status)
            self.send_header('Content-Length', '0')
            self.end_headers()

        def log_message(self, *_args):
            pass

    origin = ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    child = None
    try:
        with tempfile.TemporaryDirectory(prefix='hangang-first-check-') as folder:
            config_path = Path(folder) / 'config.json'
            config_path.write_text(json.dumps({'http': [{
                'id': 'checked', 'path_prefix': '/',
                'backends': [f'http://127.0.0.1:{origin.server_port}'],
                'balance': {'active_health': {
                    'initial_state': 'checking', 'path': '/health',
                    'interval_ms': 200, 'timeout_ms': 100,
                    'healthy_statuses': [200], 'unhealthy_statuses': [503],
                    'healthy_successes': 2, 'unhealthy_http_failures': 1,
                    'unhealthy_tcp_failures': 1, 'unhealthy_timeouts': 1,
                }},
            }]}))
            public, admin = free_port(), free_port()
            headers = {'Authorization': 'Bearer owned-first-check-token'}
            with (Path(folder) / 'gateway.log').open('wb') as log:
                child = subprocess.Popen([
                    str(BINARY), '--config', str(config_path),
                    '--listen', f'127.0.0.1:{public}', '--admin', f'127.0.0.1:{admin}',
                    '--threads', '2', '--lua-workers', '1',
                ], env={**os.environ, 'HANGANG_ADMIN_TOKEN': 'owned-first-check-token'}, stdout=log, stderr=log)

                def wait_for(predicate, description):
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline:
                        assert child.poll() is None, 'owned gateway exited'
                        try:
                            if predicate():
                                return
                        except OSError:
                            pass
                        time.sleep(.02)
                    raise AssertionError(description)

                def row():
                    status, body = call(admin, 'GET', '/v1/operations', headers=headers)
                    assert status == 200
                    return json.loads(body)['rows'][0]

                wait_for(lambda: call(admin, 'GET', '/v1/config', headers=headers)[0] == 200, 'readiness')
                assert row()['initial_check_pending'] is True
                with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
                    statuses = list(executor.map(lambda _: call(public, 'GET', '/application')[0], range(100)))
                assert statuses == [503] * 100
                with lock:
                    assert state['requests'] == 0
                wait_for(lambda: row()['probe_observed'] is True, 'failed probe observed')
                assert row()['initial_check_pending'] is True
                with lock:
                    state['healthy'] = True
                wait_for(lambda: row()['available'], 'successful qualification')
                assert row()['initial_check_pending'] is False
                assert call(public, 'GET', '/application')[0] == 200

                def set_enabled(enabled):
                    status, body = call(admin, 'GET', '/v1/config', headers=headers)
                    assert status == 200
                    document = json.loads(body)
                    document['http'][0]['enabled'] = enabled
                    status, _ = call(admin, 'PUT', '/v1/config', document,
                                     {**headers, 'If-Match': f'"{document["revision"]}"'})
                    assert status == 200

                set_enabled(False)
                with lock:
                    state['healthy'] = False
                set_enabled(True)
                assert row()['initial_check_pending'] is True
                assert call(public, 'GET', '/application')[0] == 503
                with lock:
                    assert state['requests'] == 1
                    state['healthy'] = True
                wait_for(lambda: row()['available'], 'reactivation qualification')
                assert call(public, 'GET', '/application')[0] == 200
                subprocess.run(['npx', 'playwright', 'test', 'tests/initial-health-actual.spec.js'],
                               cwd=ROOT / 'web', env={**os.environ,
                                   'HANGANG_HEALTH_ACTUAL_BASE': f'http://127.0.0.1:{admin}'}, check=True)
                print(json.dumps({'fixture': 'owned-first-check', 'prequalification_requests': 100,
                                  'prequalification_origin_requests': 0,
                                  'failed_probe_does_not_qualify': True,
                                  'reenable_requires_fresh_qualification': True,
                                  'recovery_forwarding_verified': True,
                                  'native_editor_actual_browser_passed': 1,
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
