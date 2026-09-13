#!/usr/bin/env python3
"""Owned real-process TCP health and native administration qualification."""
import concurrent.futures
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
    origin = socket.socket()
    origin.bind(('127.0.0.1', 0))  # Reserved but not listening: connect must fail.
    origin_port = origin.getsockname()[1]
    stop = threading.Event()
    lock = threading.Lock()
    seen = []

    def serve():
        origin.settimeout(.1)
        while not stop.is_set():
            try:
                stream, _ = origin.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with stream:
                stream.settimeout(.5)
                try:
                    data = stream.recv(32)
                    if data:
                        with lock:
                            seen.append(data)
                        stream.sendall(b'echo:' + data)
                except OSError:
                    pass

    child = None
    worker = None
    try:
        with tempfile.TemporaryDirectory(prefix='hangang-tcp-health-') as folder:
            admin, public, tcp = free_port(), free_port(), free_port()
            path = Path(folder) / 'config.json'
            path.write_text(json.dumps({'tcp': [{
                'id': 'checked-tcp', 'listen': f'127.0.0.1:{tcp}',
                'backends': [f'127.0.0.1:{origin_port}'],
                'health': {'initial_state': 'checking', 'interval_ms': 200,
                           'timeout_ms': 100, 'healthy_successes': 2, 'unhealthy_failures': 1},
            }]}))
            with (Path(folder) / 'process.log').open('wb') as log:
                child = subprocess.Popen([str(BINARY), '--config', str(path), '--listen', f'127.0.0.1:{public}',
                                          '--admin', f'127.0.0.1:{admin}', '--threads', '2', '--lua-workers', '1'],
                                         env={**os.environ, 'HANGANG_ADMIN_TOKEN': 'owned-tcp-health-token'}, stdout=log, stderr=log)
                auth = {'Authorization': 'Bearer owned-tcp-health-token'}

                def wait_for(predicate):
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline:
                        assert child.poll() is None, 'gateway exited'
                        try:
                            if predicate():
                                return
                        except OSError:
                            pass
                        time.sleep(.02)
                    raise AssertionError('owned TCP fixture deadline')

                def row():
                    status, body = call(admin, 'GET', '/v1/operations', headers=auth)
                    assert status == 200
                    return json.loads(body)['rows'][0]

                def exchange(_=None):
                    with socket.create_connection(('127.0.0.1', tcp), timeout=2) as stream:
                        try:
                            stream.sendall(b'owned')
                            return stream.recv(32)
                        except ConnectionResetError:
                            return b''

                wait_for(lambda: call(admin, 'GET', '/v1/config', headers=auth)[0] == 200)
                assert row()['health_mode'] == 'active_tcp'
                assert row()['initial_check_pending'] is True
                with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
                    assert list(executor.map(exchange, range(100))) == [b''] * 100
                origin.listen(128)
                worker = threading.Thread(target=serve, daemon=True)
                worker.start()
                wait_for(lambda: row()['available'])
                assert row()['initial_check_pending'] is False
                for _ in range(20):
                    assert exchange() == b'echo:owned'
                with lock:
                    assert seen == [b'owned'] * 20
                subprocess.run(['npx', 'playwright', 'test', 'tests/tcp-health-actual.spec.js'], cwd=ROOT / 'web',
                               env={**os.environ, 'HANGANG_TCP_HEALTH_ACTUAL_BASE': f'http://127.0.0.1:{admin}'}, check=True)
                wait_for(lambda: row()['available'])
                assert exchange() == b'echo:owned'
                print(json.dumps({'fixture': 'owned-tcp-health', 'checking_connections_closed': 100,
                                  'application_messages_before_qualification': 0, 'healthy_echoes': 21,
                                  'actual_native_browser_passed': 1, 'performance_comparison': False}))
    finally:
        if child is not None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        stop.set()
        origin.close()
        if worker:
            worker.join(timeout=2)


if __name__ == '__main__':
    main()
