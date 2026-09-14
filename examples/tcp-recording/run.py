#!/usr/bin/env python3
"""Owned loopback example: a TCP recording policy changes while a stream is open."""
from contextlib import ExitStack
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

ROOT = Path(__file__).resolve().parents[2]
BINARY = Path(os.environ.get('HANGANG_BINARY', ROOT / 'target/debug/hangang')).resolve()


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        payload = bytearray()
        while chunk := self.request.recv(4096):
            payload.extend(chunk)
        self.request.sendall(payload)


class Origin(socketserver.ThreadingTCPServer):
    daemon_threads = True


def ports(count):
    held = []
    try:
        for _ in range(count):
            item = socket.socket()
            item.bind(('127.0.0.1', 0))
            held.append(item)
        return [item.getsockname()[1] for item in held]
    finally:
        for item in held:
            item.close()


def stop_child(child):
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()


def main():
    token = secrets.token_hex(24)
    origin = Origin(('127.0.0.1', 0), Echo)
    tcp_port, public_port, admin_port = ports(3)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    child = None
    held = None
    try:
        with ExitStack() as stack:
            directory = stack.enter_context(tempfile.TemporaryDirectory(prefix='hangang-tcp-recording-'))
            folder = Path(directory)
            state = folder / 'hangang.json'
            state.write_text(json.dumps({'http': [], 'tcp': [{
                'id': 'echo', 'listen': f'127.0.0.1:{tcp_port}',
                'backends': [f'127.0.0.1:{origin.server_address[1]}'],
            }]}))
            with (folder / 'gateway.log').open('wb') as log:
                child = subprocess.Popen([
                    str(BINARY), '--config', str(state), '--listen', f'127.0.0.1:{public_port}',
                    '--admin', f'127.0.0.1:{admin_port}', '--threads', '2', '--lua-workers', '1',
                    '--drain-seconds', '1',
                ], env={**os.environ, 'HANGANG_ADMIN_TOKEN': token}, stdout=log, stderr=log)
                stack.callback(stop_child, child)

                def api(path, method='GET', document=None, revision=None):
                    connection = http.client.HTTPConnection('127.0.0.1', admin_port, timeout=5)
                    headers = {'Authorization': 'Bearer ' + token}
                    if document is not None:
                        headers['Content-Type'] = 'application/json'
                        headers['If-Match'] = f'"{revision}"'
                    try:
                        connection.request(method, path, body=json.dumps(document) if document is not None else None,
                                           headers=headers)
                        reply = connection.getresponse()
                        body = reply.read()
                        assert reply.status == 200, (path, reply.status, body[:200])
                        return json.loads(body)
                    finally:
                        connection.close()

                def until(check):
                    deadline = time.monotonic() + 10
                    while True:
                        if child.poll() is not None:
                            raise RuntimeError('owned gateway exited')
                        try:
                            result = check()
                            if result:
                                return result
                        except (OSError, KeyError):
                            pass
                        if time.monotonic() >= deadline:
                            raise AssertionError('owned example condition timed out')
                        time.sleep(.025)

                def set_policy(policy):
                    current = api('/v1/config')
                    revision = current['revision']
                    current.setdefault('settings', {})['tcp_recent_recording'] = policy
                    api('/v1/config', 'PUT', current, revision)
                    return until(lambda: (new := api('/v1/config'))['revision'] > revision and new['revision'])

                def finish(connection, payload):
                    connection.shutdown(socket.SHUT_WR)
                    reply = bytearray()
                    while chunk := connection.recv(4096):
                        reply.extend(chunk)
                    assert reply == payload
                    connection.close()

                until(lambda: api('/v1/status')['state']['ready'])
                payload = b'owned TCP recording example'
                held = socket.create_connection(('127.0.0.1', tcp_port), timeout=5)
                held.sendall(payload)
                until(lambda: any(row['phase'] == 'forwarding' for row in
                                 api('/v1/connections/tcp/active')['records']))
                set_policy({'default_action': 'record', 'rules': [{
                    'id': 'omit-normal-echo', 'action': 'drop',
                    'match': {'route_ids': ['echo'], 'outcomes': ['eof']},
                }]})
                assert api('/v1/connections/tcp/active')['records'], 'active inventory must stay visible'
                finish(held, payload)
                held = None
                dropped = until(lambda: (batch := api('/v1/connections/tcp/recent')).get('filtered_total') == '1' and batch)
                assert dropped['records'] == [] and dropped['latest_event_id'] == '0'

                revision = set_policy(None)
                with socket.create_connection(('127.0.0.1', tcp_port), timeout=5) as connection:
                    connection.sendall(payload)
                    finish(connection, payload)
                recorded = until(lambda: (batch := api('/v1/connections/tcp/recent'))['records'] and batch)
                assert recorded['filtered_total'] == '1' and recorded['latest_event_id'] == '1'
                row = recorded['records'][0]
                assert row['event_id'] == '1' and row['policy_revision'] == str(revision)
                assert row['outcome'] == 'eof' and row['route_id'] == 'echo'
                assert row['bytes_upstream'] == row['bytes_downstream'] == str(len(payload))
                assert payload.decode() not in json.dumps(recorded)
                print('TCP example passed: live policy publication, active visibility, intentional omission, record-all restoration and exact byte counts')
    finally:
        if held is not None:
            held.close()
        if child is not None:
            stop_child(child)
        origin.shutdown()
        origin.server_close()


if __name__ == '__main__':
    main()
