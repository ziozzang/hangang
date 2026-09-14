#!/usr/bin/env python3
"""Owned loopback demonstration of narrow node observation and token withdrawal."""
from contextlib import ExitStack
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
BINARY = Path(os.environ.get('HANGANG_BINARY', ROOT / 'target/debug/hangang')).resolve()


def replace_private(path, value):
    temporary = path.with_suffix('.new')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'w') as output:
        output.write(value)
    temporary.replace(path)


def stop(child):
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()


def unused_ports():
    with socket.socket() as public, socket.socket() as admin:
        public.bind(('127.0.0.1', 0))
        admin.bind(('127.0.0.1', 0))
        return public.getsockname()[1], admin.getsockname()[1]


def main():
    with ExitStack() as stack:
        folder = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='hangang-observer-')))
        configuration = folder / 'hangang.json'
        configuration.write_text('{"http":[],"tcp":[]}')
        observer_file = folder / 'observer.json'
        credential_file = folder / 'observer-token'
        admin_token, first_token, second_token = (secrets.token_hex(24) for _ in range(3))
        observer = {'node_id': 'owned-example-node', 'token_file': str(credential_file)}
        replace_private(observer_file, json.dumps(observer))
        replace_private(credential_file, first_token + '\n')
        public_port, admin_port = unused_ports()

        def start():
            log = stack.enter_context((folder / 'gateway.log').open('ab'))
            child = subprocess.Popen([
                str(BINARY), '--config', str(configuration),
                '--fleet-observer-config', str(observer_file),
                '--listen', f'127.0.0.1:{public_port}', '--admin', f'127.0.0.1:{admin_port}',
                '--threads', '2', '--lua-workers', '1', '--drain-seconds', '1',
            ], env={**os.environ, 'HANGANG_ADMIN_TOKEN': admin_token}, stdout=log, stderr=log)
            stack.callback(stop, child)
            return child

        def request(path, token=None, method='GET', body=None):
            connection = http.client.HTTPConnection('127.0.0.1', admin_port, timeout=3)
            headers = {} if token is None else {'Authorization': 'Bearer ' + token}
            try:
                connection.request(method, path, body=body, headers=headers)
                response = connection.getresponse()
                payload = response.read()
                assert len(payload) < 65536
                assert all(secret.encode() not in payload for secret in (admin_token, first_token, second_token))
                return response.status, payload, response.getheader('Cache-Control')
            finally:
                connection.close()

        def until(check):
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                if child.poll() is not None:
                    raise AssertionError('owned gateway exited before observation completed')
                try:
                    result = check()
                    if result:
                        return result
                except (OSError, http.client.HTTPException):
                    pass
                time.sleep(.05)
            raise AssertionError('owned observation deadline exceeded')

        def observe(token):
            status, payload, cache = request('/v1/fleet/observation', token)
            if status != 200:
                return None
            assert cache == 'no-store'
            value = json.loads(payload)
            assert value['schema_version'] == 1
            assert value['node_id'] == observer['node_id']
            assert value['configuration_source'] == 'file'
            assert value['revision'].isdigit()
            assert isinstance(value['ready'], bool)
            return value

        child = start()
        original = until(lambda: observe(first_token))
        assert request('/v1/fleet/observation')[0] == 401
        assert request('/v1/fleet/observation', admin_token)[0] == 401
        for path, method, body in [('/v1/config', 'GET', None), ('/v1/config', 'PUT', '{}'),
                                   ('/v1/fleet/observer-status', 'GET', None)]:
            assert request(path, first_token, method, body)[0] == 401

        replace_private(credential_file, second_token + '\n')
        rotated = until(lambda: observe(second_token))
        assert request('/v1/fleet/observation', first_token)[0] == 401
        assert rotated['instance_id'] == original['instance_id']
        assert rotated['observer_generation'] != original['observer_generation']

        replace_private(observer_file, '{invalid')
        until(lambda: request('/v1/fleet/observation', second_token)[0] in (401, 503))
        status, payload, _ = request('/v1/fleet/observer-status', admin_token)
        assert status == 200 and json.loads(payload)['available'] is False
        replace_private(observer_file, json.dumps(observer))
        until(lambda: observe(second_token))

        # A configured machine credential must never alias the powerful
        # process administrator credential, including during live reload.
        replace_private(credential_file, admin_token + '\n')
        until(lambda: request('/v1/fleet/observation', second_token)[0] in (401, 503))
        assert request('/v1/fleet/observation', admin_token)[0] in (401, 503)
        replace_private(credential_file, second_token + '\n')
        until(lambda: observe(second_token))

        replace_private(observer_file, json.dumps({**observer, 'node_id': 'different-node'}))
        until(lambda: request('/v1/fleet/observation', second_token)[0] in (401, 503))
        replace_private(observer_file, json.dumps(observer))
        until(lambda: observe(second_token))

        stop(child)
        child = start()
        restarted = until(lambda: observe(second_token))
        assert restarted['node_id'] == original['node_id']
        assert restarted['instance_id'] != original['instance_id']
        assert restarted['revision'] == original['revision']
        print('Node observer passed: narrow authority, live rotation, invalid-file withdrawal, recovery and stable identity across restart')


if __name__ == '__main__':
    main()
