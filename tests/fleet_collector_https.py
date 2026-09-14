#!/usr/bin/env python3
"""Owned HTTPS peers: identity/TLS failures never become fresh fleet evidence."""
from contextlib import ExitStack
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get('HANGANG_BINARY', ROOT / 'target/debug/hangang')).resolve()


def private_write(path, content):
    temporary = path.with_name(path.name + '.new')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'w') as output:
        output.write(content)
    temporary.replace(path)


def stop(child):
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()


def ports(count):
    held = [socket.socket() for _ in range(count)]
    try:
        for item in held:
            item.bind(('127.0.0.1', 0))
        return [item.getsockname()[1] for item in held]
    finally:
        for item in held:
            item.close()


def certificate(root, name):
    cert, key = root / (name + '.pem'), root / (name + '.key')
    ca, ca_key = root / (name + '-ca.pem'), root / (name + '-ca.key')
    csr, extensions = root / (name + '.csr'), root / (name + '.extensions')
    subprocess.run([
        'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=Owned fleet test CA', '-addext', 'basicConstraints=critical,CA:TRUE',
        '-keyout', str(ca_key), '-out', str(ca),
    ], check=True, capture_output=True, timeout=20)
    subprocess.run([
        'openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost',
        '-keyout', str(key), '-out', str(csr),
    ], check=True, capture_output=True, timeout=20)
    extensions.write_text('basicConstraints=critical,CA:FALSE\n'
                          'keyUsage=critical,digitalSignature,keyEncipherment\n'
                          'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n')
    subprocess.run([
        'openssl', 'x509', '-req', '-in', str(csr), '-CA', str(ca), '-CAkey', str(ca_key),
        '-CAcreateserial', '-days', '1', '-extfile', str(extensions), '-out', str(cert),
    ], check=True, capture_output=True, timeout=20)
    ca.chmod(0o600)
    ca_key.chmod(0o600)
    cert.chmod(0o600)
    key.chmod(0o600)
    return ca, cert, key


def main():
    with ExitStack() as stack:
        root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='hangang-fleet-https-')))
        ca, cert, key = certificate(root, 'trusted')
        wrong_ca, _, _ = certificate(root, 'unrelated')
        trusted = ssl.create_default_context(cafile=str(ca))
        listeners = ports(8)
        children = []
        credentials = []

        def start(folder, public, admin, extra):
            folder.mkdir(mode=0o700)
            state = folder / 'hangang.json'
            private_write(state, '{"http":[],"tcp":[]}')
            token = secrets.token_hex(24)
            credentials.append(token)
            log = stack.enter_context((folder / 'gateway.log').open('wb'))
            child = subprocess.Popen([
                str(BINARY), '--config', str(state), '--listen', f'127.0.0.1:{public}',
                '--admin', f'127.0.0.1:{admin}', '--threads', '2', '--lua-workers', '1',
                '--drain-seconds', '1', *extra,
            ], env={**os.environ, 'HANGANG_ADMIN_TOKEN': token}, stdout=log, stderr=log)
            stack.callback(stop, child)
            children.append(child)
            return token

        def request(port, path, token, tls=False):
            if tls:
                client = http.client.HTTPSConnection('localhost', port, context=trusted, timeout=3)
            else:
                client = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
            try:
                client.request('GET', path, headers={'Authorization': 'Bearer ' + token})
                reply = client.getresponse()
                body = reply.read()
                assert len(body) < 65536
                assert all(value.encode() not in body for value in credentials)
                return reply.status, json.loads(body), reply.getheader('Cache-Control')
            finally:
                client.close()

        def until(check, seconds=15):
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                assert all(child.poll() is None for child in children), 'owned gateway exited'
                try:
                    result = check()
                    if result:
                        return result
                except (OSError, http.client.HTTPException):
                    pass
                time.sleep(.1)
            raise AssertionError('owned collector observation deadline exceeded')

        peers = []
        source_tokens = []
        for index, actual_id in enumerate(('good-edge', 'different-edge', 'tls-edge')):
            token = secrets.token_hex(24)
            credentials.append(token)
            token_file, config_file = root / f'peer-{index}.token', root / f'peer-{index}.json'
            private_write(token_file, token + '\n')
            private_write(config_file, json.dumps({'node_id': actual_id, 'token_file': str(token_file)}))
            admin = listeners[index * 2 + 1]
            start(root / f'node-{index}', listeners[index * 2], admin, [
                '--admin-tls-cert', str(cert), '--admin-tls-key', str(key),
                '--fleet-observer-config', str(config_file),
            ])
            until(lambda: request(admin, '/v1/fleet/observation', token, True)[0] == 200)
            copied_token = root / f'collector-peer-{index}.token'
            private_write(copied_token, token + '\n')
            source_tokens.append(token_file)
            peers.append({
                'node_id': 'expected-edge' if index == 1 else actual_id,
                'endpoint': f'https://localhost:{admin}', 'token_file': str(copied_token),
                'ca_file': str(wrong_ca if index == 2 else ca),
            })
        inventory = root / 'inventory.json'
        private_write(inventory, json.dumps({'peers': peers}))
        admin_token = start(root / 'collector', listeners[6], listeners[7], [
            '--fleet-inventory-config', str(inventory),
        ])

        def snapshot():
            status, value, cache = request(listeners[7], '/v1/fleet/observations', admin_token)
            assert status == 200 and cache == 'no-store'
            return value

        def classified():
            value = snapshot()
            rows = {row['node_id']: row for row in value['nodes']}
            if len(rows) != 3:
                return None
            if (rows['good-edge']['condition'], rows['expected-edge']['condition'], rows['tls-edge']['condition']) != (
                'fresh', 'identity_mismatch', 'unavailable',
            ):
                return None
            return value

        initial = until(classified)
        assert initial['configured'] and initial['available']
        assert initial['expected_nodes'] == 3 and initial['fresh_nodes'] == 1
        rows = {row['node_id']: row for row in initial['nodes']}
        good = rows['good-edge']['observation']
        assert good['node_id'] == 'good-edge'
        assert rows['expected-edge']['observation'] is None
        assert rows['tls-edge']['observation'] is None

        if os.environ.get('HANGANG_FLEET_BROWSER') == '1':
            artifacts = tempfile.mkdtemp(prefix='hangang-fleet-browser-artifacts-')
            try:
                subprocess.run([
                    'npx', 'playwright', 'test', 'tests/actual-fleet.spec.js', '--output', artifacts,
                ], cwd=ROOT / 'web', env={
                    **os.environ, 'HANGANG_UI_TEST_PORT': str(ports(1)[0]),
                    'HANGANG_FLEET_ACTUAL_BASE': f'http://127.0.0.1:{listeners[7]}',
                    'HANGANG_FLEET_ACTUAL_TOKEN': admin_token,
                }, check=True)
            except BaseException:
                print(f'Owned fleet browser failure artifacts retained at {artifacts}', flush=True)
                raise
            else:
                shutil.rmtree(artifacts)

        # Rotate only the remote credential. The collector retains its old
        # credential so its next scheduled request fails after a prior success.
        private_write(source_tokens[0], secrets.token_hex(24) + '\n')

        def failed_after_success():
            value = snapshot()
            row = next(row for row in value['nodes'] if row['node_id'] == 'good-edge')
            if row['condition'] != 'unavailable':
                return None
            assert value['fresh_nodes'] == 0
            assert row['observation'] == good
            return value

        until(failed_after_success, seconds=45)
        private_write(inventory, '{invalid')
        until(lambda: not snapshot()['available'])
        private_write(inventory, '{"peers":[]}')
        until(lambda: snapshot()['available'] and snapshot()['nodes'] == [])
        print('Fleet HTTPS passed: trusted peer, identity mismatch, untrusted certificate, historical failed peer, invalid roster withdrawal and removal')


if __name__ == '__main__':
    main()
