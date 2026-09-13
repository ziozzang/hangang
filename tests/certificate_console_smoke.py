#!/usr/bin/env python3
"""Owned issuer -> status manifest -> native UDS API -> management UI fixture."""
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get('HANGANG_BIN', ROOT / 'target/x86_64-unknown-linux-gnu/release/hangang'))
TOKEN = 'owned-certificate-console-fixture'

def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]

def main():
    children = []
    with tempfile.TemporaryDirectory(prefix='hangang-cert-ui-') as directory:
        folder = Path(directory)
        output = folder / 'issued'
        generation = output / 'generation-fixture'
        generation.mkdir(parents=True, mode=0o700)
        output.chmod(0o700)
        (folder / 'account').mkdir(mode=0o700)
        (folder / 'sockets').mkdir(mode=0o700)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(generation / 'key.pem'), '-out', str(generation / 'cert.pem'),
                        '-days', '90', '-subj', '/CN=example.test',
                        '-addext', 'subjectAltName=DNS:example.test,DNS:www.example.test'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for file in generation.iterdir(): file.chmod(0o600)
        (output / 'current').symlink_to(generation.name)
        issuer = folder / 'issuer.json'
        issuer.write_text(json.dumps({'domains': ['example.test', 'www.example.test'],
                                     'directory': 'https://127.0.0.1:9/directory',
                                     'account_path': str(folder / 'account/account.json'),
                                     'challenge': 'http-01', 'output_directory': str(output)}))
        issuer.chmod(0o600)
        public, admin, challenge = port(), port(), port()
        config = folder / 'config.json'
        config.write_text(json.dumps({'http': [], 'tcp': [], 'certificates': [{
            'id': 'managed-fixture', 'hosts': ['example.test', 'www.example.test'],
            'cert_file': str(output / 'current/cert.pem'),
            'key_file': str(output / 'current/key.pem'),
            'issuer_status_file': str(output / 'issuer-status.json')
        }]}))
        config.chmod(0o600)
        def launch(binary, args):
            child = subprocess.Popen([str(BIN.with_name(binary)), *args],
                                     env={**os.environ, 'HANGANG_ADMIN_TOKEN': TOKEN},
                                     stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            children.append(child)
            return child
        def api(method, path, document=None, revision=None):
            headers = {'Authorization': 'Bearer ' + TOKEN}
            if document is not None: headers['Content-Type'] = 'application/json'
            if revision is not None: headers['If-Match'] = '"' + str(revision) + '"'
            conn = http.client.HTTPConnection('127.0.0.1', admin, timeout=5)
            try:
                conn.request(method, path, json.dumps(document) if document is not None else None, headers)
                result = conn.getresponse(); body = result.read()
                if result.status != 200: raise RuntimeError(f'fixture API status {result.status}')
                return json.loads(body)
            finally: conn.close()
        def handshake():
            context = ssl.create_default_context(cafile=str(generation / 'cert.pem'))
            with socket.create_connection(('127.0.0.1', public), timeout=2) as raw:
                with context.wrap_socket(raw, server_hostname='example.test'): pass
        try:
            issuer_child = launch('hangang-acme-issuer', ['--config', str(issuer), '--http-listen', f'127.0.0.1:{challenge}'])
            for _ in range(100):
                if issuer_child.poll() is not None: raise RuntimeError(issuer_child.stderr.read().decode())
                if (output / 'issuer-status.json').exists(): break
                time.sleep(.05)
            else: raise RuntimeError('issuer manifest readiness timeout')
            assert json.loads((output / 'issuer-status.json').read_text())['phase'] == 'ready'
            assert not (folder / 'account/account.json').exists(), 'restored pair must not register an account'
            launch('hangang', ['--config', str(config), '--listen', f'127.0.0.1:{public}', '--config-tls',
                              '--admin-socket', str(folder / 'sockets/admin.sock'), '--threads', '2', '--lua-workers', '1'])
            launch('hangang-admin-gateway', ['--listen', f'127.0.0.1:{admin}', '--admin-socket', str(folder / 'sockets/admin.sock')])
            for _ in range(100):
                try:
                    inventory = api('GET', '/v1/certificates')
                    break
                except (OSError, RuntimeError): time.sleep(.05)
            else: raise RuntimeError('native management readiness timeout')
            entry = inventory['certificates'][0]
            assert entry['source'] == 'standalone_acme' and entry['renewal']['state'] == 'ready'
            assert entry['read_state'] == 'ok' and len(entry['san_dns']) == 2
            handshake()
            document = api('GET', '/v1/config')
            document['certificates'][0]['enabled'] = False
            document = api('PUT', '/v1/config', document, document['revision'])
            assert api('GET', '/v1/certificates')['certificates'][0]['tls_binding'] == 'disabled'
            try: handshake()
            except (ssl.SSLError, ConnectionError): pass
            else: raise AssertionError('disabled certificate still accepts a new handshake')
            document['certificates'][0]['enabled'] = True
            api('PUT', '/v1/config', document, document['revision'])
            handshake()
            subprocess.run(['npx', 'playwright', 'test', 'tests/actual-server.spec.js', 'tests/certificate-actual.spec.js', '--trace=off', '--workers=1'], cwd=ROOT / 'web',
                           env={**os.environ, 'HANGANG_ACTUAL_BASE': f'http://127.0.0.1:{admin}',
                                'HANGANG_ACTUAL_TOKEN': TOKEN, 'HANGANG_CERT_ACTUAL': '1'}, check=True)
            print('PASS restored issuer status without CA contact; UDS inventory; TLS certificate deactivate/reactivate; actual UI')
        finally:
            for child in reversed(children):
                child.terminate()
                try: child.wait(timeout=5)
                except subprocess.TimeoutExpired: child.kill(); child.wait()
                child.stderr.close()

if __name__ == '__main__': main()
