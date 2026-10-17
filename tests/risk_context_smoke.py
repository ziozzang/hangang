#!/usr/bin/env python3
"""Hopae risk context end to end (Hopae ADR-0023): real Sumunjang, Hopae, Hangang.

Sumunjang (with `include_evidence`, observe mode) answers the gRPC Network
service over mTLS; Hangang maps its evidence to a level, signs
`x-hopae-risk-context` and sends it on the Hopae verify call of a route with
`auth.risk_context`; Hopae (built with `test-hooks`, from feat/risk-step-up)
applies `apps[].risk`. The client address picks the evidence:

- 192.0.2.10 is allowlisted: `low`, allowed.
- 192.0.2.20 matches nothing (policy default; `--risk-unlisted-elevated`):
  `elevated`, so `/admin` requires a step-up (`401 step_up_required`).
- 192.0.2.30 is blocked while the policy is observed (enforcement would
  deny): `high`, `403 risk_denied`.
- 192.0.2.50 matches nothing (`elevated`: `/public` is allowed) until it hits
  the honeypot path; its Sumunjang risk stage then becomes `suspicious`
  (`--risk-high-stage suspicious`): `high`, `403 risk_denied` on `/public`.
- Zones: 192.0.2.10 is in Sumunjang zone `corp-vpn`; Hopae denies `/internal`
  outside it (`outside_zones`), so the `zones` claim decides.

A client-supplied `x-hopae-risk-context` never reaches Hopae or the upstream,
and the upstream never sees the header. Run with SUMUNJANG_BIN (guard-server,
`sumunjang`), HOPAE_BIN (hopae with test-hooks) and HANGANG_BIN_DIR (default
target/debug). No operational credentials.
"""
import http.server, json, os, pathlib, secrets, socket, subprocess, tempfile, threading, time, urllib.request, urllib.error

ROOT = pathlib.Path(__file__).resolve().parents[1]
BIN = pathlib.Path(os.environ.get('HANGANG_BIN_DIR', ROOT / 'target/debug'))
SUMUNJANG = pathlib.Path(os.environ['SUMUNJANG_BIN'])
HOPAE = pathlib.Path(os.environ['HOPAE_BIN'])
RISK_KEY = secrets.token_hex(32)


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def run(*argv, cwd):
    subprocess.run(argv, check=True, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def certificate(root, name, ca=None, usage=None):
    run('openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', f'{name}.key', '-out', f'{name}.csr', '-subj', f'/CN={name}', cwd=root)
    if ca:
        (root / f'{name}.ext').write_text(f'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage={usage}\nsubjectAltName=DNS:sumunjang.example.test,IP:127.0.0.1\n')
        run('openssl', 'x509', '-req', '-in', f'{name}.csr', '-CA', f'{ca}.pem', '-CAkey', f'{ca}.key', '-CAcreateserial', '-days', '1', '-extfile', f'{name}.ext', '-out', f'{name}.pem', cwd=root)
    else:
        run('openssl', 'req', '-x509', '-key', f'{name}.key', '-in', f'{name}.csr', '-days', '1', '-out', f'{name}.pem', '-addext', 'basicConstraints=critical,CA:TRUE', cwd=root)


def call(url, method='GET', body=None, headers=None):
    req = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(), method=method,
                                 headers={'Content-Type': 'application/json', **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def eventually(check, what, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except OSError:
            pass
        time.sleep(.1)
    raise AssertionError(what)


class Origin(http.server.BaseHTTPRequestHandler):
    seen = []

    def do_GET(self):
        Origin.seen.append({k.lower(): v for k, v in self.headers.items()})
        self.send_response(200)
        self.send_header('content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'origin')

    def log_message(self, *args):
        pass


def main():
    children = []
    with tempfile.TemporaryDirectory(prefix='hangang-risk-context-') as tmp:
        root = pathlib.Path(tmp)
        root.chmod(0o700)
        for name, ca, usage in [('ca', None, None), ('server', 'ca', 'serverAuth'), ('client', 'ca', 'clientAuth')]:
            certificate(root, name, ca, usage)
        admin_token, collector = secrets.token_hex(24), secrets.token_hex(24)
        gateway_key = secrets.token_hex(32)
        env = {**os.environ, 'HANGANG_GUARD_ADMIN_TOKEN': admin_token, 'HANGANG_GUARD_COLLECTOR_TOKEN': collector,
               'HANGANG_ADMIN_TOKEN': secrets.token_hex(32), 'RISK_CONTEXT_KEY': RISK_KEY, 'HOPAE_GATEWAY_KEY': gateway_key,
               'HOPAE_TEST_MOCK_SECRET': secrets.token_hex(16)}
        log = open(root / 'servers.log', 'wb')
        origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        try:
            # Sumunjang: observe mode, 192.0.2.10 allowlisted, 192.0.2.30 blocked.
            s_http, s_native, s_grpc = port(), port(), port()
            (root / 'bootstrap.json').write_text('{"mode":"observe","allow":["192.0.2.10/32","192.0.2.40/32"]}')
            children.append(subprocess.Popen([str(SUMUNJANG), '--bootstrap-policy', str(root / 'bootstrap.json'), '--listen', f'127.0.0.1:{s_http}',
                                              '--database', str(root / 'policy.sqlite3'), '--decision-listen', f'127.0.0.1:{s_native}',
                                              '--grpc-listen', f'127.0.0.1:{s_grpc}', '--decision-tls-cert', str(root / 'server.pem'),
                                              '--decision-tls-key', str(root / 'server.key'), '--decision-client-ca', str(root / 'ca.pem')],
                                             env=env, stdout=log, stderr=log))
            sumunjang = f'http://127.0.0.1:{s_http}'
            eventually(lambda: call(sumunjang + '/healthz')[0] == 200, 'sumunjang readiness')
            status, _, body = call(sumunjang + '/v1/blocks', 'POST', {'network': '192.0.2.30/32', 'expires_at': int(time.time()) + 600, 'reason': 'manual'}, {'Authorization': 'Bearer ' + admin_token})
            assert status in (200, 201), (status, body)
            admin_auth = {'Authorization': 'Bearer ' + admin_token}
            revision = json.loads(call(sumunjang + '/v1/zones', headers=admin_auth)[2])['revision']
            status, _, body = call(sumunjang + '/v1/zones', 'POST', {'expected_revision': revision, 'zone': {'id': 'corp-vpn', 'prefixes': ['192.0.2.10/32']}}, admin_auth)
            assert status in (200, 201), (status, body)

            # Hopae: the application and its risk rules; a session for a user.
            h_portal, h_gateway, h_hooks = port(), port(), port()
            hopae_config = {
                'state_dir': str(root / 'hopae'), 'listen': {'portal': f'127.0.0.1:{h_portal}', 'gateway': f'127.0.0.1:{h_gateway}'},
                'portal': {'public_url': 'https://auth.example.test'},
                'gateway': {'kind': 'hangang', 'caller_key_env': 'HOPAE_GATEWAY_KEY'},
                'cookie': {'name': '__Host-hopae', 'secure': True},
                'trusted_proxies': ['127.0.0.1/32'],
                'risk': {'context_key_env': 'RISK_CONTEXT_KEY'},
                'apps': [{'app_id': 'app', 'hosts': ['app.example.test'], 'binding': {'ip': 'off', 'ua': 'off'},
                          'risk': {'rules': [
                              {'path_prefix': '/admin', 'when': {'level_at_least': 'elevated'}, 'then': {'step_up': {'aal': 2, 'max_age_secs': 600}}},
                              {'path_prefix': '/internal', 'when': {'outside_zones': ['corp-vpn']}, 'then': 'deny'},
                              {'when': {'level_at_least': 'high'}, 'then': 'deny'}]}}],
                'providers': [{'provider_id': 'mock', 'kind': 'oidc', 'client_id': 'c', 'client_secret_env': 'HOPAE_TEST_MOCK_SECRET',
                               'issuer': 'http://127.0.0.1:1', 'allow_private_endpoints': True}],
            }
            (root / 'hopae.json').write_text(json.dumps(hopae_config))
            children.append(subprocess.Popen([str(HOPAE), '--config', str(root / 'hopae.json')],
                                             env={**env, 'HOPAE_TEST_HOOKS': f'127.0.0.1:{h_hooks}'}, stdout=log, stderr=log))
            hooks = f'http://127.0.0.1:{h_hooks}'
            eventually(lambda: call(f'http://127.0.0.1:{h_portal}/healthz')[0] == 200, 'hopae readiness')
            assert call(hooks + '/bulk/users', 'POST', {'n': 1})[0] == 200
            status, _, body = call(hooks + '/sessions/legacy', 'POST', {'user_id': 'u_blk000000001', 'host': 'app.example.test'})
            assert status == 200, body
            handle = json.loads(body)['handle']

            # Hangang: the protected route sends the risk context.
            public, admin = port(), port()
            route = {'id': 'app', 'hosts': ['app.example.test'], 'backends': [f'http://127.0.0.1:{origin.server_port}'],
                     'auth': {'url': f'http://127.0.0.1:{h_gateway}/_hopae/verify',
                              'request_headers': ['cookie', 'user-agent', 'accept', 'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site'],
                              'response_headers': ['x-forwarded-user'], 'forward_response': True,
                              'static_request_headers': {'x-hopae-gateway-key': {'env': 'HOPAE_GATEWAY_KEY'}},
                              'risk_context': True}}
            (root / 'config.json').write_text(json.dumps({'http': [route], 'tcp': []}))
            children.append(subprocess.Popen([str(BIN / 'hangang'), '--config', str(root / 'config.json'), '--listen', f'127.0.0.1:{public}',
                                              '--admin', f'127.0.0.1:{admin}', '--threads', '2', '--lua-workers', '1',
                                              '--trusted-proxy-cidrs', '127.0.0.1/32',
                                              '--guard-url', sumunjang, '--guard-decision-tcp', f'127.0.0.1:{s_grpc}', '--guard-decision-grpc',
                                              '--guard-decision-server-name', 'sumunjang.example.test', '--guard-decision-ca', str(root / 'ca.pem'),
                                              '--guard-decision-cert', str(root / 'client.pem'), '--guard-decision-key', str(root / 'client.key'),
                                              '--guard-timeout-ms', '1000',
                                              '--risk-context-key-env', 'RISK_CONTEXT_KEY', '--risk-unlisted-elevated',
                                              '--risk-high-stage', 'suspicious', '--guard-honeypot-path', '/trap'],
                                             env=env, stdout=log, stderr=log))
            gateway = f'http://127.0.0.1:{public}'
            eventually(lambda: call(f'http://127.0.0.1:{admin}/v1/status', headers={'Authorization': 'Bearer ' + env['HANGANG_ADMIN_TOKEN']})[0] == 200, 'hangang readiness')

            def get(path, client, extra=None):
                return call(gateway + path, headers={'Host': 'app.example.test', 'X-Forwarded-For': client, 'X-Forwarded-Proto': 'https',
                                                     'X-Forwarded-Port': '443', 'Accept': 'application/json',
                                                     'Cookie': f'__Host-hopae={handle}', **(extra or {})})

            # Low: allowed, the upstream never sees the header.
            status, _, body = get('/admin/x', '192.0.2.10', {'x-hopae-risk-context': 'v1.forged.forged'})
            assert status == 200 and body == b'origin', (status, body)
            assert all('x-hopae-risk-context' not in h for h in Origin.seen), Origin.seen
            # Elevated: a step-up on /admin, nothing elsewhere.
            if os.environ.get('SMOKE_DEBUG'):
                print([l for l in call(f'http://127.0.0.1:{admin}/metrics', headers={'Authorization': 'Bearer ' + env['HANGANG_ADMIN_TOKEN']})[2].decode().splitlines() if 'risk' in l])
            status, _, body = get('/admin/x', '192.0.2.20')
            assert status == 401 and b'step_up_required' in body, (status, body)
            status, _, _ = get('/public', '192.0.2.20')
            assert status == 200
            # High: denied by Hopae's risk rule (observe mode lets the request through Hangang).
            status, headers, body = get('/public', '192.0.2.30')
            assert status == 403 and b'risk_denied' in body, (status, body)
            # A client-chosen context never replaces Hangang's: still denied.
            status, _, _ = get('/public', '192.0.2.30', {'x-hopae-risk-context': 'v1.eyJsZXZlbCI6ImxvdyJ9.AAAA'})
            assert status == 403
            # Zones: inside corp-vpn /internal is allowed, outside it is denied.
            status, _, body = get('/internal/x', '192.0.2.10')
            assert status == 200, (status, body)
            status, _, body = get('/internal/x', '192.0.2.40')
            assert status == 403 and b'risk_denied' in body, (status, body)
            # Risk stage: 192.0.2.50 is elevated (allowed on /public) until a
            # honeypot hit makes its stage suspicious, which maps to high.
            status, _, body = get('/public', '192.0.2.50')
            assert status == 200, (status, body)
            get('/trap', '192.0.2.50')
            eventually(lambda: get('/public', '192.0.2.50')[0] == 403, 'a suspicious stage is high')
            metrics = call(f'http://127.0.0.1:{admin}/metrics', headers={'Authorization': 'Bearer ' + env['HANGANG_ADMIN_TOKEN']})[2].decode()
            for level in ['low', 'elevated', 'high']:
                assert f'hangang_risk_context_sent_total{{level="{level}"}} 0' not in metrics, metrics
            print('PASS: Sumunjang evidence becomes a signed risk context on Hopae verify: low allowed, elevated stepped up on /admin, high denied, zones and the risk stage decide; client copies stripped and never upstream.')
        finally:
            for child in reversed(children):
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait()
            origin.shutdown()
            log.close()
            if os.environ.get('SMOKE_DEBUG'):
                print((root / 'servers.log').read_text(errors='replace')[-6000:])


if __name__ == '__main__':
    main()
