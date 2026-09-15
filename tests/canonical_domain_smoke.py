#!/usr/bin/env python3
"""Owned gateway: canonical domain publication, exclusions and retirement."""
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import copy
import http.client
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import threading
import time

from http2_cookie_browser import free_ports, stop

BINARY = Path(os.environ.get('HANGANG_BINARY', 'target/debug/hangang')).resolve()


class Origin(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def handle_request(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        with self.server.lock:
            self.server.calls.append((self.command, self.path, body))
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    do_GET = do_HEAD = do_POST = handle_request


def request(port, method, path, body=None, headers=None):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    with ExitStack() as stack:
        root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='hangang-canonical-')))
        public, admin = free_ports(2)
        origin = ThreadingHTTPServer(('127.0.0.1', 0), Origin)
        origin.daemon_threads = True
        origin.lock, origin.calls = threading.Lock(), []
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        stack.callback(origin.server_close)
        stack.callback(origin.shutdown)
        policy = {'host': 'example.test', 'scheme': 'https', 'status': 302,
                  'path_prefixes': ['/wp-login.php', '/wp-admin'],
                  'exclude_path_prefixes': ['/wp-admin/admin-ajax.php', '/wp-admin/admin-post.php'],
                  'methods': ['GET', 'HEAD']}
        config = {'http': [{'id': 'site', 'hosts': ['example.test', 'www.example.test'],
                           'backends': [f'http://127.0.0.1:{origin.server_port}'],
                           'canonical_domain': policy}], 'tcp': []}
        path = root / 'config.json'
        path.write_text(json.dumps(config))
        token = secrets.token_hex(24)
        log = stack.enter_context((root / 'gateway.log').open('wb'))
        child = subprocess.Popen([str(BINARY), '--config', str(path), '--listen', f'127.0.0.1:{public}',
                                  '--admin', f'127.0.0.1:{admin}', '--threads', '2', '--lua-workers', '1'],
                                 env={**os.environ, 'HANGANG_ADMIN_TOKEN': token}, stdout=log, stderr=log)
        stack.callback(stop, child)
        auth = {'Authorization': 'Bearer ' + token}
        deadline = time.monotonic() + 15
        while True:
            require(child.poll() is None, 'owned gateway failed startup')
            try:
                status, _, _ = request(admin, 'GET', '/v1/status', headers=auth)
                if status == 200:
                    break
            except OSError:
                pass
            require(time.monotonic() < deadline, 'owned gateway readiness deadline')
            time.sleep(.05)

        def current():
            status, headers, body = request(admin, 'GET', '/v1/config', headers=auth)
            require(status == 200, 'config GET failed')
            return headers['etag'], json.loads(body)

        def publish(document, etag):
            return request(admin, 'PUT', '/v1/config', json.dumps(document),
                           {**auth, 'Content-Type': 'application/json', 'If-Match': etag})[0]

        def probe(method, path, redirect, host='www.example.test', body=None):
            before = len(origin.calls)
            status, headers, received = request(public, method, path, body, {'Host': host})
            require(status == (302 if redirect else 200), f'{method} {path}: unexpected status {status}')
            if redirect:
                require(headers.get('location') == 'https://example.test' + path, 'raw redirect target changed')
                require(len(origin.calls) == before, 'redirect reached the origin')
            else:
                require(len(origin.calls) == before + 1, 'bypass did not reach origin exactly once')
                if body:
                    require(received == body.encode(), 'POST body changed')

        probe('GET', '/wp-login.php?redirect_to=%2Fwp-admin%2F&x=1&x=2', True)
        probe('HEAD', '/wp-admin/', True)
        probe('GET', '/wp-admin/edit.php?post_type=page', True)
        probe('GET', '/wp-admin', True)
        for excluded in ['/wp-admin/admin-ajax.php?action=a', '/wp-admin/admin-post.php',
                         '/wp-admin/admin-ajax.php/path-info', '/wp-adminx', '/wp-login.phpx', '/']:
            probe('GET', excluded, False)
        probe('POST', '/wp-login.php', False, body='log=owned&pwd=synthetic')
        probe('GET', '/wp-login.php', False, host='example.test')

        etag, original = current()
        invalid = copy.deepcopy(original)
        invalid['http'][0]['canonical_domain']['host'] = 'outside.test'
        require(publish(invalid, etag) == 422, 'off-group destination did not return validation error')
        require(current() == (etag, original), 'invalid publication changed live state')
        disabled = copy.deepcopy(original)
        disabled['http'][0]['canonical_domain']['enabled'] = False
        require(publish(disabled, etag) == 200, 'disable publication failed')
        probe('GET', '/wp-login.php', False)
        etag, disabled = current()
        require(disabled['http'][0]['canonical_domain']['host'] == 'example.test', 'disable lost policy')
        disabled['http'][0]['canonical_domain']['enabled'] = True
        require(publish(disabled, etag) == 200, 'reactivation failed')
        probe('GET', '/wp-login.php', True)
        etag, restored = current()
        del restored['http'][0]['canonical_domain']
        require(publish(restored, etag) == 200, 'policy removal failed')
        probe('GET', '/wp-login.php', False)
        print('Owned canonical domain: redirects, raw queries, origin bypass, exclusions, POST body, '
              'no apex loop, rejected publication and dynamic disable/reactivate/remove passed')


if __name__ == '__main__':
    main()
