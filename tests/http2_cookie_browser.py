#!/usr/bin/env python3
"""Owned Chromium regression for HTTP/2 cookie crumbs translated to an HTTP/1 origin."""
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json, os, secrets, shutil, socket, subprocess, tempfile, threading, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get('HANGANG_BINARY', ROOT / 'target/debug/hangang')).resolve()
EXPECT = os.environ.get('HANGANG_COOKIE_EXPECT', 'pass')


def free_ports(count):
    held = [socket.socket() for _ in range(count)]
    try:
        for sock in held: sock.bind(('127.0.0.1', 0))
        return [sock.getsockname()[1] for sock in held]
    finally:
        for sock in held: sock.close()


def certificate(root):
    cert, key = root / 'localhost.pem', root / 'localhost.key'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
        '-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost',
        '-keyout',str(key),'-out',str(cert)], check=True, capture_output=True, timeout=20)
    cert.chmod(0o600); key.chmod(0o600)
    return cert, key


def cookie_names(handler):
    values = handler.headers.get_all('Cookie', [])
    return sorted({part.split('=', 1)[0].strip() for value in values for part in value.split(';') if '=' in part})


class Origin(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *_): pass
    def reply(self, status, value, cookies=()):
        body = json.dumps(value, separators=(',', ':')).encode()
        self.send_response(status)
        for cookie in cookies: self.send_header('Set-Cookie', cookie)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        names = cookie_names(self)
        if self.path == '/seed':
            return self.reply(200, {'seed': True}, (
                'wordpress_test_cookie=WP%20Cookie%20check; Path=/; Secure; SameSite=Lax',
                'wordpress_logged_in=owned-session; Path=/; Secure; HttpOnly; SameSite=Lax'))
        if self.path == '/account':
            ok = {'wordpress_sec','wordpress_pref'}.issubset(names)
            return self.reply(200 if ok else 401, {'cookie_names': names})
        self.reply(404, {})
    def do_POST(self):
        size = int(self.headers.get('Content-Length', '0')); body = self.rfile.read(size).decode()
        names = cookie_names(self)
        ok = self.path == '/login' and {'wordpress_test_cookie','wordpress_logged_in'}.issubset(names)
        self.reply(200 if ok else 403, {'method':'POST','body':body,'cookie_names':names,'set_cookie_count':2}, (
            'wordpress_sec=owned-sec; Path=/; Secure; HttpOnly; SameSite=Lax',
            'wordpress_pref=dashboard; Path=/; Secure; SameSite=Lax'))


def stop(child):
    if child.poll() is None:
        child.terminate()
        try: child.wait(timeout=10)
        except subprocess.TimeoutExpired: child.kill(); child.wait(timeout=5)


def main():
    if EXPECT not in ('pass','fail'): raise RuntimeError('HANGANG_COOKIE_EXPECT must be pass or fail')
    with ExitStack() as stack:
        root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='hangang-cookie-browser-')))
        public, admin, origin_port, fixture_port = free_ports(4)
        server = ThreadingHTTPServer(('127.0.0.1', origin_port), Origin)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        stack.callback(server.server_close); stack.callback(server.shutdown)
        cert, key = certificate(root)
        config = root / 'config.json'
        config.write_text(json.dumps({'http':[{'id':'wordpress','listener_ids':['browser'],
            'backends':[f'http://127.0.0.1:{origin_port}']}], 'tcp':[], 'public_http':[{
            'id':'browser','listen':f'127.0.0.1:{public}','certificates':[{'id':'local',
            'hosts':['localhost'],'cert_file':str(cert),'key_file':str(key)}]}]}))
        token = secrets.token_hex(24); log = stack.enter_context((root/'gateway.log').open('wb'))
        child = subprocess.Popen([str(BINARY),'--config',str(config),'--listen','127.0.0.1:0',
            '--admin',f'127.0.0.1:{admin}','--threads','2','--lua-workers','1'],
            env={**os.environ,'HANGANG_ADMIN_TOKEN':token},stdout=log,stderr=log)
        stack.callback(stop, child)
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            if child.poll() is not None: raise RuntimeError((root/'gateway.log').read_text()[-3000:])
            try:
                with socket.create_connection(('127.0.0.1',public),timeout=.2): break
            except OSError: time.sleep(.05)
        else: raise RuntimeError('gateway readiness deadline')
        artifacts = tempfile.mkdtemp(prefix='hangang-cookie-browser-artifacts-')
        try:
            subprocess.run(['npx','playwright','test','tests/actual-cookie.spec.js','--workers=1','--reporter=line','--output',artifacts],
                cwd=ROOT/'web',env={**os.environ,'HANGANG_UI_TEST_PORT':str(fixture_port),
                'HANGANG_COOKIE_ACTUAL_BASE':f'https://localhost:{public}','HANGANG_COOKIE_EXPECT':EXPECT},check=True)
        except BaseException:
            print(f'Cookie browser artifacts retained at {artifacts}',flush=True); raise
        else: shutil.rmtree(artifacts)
    print(f'Owned Chromium H2/H1 cookie regression: expected {EXPECT} observed')

if __name__ == '__main__': main()
