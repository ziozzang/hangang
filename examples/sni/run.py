#!/usr/bin/env python3
"""Owned loopback demonstration: managed TLS termination and SNI TLS passthrough."""
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
TOKEN = 'hangang-sni-owned-example'

def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]

def fetch(port, host, context):
    with socket.create_connection(('127.0.0.1', port), timeout=3) as raw:
        with context.wrap_socket(raw, server_hostname=host) as stream:
            stream.sendall(f'GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'.encode())
            chunks = []
            while data := stream.recv(4096):
                chunks.append(data)
            return b''.join(chunks)

def main():
    binary = Path(os.environ.get('HANGANG_BINARY', ROOT / 'target/debug/hangang')).resolve()
    servers = []
    child = None
    try:
        with tempfile.TemporaryDirectory(prefix='hangang-sni-example-') as folder:
            folder = Path(folder)
            certificates, routes = [], []
            context = ssl.create_default_context()
            public, admin, passthrough = free_port(), free_port(), free_port()
            while len({public, admin, passthrough}) != 3:
                public, admin, passthrough = free_port(), free_port(), free_port()
            for index, name in enumerate(['one.example.test', 'two.example.test']):
                cert, key = folder / f'{index}.pem', folder / f'{index}.key'
                subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', f'/CN={name}', '-addext', f'subjectAltName=DNS:{name}', '-keyout', str(key), '-out', str(cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                context.load_verify_locations(cafile=str(cert))
                class Handler(http.server.BaseHTTPRequestHandler):
                    def do_GET(self):
                        data = self.server.identity.encode()
                        self.send_response(200)
                        self.send_header('Content-Length', str(len(data)))
                        self.end_headers()
                        self.wfile.write(data)
                    def log_message(self, *_args):
                        pass
                server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
                server.daemon_threads = True
                server.identity = name
                tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                tls.load_cert_chain(cert, key)
                server.socket = tls.wrap_socket(server.socket, server_side=True)
                servers.append(server)
                threading.Thread(target=server.serve_forever, daemon=True).start()
                certificates.append({'id': f'cert-{index}', 'hosts': [name], 'cert_file': str(cert), 'key_file': str(key)})
                routes.append({'id': f'pass-{index}', 'listen': f'127.0.0.1:{passthrough}', 'sni': {'hosts': [name]}, 'backends': [f'127.0.0.1:{server.server_port}']})
            config = folder / 'config.json'
            config.write_text(json.dumps({'certificates': certificates, 'tcp': routes}))
            with (folder / 'gateway.log').open('w+') as log:
                child = subprocess.Popen([str(binary), '--config', str(config), '--config-tls', '--listen', f'127.0.0.1:{public}', '--admin', f'127.0.0.1:{admin}', '--threads', '2', '--lua-workers', '1'], env={**os.environ, 'HANGANG_ADMIN_TOKEN': TOKEN}, stdout=log, stderr=log)
                for _ in range(100):
                    if child.poll() is not None:
                        raise RuntimeError('gateway exited; configuration example failed')
                    connection = http.client.HTTPConnection('127.0.0.1', admin, timeout=1)
                    try:
                        connection.request('GET', '/healthz', headers={'Authorization': f'Bearer {TOKEN}'})
                        if connection.getresponse().status == 200:
                            break
                    except OSError:
                        pass
                    finally:
                        connection.close()
                    time.sleep(.05)
                else:
                    raise RuntimeError('gateway readiness timeout')
                for name in ['one.example.test', 'two.example.test']:
                    assert fetch(public, name, context).startswith(b'HTTP/1.1 404')
                    assert fetch(passthrough, name, context).endswith(name.encode())
                print('PASS: two configured TLS certificates and two SNI passthrough backends')
    finally:
        if child is not None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        for server in servers:
            server.shutdown()
            server.server_close()

if __name__ == '__main__':
    main()
