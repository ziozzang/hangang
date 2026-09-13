#!/usr/bin/env python3
"""Run and verify all examples using owned loopback listeners and a temporary config."""
import contextlib
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = Path(__file__).resolve().parent


class Backend(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def do_POST(self):
        if self.headers.get('Transfer-Encoding', '').lower() == 'chunked':
            parts = []
            while True:
                size = int(self.rfile.readline().strip().split(b';')[0], 16)
                if not size:
                    self.rfile.readline()
                    break
                parts.append(self.rfile.read(size))
                self.rfile.read(2)
            payload = b''.join(parts)
        else:
            payload = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        self.send_response(200)
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Content-Type', 'application/xml' if self.path.endswith('xml') else 'application/json')
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        name = self.path.lstrip('/')
        if name.endswith('lines') and not name.endswith('ndjson'):
            chunks = [b'internal token=abc\n', b'internal token=xyz\n']
            content_type = 'text/plain'
        elif name.endswith('ndjson'):
            chunks = [b'{"n":1,"secret":"a"}\n', b'{"n":2,"secret":"b"}\n']
            content_type = 'application/x-ndjson'
        elif name.endswith('sse'):
            chunks = [b'id: 1\r\ndata: {"n":1,"secret":"a"}\r\n\r\n', b': heartbeat\n\n', b'data: [DONE]\n\n' if name.startswith('lua') else b'data: {"n":2,"secret":"b"}\n\n']
            content_type = 'text/event-stream'
        else:
            chunks = [b'\x00\xff\x01']
            content_type = 'application/octet-stream'
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Transfer-Encoding', 'chunked')
        self.end_headers()
        try:
            for chunk in chunks:
                # Split records and UTF-8-independent framing across transport chunks.
                for split in (chunk[:3], chunk[3:]):
                    if split:
                        self.wfile.write(f'{len(split):x}\r\n'.encode() + split + b'\r\n')
                        self.wfile.flush()
                time.sleep(0.02)
            self.wfile.write(b'0\r\n\r\n')
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass


def unused_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def request(port, path, payload=None):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    try:
        connection.request('POST' if payload is not None else 'GET', '/' + path, payload)
        reply = connection.getresponse()
        data = reply.read()
        assert reply.status == 200, (path, reply.status, data)
        return data
    finally:
        connection.close()


def main():
    binary = Path(os.environ.get('HANGANG_BINARY', ROOT / 'target/debug/hangang')).resolve()
    if not binary.exists():
        raise SystemExit('Run cargo build first, or set HANGANG_BINARY.')
    backend = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Backend)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix='hangang-transform-examples-') as temp:
            config = json.loads((EXAMPLES / 'hangang.json').read_text())
            for route in config['http']:
                route['backends'] = [f'http://127.0.0.1:{backend.server_port}']
            path = Path(temp) / 'hangang.json'
            path.write_text(json.dumps(config))
            subprocess.run([str(binary), '--config', str(path), '--check'], check=True, capture_output=True)
            public, admin = unused_port(), unused_port()
            while public == admin:
                admin = unused_port()
            with (Path(temp) / 'gateway.log').open('w+') as log:
                process = subprocess.Popen([str(binary), '--config', str(path), '--listen', f'127.0.0.1:{public}', '--admin', f'127.0.0.1:{admin}', '--admin-token', 'example-local-token-123456', '--lua-workers', '4'], stdout=log, stderr=log)
                for _ in range(100):
                    if process.poll() is not None:
                        log.seek(0)
                        raise AssertionError(log.read())
                    try:
                        with socket.create_connection(('127.0.0.1', public), timeout=0.1):
                            break
                    except OSError:
                        time.sleep(0.05)
                else:
                    raise AssertionError('gateway did not start')
                body = b'{"client_role":"admin","secret":"hidden","keep":1}'
                assert json.loads(request(public, 'native-json', body)) == {'keep': 1, 'source': 'hangang'}
                xml = request(public, 'native-xml', b'<root><name>old</name><secret>hidden</secret></root>')
                assert b'Hangang &amp; friends' in xml and b'secret' not in xml
                assert json.loads(request(public, 'lua-json', body)) == {'keep': 1, 'source': 'hangang', 'tags': [], 'processed': True, 'optional': None}
                assert request(public, 'native-lines') == b'public token=abc\npublic token=xyz\n'
                assert request(public, 'lua-lines') == b'internal token=[redacted]\ninternal token=[redacted]\n'
                for name in ['native-ndjson', 'lua-ndjson']:
                    rows = [json.loads(line) for line in request(public, name).splitlines()]
                    assert [row['n'] for row in rows] == [1, 2] and all('secret' not in row for row in rows)
                for name in ['native-sse', 'lua-sse']:
                    data = request(public, name)
                    assert b'secret' not in data and b'id: 1\n' in data and b': heartbeat\n\n' in data
                    if name.startswith('lua'):
                        assert b'data: [DONE]\n\n' in data
                assert request(public, 'binary') == b'HG\0\x00\xff\x01'
                print('PASS: all 10 native/Lua JSON, XML, lines, NDJSON, SSE and binary examples')
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        backend.shutdown()
        backend.server_close()


if __name__ == '__main__':
    main()
