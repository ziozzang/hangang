#!/usr/bin/env python3
"""PROXY protocol v2 on the public listener (black box, loopback only).

The gateway trusts 127.0.0.1/32 as its load balancer: connections from it
must start with a PROXY v2 header whose source becomes the client address;
a connection from 127.0.0.2 is served directly and its bytes are never
parsed as a PROXY header.
"""
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest

BINARY = Path(os.environ.get("HANGANG_BINARY", "target/debug/hangang")).resolve()
TOKEN = "hangang-test-token-do-not-use"
SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def header(source, source_port, destination, destination_port):
    block = socket.inet_aton(source) + socket.inet_aton(destination) + struct.pack("!HH", source_port, destination_port)
    return SIGNATURE + bytes([0x21, 0x11]) + struct.pack("!H", len(block)) + block


class Backend(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = json.dumps({k.lower(): v for k, v in self.headers.items()}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


class ProxyProtocol(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not BINARY.is_file():
            raise unittest.SkipTest("build first with cargo build")
        cls.temp = tempfile.TemporaryDirectory(prefix="hangang-proxy-protocol-")
        cls.backend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Backend)
        cls.backend.daemon_threads = True
        threading.Thread(target=cls.backend.serve_forever, daemon=True).start()
        cls.public, cls.admin = free_port(), free_port()
        while cls.admin == cls.public:
            cls.admin = free_port()
        state = Path(cls.temp.name) / "config.json"
        state.write_text(json.dumps({"revision": 0, "tcp": [], "http": [
            {"id": "main", "backends": [f"http://127.0.0.1:{cls.backend.server_port}"]}]}))
        cls.log = open(Path(cls.temp.name) / "server.log", "w+")
        cls.proc = subprocess.Popen(
            [str(BINARY), "--config", str(state), "--listen", f"127.0.0.1:{cls.public}",
             "--admin", f"127.0.0.1:{cls.admin}", "--threads", "1", "--lua-workers", "1",
             "--drain-seconds", "1", "--proxy-protocol-from", "127.0.0.1/32"],
            env={**os.environ, "HANGANG_ADMIN_TOKEN": TOKEN}, stdout=cls.log, stderr=cls.log)
        for _ in range(200):
            if cls.proc.poll() is not None:
                cls.log.seek(0)
                raise RuntimeError(cls.log.read())
            try:
                with socket.create_connection(("127.0.0.1", cls.admin), timeout=1):
                    return
            except OSError:
                time.sleep(.05)
        raise RuntimeError("server did not start")

    @classmethod
    def tearDownClass(cls):
        if cls.proc.poll() is None:
            cls.proc.send_signal(signal.SIGTERM)
            try:
                cls.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
                cls.proc.wait()
        cls.backend.shutdown()
        cls.backend.server_close()
        cls.log.close()
        cls.temp.cleanup()

    def exchange(self, payload, source="127.0.0.1"):
        with socket.socket() as connection:
            connection.settimeout(5)
            connection.bind((source, 0))
            connection.connect(("127.0.0.1", self.public))
            connection.sendall(payload)
            chunks = []
            try:
                while True:
                    chunk = connection.recv(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
            except ConnectionResetError:
                pass
            return b"".join(chunks)

    def request(self):
        return b"GET /who HTTP/1.1\r\nHost: app.example.test\r\nConnection: close\r\n\r\n"

    def test_trusted_load_balancer_supplies_the_client_address(self):
        reply = self.exchange(header("203.0.113.7", 4444, "127.0.0.1", self.public) + self.request())
        self.assertTrue(reply.startswith(b"HTTP/1.1 200"), reply[:200])
        seen = json.loads(reply.split(b"\r\n\r\n", 1)[1])
        self.assertEqual(seen.get("x-forwarded-for"), "203.0.113.7")

    def test_trusted_peer_without_header_is_refused(self):
        self.assertEqual(self.exchange(self.request()), b"")

    def test_untrusted_peer_is_served_directly_and_cannot_claim_an_address(self):
        reply = self.exchange(self.request(), source="127.0.0.2")
        self.assertTrue(reply.startswith(b"HTTP/1.1 200"), reply[:200])
        self.assertEqual(json.loads(reply.split(b"\r\n\r\n", 1)[1]).get("x-forwarded-for"), "127.0.0.2")
        spoofed = self.exchange(header("203.0.113.7", 4444, "127.0.0.1", self.public) + self.request(), source="127.0.0.2")
        self.assertNotIn(b"203.0.113.7", spoofed)
        self.assertFalse(spoofed.startswith(b"HTTP/1.1 200"), spoofed[:200])


if __name__ == "__main__":
    unittest.main()
