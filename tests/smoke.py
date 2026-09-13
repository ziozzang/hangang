#!/usr/bin/env python3
"""Black-box tests. Only loopback listeners and child processes owned here."""
import concurrent.futures
import base64
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import unittest

BINARY = Path(os.environ.get("HANGANG_BINARY", "target/debug/hangang")).resolve()
TOKEN = "hangang-test-token-do-not-use"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def recv_exact(stream, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = stream.recv(remaining)
        if not chunk:
            raise ConnectionError("stream closed before expected echo")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class Backend(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = json.dumps({"path": self.path, "headers": dict(self.headers), "backend": self.server.label}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


class UpgradeBackend(http.server.BaseHTTPRequestHandler):
    """Minimal RFC 6455 handshake followed by an opaque upgrade echo tunnel."""
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        key = self.headers.get("Sec-WebSocket-Key", "")
        accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        self.send_response_only(101)
        self.send_header("Connection", "Upgrade")
        self.send_header("Upgrade", "websocket")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        while True:
            data = self.connection.recv(4096)
            if not data:
                return
            self.connection.sendall(data)

    def log_message(self, *_):
        pass


class TcpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(4096)
            if not data:
                return
            self.request.sendall(data)


class ThreadingTcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Smoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not BINARY.is_file():
            raise RuntimeError("build first with cargo build")
        cls.temp = tempfile.TemporaryDirectory(prefix="hangang-smoke-")
        cls.backends = []
        for label in ("a", "b"):
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Backend)
            server.daemon_threads = True
            server.label = label
            threading.Thread(target=server.serve_forever, daemon=True).start()
            cls.backends.append(server)
        cls.public, cls.admin = free_port(), free_port()
        while cls.admin == cls.public:
            cls.admin = free_port()
        cls.state = Path(cls.temp.name) / "config.json"
        cls.state.write_text('{"revision":0,"http":[],"tcp":[]}')
        cls.log = open(Path(cls.temp.name) / "server.log", "w+")
        cls.proc = subprocess.Popen([str(BINARY), "--config", str(cls.state), "--listen", f"127.0.0.1:{cls.public}", "--admin", f"127.0.0.1:{cls.admin}", "--threads", "2", "--lua-workers", "1", "--drain-seconds", "2"], env={**os.environ, "HANGANG_ADMIN_TOKEN": TOKEN}, stdout=cls.log, stderr=cls.log)
        try:
            for _ in range(100):
                if cls.proc.poll() is not None:
                    cls.log.seek(0)
                    raise RuntimeError(cls.log.read())
                try:
                    if cls.request(cls.admin, "GET", "/healthz", auth=True)[0] == 200:
                        return
                except OSError:
                    time.sleep(.05)
            raise RuntimeError("server did not become ready")
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        if cls.proc.poll() is None:
            cls.proc.send_signal(signal.SIGTERM)
            try:
                cls.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
                cls.proc.wait()
        for server in cls.backends:
            server.shutdown()
            server.server_close()
        cls.log.close()
        cls.temp.cleanup()

    @staticmethod
    def request(port, method, path, body=None, headers=None, auth=False):
        headers = dict(headers or {})
        if auth:
            headers["Authorization"] = "Bearer " + TOKEN
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers)
            r = conn.getresponse()
            return r.status, dict(r.getheaders()), r.read()
        finally:
            conn.close()

    def current(self):
        status, headers, body = self.request(self.admin, "GET", "/v1/config", auth=True)
        self.assertEqual(status, 200)
        return headers, json.loads(body)

    def apply(self, routes, tcp=None):
        headers, cfg = self.current()
        cfg["http"] = routes
        if tcp is not None:
            cfg["tcp"] = tcp
        result = self.request(self.admin, "PUT", "/v1/config", json.dumps(cfg), {"Content-Type": "application/json", "If-Match": headers["etag"]}, auth=True)
        self.assertEqual(result[0], 200, result)
        return json.loads(result[2])

    def route(self, **kwargs):
        return {"id": "main", "backends": [f"http://127.0.0.1:{self.backends[0].server_port}"], **kwargs}

    def lua_worker_pids(self):
        """Find only this server's direct children explicitly running lua-worker."""
        proc = Path("/proc") / str(self.proc.pid)
        if not proc.is_dir():
            return []
        children = set()
        for child_file in (proc / "task").glob("*/children"):
            try:
                children.update(map(int, child_file.read_text().split()))
            except (FileNotFoundError, ProcessLookupError):
                pass
        workers = []
        for pid in children:
            try:
                argv = (Path("/proc") / str(pid) / "cmdline").read_bytes().split(b"\0")
            except (FileNotFoundError, ProcessLookupError):
                continue
            if b"--lua-worker" in argv:
                workers.append(pid)
        return workers

    def test_admin_auth_and_revision(self):
        self.assertEqual(self.request(self.admin, "GET", "/v1/config")[0], 401)
        self.assertEqual(self.request(self.admin, "PUT", "/v1/config", "{}", auth=True)[0], 428)
        h, c = self.current()
        conditional = {"If-Match": h["etag"]}
        self.assertEqual(self.request(self.admin, "PUT", "/v1/config", json.dumps(c), conditional, auth=True)[0], 415)
        conn = http.client.HTTPConnection("127.0.0.1", self.admin, timeout=6)
        try:
            conn.putrequest("PUT", "/v1/config")
            conn.putheader("Authorization", "Bearer " + TOKEN)
            conn.putheader("If-Match", h["etag"])
            conn.putheader("Content-Type", "application/json")
            conn.putheader("Content-Length", str(1024 * 1024 + 1))
            conn.endheaders()
            oversized = conn.getresponse()
            self.assertEqual(oversized.status, 413)
            oversized.read()
        finally:
            conn.close()
        self.assertEqual(self.current()[1], c)
        self.apply([self.route()])
        self.assertEqual(self.request(self.admin, "PUT", "/v1/config", json.dumps(c), {"Content-Type": "application/json", "If-Match": h["etag"]}, auth=True)[0], 409)

    def test_balance_and_forwarding_headers(self):
        self.apply([self.route(backends=[f"http://127.0.0.1:{s.server_port}" for s in self.backends])])
        results = [json.loads(self.request(self.public, "GET", "/hello?q=1", headers={"X-Forwarded-For": "evil", "Forwarded": "for=evil"})[2]) for _ in range(4)]
        self.assertEqual(sorted(r["backend"] for r in results), ["a", "a", "b", "b"])
        for r in results:
            self.assertEqual(r["path"], "/hello?q=1")
            lower = {k.lower(): v for k, v in r["headers"].items()}
            self.assertEqual(lower.get("x-forwarded-for"), "127.0.0.1")
            self.assertNotIn("evil", lower.get("forwarded", ""))

    def test_json_match_preserves_body(self):
        self.apply([self.route(json={"/tenant": "blue"})])
        body = '{ "tenant": "blue", "value": 3 }'
        result = self.request(self.public, "POST", "/", body, {"Content-Type": "application/json"})
        self.assertEqual((result[0], result[2]), (200, body.encode()))
        self.assertEqual(self.request(self.public, "POST", "/", '{"tenant":"red"}')[0], 404)
        conn = http.client.HTTPConnection("127.0.0.1", self.public, timeout=2)
        try:
            conn.putrequest("POST", "/")
            conn.putheader("Content-Type", "application/json")
            conn.putheader("Content-Length", str(1024 * 1024 + 1))
            conn.endheaders()
            oversized = conn.getresponse()
            self.assertEqual(oversized.status, 413)
            oversized.read()
        finally:
            conn.close()

    def test_bad_config_preserves_revision(self):
        h, before = self.current()
        bad = {"http": [self.route(backends=["file:///etc/passwd"])]}
        r = self.request(self.admin, "PUT", "/v1/config", json.dumps(bad), {"Content-Type": "application/json", "If-Match": h["etag"]}, auth=True)
        self.assertEqual(r[0], 422)
        self.assertEqual(self.current()[1], before)
        self.assertEqual(json.loads(self.state.read_text()), before)

    def test_lua_fault_then_native_traffic(self):
        self.apply([self.route(lua="while true do end")])
        self.assertEqual(self.request(self.public, "GET", "/")[0], 503)
        self.apply([self.route()])
        self.assertEqual(self.request(self.public, "GET", "/")[0], 200)
        self.assertIsNone(self.proc.poll())

    def test_lua_api(self):
        self.apply([self.route(lua='if hangang.header("x-deny") == "yes" then hangang.reject(403) end')])
        self.assertEqual(self.request(self.public, "GET", "/", headers={"x-deny": "yes"})[0], 403)
        self.assertEqual(self.request(self.public, "GET", "/")[0], 200)

    @unittest.skipUnless(Path("/proc/self/task").is_dir(), "requires Linux procfs")
    def test_lua_worker_sigkill_preserves_native_and_recovers_lua(self):
        self.apply([self.route(lua='hangang.header("x-probe")')])
        self.assertEqual(self.request(self.public, "GET", "/")[0], 200)
        workers = []
        for _ in range(40):
            workers = self.lua_worker_pids()
            if workers:
                break
            time.sleep(.025)
        self.assertEqual(len(workers), 2, workers)  # One data worker and one reserved validation worker.
        for worker in workers:
            os.kill(worker, signal.SIGKILL)

        self.apply([self.route()])
        self.assertEqual(self.request(self.public, "GET", "/")[0], 200)
        self.apply([self.route(lua='hangang.header("x-after-restart")')])
        self.assertEqual(self.request(self.public, "GET", "/")[0], 200)
        self.assertIsNone(self.proc.poll())

    def test_file_reload_and_bad_edit_retention(self):
        self.apply([self.route()])
        before = self.current()[1]
        updated = {"http": [self.route(headers={"x-enabled": "yes"})], "tcp": []}
        replacement = self.state.with_suffix(".next")
        replacement.write_text(json.dumps(updated))
        replacement.replace(self.state)
        for _ in range(60):
            if self.current()[1]["revision"] != before["revision"]:
                break
            time.sleep(.05)
        self.assertEqual(self.request(self.public, "GET", "/")[0], 404)
        self.assertEqual(self.request(self.public, "GET", "/", headers={"x-enabled": "yes"})[0], 200)
        good = self.current()[1]
        self.state.write_text('{"http": [')
        time.sleep(.65)
        self.assertEqual(self.current()[1], good)
        self.assertEqual(self.request(self.public, "GET", "/", headers={"x-enabled": "yes"})[0], 200)
        # A schema-valid edit whose TCP listener cannot bind is also rolled back.
        bind_conflict = dict(good)
        bind_conflict["tcp"] = [{"id": "occupied", "listen": f"127.0.0.1:{self.public}", "backends": ["127.0.0.1:9"]}]
        self.state.write_text(json.dumps(bind_conflict))
        time.sleep(.65)
        self.assertEqual(self.current()[1], good)
        self.assertEqual(self.request(self.public, "GET", "/", headers={"x-enabled": "yes"})[0], 200)
        # Repair with API; its own file event must not produce another revision.
        restored = self.apply([self.route()])
        time.sleep(.65)
        self.assertEqual(self.current()[1]["revision"], restored["revision"])

    def test_concurrent_native_requests(self):
        self.apply([self.route()])
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            statuses = list(pool.map(lambda _: self.request(self.public, "GET", "/")[0], range(64)))
        self.assertEqual(statuses, [200] * 64)
        self.assertEqual(self.request(self.admin, "GET", "/metrics", auth=True)[0], 200)

    def test_z_graceful_shutdown_drains_websocket_and_tcp_streams(self):
        """Runs last: it intentionally terminates the shared Hangang child."""
        websocket_backend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), UpgradeBackend)
        websocket_backend.daemon_threads = True
        tcp_backend = ThreadingTcpServer(("127.0.0.1", 0), TcpEcho)
        fixtures = []
        websocket = tcp = None
        try:
            for server in (websocket_backend, tcp_backend):
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                fixtures.append((server, thread))

            tcp_front = free_port()
            self.apply(
                [self.route(backends=[f"http://127.0.0.1:{websocket_backend.server_port}"])],
                [{
                    "id": "tcp-grace",
                    "listen": f"127.0.0.1:{tcp_front}",
                    "backends": [f"127.0.0.1:{tcp_backend.server_address[1]}"],
                }],
            )

            websocket = socket.create_connection(("127.0.0.1", self.public), timeout=2)
            websocket.sendall(
                b"GET /socket HTTP/1.1\r\n"
                + f"Host: 127.0.0.1:{self.public}\r\n".encode()
                + b"Connection: Upgrade\r\n"
                + b"Upgrade: websocket\r\n"
                + b"Sec-WebSocket-Version: 13\r\n"
                + b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n" # gitleaks:allow -- isolated test fixture
            )
            headers = b""
            while not headers.endswith(b"\r\n\r\n"):
                headers += websocket.recv(1)
            self.assertTrue(headers.startswith(b"HTTP/1.1 101"), headers)

            tcp = socket.create_connection(("127.0.0.1", tcp_front), timeout=2)
            websocket.sendall(b"websocket-before")
            self.assertEqual(recv_exact(websocket, 16), b"websocket-before")
            tcp.sendall(b"tcp-before")
            self.assertEqual(recv_exact(tcp, 10), b"tcp-before")

            self.proc.send_signal(signal.SIGTERM)
            time.sleep(.1)
            self.assertIsNone(self.proc.poll(), "process exited before open streams drained")
            websocket.sendall(b"websocket-during")
            self.assertEqual(recv_exact(websocket, 16), b"websocket-during")
            tcp.sendall(b"tcp-during")
            self.assertEqual(recv_exact(tcp, 10), b"tcp-during")

            websocket.close()
            websocket = None
            tcp.close()
            tcp = None
            self.assertEqual(self.proc.wait(timeout=5), 0)
        finally:
            if websocket is not None:
                websocket.close()
            if tcp is not None:
                tcp.close()
            for server, thread in fixtures:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
