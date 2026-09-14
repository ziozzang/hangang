#!/usr/bin/env python3
"""Owned loopback TLS peers exercising fleet collector transport boundaries."""
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("HANGANG_BINARY", ROOT / "target/debug/hangang")).resolve()
ADMIN = "admin-owned-collector-fixture-credential"
PEER = "P" * 48


def private_write(path, data):
    temporary = path.with_name(path.name + ".new")
    with temporary.open("xb") as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def observation(node_id):
    return {"schema_version": 1, "node_id": node_id, "observer_generation": "1",
            "instance_id": "a" * 16, "configuration_source": "file", "revision": "0",
            "config_digest": "b" * 16, "ready": True, "store_epoch": None}


class PeerServer:
    def __init__(self, cert, key, reply):
        self.reply = reply
        self.requests = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def handle(self):
                try:
                    super().handle()
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    # Generation cancellation closes held TLS sockets.
                    pass

            def do_GET(self):
                owner.requests.append((self.path, self.headers.get("Authorization")))
                status, headers, body = owner.reply()
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                if "Transfer-Encoding" not in headers:
                    self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    pass

            def log_message(self, *_args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def origin(self):
        return f"https://localhost:{self.server.server_port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


class CollectorTransport(unittest.TestCase):
    def setUp(self):
        self.assertTrue(BINARY.is_file(), "set HANGANG_BINARY to an owned gateway binary")
        self.directory = tempfile.TemporaryDirectory(prefix="hangang-collector-transport-")
        self.root = Path(self.directory.name)
        self.cert, self.key = self.root / "ca.pem", self.root / "server.key"
        ca_key, csr, self.server_cert = self.root / "ca.key", self.root / "server.csr", self.root / "server.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-days", "1", "-subj", "/CN=Owned Collector CA",
                        "-addext", "basicConstraints=critical,CA:TRUE",
                        "-keyout", str(ca_key), "-out", str(self.cert)],
                       check=True, capture_output=True, timeout=20)
        subprocess.run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                        "-subj", "/CN=localhost", "-keyout", str(self.key), "-out", str(csr)],
                       check=True, capture_output=True, timeout=20)
        ext = self.root / "server.ext"
        ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n")
        subprocess.run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(self.cert),
                        "-CAkey", str(ca_key), "-CAcreateserial", "-days", "1",
                        "-extfile", str(ext), "-out", str(self.server_cert)],
                       check=True, capture_output=True, timeout=20)
        os.chmod(self.cert, 0o600)
        os.chmod(self.key, 0o600)
        self.peers = []
        self.child = None

    def tearDown(self):
        if self.child is not None:
            self.child.terminate()
            try:
                self.child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait(timeout=5)
            self.log.close()
        for peer in self.peers:
            peer.close()
        self.directory.cleanup()

    def peer(self, reply):
        peer = PeerServer(self.server_cert, self.key, reply)
        self.peers.append(peer)
        return peer

    def start(self, entries):
        config = self.root / "config.json"
        self.inventory = self.root / "inventory.json"
        self.token = self.root / "peer.token"
        private_write(config, b'{"revision":0,"http":[],"tcp":[]}')
        private_write(self.token, PEER.encode())
        self.publish(entries)
        public_port, self.admin_port = free_port(), free_port()
        self.log = (self.root / "gateway.log").open("wb")
        self.child = subprocess.Popen([
            str(BINARY), "--config", str(config), "--listen", f"127.0.0.1:{public_port}",
            "--admin", f"127.0.0.1:{self.admin_port}", "--admin-token", ADMIN,
            "--fleet-inventory-config", str(self.inventory), "--threads", "2",
            "--lua-workers", "1", "--drain-seconds", "1",
        ], stdout=self.log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            start_new_session=True)
        self.wait(lambda value: value["configured"] and value["expected_nodes"] == len(entries))

    def publish(self, entries):
        private_write(self.inventory, json.dumps({"peers": [
            {"node_id": node_id, "endpoint": peer.origin,
             "token_file": str(self.token), "ca_file": str(self.cert)}
            for node_id, peer in entries
        ]}).encode())

    def status(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.admin_port, timeout=2)
        try:
            connection.request("GET", "/v1/fleet/observations",
                               headers={"Authorization": "Bearer " + ADMIN})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            return json.loads(response.read())
        finally:
            connection.close()

    def wait(self, predicate, seconds=8):
        deadline = time.monotonic() + seconds
        while True:
            self.assertIsNone(self.child.poll(), "owned gateway exited")
            try:
                value = self.status()
                if predicate(value):
                    return value
            except (OSError, ConnectionError):
                pass
            self.assertLess(time.monotonic(), deadline, "collector state did not converge")
            time.sleep(0.05)

    def test_redirect_chunked_oversize_and_invalid_identity(self):
        target = self.peer(lambda: (200, {}, b"target"))
        redirect = self.peer(lambda: (302, {"Location": target.origin + "/capture"}, b""))
        oversized = self.peer(lambda: (200, {"Transfer-Encoding": "chunked"},
                                        b"4000\r\n" + b"x" * 16384 + b"\r\n400\r\n" + b"y" * 1024 + b"\r\n0\r\n\r\n"))
        missing_epoch = observation("missing-epoch")
        missing_epoch["configuration_source"] = "shared"
        missing_epoch.pop("store_epoch")
        invalid = self.peer(lambda: (200, {}, json.dumps(missing_epoch).encode()))
        mismatch = self.peer(lambda: (200, {}, json.dumps(observation("wrong-id")).encode()))
        self.start([("redirect", redirect), ("oversized", oversized),
                    ("missing-epoch", invalid), ("expected-id", mismatch)])
        value = self.wait(lambda v: all(n["condition"] != "unknown" for n in v["nodes"]))
        errors = {n["node_id"]: n["last_error"] for n in value["nodes"]}
        self.assertEqual(errors, {"redirect": "http_status", "oversized": "body_too_large",
                                  "missing-epoch": "invalid_observation",
                                  "expected-id": "identity_mismatch"})
        self.assertEqual(target.requests, [], "redirect target must never receive bearer")
        for peer in (redirect, oversized, invalid, mismatch):
            self.assertEqual(peer.requests[0], ("/v1/fleet/observation", "Bearer " + PEER))

    def test_four_poll_limit_and_removed_generation_cannot_reappear(self):
        release = threading.Event()
        lock = threading.Lock()
        active = 0
        maximum = 0

        def held():
            nonlocal active, maximum
            with lock:
                active += 1
                maximum = max(maximum, active)
            release.wait(timeout=2)
            with lock:
                active -= 1
            return (200, {}, json.dumps(observation("held")).encode())

        peers = [self.peer(held) for _ in range(5)]
        self.start([(f"peer-{index}", peer) for index, peer in enumerate(peers)])
        deadline = time.monotonic() + 3
        while maximum < 4 and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertEqual(maximum, 4)
        time.sleep(0.2)
        self.assertLessEqual(maximum, 4, "collector exceeded the four-request cap")
        before = self.status()["generation"]
        self.publish([])
        value = self.wait(lambda v: v["generation"] != before and v["expected_nodes"] == 0)
        self.assertEqual(value["nodes"], [])
        release.set()
        time.sleep(0.2)
        self.assertEqual(self.status()["nodes"], [], "old response restored removed peer")


if __name__ == "__main__":
    unittest.main()
