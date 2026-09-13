#!/usr/bin/env python3
"""Signed HTTPS upgrade with listener handoff; all resources are test-owned."""

import base64
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

import smoke
from smoke import BINARY, TOKEN, TcpEcho, ThreadingTcpServer, free_port, recv_exact


WORKSPACE = Path(__file__).resolve().parents[1]
SIGNER = BINARY.with_name("hangang-release-sign")
TARGET = subprocess.run(
    ["rustc", "-vV"], check=True, capture_output=True, text=True
).stdout.split("host: ", 1)[1].splitlines()[0]


class GatewayBackend(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.headers.get("Upgrade", "").lower() == "websocket":
            key = self.headers.get("Sec-WebSocket-Key", "")
            accept = base64.b64encode(
                hashlib.sha1(
                    (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
                ).digest()
            ).decode()
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
        elif self.path == "/slow":
            before, after = b"http-before-", b"http-after"
            self.send_response(200)
            self.send_header("Content-Length", str(len(before) + len(after)))
            self.end_headers()
            self.wfile.write(before)
            self.wfile.flush()
            self.server.slow_started.set()
            if not self.server.release_slow.wait(30):
                return
            self.wfile.write(after)
            self.wfile.flush()
        else:
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *_):
        pass


class ReleaseHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path == "/manifest":
            body = self.server.manifest
        elif self.path == "/artifact":
            body = self.server.artifact
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def build_candidate(root: Path) -> Path:
    package = root / "candidate-source"
    package.mkdir()
    cargo = (WORKSPACE / "Cargo.toml").read_text()
    cargo = cargo.replace('version = "0.1.0"', 'version = "0.1.1"', 1)
    cargo += "\n[profile.dev]"
    cargo += "\ndebug = 0"
    cargo += "\nstrip = \"debuginfo\""
    (package / "Cargo.toml").write_text(cargo)
    shutil.copy2(WORKSPACE / "Cargo.lock", package / "Cargo.lock")
    shutil.copy2(WORKSPACE / "build.rs", package / "build.rs")
    for name in ("src", "docs", "web"):
        os.symlink(WORKSPACE / name, package / name, target_is_directory=True)
    # Keep dependency artifacts between runs. This is a dedicated target tree
    # and never overwrites the workspace's active debug/release executable.
    target = WORKSPACE / "target" / "upgrade-smoke"
    subprocess.run(
        [
            "cargo",
            "build",
            "--offline",
            "--manifest-path",
            str(package / "Cargo.toml"),
            "--target-dir",
            str(target),
            "--bin",
            "hangang",
        ],
        cwd=WORKSPACE,
        check=True,
        timeout=600,
    )
    candidate = target / "debug" / "hangang"
    if candidate.stat().st_size > 128 * 1024 * 1024:
        raise AssertionError("candidate exceeds updater artifact bound")
    reported = subprocess.run(
        [candidate, "--version"], check=True, capture_output=True, text=True
    ).stdout.strip()
    if reported != "hangang 0.1.1":
        raise AssertionError(f"unexpected candidate version: {reported}")
    return candidate


def generate_certificate(root: Path):
    ca = root / "release-ca.pem"
    ca_key = root / "release-ca-key.pem"
    certificate = root / "release-server.pem"
    key = root / "release-server-key.pem"
    request = root / "release-server.csr"
    extensions = root / "release-server.ext"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=hangang-loopback-release",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-keyout",
            str(ca_key),
            "-out",
            str(ca),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        [
            "openssl",
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=127.0.0.1",
            "-keyout",
            str(key),
            "-out",
            str(request),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    extensions.write_text(
        "subjectAltName=IP:127.0.0.1\n"
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
    )
    subprocess.run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(request),
            "-CA",
            str(ca),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            str(extensions),
            "-out",
            str(certificate),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return ca, certificate, key


def signed_manifest(root: Path, seed: Path, version: str, url: str, artifact: bytes):
    payload = root / f"payload-{version}.json"
    envelope = root / f"manifest-{version}.json"
    payload.write_text(
        json.dumps(
            {
                "version": version,
                "target": TARGET,
                "artifact_url": url,
                "sha256": hashlib.sha256(artifact).hexdigest(),
                "size": len(artifact),
            },
            separators=(",", ":"),
        )
    )
    subprocess.run([SIGNER, payload, seed, envelope], check=True, capture_output=True)
    return envelope.read_bytes()


class SignedUpgrade(unittest.TestCase):
    def test_private_ca_signed_upgrade_preserves_http_websocket_and_tcp(self):
        with tempfile.TemporaryDirectory(prefix="hangang-upgrade-") as directory:
            root = Path(directory)
            if not SIGNER.exists():
                subprocess.run(
                    ["cargo", "build", "--offline", "--bin", "hangang-release-sign"],
                    cwd=WORKSPACE,
                    check=True,
                )
            candidate = build_candidate(root)
            executable = root / "hangang"
            shutil.copy2(BINARY, executable)

            seed = root / "ed25519-seed.base64"
            seed.write_text(base64.b64encode(bytes([37]) * 32).decode())
            seed.chmod(0o600)
            public_key = subprocess.run(
                [SIGNER, "--public-key", seed],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

            release_ca, certificate, certificate_key = generate_certificate(root)
            release = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ReleaseHandler)
            release.daemon_threads = True
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certificate, certificate_key)
            release.socket = context.wrap_socket(release.socket, server_side=True)
            artifact_url = f"https://127.0.0.1:{release.server_port}/artifact"
            # Equal-version checks stop before fetching; keep this signed marker
            # small even when the local debug server binary exceeds 128 MiB.
            release.artifact = b"already-running"
            release.manifest = signed_manifest(
                root, seed, "0.1.0", artifact_url, release.artifact
            )

            backend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), GatewayBackend)
            backend.daemon_threads = True
            backend.slow_started = threading.Event()
            backend.release_slow = threading.Event()
            echo = ThreadingTcpServer(("127.0.0.1", 0), TcpEcho)
            for server in (release, backend, echo):
                threading.Thread(target=server.serve_forever, daemon=True).start()

            ports = set()
            def allocate():
                port = free_port()
                while port in ports:
                    port = free_port()
                ports.add(port)
                return port

            public, admin, tcp = allocate(), allocate(), allocate()
            state = root / "config.json"
            state.write_text(
                json.dumps(
                    {
                        "http": [
                            {
                                "id": "gateway",
                                "backends": [f"http://127.0.0.1:{backend.server_port}"],
                            }
                        ],
                        "tcp": [
                            {
                                "id": "echo",
                                "listen": f"127.0.0.1:{tcp}",
                                "backends": [f"127.0.0.1:{echo.server_address[1]}"],
                            }
                        ],
                    }
                )
            )
            status_file = root / "update-status.json"
            log_path = root / "hangang.log"
            command = [
                executable,
                "--supervised",
                "--config",
                state,
                "--listen",
                f"127.0.0.1:{public}",
                "--admin",
                f"127.0.0.1:{admin}",
                "--threads",
                "2",
                "--lua-workers",
                "1",
                "--drain-seconds",
                "20",
                "--update-manifest",
                f"https://127.0.0.1:{release.server_port}/manifest",
                "--update-key",
                public_key,
                "--update-ca",
                release_ca,
                "--update-interval-seconds",
                "10",
                "--update-status-file",
                status_file,
            ]
            command = [str(value) for value in command]
            log = open(log_path, "w+")
            supervisor = subprocess.Popen(
                command,
                env={**os.environ, "HANGANG_ADMIN_TOKEN": TOKEN},
                stdout=log,
                stderr=log,
            )
            stable_supervisor_pid = supervisor.pid
            websocket = tcp_stream = slow = None

            def request(method, path):
                return smoke.Smoke.request(admin, method, path, auth=True)

            def await_json(path, predicate, timeout=30):
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    if supervisor.poll() is not None:
                        log.seek(0)
                        self.fail(log.read())
                    try:
                        code, _, body = request("GET", path)
                        if code == 200:
                            value = json.loads(body)
                            if predicate(value):
                                return value
                    except (OSError, http.client.HTTPException, json.JSONDecodeError):
                        pass
                    time.sleep(0.05)
                log.seek(0)
                self.fail(f"timeout waiting for {path}: " + log.read())

            try:
                initial = await_json("/v1/status", lambda _: True)
                await_json("/v1/update/status", lambda value: value["phase"] == "up_to_date")

                slow = socket.create_connection(("127.0.0.1", public), timeout=3)
                slow.sendall(
                    f"GET /slow HTTP/1.1\r\nHost: 127.0.0.1:{public}\r\nConnection: close\r\n\r\n".encode()
                )
                slow_bytes = b""
                while b"\r\n\r\n" not in slow_bytes:
                    slow_bytes += slow.recv(4096)
                slow_headers, slow_body = slow_bytes.split(b"\r\n\r\n", 1)
                self.assertTrue(slow_headers.startswith(b"HTTP/1.1 200"), slow_headers)
                while len(slow_body) < len(b"http-before-"):
                    slow_body += slow.recv(4096)
                self.assertEqual(slow_body, b"http-before-")
                self.assertTrue(backend.slow_started.wait(2))

                websocket = socket.create_connection(("127.0.0.1", public), timeout=3)
                websocket.sendall(
                    b"GET /socket HTTP/1.1\r\n"
                    + f"Host: 127.0.0.1:{public}\r\n".encode()
                    + b"Connection: Upgrade\r\nUpgrade: websocket\r\n"
                    + b"Sec-WebSocket-Version: 13\r\n"
                    + b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n" # gitleaks:allow -- isolated test fixture
                )
                headers = b""
                while not headers.endswith(b"\r\n\r\n"):
                    headers += websocket.recv(1)
                self.assertTrue(headers.startswith(b"HTTP/1.1 101"), headers)
                websocket.sendall(b"ws-before")
                self.assertEqual(recv_exact(websocket, 9), b"ws-before")

                tcp_stream = socket.create_connection(("127.0.0.1", tcp), timeout=3)
                tcp_stream.sendall(b"tcp-before")
                self.assertEqual(recv_exact(tcp_stream, 10), b"tcp-before")

                release.artifact = candidate.read_bytes()
                release.manifest = signed_manifest(
                    root, seed, "0.1.1", artifact_url, release.artifact
                )
                code, _, _ = request("POST", "/v1/update/check")
                self.assertEqual(code, 202)
                active = await_json(
                    "/v1/status",
                    lambda value: value["process_id"] != initial["process_id"],
                    timeout=45,
                )
                self.assertIsNone(supervisor.poll())
                os.kill(stable_supervisor_pid, 0)
                update = await_json(
                    "/v1/update/status",
                    lambda value: value["current_version"] == "0.1.1",
                )
                self.assertEqual(update["phase"], "active")
                self.assertEqual(active["version"], "0.1.1")

                backend.release_slow.set()
                slow_body += recv_exact(slow, len(b"http-after"))
                self.assertEqual(slow_body, b"http-before-http-after")
                websocket.sendall(b"ws-after")
                self.assertEqual(recv_exact(websocket, 8), b"ws-after")
                tcp_stream.sendall(b"tcp-after")
                self.assertEqual(recv_exact(tcp_stream, 9), b"tcp-after")
                self.assertEqual(smoke.Smoke.request(public, "GET", "/fresh")[0], 200)
                fresh_tcp = socket.create_connection(("127.0.0.1", tcp), timeout=3)
                fresh_tcp.sendall(b"fresh")
                self.assertEqual(recv_exact(fresh_tcp, 5), b"fresh")
                fresh_tcp.close()
                reported = subprocess.run(
                    [executable, "--version"],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.strip()
                self.assertEqual(reported, "hangang 0.1.1")
            finally:
                backend.release_slow.set()
                for stream in (slow, websocket, tcp_stream):
                    if stream is not None:
                        stream.close()
                if supervisor.poll() is None:
                    supervisor.terminate()
                try:
                    supervisor.wait(timeout=25)
                except subprocess.TimeoutExpired:
                    supervisor.kill()
                    supervisor.wait()
                log.close()
                for server in (release, backend, echo):
                    server.shutdown()
                    server.server_close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
