#!/usr/bin/env python3
"""Owned loopback demo for per-route address, TLS, Host, and SOCKS5 choices."""

import http.client
import http.server
import json
import os
from pathlib import Path
import select
import signal
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parents[2]
TOKEN = "hangang-upstream-example-token"


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def read_exact(stream, length):
    result = bytearray()
    while len(result) < length:
        block = stream.recv(length - len(result))
        if not block:
            raise ConnectionError("unexpected end of stream")
        result.extend(block)
    return bytes(result)


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        body = json.dumps(
            {
                "path": self.path,
                "host": self.headers["Host"],
                "sni": getattr(self.request, "seen_sni", None),
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Socks(socketserver.BaseRequestHandler):
    def handle(self):
        version, count = read_exact(self.request, 2)
        assert version == 5 and 0 in read_exact(self.request, count)
        self.request.sendall(b"\x05\x00")
        version, command, reserved, kind = read_exact(self.request, 4)
        assert (version, command, reserved) == (5, 1, 0)
        if kind == 1:
            host = socket.inet_ntop(socket.AF_INET, read_exact(self.request, 4))
        elif kind == 3:
            host = read_exact(self.request, read_exact(self.request, 1)[0]).decode()
        elif kind == 4:
            host = socket.inet_ntop(socket.AF_INET6, read_exact(self.request, 16))
        else:
            raise AssertionError(f"unexpected SOCKS5 address type {kind}")
        port = int.from_bytes(read_exact(self.request, 2), "big")
        self.server.targets.append(f"{host}:{port}")
        with socket.create_connection(self.server.destination, timeout=3) as upstream:
            self.request.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x01")
            sockets = [self.request, upstream]
            while sockets:
                readable, _, _ = select.select(sockets, [], [], 3)
                if not readable:
                    break
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    (upstream if source is self.request else self.request).sendall(data)


class ThreadingSocks(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def request(port, path):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("GET", path, headers={"Host": "public.example"})
        response = connection.getresponse()
        body = response.read()
        assert response.status == 200, (path, response.status, body)
        return json.loads(body)
    finally:
        connection.close()


def wait_ready(process, admin, log):
    for _ in range(100):
        if process.poll() is not None:
            log.seek(0)
            raise AssertionError(log.read())
        try:
            connection = http.client.HTTPConnection("127.0.0.1", admin, timeout=0.2)
            connection.request("GET", "/healthz", headers={"Authorization": f"Bearer {TOKEN}"})
            if connection.getresponse().status == 200:
                connection.close()
                return
            connection.close()
        except OSError:
            pass
        time.sleep(0.05)
    raise AssertionError("gateway did not become ready")


def main():
    binary = Path(os.environ.get("HANGANG_BINARY", ROOT / "target/debug/hangang")).resolve()
    if not binary.exists():
        raise SystemExit("Run cargo build first, or set HANGANG_BINARY.")
    origin = socks = process = None
    try:
        with tempfile.TemporaryDirectory(prefix="hangang-upstream-example-") as temporary:
            temporary = Path(temporary)
            ca, ca_key = temporary / "ca.pem", temporary / "ca.key"
            cert, key, csr = temporary / "foo.pem", temporary / "foo.key", temporary / "foo.csr"
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                 "-subj", "/CN=Hangang owned CA", "-addext", "basicConstraints=critical,CA:TRUE",
                 "-keyout", str(ca_key), "-out", str(ca)],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                 ["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=foo.bar",
                 "-keyout", str(key), "-out", str(csr)], check=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            extensions = temporary / "extensions.cnf"
            extensions.write_text("subjectAltName=DNS:foo.bar\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n")
            subprocess.run(
                ["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca),
                 "-CAkey", str(ca_key), "-CAcreateserial", "-days", "1", "-extfile",
                 str(extensions), "-out", str(cert)], check=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
            origin.daemon_threads = True
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(cert, key)
            tls.set_servername_callback(lambda stream, name, _context: setattr(stream, "seen_sni", name))
            origin.socket = tls.wrap_socket(origin.socket, server_side=True)
            threading.Thread(target=origin.serve_forever, daemon=True).start()
            socks = ThreadingSocks(("127.0.0.1", 0), Socks)
            socks.destination, socks.targets = origin.server_address, []
            threading.Thread(target=socks.serve_forever, daemon=True).start()

            origin_port, public, admin = origin.server_port, free_port(), free_port()
            while public == admin:
                admin = free_port()
            common = {"upstream_host": "foo.bar"}
            routes = [
                {"id": "verified", "path_prefix": "/verified", "backends": [f"https://foo.bar:{origin_port}"],
                 "upstream": {"connect_address": f"127.0.0.1:{origin_port}", "tls": {"server_name": "foo.bar", "ca_file": str(ca)}}, **common},
                {"id": "insecure", "path_prefix": "/insecure", "backends": [f"https://wrong.name:{origin_port}"],
                 "upstream": {"connect_address": f"127.0.0.1:{origin_port}", "tls": {"server_name": "foo.bar", "insecure_skip_verify": True}}, **common},
                {"id": "proxy", "path_prefix": "/proxy", "backends": [f"https://foo.bar:{origin_port}"],
                 "upstream": {"socks5": {"address": f"127.0.0.1:{socks.server_address[1]}"}, "tls": {"server_name": "foo.bar", "ca_file": str(ca)}}, **common},
            ]
            config = temporary / "hangang.json"
            config.write_text(json.dumps({"http": routes}, indent=2) + "\n")
            subprocess.run([str(binary), "--config", str(config), "--check"], check=True)
            with (temporary / "gateway.log").open("w+") as log:
                process = subprocess.Popen(
                    [str(binary), "--config", str(config), "--listen", f"127.0.0.1:{public}",
                     "--admin", f"127.0.0.1:{admin}", "--admin-token", TOKEN], stdout=log, stderr=log,
                    env={**os.environ, "RUST_LOG": "hangang=debug"},
                )
                wait_ready(process, admin, log)
                try:
                    for path in ("/verified", "/insecure", "/proxy"):
                        seen = request(public, path)
                        assert seen == {"path": path, "host": "foo.bar", "sni": "foo.bar"}, seen
                    assert socks.targets == [f"foo.bar:{origin_port}"], socks.targets
                except Exception:
                    log.flush()
                    log.seek(0)
                    print(log.read())
                    raise
                print("PASS: forced address, verified/insecure TLS, Host/SNI, and SOCKS5 route choice")
    finally:
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for server in (socks, origin):
            if server is not None:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    main()
