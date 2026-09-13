#!/usr/bin/env python3
"""Exercise the embedded Docker UI against one owned Hangang and two fake Unix sockets.

Set HANGANG_BINARY to the binary under test. No Docker daemon, container, or
production configuration is contacted or modified.
"""
import http.client
import http.server
import json
import os
from pathlib import Path
import secrets
import signal
import socketserver
import subprocess
import tempfile
import threading
import time

from smoke import BINARY, free_port


class UnixHttp(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class FakeDocker(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.hits.append(self.path)
        if self.path == "/_ping":
            body = b"OK"
        elif self.path == "/containers/api/json":
            body = json.dumps({
                "State": {"Running": True},
                "NetworkSettings": {"Networks": {
                    "edge": {"IPAddress": self.server.ip, "GlobalIPv6Address": ""},
                }},
            }).encode()
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def stop_group(child):
    if child is None:
        return
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait(timeout=5)


def wait_for_ui(child, admin_port):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError(f"owned Hangang exited before readiness ({child.returncode})")
        connection = http.client.HTTPConnection("127.0.0.1", admin_port, timeout=1)
        try:
            connection.request("GET", "/ui/")
            response = connection.getresponse()
            response.read()
            if response.status == 200:
                return
        except (OSError, http.client.HTTPException):
            pass
        finally:
            connection.close()
        time.sleep(0.05)
    raise RuntimeError("owned Hangang UI readiness timed out")


def main():
    if not BINARY.is_file():
        raise SystemExit(f"HANGANG_BINARY does not name a file: {BINARY}")
    repository = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="hg-docker-ui-") as directory:
        root = Path(directory)
        candidate_socket = root / "candidate.sock"
        default_socket = Path(f"{candidate_socket}.default")
        servers = []
        gateway = None
        browser = None
        try:
            for path, ip in [(candidate_socket, "192.0.2.41"), (default_socket, "192.0.2.42")]:
                server = UnixHttp(str(path), FakeDocker)
                server.ip = ip
                server.hits = []
                servers.append(server)
                threading.Thread(target=server.serve_forever, daemon=True).start()

            config = root / "config.json"
            config.write_text('{"http":[],"tcp":[]}')
            public_port, admin_port = free_port(), free_port()
            token = "hangang-docker-ui-" + secrets.token_hex(24)
            gateway = subprocess.Popen([
                str(BINARY), "--config", str(config),
                "--listen", f"127.0.0.1:{public_port}",
                "--admin", f"127.0.0.1:{admin_port}",
                "--admin-users-db", str(root / "users.sqlite3"),
                "--docker-socket", str(default_socket),
                "--docker-connection-state", str(root / "docker-connection.json"),
                "--threads", "2", "--lua-workers", "1",
            ], cwd=repository, env={**os.environ, "HANGANG_ADMIN_TOKEN": token},
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            wait_for_ui(gateway, admin_port)

            browser = subprocess.Popen([
                "npx", "playwright", "test", "tests/docker-actual.spec.js", "--workers=1",
            ], cwd=repository / "web", env={
                **os.environ,
                "HANGANG_DOCKER_ACTUAL_BASE": f"http://127.0.0.1:{admin_port}",
                "HANGANG_DOCKER_ACTUAL_TOKEN": token,
                "HANGANG_DOCKER_ACTUAL_SOCKET": str(candidate_socket),
                "HANGANG_DOCKER_ACTUAL_DEFAULT_SOCKET": str(default_socket),
            }, start_new_session=True)
            result = browser.wait(timeout=90)
            if result:
                raise RuntimeError(f"owned Docker browser smoke failed ({result})")
            if "/_ping" not in servers[0].hits:
                raise AssertionError("candidate Docker socket was not tested")
            if "/containers/api/json" not in servers[0].hits:
                raise AssertionError("candidate Docker socket was not used for inspection")
            if "/containers/api/json" not in servers[1].hits:
                raise AssertionError("default Docker socket was not restored for inspection")
        finally:
            stop_group(browser)
            stop_group(gateway)
            for server in servers:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    main()
