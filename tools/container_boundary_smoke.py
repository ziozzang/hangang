#!/usr/bin/env python3
"""Bounded HTTP boundary checks on an internal disposable Docker network.

Uses existing local images only (resolved to immutable image IDs). No host
ports, production volumes, internet requests, or traffic generators are used.
Usage: python3 tools/container_boundary_smoke.py --image IMAGE
"""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import uuid


ORIGIN = r'''
import http.server, json, threading
records = []
lock = threading.Lock()
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *args): pass
    def respond(self, status, payload):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def do_GET(self): self.handle_request()
    def do_POST(self): self.handle_request()
    def handle_request(self):
        if self.path == "/state":
            with lock: payload = list(records)
            return self.respond(200, payload)
        if self.path == "/check":
            return self.respond(200 if self.headers.get("Authorization") == "Bearer fixture-allow" else 403, {})
        if self.path == "/public/disconnect":
            self.close_connection = True
            return
        body = b""
        complete = True
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            while True:
                line = self.rfile.readline(128)
                if not line:
                    complete = False
                    break
                size = int(line.strip().split(b";", 1)[0], 16)
                if not size:
                    while self.rfile.readline(4096).strip(): pass
                    break
                chunk = self.rfile.read(size)
                body += chunk
                if len(chunk) != size or self.rfile.read(2) != b"\r\n":
                    complete = False
                    break
        else:
            size = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(size)
            complete = len(body) == size
        record = {"path": self.path, "headers": list(self.headers.items()),
                  "body": body.decode("ascii"), "complete": complete}
        with lock: records.append(record)
        if complete: self.respond(200, record)
server = http.server.ThreadingHTTPServer(("0.0.0.0", 8081), Handler)
server.daemon_threads = True
server.serve_forever()
'''

CLIENT = r'''
import http.client, json, socket, time

def raw(head):
    with socket.create_connection(("gateway", 8080), timeout=3) as sock:
        sock.settimeout(3)
        sock.sendall(head)
        data = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk: break
            data += chunk
    return int(data.split(b" ", 2)[1]), data

def request(path, auth=False):
    return raw((f"GET {path} HTTP/1.1\r\nHost: fixture.test\r\nConnection: close\r\n"
                + ("Authorization: Bearer fixture-allow\r\n" if auth else "") + "\r\n").encode())

def state():
    connection = http.client.HTTPConnection("origin", 8081, timeout=3)
    connection.request("GET", "/state")
    response = connection.getresponse()
    result = json.loads(response.read())
    connection.close()
    return result

for attempt in range(60):
    try:
        if request("/public/ready")[0] == 200: break
    except (OSError, ValueError): pass
    time.sleep(.1)
else: raise AssertionError("gateway readiness failed")
checks = []
assert request("/private/no-auth")[0] == 403
checks.append("external_auth_denies_missing_credentials")
assert request("/private/allowed", True)[0] == 200
checks.append("external_auth_allows_fixture_credentials")
assert request("/private/%2e%2e/public/bypass")[0] == 400
checks.append("encoded_traversal_rejected")
status, _ = raw(b"POST /public/cl-conflict HTTP/1.1\r\nHost: fixture.test\r\nContent-Length: 1\r\nContent-Length: 2\r\nConnection: close\r\n\r\nab")
assert status == 400, status
checks.append("conflicting_content_lengths_rejected")
status, data = raw(b"POST /public/te-cl HTTP/1.1\r\nHost: fixture.test\r\nTransfer-Encoding: chunked\r\nContent-Length: 999\r\nConnection: close\r\n\r\n4\r\ndata\r\n0\r\n\r\n")
assert status in (200, 400), status
if status == 200:
    record = json.loads(data.split(b"\r\n\r\n", 1)[1])
    headers = {name.lower(): value for name, value in record["headers"]}
    assert record["body"] == "data"
    assert not ("content-length" in headers and "transfer-encoding" in headers)
checks.append("transfer_encoding_and_content_length_have_one_origin_framing")
status, data = raw(b"GET /public/pipeline-one HTTP/1.1\r\nHost: fixture.test\r\n\r\nGET /public/pipeline-two HTTP/1.1\r\nHost: fixture.test\r\nConnection: close\r\n\r\n")
assert status == 200 and data.count(b"HTTP/1.1 200") == 2, data
checks.append("pipelined_requests_keep_separate_boundaries")
assert request("/public/disconnect")[0] == 502
assert request("/public/after-disconnect")[0] == 200
checks.append("origin_disconnect_fails_closed_and_recovers")
status, data = raw(b"POST /public/chunked HTTP/1.1\r\nHost: fixture.test\r\nTransfer-Encoding: chunked\r\nX-Forwarded-For: 198.51.100.77\r\nConnection: close\r\n\r\n4\r\ndata\r\n0\r\n\r\n")
assert status == 200
record = json.loads(data.split(b"\r\n\r\n", 1)[1])
headers = {name.lower(): value for name, value in record["headers"]}
assert record["body"] == "data"
assert headers["x-forwarded-for"] != "198.51.100.77"
assert "content-length" not in headers or "transfer-encoding" not in headers
checks.append("chunked_data_and_forwarded_identity_consistent")
# Cancel one incomplete upload, then prove bounded request capacity recovers.
with socket.create_connection(("gateway", 8080), timeout=3) as sock:
    sock.sendall(b"POST /public/cancel HTTP/1.1\r\nHost: fixture.test\r\nContent-Length: 100000\r\n\r\npartial")
    time.sleep(.1)
for attempt in range(30):
    if request("/public/after-cancel")[0] == 200: break
    time.sleep(.1)
else: raise AssertionError("request capacity did not recover after cancelled upload")
checks.append("cancelled_upload_releases_request_capacity")
records = state()
assert not any(record["path"] in ("/private/no-auth", "/public/cl-conflict") for record in records)
assert not any(record["path"] == "/public/cancel" and record["complete"] for record in records)
checks.append("denied_malformed_cancelled_requests_not_committed")
print(json.dumps({"passed": checks, "origin_requests": len(records)}))
'''


def docker(*args):
    result = subprocess.run(["docker", *args], capture_output=True,
                            text=True, timeout=45)
    if result.returncode:
        raise RuntimeError(f"Docker command failed: {result.stderr.strip()}")
    return result.stdout.strip()


def run(image, python_image):
    gateway_id = docker("image", "inspect", image, "--format", "{{.Id}}")
    python_id = docker("image", "inspect", python_image, "--format", "{{.Id}}")
    prefix = "hangang-review-round4-" + uuid.uuid4().hex[:12]
    network = prefix + "-net"
    containers = []
    created_network = False
    with tempfile.TemporaryDirectory(prefix=prefix) as directory:
        root = Path(directory)
        root.chmod(0o755)
        state_dir = root / "gateway-state"
        state_dir.mkdir(mode=0o700)
        (root / "origin.py").write_text(ORIGIN)
        (root / "client.py").write_text(CLIENT)
        config = {"http": [
            {"id": "private", "path_prefix": "/private", "backends": ["http://origin:8081"],
             "auth": {"url": "http://origin:8081/check", "request_headers": ["authorization"],
                      "response_headers": [], "forward_response": True}},
            {"id": "public", "path_prefix": "/public", "backends": ["http://origin:8081"]}
        ]}
        (state_dir / "config.json").write_text(json.dumps(config))
        try:
            docker("network", "create", "--internal", "--label", "hangang.review=round4", network)
            created_network = True
            for role, selected, args in [
                ("origin", python_id, ["python", "/fixture/origin.py"]),
                ("gateway", gateway_id, ["/hangang", "--config", "/data/config.json",
                    "--listen", "0.0.0.0:8080", "--admin-socket", "/data/admin.sock",
                    "--admin-users-db", "/data/users.sqlite3",
                    "--admin-token", "fixture-only-admin-not-a-secret",
                    "--max-requests", "1", "--max-connections", "16",
                    "--threads", "2", "--lua-workers", "1", "--connection-idle-seconds", "5"]),
            ]:
                name = prefix + "-" + role
                containers.append(name)
                writable = (["--mount", f"type=bind,source={state_dir},target=/data"]
                            if role == "gateway" else [])
                docker("run", "--detach", "--pull=never", "--name", name,
                       "--network", network, "--network-alias", role,
                       "--label", "hangang.review=round4", "--read-only",
                       "--cap-drop=ALL", "--security-opt=no-new-privileges",
                       "--memory=128m", "--pids-limit=64", "--cpus=1",
                       "--tmpfs", "/tmp:rw,nosuid,nodev,size=16m,mode=1777",
                       "--mount", f"type=bind,source={root},target=/fixture,readonly",
                       *writable,
                       "--entrypoint", args[0], selected, *args[1:])
            client_name = prefix + "-client"
            containers.append(client_name)
            output = docker("run", "--rm", "--pull=never", "--name", client_name,
                            "--network", network, "--label", "hangang.review=round4",
                            "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                            "--memory=128m", "--pids-limit=32", "--cpus=1",
                            "--mount", f"type=bind,source={root},target=/fixture,readonly",
                            python_id, "python", "/fixture/client.py")
            report = json.loads(output)
            report.update(gateway_image=gateway_id, python_image=python_id,
                          internal_network=True, published_ports=0)
            return report
        except Exception:
            for name in containers[:2]:
                logs = subprocess.run(["docker", "logs", "--tail", "20", name],
                                      capture_output=True, text=True, timeout=10)
                print(logs.stdout + logs.stderr)
            raise
        finally:
            for name in reversed(containers):
                subprocess.run(["docker", "rm", "--force", name], capture_output=True, timeout=15)
            if created_network:
                docker("network", "rm", network)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="Existing local gateway image")
    parser.add_argument("--python-image", default="python:3.12.13-slim")
    args = parser.parse_args()
    print(json.dumps(run(args.image, args.python_image), indent=2))


if __name__ == "__main__":
    main()
