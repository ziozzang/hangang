#!/usr/bin/env python3
"""Exercise memory/disk caching, reload, API update, restart and purge locally."""

import http.client
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = Path(__file__).with_name("hangang.json")
TOKEN = "hangang-cache-example-token"


class Backend(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    requests = 0
    lock = threading.Lock()

    def log_message(self, *_):
        pass

    def do_GET(self):
        with self.lock:
            type(self).requests += 1
            count = type(self).requests
        if self.path == "/catalog":
            body = json.dumps({"catalog_version": count, "items": ["river-map", "trail-guide"]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "public, max-age=60")
        else:
            body = b"ok\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def request(port, path, method="GET", body=None, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        data = response.read()
        return response.status, {key.lower(): value for key, value in response.getheaders()}, data
    finally:
        connection.close()


def admin(port, path, method="GET", payload=None, headers=None):
    request_headers = {"Authorization": f"Bearer {TOKEN}"}
    request_headers.update(headers or {})
    body = None
    if payload is not None:
        body = json.dumps(payload).encode()
        request_headers["Content-Type"] = "application/json"
    status, response_headers, data = request(
        port, path, method=method, body=body, headers=request_headers
    )
    if status // 100 != 2:
        raise AssertionError((method, path, status, data))
    return response_headers, json.loads(data) if data else None


def wait_ready(process, admin_port, log):
    for _ in range(200):
        if process.poll() is not None:
            log.seek(0)
            raise AssertionError(log.read())
        try:
            status, _, _ = request(
                admin_port,
                "/healthz",
                headers={"Authorization": f"Bearer {TOKEN}"},
            )
            if status == 200:
                return
        except OSError:
            pass
        time.sleep(0.05)
    raise AssertionError("gateway did not become ready")


def start(binary, config_path, log, public=None, admin_port=None):
    public = public or free_port()
    admin_port = admin_port or free_port()
    while public == admin_port:
        admin_port = free_port()
    process = subprocess.Popen(
        [
            str(binary),
            "--config",
            str(config_path),
            "--listen",
            f"127.0.0.1:{public}",
            "--admin",
            f"127.0.0.1:{admin_port}",
            "--admin-token",
            TOKEN,
            "--drain-seconds",
            "1",
        ],
        stdout=log,
        stderr=log,
    )
    wait_ready(process, admin_port, log)
    return process, public, admin_port


def stop(process):
    if process is None or process.poll() is not None:
        return
    process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def catalog(public_port):
    status, headers, body = request(public_port, "/catalog")
    assert status == 200, (status, body)
    return json.loads(body), headers


def wait_config(admin_port, ttl):
    for _ in range(100):
        _, config = admin(admin_port, "/v1/config")
        if config["http"][0]["cache"]["ttl_seconds"] == ttl:
            return config
        time.sleep(0.05)
    raise AssertionError("configuration reload did not publish")


def wait_disk_entries(admin_port, minimum):
    for _ in range(100):
        _, state = admin(admin_port, "/v1/cache")
        if state["active_fills"] == 0 and state["stats"]["disk_entries"] >= minimum:
            return
        time.sleep(0.05)
    raise AssertionError(f"disk cache did not publish {minimum} entries")


def main():
    binary = Path(os.environ.get("HANGANG_BINARY", ROOT / "target/debug/hangang")).resolve()
    if not binary.exists():
        raise SystemExit("Run cargo build first, or set HANGANG_BINARY.")
    backend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Backend)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="hangang-cache-example-") as temporary:
            temporary = Path(temporary)
            config_path = temporary / "hangang.json"
            config = json.loads(EXAMPLE.read_text())
            config["cache"]["disk"]["directory"] = str(temporary / "cache" / "instance-a")
            for route in config["http"]:
                route["backends"] = [f"http://127.0.0.1:{backend.server_port}"]
            config_path.write_text(json.dumps(config, indent=2) + "\n")
            subprocess.run(
                [str(binary), "--config", str(config_path), "--check"],
                check=True,
                capture_output=True,
            )

            with (temporary / "gateway.log").open("w+") as log:
                process, public, admin_port = start(binary, config_path, log)
                first, first_headers = catalog(public)
                second, second_headers = catalog(public)
                assert first == second and Backend.requests == 1
                assert "age" not in first_headers and "age" in second_headers
                wait_disk_entries(admin_port, 1)

                config["http"][0]["cache"]["ttl_seconds"] = 45
                replacement = temporary / "hangang.next.json"
                replacement.write_text(json.dumps(config, indent=2) + "\n")
                replacement.replace(config_path)
                wait_config(admin_port, 45)
                third, _ = catalog(public)
                assert third["catalog_version"] == 2 and Backend.requests == 2
                wait_disk_entries(admin_port, 2)

                response_headers, active = admin(admin_port, "/v1/config")
                active["http"][0]["cache"]["ttl_seconds"] = 60
                _, applied = admin(
                    admin_port,
                    "/v1/config",
                    method="PUT",
                    payload=active,
                    headers={"If-Match": response_headers["etag"]},
                )
                assert applied["http"][0]["cache"]["ttl_seconds"] == 60
                fourth, _ = catalog(public)
                assert fourth["catalog_version"] == 3 and Backend.requests == 3
                wait_disk_entries(admin_port, 3)
                stop(process)
                process = None

                # The public address is part of the upstream Host header and therefore the
                # conservative cache key. Keep it stable across restarts.
                process, public, admin_port = start(
                    binary, config_path, log, public=public, admin_port=admin_port
                )
                restarted, restarted_headers = catalog(public)
                assert restarted == fourth and Backend.requests == 3
                assert "age" in restarted_headers

                _, purged = admin(admin_port, "/v1/cache/purge", method="POST")
                assert purged == {"purged": True, "scope": "instance"}
                stop(process)
                process = None

                # Purge is durable: the removed disk entry must not reappear after restart.
                process, public, admin_port = start(
                    binary, config_path, log, public=public, admin_port=admin_port
                )
                after_purge, _ = catalog(public)
                assert after_purge["catalog_version"] == 4 and Backend.requests == 4
                wait_disk_entries(admin_port, 1)
                stop(process)
                process = None

                # A new entry written after purge remains addressable after the in-memory
                # purge generation resets on process restart.
                process, public, admin_port = start(
                    binary, config_path, log, public=public, admin_port=admin_port
                )
                post_purge_restart, post_purge_headers = catalog(public)
                assert post_purge_restart == after_purge and Backend.requests == 4
                assert "age" in post_purge_headers
                print("PASS: memory hit, disk restart, hot reload, API update and purge")
    finally:
        stop(process)
        backend.shutdown()
        backend.server_close()


if __name__ == "__main__":
    main()
