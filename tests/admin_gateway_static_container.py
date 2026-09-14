#!/usr/bin/env python3
"""Exercise the static admin relay as Docker PID 1 with a hanging SSE response.

Build the binary first with `make static` (or set HANGANG_ADMIN_RELAY_BINARY).
Set HANGANG_ADMIN_RELAY_IMAGE to test an existing owned image without rebuilding it.
Only a uniquely named fixture container and, by default, a fixture image are created.
"""
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BINARY = ROOT / "target/x86_64-unknown-linux-gnu/release/hangang-admin-gateway"


def docker(*args, check=True, **kwargs):
    return subprocess.run(["docker", *args], check=check, **kwargs)


def inspect(name, field):
    return docker("inspect", "--format", field, name, capture_output=True, text=True).stdout.strip()


def await_relay_address(name):
    for _ in range(100):
        logs = docker("logs", name, capture_output=True, text=True)
        match = re.search(r"HANGANG_ADMIN_GATEWAY_LISTEN (127\.0\.0\.1:\d+)", logs.stdout)
        if match:
            return match.group(1)
        if inspect(name, "{{.State.Running}}") != "true":
            raise AssertionError(f"fixture relay exited before readiness: {logs.stderr}")
        time.sleep(0.1)
    raise AssertionError(f"fixture relay did not report readiness: {logs.stdout}{logs.stderr}")


def serve_sse(listener, first_sent, release):
    connection = None
    try:
        listener.settimeout(10)
        connection, _ = listener.accept()
        connection.settimeout(10)
        request = b""
        while b"\r\n\r\n" not in request:
            part = connection.recv(4096)
            if not part or len(request) + len(part) > 8192:
                return
            request += part
        assert request.startswith(b"GET /events HTTP/1.1\r\n"), request[:100]
        connection.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/event-stream\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"d\r\ndata: first\n\n\r\n"
        )
        first_sent.set()
        release.wait(10)
    finally:
        if connection is not None:
            connection.close()
        listener.close()


def main():
    suffix = secrets.token_hex(6)
    image = os.environ.get("HANGANG_ADMIN_RELAY_IMAGE")
    owned_image = image is None
    if owned_image:
        image = f"hangang-admin-relay-static-check:{suffix}"
    name = f"hangang-admin-relay-static-check-{suffix}"
    created = False
    first_sent = threading.Event()
    release = threading.Event()
    client = None
    with tempfile.TemporaryDirectory(prefix="hangang-admin-relay-static-") as directory:
        root = Path(directory)
        root.chmod(0o755)
        socket_path = root / "admin.sock"
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(str(socket_path))
        socket_path.chmod(0o777)
        listener.listen(1)
        backend = threading.Thread(target=serve_sse, args=(listener, first_sent, release), daemon=True)
        backend.start()
        try:
            if owned_image:
                binary = Path(os.environ.get("HANGANG_ADMIN_RELAY_BINARY", DEFAULT_BINARY))
                if not binary.is_file():
                    raise FileNotFoundError(f"build the static admin relay first: {binary}")
                image_root = root / "image"
                image_root.mkdir()
                shutil.copy2(binary, image_root / "hangang-admin-gateway")
                (image_root / "Dockerfile").write_text(
                    "FROM scratch\n"
                    "COPY --chmod=0555 hangang-admin-gateway /hangang-admin-gateway\n"
                    "USER 65532:65532\n"
                    "WORKDIR /data\n"
                    'ENTRYPOINT ["/hangang-admin-gateway"]\n'
                )
                docker("build", "--network=none", "--pull=false", "-t", image, str(image_root), stdout=subprocess.DEVNULL, timeout=120)
            docker(
                "run", "-d", "--name", name, "--read-only", "--network=host",
                "--memory=256m", "--cpus=1",
                "--mount", f"type=bind,source={root},target=/data,readonly",
                image, "--listen", "127.0.0.1:0", "--admin-socket", "/data/admin.sock",
                "--shutdown-grace-seconds", "1", stdout=subprocess.DEVNULL, timeout=20,
            )
            created = True
            assert inspect(name, "{{.Path}}") == "/hangang-admin-gateway"
            address = await_relay_address(name)
            client = socket.create_connection(("127.0.0.1", int(address.rsplit(":", 1)[1])), timeout=3)
            client.settimeout(3)
            client.sendall(b"GET /events HTTP/1.1\r\nHost: console.example.test\r\n\r\n")
            response = b""
            while b"data: first" not in response:
                part = client.recv(4096)
                assert part, f"relay closed before the SSE frame: {response!r}"
                response += part
            assert response.startswith(b"HTTP/1.1 200"), response[:100]
            assert first_sent.wait(2), "fake admin did not send the SSE frame"

            started = time.monotonic()
            docker("stop", "--time", "5", name, stdout=subprocess.DEVNULL, timeout=10)
            elapsed = time.monotonic() - started
            assert inspect(name, "{{.State.ExitCode}}") == "0", "PID 1 did not exit cleanly"
            assert inspect(name, "{{.State.OOMKilled}}") == "false"
            assert 0.8 <= elapsed < 4, f"SSE drain exceeded the one-second grace: {elapsed:.2f}s"
            assert client.recv(1) == b"", "client SSE socket remained open after relay exit"
            print(f"Static admin relay PID 1: SIGTERM clean exit and SSE deadline passed ({elapsed:.2f}s)")
        finally:
            release.set()
            if client is not None:
                client.close()
            backend.join(timeout=2)
            if created:
                docker("rm", "--force", name, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if owned_image:
                docker("image", "rm", image, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
