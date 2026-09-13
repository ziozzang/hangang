#!/usr/bin/env python3
"""Run Redis integration tests against one disposable, loopback-only fixture."""
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def main():
    name = "hangang-configstore-redis-" + secrets.token_hex(6)
    port = free_port()
    tls_port = free_port()
    while tls_port == port:
        tls_port = free_port()
    created = False
    with tempfile.TemporaryDirectory(prefix="hangang-redis-tls-") as directory:
        root = Path(directory)
        # Redis runs unprivileged and must traverse/read the mounted fixture.
        os.chmod(root, 0o755)
        cert = root / "server.crt"
        key = root / "server.key"
        ca_cert = root / "ca.crt"
        ca_key = root / "ca.key"
        csr = root / "server.csr"
        extensions = root / "server.ext"
        wrong_ca = root / "wrong-ca.crt"
        run(
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=Hangang Redis Test CA",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout", str(ca_key), "-out", str(ca_cert),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        run(
            "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-subj", "/CN=localhost", "-keyout", str(key), "-out", str(csr),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        extensions.write_text(
            "[server_ext]\n"
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
            "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
        )
        run(
            "openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_cert),
            "-CAkey", str(ca_key), "-CAcreateserial", "-days", "1", "-out", str(cert),
            "-extfile", str(extensions), "-extensions", "server_ext",
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        # The disposable Redis process runs as the image's unprivileged user.
        os.chmod(key, 0o644)
        os.chmod(cert, 0o644)
        os.chmod(ca_cert, 0o644)
        run(
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=wrong-redis-ca", "-keyout", os.devnull, "-out", str(wrong_ca),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            run(
                "docker", "run", "-d", "--name", name,
                "-p", f"127.0.0.1:{port}:6379", "-p", f"127.0.0.1:{tls_port}:6380",
                "-v", f"{root}:/tls:ro", "redis:7-alpine",
                "redis-server", "--port", "6379", "--tls-port", "6380",
                "--tls-cert-file", "/tls/server.crt", "--tls-key-file", "/tls/server.key",
                "--tls-ca-cert-file", "/tls/ca.crt", "--tls-auth-clients", "no",
                stdout=subprocess.DEVNULL,
            )
            created = True
            for _ in range(120):
                ready = subprocess.run(
                    ["docker", "exec", name, "redis-cli", "-p", "6379", "PING"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                if ready.returncode == 0:
                    break
                time.sleep(.25)
            else:
                raise RuntimeError("Redis readiness timeout")
            for _ in range(120):
                ready = subprocess.run(
                    ["docker", "exec", name, "redis-cli", "--tls", "--insecure", "-p", "6380", "PING"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                if ready.returncode == 0:
                    break
                time.sleep(.25)
            else:
                raise RuntimeError("Redis TLS readiness timeout")
            env = {
                **os.environ,
                "HANGANG_TEST_REDIS_URL": f"redis://127.0.0.1:{port}/",
                "HANGANG_TEST_REDIS_TLS_URL": f"rediss://localhost:{tls_port}/",
                "HANGANG_TEST_REDIS_CA": str(ca_cert),
                "HANGANG_TEST_REDIS_WRONG_CA": str(wrong_ca),
                "HANGANG_TEST_REDIS_CONTAINER": name,
            }
            env["HANGANG_TEST_SHARED_DATABASE"] = env["HANGANG_TEST_REDIS_URL"]
            env["HANGANG_TEST_REDIS_KEY"] = "hangang:test:runtime:" + secrets.token_hex(12)
            command = ["cargo", "llvm-cov", "--no-report"] if os.environ.get("HANGANG_REDIS_COVERAGE") == "1" else ["cargo", "test"]
            run(*command, "--locked", "--test", "redis_store", "--", "redis_", "--test-threads=1", "--nocapture", "--include-ignored", env=env)
            run("cargo", "build", "--locked", "--bin", "hangang")
            run("python3", "tests/sql_smoke.py", env=env)
        finally:
            if created:
                run("docker", "rm", "--force", name, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
