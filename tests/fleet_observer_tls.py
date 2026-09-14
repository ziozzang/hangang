#!/usr/bin/env python3
"""Owned loopback HTTPS qualification for the local fleet observation endpoint."""
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("HANGANG_BINARY", ROOT / "target/debug/hangang")).resolve()
ADMIN = "admin-owned-fixture-only-credential"
OLD = "A" * 48
NEW = "B" * 48


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def private_write(path, data):
    temp = path.with_name(path.name + ".new")
    with temp.open("xb") as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temp, path)


class FleetObserverTls(unittest.TestCase):
    def test_https_trust_auth_scope_and_rotation(self):
        self.assertTrue(BINARY.is_file(), "set HANGANG_BINARY to the qualified gateway")
        with tempfile.TemporaryDirectory(prefix="hangang-observer-tls-") as name:
            root = Path(name)
            cert, key = root / "cert.pem", root / "key.pem"
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-days", "1", "-subj", "/CN=localhost",
                "-addext", "subjectAltName=DNS:localhost",
                "-keyout", str(key), "-out", str(cert),
            ], check=True, capture_output=True, timeout=20)
            os.chmod(key, 0o600)
            config, observer, secret = root / "config.json", root / "observer.json", root / "observer.token"
            private_write(config, b'{"revision":0,"http":[],"tcp":[]}')
            private_write(secret, (OLD + "\n").encode())
            private_write(observer, json.dumps({"node_id": "owned.edge", "token_file": str(secret)}).encode())
            public_port, admin_port = free_port(), free_port()
            self.assertNotEqual(public_port, admin_port)
            command = [str(BINARY), "--config", str(config),
                       "--listen", f"127.0.0.1:{public_port}",
                       "--admin", f"127.0.0.1:{admin_port}",
                       "--admin-tls-cert", str(cert), "--admin-tls-key", str(key),
                       "--fleet-observer-config", str(observer), "--admin-token", ADMIN]
            trusted = ssl.create_default_context(cafile=str(cert))
            output = (root / "gateway.log").open("wb")
            child = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                     stdin=subprocess.DEVNULL, start_new_session=True)
            try:
                def request(path, token, context=trusted):
                    connection = http.client.HTTPSConnection("localhost", admin_port,
                                                             context=context, timeout=3)
                    try:
                        connection.request("GET", path, headers={"Authorization": "Bearer " + token})
                        response = connection.getresponse()
                        return response.status, response.read()
                    finally:
                        connection.close()

                deadline = time.monotonic() + 10
                while True:
                    self.assertIsNone(child.poll(), "owned gateway exited before readiness")
                    try:
                        if request("/v1/fleet/observation", OLD)[0] == 200:
                            break
                    except (OSError, ssl.SSLError):
                        pass
                    self.assertLess(time.monotonic(), deadline, "owned gateway did not become ready")
                    time.sleep(0.1)
                status, body = request("/v1/fleet/observation", OLD)
                self.assertEqual(status, 200)
                value = json.loads(body)
                self.assertEqual(value["node_id"], "owned.edge")
                self.assertNotIn(OLD.encode(), body)
                self.assertEqual(request("/v1/config", OLD)[0], 401)
                self.assertEqual(request("/v1/fleet/observation", ADMIN)[0], 401)
                with self.assertRaises(ssl.SSLCertVerificationError):
                    request("/v1/fleet/observation", OLD, ssl.create_default_context())
                private_write(secret, (NEW + "\n").encode())
                deadline = time.monotonic() + 4
                while True:
                    if request("/v1/fleet/observation", NEW)[0] == 200:
                        break
                    self.assertLess(time.monotonic(), deadline, "observer rotation not published")
                    time.sleep(0.1)
                self.assertEqual(request("/v1/fleet/observation", OLD)[0], 401)
            finally:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
                output.close()


if __name__ == "__main__":
    unittest.main()
