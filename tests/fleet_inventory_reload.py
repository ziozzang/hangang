#!/usr/bin/env python3
"""Owned process: group/role reload preserves administration and withdraws invalid inventory."""
from contextlib import ExitStack
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("HANGANG_BINARY", ROOT / "target/debug/hangang")).resolve()


def replace(path, value):
    staging = path.with_suffix(".new")
    with os.fdopen(os.open(staging, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w") as output:
        json.dump(value, output)
    staging.replace(path)


def stop(child):
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=8)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()


def main():
    with ExitStack() as stack:
        folder = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="hangang-fleet-labels-")))
        # Keep the unavailable peer socket owned throughout the fixture.
        peer = stack.enter_context(socket.socket())
        peer.bind(("127.0.0.1", 0))
        peer.listen(32)
        reserved = [socket.socket(), socket.socket()]
        try:
            for listener in reserved:
                listener.bind(("127.0.0.1", 0))
            public, admin = [listener.getsockname()[1] for listener in reserved]
        finally:
            for listener in reserved:
                listener.close()
        config, inventory, token_file = (folder / name for name in ("gateway.json", "inventory.json", "token"))
        replace(config, {"http": [], "tcp": []})
        token = secrets.token_hex(24)
        token_file.write_text(token + "\n")
        token_file.chmod(0o600)
        registered = {"node_id": "owned-peer", "endpoint": f"https://127.0.0.1:{peer.getsockname()[1]}", "token_file": str(token_file)}
        replace(inventory, {"peers": [registered]})
        admin_token = secrets.token_hex(24)
        log = stack.enter_context((folder / "gateway.log").open("wb"))
        child = subprocess.Popen([str(BINARY), "--config", str(config), "--fleet-inventory-config", str(inventory),
            "--listen", f"127.0.0.1:{public}", "--admin", f"127.0.0.1:{admin}",
            "--threads", "2", "--lua-workers", "1", "--drain-seconds", "1"],
            env={**os.environ, "HANGANG_ADMIN_TOKEN": admin_token}, stdout=log, stderr=log)
        stack.callback(stop, child)

        def get(path):
            connection = http.client.HTTPConnection("127.0.0.1", admin, timeout=2)
            try:
                connection.request("GET", path, headers={"Authorization": "Bearer " + admin_token})
                response = connection.getresponse()
                raw = response.read()
                assert response.status == 200
                assert token.encode() not in raw and admin_token.encode() not in raw
                assert str(folder).encode() not in raw
                return json.loads(raw)
            finally:
                connection.close()

        def until(predicate):
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                assert child.poll() is None, "owned process exited"
                try:
                    snapshot = get("/v1/fleet/observations")
                    if predicate(snapshot):
                        return snapshot
                except (OSError, http.client.HTTPException):
                    pass
                time.sleep(.05)
            raise AssertionError("inventory reload deadline exceeded")

        initial = until(lambda s: s["available"] and len(s["nodes"]) == 1)
        assert initial["nodes"][0]["group_id"] is None and initial["nodes"][0]["role"] is None
        process = initial["observer_instance_id"]
        replace(inventory, {"peers": [{**registered, "group_id": "east", "role": "gateway"}]})
        labeled = until(lambda s: s["generation"] != initial["generation"] and s["available"])
        assert labeled["observer_instance_id"] == process
        assert labeled["nodes"][0]["group_id"] == "east" and labeled["nodes"][0]["role"] == "gateway"
        assert labeled["nodes"][0]["observation"] is None and labeled["fresh_nodes"] == 0
        replace(inventory, {"peers": [{**registered, "group_id": "east", "role": "gateway"}]})
        time.sleep(1.3)
        assert get("/v1/fleet/observations")["generation"] == labeled["generation"]
        replace(inventory, {"peers": [{**registered, "group_id": " east", "role": "gateway"}]})
        withdrawn = until(lambda s: not s["available"])
        assert withdrawn["nodes"] == [] and withdrawn["expected_nodes"] is None and withdrawn["fresh_nodes"] is None
        assert get("/v1/config")["http"] == []
        replace(inventory, {"peers": [registered]})
        restored = until(lambda s: s["available"])
        assert restored["generation"] != withdrawn["generation"]
        assert restored["observer_instance_id"] == process
        assert restored["nodes"][0]["group_id"] is None and restored["nodes"][0]["role"] is None
        replace(inventory, {"peers": []})
        empty = until(lambda s: s["available"] and s["nodes"] == [])
        assert empty["expected_nodes"] == 0 and empty["fresh_nodes"] == 0
        print("Fleet labels passed: defaults, dynamic relabel, unchanged generation, withdrawal, recovery and removal")


if __name__ == "__main__":
    main()
