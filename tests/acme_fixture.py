#!/usr/bin/env python3
"""Start an isolated, test-owned Pebble + challtestsrv pair.

This helper never pulls images. Set HANGANG_PEBBLE_TEST=1 and make the
Pebble images available locally before running the ignored integration tests.
The process prints one JSON line, then keeps the containers alive until it is
terminated. Cleanup is performed in a finally block.
"""
import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request


def run(*args, check=True, capture=False):
    return subprocess.run(args, check=check, text=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None)


def image():
    requested = os.environ.get("HANGANG_PEBBLE_IMAGE")
    candidates = [requested] if requested else [
        "ghcr.io/letsencrypt/pebble:latest", "letsencrypt/pebble:latest"
    ]
    for value in candidates:
        if value and run("docker", "image", "inspect", value, check=False, capture=True).returncode == 0:
            return value
    return None


def mapped_port(container, target):
    value = run("docker", "port", container, str(target), capture=True).stdout.strip()
    # docker prints 127.0.0.1:NNNN or 0.0.0.0:NNNN.
    return int(value.rsplit(":", 1)[1])


def wait_directory(port, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(
                    urllib.request.Request(f"https://127.0.0.1:{port}/dir"),
                    context=__import__("ssl")._create_unverified_context(),
                    timeout=1):
                return
        except Exception:
            time.sleep(.2)
    raise RuntimeError("Pebble directory did not become ready")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--start", action="store_true")
    parser.add_argument("--hostname", action="append", default=[])
    parser.add_argument("--eab", action="store_true",
                        help="require Pebble EAB using the documented test key")
    args = parser.parse_args()
    if not args.start:
        parser.error("--start is required")
    if shutil.which("docker") is None:
        print(json.dumps({"skip": "docker is unavailable"}), flush=True)
        return 0
    pebble_image = image()
    challenge_image = os.environ.get("HANGANG_PEBBLE_CHALLTESTSRV_IMAGE",
                                     pebble_image.replace(":latest", "-challtestsrv:latest")
                                     if pebble_image else "")
    if not pebble_image or run("docker", "image", "inspect", challenge_image,
                               check=False, capture=True).returncode != 0:
        print(json.dumps({"skip": "Pebble and pebble-challtestsrv images must already be local"}),
              flush=True)
        return 0

    suffix = f"hangang-acme-{os.getpid()}"
    network = suffix
    challenge = suffix + "-challtestsrv"
    pebble = suffix + "-pebble"
    temp = tempfile.mkdtemp(prefix="hangang-pebble-")
    alive = True
    try:
        run("docker", "network", "create", network, capture=True)
        gateway = run("docker", "network", "inspect", "-f",
                      "{{(index .IPAM.Config 0).Gateway}}", network,
                      capture=True).stdout.strip()
        run("docker", "run", "-d", "--name", challenge, "--network", network,
            "-p", "127.0.0.1::8055", challenge_image,
            "-defaultIPv4", gateway, "-defaultIPv6", "", "-dnsserver", ":8053",
            "-http01", "", "-https01", "", "-tlsalpn01", "", "-management", ":8055", capture=True)
        host_args = []
        for host in args.hostname:
            host_args += ["--add-host", f"{host}:host-gateway"]
        pebble_config = os.path.join(temp, "pebble-config.json")
        eab_kid = "kid-1"
        eab_key = "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W" # gitleaks:allow -- isolated test fixture
        if args.eab:
            config = {
                "pebble": {
                    "listenAddress": "0.0.0.0:14000",
                    "managementListenAddress": "0.0.0.0:15000",
                    "certificate": "test/certs/localhost/cert.pem",
                    "privateKey": "test/certs/localhost/key.pem",
                    "httpPort": 5002, "tlsPort": 5001,
                    "ocspResponderURL": "",
                    "externalAccountBindingRequired": True,
                    "externalAccountMACKeys": {eab_kid: eab_key},
                    "retryAfter": {"authz": 3, "order": 5},
                    "keyAlgorithm": "ecdsa",
                    "profiles": {"default": {"description": "test", "validityPeriod": 7776000}}
                }
            }
            with open(pebble_config, "w", encoding="utf-8") as output:
                json.dump(config, output)
        else:
            pebble_config = "/test/config/pebble-config.json"
        pebble_args = [
            "-e", "PEBBLE_VA_NOSLEEP=1", *host_args, "-p", "127.0.0.1::14000",
            "-p", "127.0.0.1::15000",
        ]
        if args.eab:
            pebble_args += ["--mount", f"type=bind,src={pebble_config},target=/test/config/acme-config.json,readonly"]
        run("docker", "run", "-d", "--name", pebble, "--network", network,
            *pebble_args,
            pebble_image, "-config", "/test/config/acme-config.json" if args.eab else "/test/config/pebble-config.json",
            "-strict", "-dnsserver", f"{challenge}:8053", capture=True)
        port = mapped_port(pebble, 14000)
        pebble_management = mapped_port(pebble, 15000)
        management = mapped_port(challenge, 8055)
        wait_directory(port)
        ca = os.path.join(temp, "pebble.minica.pem")
        run("docker", "cp", f"{pebble}:/test/certs/pebble.minica.pem", ca, capture=True)
        # Pebble's ACME issuer root is generated on startup and is distinct
        # from the static MiniCA root used by its HTTPS management endpoint.
        issuer_ca = os.path.join(temp, "pebble.issuer.pem")
        with urllib.request.urlopen(
                urllib.request.Request(f"https://127.0.0.1:{pebble_management}/roots/0"),
                context=__import__("ssl")._create_unverified_context(),
                timeout=2) as response:
            with open(issuer_ca, "wb") as output:
                output.write(response.read(128 * 1024 + 1))
        if os.path.getsize(issuer_ca) > 128 * 1024:
            raise RuntimeError("Pebble issuer root response is too large")
        print(json.dumps({
            "directory": f"https://127.0.0.1:{port}/dir",
            "management": f"http://127.0.0.1:{management}",
            "ca_path": ca,
            "issuer_ca_path": issuer_ca,
            "http_port": 5002,
            "eab_kid": eab_kid if args.eab else None,
            "eab_hmac_key_base64": eab_key if args.eab else None,
        }), flush=True)
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
        while True:
            time.sleep(60)
    except Exception as error:
        print(json.dumps({"skip": f"fixture failed: {error}"}), flush=True)
        return 0
    finally:
        for container in (pebble, challenge):
            run("docker", "rm", "-f", container, check=False, capture=True)
        run("docker", "network", "rm", network, check=False, capture=True)
        shutil.rmtree(temp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
