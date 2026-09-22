#!/usr/bin/env python3
"""Owned Docker TCP/UDP IPVS direct-return proof."""
import ipaddress, json, os, shutil, subprocess, sys, tempfile, uuid
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run(args, check=True, timeout=90, env=None):
    if args and args[0] == "docker":
        args = ["docker", "--host", "unix:///var/run/docker.sock", *args[1:]]
    env = {key: value for key, value in (os.environ if env is None else env).items()
           if key not in ("DOCKER_HOST", "DOCKER_CONTEXT")}
    return subprocess.run(args, check=check, text=True, capture_output=True, timeout=timeout, env=env)

def run_input(args, data, timeout=90):
    if args and args[0] == "docker":
        args = ["docker", "--host", "unix:///var/run/docker.sock", *args[1:]]
    env = {key: value for key, value in os.environ.items() if key not in ("DOCKER_HOST", "DOCKER_CONTEXT")}
    return subprocess.run(args, check=True, input=data, capture_output=True, timeout=timeout, env=env)

def service_keys(listing):
    return {(parts[0], parts[1]) for line in listing.splitlines()
            if len(parts := line.split()) >= 2 and parts[0] in ("TCP", "UDP")}

def main():
    if sys.platform != "linux" or shutil.which("docker") is None:
        print(json.dumps({"status": "blocked", "reason": "Linux Docker required"})); return 1
    if run(["docker", "info"], check=False, timeout=20).returncode:
        print(json.dumps({"status": "blocked", "reason": "Docker daemon unavailable"})); return 1
    token = uuid.uuid4().hex[:12]
    network = f"hangang-dsr-test-{token}"
    build_network = f"hangang-dsr-build-{token}"
    image = f"hangang-dsr-test:{token}"
    label = f"org.hangang.dsr.test={token}"
    names = {role: f"hangang-dsr-{token}-{role}" for role in ("backend1", "backend2", "director", "client")}
    config_path = None
    try:
        run(["docker", "network", "create", "--driver", "bridge", "--label", label, build_network])
        build_env = os.environ.copy(); build_env["DOCKER_BUILDKIT"] = "0"
        run(["docker", "build", "--network", build_network, "--tag", image,
             "--file", os.path.join(ROOT, "examples/dsr/Dockerfile"),
             os.path.join(ROOT, "examples/dsr")], timeout=300, env=build_env)
        run(["docker", "network", "rm", build_network], check=False)
        run(["docker", "network", "create", "--driver", "bridge", "--internal", "--label", label,
             "--opt", "com.docker.network.bridge.gateway_mode_ipv4=isolated", network])
        metadata = json.loads(run(["docker", "network", "inspect", network]).stdout)[0]
        if metadata.get("Driver") != "bridge" or not metadata.get("Internal"):
            raise RuntimeError("owned network is not an internal bridge")
        subnet = ipaddress.ip_network(metadata["IPAM"]["Config"][0]["Subnet"])
        vip = str(subnet.broadcast_address - 2)
        addresses = {"backend1": str(subnet.network_address + 10), "backend2": str(subnet.network_address + 11),
                     "director": str(subnet.network_address + 12), "client": str(subnet.network_address + 13)}
        common = ["docker", "run", "-d", "--network", network, "--label", label, "--cap-drop", "ALL",
                  "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=8m", "--tmpfs", "/run/dsr:rw,exec,nosuid,size=16m", "--pids-limit", "64",
                  "--memory", "128m", "--security-opt", "no-new-privileges", "--cap-add", "NET_ADMIN",
                  "--cap-add", "NET_RAW"]
        for role in ("backend1", "backend2"):
            run(common + ["--sysctl", "net.ipv4.conf.all.arp_ignore=1", "--sysctl", "net.ipv4.conf.all.arp_announce=2",
                          "--name", names[role], "--ip", addresses[role], image,
                          "python3", "/opt/dsr/backend.py", role, vip, addresses["client"]])
        for role in ("backend1", "backend2"):
            for _ in range(30):
                probe = run(["docker", "exec", names[role], "python3", "-c",
                             f"import socket; s=socket.create_connection(('{vip}',18080),.2); s.close()"], check=False)
                if probe.returncode == 0: break
                time.sleep(.2)
            else: raise RuntimeError(f"{role} did not start")
        run(common + ["--name", names["director"], "--ip", addresses["director"], image, "sleep", "120"])
        run(common + ["--name", names["client"], "--ip", addresses["client"], image, "sleep", "60"])
        binary = os.environ.get("HANGANG_DSR_BIN", os.path.join(ROOT, "target/release/hangang-dsr"))
        if not os.path.isfile(binary):
            run(["cargo", "build", "--locked", "--release", "--bin", "hangang-dsr"], timeout=300)
        config = {"services": []}
        for protocol, port in (("tcp", 18080), ("udp", 18081)):
            config["services"].append({"vip": vip, "port": port, "protocol": protocol,
                                        "scheduler": "rr", "backends": [
                                            {"address": addresses["backend1"], "port": port},
                                            {"address": addresses["backend2"], "port": port}]})
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as source:
            json.dump(config, source); config_path = source.name
        with open(binary, "rb") as source:
            run_input(["docker", "exec", "-i", names["director"], "python3", "-c",
                       "import sys; p='/run/dsr/hangang-dsr'; open(p,'wb').write(sys.stdin.buffer.read())"], source.read())
        with open(config_path, "rb") as source:
            run_input(["docker", "exec", "-i", names["director"], "python3", "-c",
                       "import sys; p='/tmp/dsr.json'; open(p,'wb').write(sys.stdin.buffer.read())"], source.read())
        run(["docker", "exec", names["director"], "chmod", "755", "/run/dsr/hangang-dsr"])
        run(["docker", "exec", names["director"], "chmod", "600", "/tmp/dsr.json"])
        run(["docker", "exec", names["director"], "ip", "addr", "add", vip + "/32", "dev", "eth0"])
        run(["docker", "exec", names["director"], "/run/dsr/hangang-dsr", "--config", "/tmp/dsr.json", "--apply"])
        run(["docker", "exec", names["director"], "ipvsadm", "-A", "-t", "192.0.2.254:18082", "-s", "rr"])
        # A later conflicting service must roll back only this invocation's additions.
        conflict = {"services": [dict(config["services"][0], port=18083,
                    backends=[dict(backend, port=18083) for backend in config["services"][0]["backends"]]),
                    config["services"][0]]}
        run_input(["docker", "exec", "-i", names["director"], "python3", "-c",
                   "import sys,os; p='/tmp/conflict.json'; open(p,'wb').write(sys.stdin.buffer.read()); os.chmod(p,0o600)"],
                  json.dumps(conflict).encode())
        rejected = run(["docker", "exec", names["director"], "/run/dsr/hangang-dsr",
                        "--config", "/tmp/conflict.json", "--apply"], check=False)
        if rejected.returncode == 0:
            raise RuntimeError("apply overwrote an existing service")
        listing = run(["docker", "exec", names["director"], "ipvsadm", "-Ln"]).stdout
        if ("TCP", f"{vip}:18083") in service_keys(listing) or ("TCP", f"{vip}:18080") not in service_keys(listing):
            raise RuntimeError("failed apply did not preserve existing services and roll back additions")
        # A mismatch in the second service must leave the first service intact too.
        run(["docker", "exec", names["director"], "ipvsadm", "-e", "-u", f"{vip}:18081",
             "-r", addresses["backend1"] + ":18081", "-g", "-w", "2"])
        rejected = run(["docker", "exec", names["director"], "/run/dsr/hangang-dsr",
                        "--config", "/tmp/dsr.json", "--cleanup"], check=False)
        if rejected.returncode == 0:
            raise RuntimeError("cleanup accepted a mismatched service")
        listing = run(["docker", "exec", names["director"], "ipvsadm", "-Ln"]).stdout
        if ("TCP", f"{vip}:18080") not in service_keys(listing) or ("UDP", f"{vip}:18081") not in service_keys(listing):
            raise RuntimeError("rejected cleanup partially removed configured services")
        run(["docker", "exec", names["director"], "ipvsadm", "-e", "-u", f"{vip}:18081",
             "-r", addresses["backend1"] + ":18081", "-g", "-w", "1"])
        macs = []
        for role in ("backend1", "backend2"):
            inspect = json.loads(run(["docker", "inspect", names[role]]).stdout)[0]
            macs.append(inspect["NetworkSettings"]["Networks"][network]["MacAddress"])
        director_inspect = json.loads(run(["docker", "inspect", names["director"]]).stdout)[0]
        director_mac = director_inspect["NetworkSettings"]["Networks"][network]["MacAddress"]
        result = run(["docker", "exec", names["client"], "python3", "/opt/dsr/client.py", vip,
                      addresses["client"], *macs, director_mac], timeout=60)
        evidence = json.loads(result.stdout)
        if not evidence.get("passed"):
            raise RuntimeError("direct-return proof did not pass")
        run(["docker", "exec", names["director"], "/run/dsr/hangang-dsr", "--config", "/tmp/dsr.json", "--cleanup"])
        listing = run(["docker", "exec", names["director"], "ipvsadm", "-Ln"]).stdout
        if ("TCP", "192.0.2.254:18082") not in service_keys(listing):
            raise RuntimeError("cleanup removed or failed to preserve unrelated IPVS service")
        if ("TCP", f"{vip}:18080") in service_keys(listing) or ("UDP", f"{vip}:18081") in service_keys(listing):
            raise RuntimeError("cleanup left a configured IPVS service behind")
        os.unlink(config_path)
        config_path = None
        print(json.dumps({"status": "passed", "network": "owned_internal_bridge",
                          "tcp_udp": True, "source_ip_preserved": True,
                          "backend_direct_return": True, "evidence": evidence}))
        return 0
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError, json.JSONDecodeError) as error:
        detail = getattr(error, "stderr", "") or str(error)
        logs = {}
        for role in ("backend1", "backend2", "director", "client"):
            output = run(["docker", "logs", names[role]], check=False, timeout=20)
            logs[role] = (output.stdout + output.stderr)[-1200:]
        listing = run(["docker", "exec", names["director"], "ipvsadm", "-Ln", "--stats"], check=False, timeout=20)
        logs["ipvs"] = (listing.stdout + listing.stderr)[-2400:]
        print(json.dumps({"status": "blocked", "reason": str(detail)[-1200:], "logs": logs})); return 1
    finally:
        if config_path:
            try: os.unlink(config_path)
            except OSError: pass
        for name in names.values():
            run(["docker", "rm", "-f", name], check=False, timeout=30)
        run(["docker", "network", "rm", network], check=False, timeout=30)
        run(["docker", "network", "rm", build_network], check=False, timeout=30)
        run(["docker", "image", "rm", "-f", image], check=False, timeout=60)
        if run(["docker", "ps", "-aq", "--filter", "label=" + label]).stdout.strip():
            raise RuntimeError("owned DSR containers remain after cleanup")
        if run(["docker", "network", "ls", "-q", "--filter", "label=" + label]).stdout.strip():
            raise RuntimeError("owned DSR networks remain after cleanup")

if __name__ == "__main__":
    raise SystemExit(main())
