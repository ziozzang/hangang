#!/usr/bin/env python3
"""Owned, disposable kind qualification for the live Ingress controller."""
from __future__ import annotations

import base64
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
KIND = ROOT / "target/test-tools/kind"


def run(*args: str, input_text: str | None = None, timeout: int = 300) -> str:
    result = subprocess.run(
        args,
        cwd=ROOT,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
    if result.returncode:
        raise RuntimeError(f"command failed ({' '.join(args)}):\n{result.stdout}")
    return result.stdout


def kubectl(node: str, *args: str, input_text: str | None = None) -> str:
    return run("docker", "exec", "-i", node, "kubectl", *args, input_text=input_text)


def child_pid(node: str) -> str:
    return kubectl(
        node, "exec", "deployment/hangang", "--", "/bin/sh", "-c",
        "cat /proc/1/task/1/children",
    ).strip()


def wait_generation_replaced(node: str, previous: str, timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        current = child_pid(node)
        if current and current != previous:
            return
        time.sleep(0.25)
    raise AssertionError("supervisor did not replace the serving child")


def wait_status(node: str, expected: str, timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = kubectl(
            node, "get", "ingress", "live", "-o",
            "jsonpath={.status.loadBalancer.ingress[0].ip}",
        )
        if value == expected:
            return
        time.sleep(0.25)
    raise AssertionError(f"Ingress status was not published as {expected}")


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def get(url: str, expected: int, timeout: float = 30) -> bytes:
    deadline = time.monotonic() + timeout
    last = "no response"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                body = response.read()
                if response.status == expected:
                    return body
                last = f"HTTP {response.status}"
        except urllib.error.HTTPError as error:
            if error.code == expected:
                return error.read()
            last = f"HTTP {error.code}"
        except OSError as error:
            last = str(error)
        time.sleep(0.25)
    raise AssertionError(f"{url} did not return {expected}: {last}")


def tls_get(port: int, ca: Path, expected: int = 200, timeout: float = 30) -> bytes:
    deadline = time.monotonic() + timeout
    last = "no response"
    while time.monotonic() < deadline:
        try:
            context = ssl.create_default_context(cafile=str(ca))
            with socket.create_connection(("127.0.0.1", port), timeout=2) as raw:
                with context.wrap_socket(raw, server_hostname="app.test") as stream:
                    stream.sendall(b"GET /ui/ HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n")
                    data = b""
                    while chunk := stream.recv(65536):
                        data += chunk
            status = int(data.split(b" ", 2)[1])
            if status == expected:
                return data.split(b"\r\n\r\n", 1)[1]
            last = f"HTTP {status}"
        except (OSError, ssl.SSLError, ValueError, IndexError) as error:
            last = str(error)
        time.sleep(0.25)
    raise AssertionError(f"TLS endpoint did not return {expected}: {last}")


def certificate(temp: Path, name: str) -> tuple[Path, Path]:
    cert = temp / f"{name}.crt"
    key = temp / f"{name}.key"
    run(
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-days", "1", "-subj", "/CN=app.test",
        "-addext", "subjectAltName=DNS:app.test",
        "-keyout", str(key), "-out", str(cert), timeout=60,
    )
    return cert, key


def secret_manifest(cert: Path, key: Path) -> str:
    cert_data = base64.b64encode(cert.read_bytes()).decode()
    key_data = base64.b64encode(key.read_bytes()).decode()
    return f"""apiVersion: v1
kind: Secret
metadata:
  name: live-tls
type: kubernetes.io/tls
data:
  tls.crt: {cert_data}
  tls.key: {key_data}
"""


def main() -> None:
    if not KIND.exists():
        print(f"SKIP: kind binary is absent: {KIND}")
        return
    run("docker", "info", timeout=30)
    binary_override = os.environ.get("HANGANG_BINARY")
    if binary_override is None:
        run("cargo", "build", "--bin", "hangang", timeout=600)
        binary = ROOT / "target/debug/hangang"
    else:
        binary = Path(binary_override).resolve()
    suffix = uuid.uuid4().hex[:10]
    cluster = f"hangang-controller-{suffix}"
    node = f"{cluster}-control-plane"
    image = f"hangang-kind:{suffix}"
    network = f"hangang-kind-{suffix}"
    host_port = free_port()
    with tempfile.TemporaryDirectory(prefix="hangang-kind-") as directory:
        temp = Path(directory)
        kubeconfig = temp / "kubeconfig"
        dockerfile = temp / "Dockerfile"
        dockerfile.write_text(
            "FROM debian:trixie-slim\n"
            "COPY hangang /usr/local/bin/hangang\n"
            "USER 65532:65532\n"
            "ENTRYPOINT [\"/usr/local/bin/hangang\"]\n",
            encoding="utf-8",
        )
        executable = temp / "hangang"
        executable.write_bytes(binary.read_bytes())
        executable.chmod(0o755)
        cert1, key1 = certificate(temp, "first")
        cert2, key2 = certificate(temp, "second")
        run("docker", "build", "-t", image, str(temp), timeout=600)
        kind_config = f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraPortMappings:
      - containerPort: 30080
        hostPort: {host_port}
        listenAddress: 127.0.0.1
        protocol: TCP
"""
        try:
            run("docker", "network", "create", network)
            os.environ["KIND_EXPERIMENTAL_DOCKER_NETWORK"] = network
            run(
                str(KIND), "create", "cluster", "--name", cluster,
                "--kubeconfig", str(kubeconfig), "--config", "-",
                input_text=kind_config, timeout=600,
            )
            run(str(KIND), "load", "docker-image", image, "--name", cluster, timeout=300)
            manifest = resources(image) + "---\n" + secret_manifest(cert1, key1)
            kubectl(node, "apply", "-f", "-", input_text=manifest)
            kubectl(node, "rollout", "status", "deployment/backend", "--timeout=90s")
            kubectl(node, "rollout", "status", "deployment/hangang", "--timeout=90s")
            body = tls_get(host_port, cert1)
            assert b"Hangang" in body

            wait_status(node, "192.0.2.1")

            # A malformed neighboring Secret must not block rotation of a valid
            # Ingress. Successful trust in cert2 proves a new snapshot applied,
            # rather than merely observing the controller's last-good state.
            invalid_ingress = ingress_manifest().replace("name: live", "name: z.invalid").replace(
                "app.test", "invalid.test"
            ).replace("secretName: live-tls", "secretName: invalid-tls")
            invalid_secret = secret_manifest(cert1, key1).replace("name: live-tls", "name: invalid-tls").replace(
                base64.b64encode(cert1.read_bytes()).decode(),
                base64.b64encode(b"invalid certificate").decode(),
            )
            kubectl(node, "apply", "-f", "-", input_text=invalid_ingress + "---\n" + invalid_secret)
            kubectl(node, "apply", "-f", "-", input_text=secret_manifest(cert2, key2))
            body = tls_get(host_port, cert2)
            assert b"Hangang" in body

            kubectl(node, "delete", "secret", "live-tls", "--wait=true")
            try:
                tls_get(host_port, cert2, timeout=3)
                raise AssertionError("deleted TLS Secret remained active")
            except AssertionError as error:
                if "remained active" in str(error):
                    raise
            kubectl(node, "apply", "-f", "-", input_text=secret_manifest(cert2, key2))
            tls_get(host_port, cert2)

            kubectl(node, "delete", "ingress", "live", "--wait=true")
            try:
                tls_get(host_port, cert2, timeout=3)
                raise AssertionError("deleted Ingress remained active")
            except AssertionError as error:
                if "remained active" in str(error):
                    raise
            kubectl(node, "apply", "-f", "-", input_text=ingress_manifest())
            body = tls_get(host_port, cert2)
            assert b"Hangang" in body

            previous_child = child_pid(node)
            assert previous_child, "supervisor child PID is missing"
            kubectl(node, "exec", "deployment/hangang", "--", "/bin/sh", "-c", "kill -HUP 1")
            wait_generation_replaced(node, previous_child)
            body = tls_get(host_port, cert2)
            assert b"Hangang" in body
            print("kind Kubernetes controller qualification passed")
        except Exception:
            for command in [
                ("logs", "deployment/hangang", "--all-containers=true"),
                ("get", "ingress,service,secret,pod", "-o", "wide"),
                ("describe", "pod", "-l", "app=hangang"),
            ]:
                try:
                    print(kubectl(node, *command))
                except Exception as diagnostic_error:
                    print(f"diagnostic failed: {diagnostic_error}")
            raise
        finally:
            run(str(KIND), "delete", "cluster", "--name", cluster, timeout=300)
            subprocess.run(["docker", "image", "rm", "-f", image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["docker", "network", "rm", network], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def ingress_manifest() -> str:
    return """apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: live
spec:
  ingressClassName: hangang
  tls:
    - hosts: [app.test]
      secretName: live-tls
  rules:
    - host: app.test
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: backend
                port:
                  name: admin
"""


def resources(image: str) -> str:
    return f"""apiVersion: v1
kind: ServiceAccount
metadata:
  name: hangang
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: hangang
rules:
  - apiGroups: [\"\"]
    resources: [\"services\", \"secrets\"]
    verbs: [\"get\", \"list\", \"watch\"]
  - apiGroups: [\"networking.k8s.io\"]
    resources: [\"ingresses\"]
    verbs: [\"get\", \"list\", \"watch\"]
  - apiGroups: [\"networking.k8s.io\"]
    resources: [\"ingresses/status\"]
    verbs: [\"get\", \"patch\", \"update\"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: hangang
subjects:
  - kind: ServiceAccount
    name: hangang
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: hangang
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
spec:
  replicas: 1
  selector:
    matchLabels: {{app: backend}}
  template:
    metadata:
      labels: {{app: backend}}
    spec:
      automountServiceAccountToken: false
      securityContext:
        fsGroup: 65532
      containers:
        - name: backend
          image: {image}
          imagePullPolicy: Never
          args: [\"--config\", \"/data/routes.json\", \"--listen\", \"127.0.0.1:8081\", \"--admin\", \"0.0.0.0:9001\", \"--allow-insecure-admin\"]
          env:
            - name: HANGANG_ADMIN_TOKEN
              value: fixture-token-at-least-32-bytes
          volumeMounts:
            - name: data
              mountPath: /data
      volumes:
        - name: data
          emptyDir: {{}}
---
apiVersion: v1
kind: Service
metadata:
  name: backend
spec:
  selector: {{app: backend}}
  ports:
    - name: admin
      port: 9001
      targetPort: 9001
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hangang
spec:
  replicas: 1
  selector:
    matchLabels: {{app: hangang}}
  template:
    metadata:
      labels: {{app: hangang}}
    spec:
      serviceAccountName: hangang
      securityContext:
        fsGroup: 65532
      containers:
        - name: hangang
          image: {image}
          imagePullPolicy: Never
          args: [\"--supervised\", \"--kubernetes-controller\", \"--kubernetes-namespace\", \"default\", \"--kubernetes-tls\", \"--kubernetes-publish-address\", \"192.0.2.1\", \"--config\", \"/data/routes.json\", \"--listen\", \"0.0.0.0:8080\"]
          env:
            - name: HANGANG_ADMIN_TOKEN
              value: fixture-token-at-least-32-bytes
          volumeMounts:
            - name: data
              mountPath: /data
      volumes:
        - name: data
          emptyDir: {{}}
---
apiVersion: v1
kind: Service
metadata:
  name: hangang
spec:
  type: NodePort
  selector: {{app: hangang}}
  ports:
    - port: 80
      targetPort: 8080
      nodePort: 30080
---
{ingress_manifest()}"""


if __name__ == "__main__":
    main()
