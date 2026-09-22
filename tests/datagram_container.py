#!/usr/bin/env python3
"""UDP and real HTTP/3 over opaque QUIC, entirely within an owned Docker bridge."""
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get('HANGANG_BINARY', ROOT / 'target/x86_64-unknown-linux-gnu/release/hangang')).resolve()
ENV = {k: v for k, v in os.environ.items() if k not in ('DOCKER_HOST', 'DOCKER_CONTEXT')}
ENDPOINT = 'unix:///var/run/docker.sock'


def docker(*args, timeout=60, check=True):
    result = subprocess.run(['docker', '--host', ENDPOINT, *map(str, args)], env=ENV, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f'Docker {args[0]} failed: {result.stderr[-1500:]}')
    return result


def main():
    if not BINARY.is_file():
        raise SystemExit('Build a static binary with make static, or set HANGANG_BINARY to a container-compatible binary')
    if not stat.S_ISSOCK(Path('/var/run/docker.sock').stat().st_mode):
        raise SystemExit('A local Docker Unix socket is required')
    token = uuid.uuid4().hex[:12]
    label = 'hangang.datagram-test=' + token
    network = 'hangang-datagram-' + token
    image = 'hangang-datagram-test:' + token
    names = []
    with tempfile.TemporaryDirectory(prefix='hangang-datagram-') as directory:
        root = Path(directory)
        (root / 'Dockerfile').write_text('FROM python:3.12-slim\nCOPY wheels /wheels\nRUN pip install --no-cache-dir --no-index --find-links=/wheels aioquic==1.3.0\n')
        try:
            subprocess.run([os.sys.executable, '-m', 'pip', 'download', '--only-binary=:all:', '--python-version', '3.12', '--platform', 'manylinux2014_x86_64', '--platform', 'manylinux_2_28_x86_64', '--implementation', 'cp', '--abi', 'cp312', '--abi', 'abi3', '--dest', str(root/'wheels'), 'aioquic==1.3.0'], check=True, stdout=subprocess.DEVNULL, timeout=180)
            docker('build', '--network', 'none', '--label', label, '-t', image, root, timeout=300)
            docker('network', 'create', '--internal', '--label', label, network)
            info = json.loads(docker('network', 'inspect', network).stdout)[0]
            assert info['Internal'] and info['Driver'] == 'bridge'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=backend.example.test', '-addext', 'subjectAltName=DNS:backend.example.test', '-keyout', str(root/'tls.key'), '-out', str(root/'tls.pem')], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            (root/'tls.key').chmod(0o600)
            (root/'admin-token').write_text(secrets.token_hex(32))
            (root/'admin-token').chmod(0o600)
            (root/'admin.env').write_text('HANGANG_ADMIN_TOKEN='+(root/'admin-token').read_text()+'\n')
            (root/'admin.env').chmod(0o600)

            def start(role, command, extras=()):
                name = network + '-' + role
                names.append(name)
                docker('run', '-d', '--name', name, '--label', label, '--network', network, '--network-alias', role, '--user', f'{os.getuid()}:{os.getgid()}', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--read-only', '--tmpfs', '/tmp:rw,nosuid,size=32m', '--tmpfs', '/state:rw,nosuid,size=32m', '--pids-limit', '128', '--memory', '512m', '-e', 'PYTHONDONTWRITEBYTECODE=1', '-v', str(root)+':/fixture:ro', '-v', str(ROOT/'tests/fixtures/datagram/node.py')+':/node.py:ro', *extras, image, *command)
                return name

            backends = []
            for role in ('backend-a', 'backend-b'):
                name = start(role, ['python', '-u', '/node.py', 'server'], ['-e', 'BACKEND_LABEL='+role])
                for _ in range(100):
                    if 'ready' in docker('logs', name).stdout:
                        break
                    time.sleep(.1)
                else:
                    raise RuntimeError('backend did not start: '+docker('logs', name).stderr[-2000:])
                address = json.loads(docker('inspect', name).stdout)[0]['NetworkSettings']['Networks'][network]['IPAddress']
                backends.append(address)
            config = {'revision': 0, 'http': [], 'tcp': [], 'udp': [
                {'id': 'quic', 'protocol': 'quic', 'listen': '0.0.0.0:5443', 'backends': [ip+':4443' for ip in backends]},
                {'id': 'datagrams', 'protocol': 'udp', 'listen': '0.0.0.0:5444', 'backends': [ip+':4444' for ip in backends], 'max_datagram_bytes': 2048},
            ]}
            (root/'config.json').write_text(json.dumps(config))
            gateway = start('gateway', ['sh', '-c', 'cp /fixture/config.json /state/config.json && exec /hangang --config /state/config.json --listen 0.0.0.0:8080 --admin 0.0.0.0:9000 --allow-insecure-admin --threads 2 --lua-workers 1'], ['--env-file', str(root/'admin.env'), '-v', str(BINARY)+':/hangang:ro'])
            for _ in range(100):
                ready = docker('exec', gateway, 'python', '-c', "import os,urllib.request; urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:9000/healthz',headers={'Authorization':'Bearer '+os.environ['HANGANG_ADMIN_TOKEN']}),timeout=1)", check=False)
                if ready.returncode == 0:
                    break
                time.sleep(.1)
            else:
                raise RuntimeError('gateway did not become ready: '+docker('logs', gateway).stdout[-1500:]+docker('logs', gateway).stderr[-1000:]+ready.stderr[-1000:])
            client = start('client', ['python', '-u', '/node.py', 'client'])
            result = docker('wait', client, timeout=120)
            output = docker('logs', client)
            if result.stdout.strip() != '0':
                raise RuntimeError('datagram client failed: '+output.stdout[-2000:]+output.stderr[-2000:])
            print(output.stdout.strip())
        finally:
            for name in reversed(names):
                docker('rm', '-f', name, check=False)
            docker('network', 'rm', network, check=False)
            docker('image', 'rm', image, check=False)
        assert not docker('ps', '-aq', '--filter', 'label='+label).stdout.strip()
        assert not docker('network', 'ls', '-q', '--filter', 'label='+label).stdout.strip()
        print('Owned containers and network cleaned up')


if __name__ == '__main__':
    main()
