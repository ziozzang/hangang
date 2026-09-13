#!/usr/bin/env python3
"""Owned-process certificate restore, config reload, and listener handoff checks."""
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import tempfile
import time
import unittest
from smoke import BINARY, TOKEN, free_port

class AcmeRuntime(unittest.TestCase):
    def test_idle_connections_expire_and_remote_admin_needs_explicit_transport(self):
        rejected = subprocess.run([str(BINARY), '--admin', '192.0.2.1:9000', '--check'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn('non-loopback administration requires TLS', rejected.stderr)
        with tempfile.TemporaryDirectory(prefix='hangang-idle-') as directory:
            public, admin = free_port(), free_port()
            while public == admin: admin = free_port()
            process = subprocess.Popen([str(BINARY), '--config', str(Path(directory)/'routes.json'), '--listen', f'127.0.0.1:{public}', '--admin', f'127.0.0.1:{admin}', '--connection-idle-seconds', '1', '--threads', '2', '--lua-workers', '1'], env={**os.environ, 'HANGANG_ADMIN_TOKEN': TOKEN}, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic()+5
                while True:
                    try:
                        stream=socket.create_connection(('127.0.0.1',public),timeout=2)
                        break
                    except OSError:
                        if time.monotonic() > deadline: self.fail('idle test startup timeout')
                        time.sleep(.05)
                with stream:
                    started=time.monotonic()
                    self.assertEqual(stream.recv(1),b'')
                    self.assertLess(time.monotonic()-started,2)
                with socket.create_connection(('127.0.0.1',public),timeout=2) as stream:
                    stream.sendall(b'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
                    self.assertIn(b'404',stream.recv(256).split(b'\r\n')[0])
            finally:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: process.kill(); process.wait()
                process.stderr.close()

    def test_restore_reload_and_supervised_http_listener_handoff(self):
        with tempfile.TemporaryDirectory(prefix='hangang-acme-runtime-') as directory:
            root = Path(directory)
            cert, key = root/'cert.pem', root/'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','90','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            end = subprocess.check_output(['openssl','x509','-in',str(cert),'-noout','-enddate'],text=True).strip().split('=',1)[1]
            expires = int(ssl.cert_time_to_seconds(end))
            config = {'directory':'https://127.0.0.1:1/dir','domains':['localhost'],'account_path':str(root/'account.json'),'challenge':'http-01'}
            path=root/'acme.json'; path.write_text(json.dumps(config))
            (root/'account.tls.json').write_text(json.dumps({'domains':['localhost'],'certificate_pem':list(cert.read_bytes()),'private_key_pem':list(key.read_bytes()),'expires':expires}))
            ports=set()
            while len(ports)<3: ports.add(free_port())
            public,admin,challenge=ports
            command=[str(BINARY),'--supervised','--config',str(root/'routes.json'),'--listen',f'127.0.0.1:{public}','--admin',f'127.0.0.1:{admin}','--acme-config',str(path),'--acme-http-listen',f'127.0.0.1:{challenge}','--threads','2','--lua-workers','1','--drain-seconds','2']
            with (root/'process.log').open('w+') as log:
                process=subprocess.Popen(command,env={**os.environ,'HANGANG_ADMIN_TOKEN':TOKEN},stdout=log,stderr=log)
                def status():
                    connection=http.client.HTTPConnection('127.0.0.1',admin,timeout=2)
                    connection.request('GET','/v1/status',headers={'Authorization':f'Bearer {TOKEN}'})
                    response=connection.getresponse(); data=json.loads(response.read()); connection.close()
                    self.assertEqual(response.status,200)
                    return data
                def await_status(predicate):
                    deadline=time.monotonic()+12
                    while time.monotonic()<deadline:
                        if process.poll() is not None:
                            log.seek(0); self.fail(log.read())
                        try:
                            value=status()
                            if predicate(value): return value
                        except OSError: pass
                        time.sleep(.05)
                    log.seek(0); self.fail('status timeout: '+log.read())
                def probe():
                    context=ssl.create_default_context(cafile=str(cert))
                    with context.wrap_socket(socket.create_connection(('127.0.0.1',public),timeout=2),server_hostname='localhost') as stream:
                        stream.sendall(b'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
                        self.assertIn(b'404',stream.recv(256).split(b'\r\n')[0])
                    connection=http.client.HTTPConnection('127.0.0.1',challenge,timeout=2)
                    connection.request('GET','/.well-known/acme-challenge/not-owned',headers={'Host':'localhost'})
                    response=connection.getresponse(); response.read(); connection.close()
                    self.assertEqual(response.status,404)
                try:
                    first=await_status(lambda s:s['acme']['phase']=='ready')
                    self.assertEqual(first['acme']['expires_unix'],expires); probe()
                    path.write_text('{invalid')
                    await_status(lambda s:s['acme']['phase']=='configuration-error'); probe()
                    path.write_text(json.dumps(config))
                    # Malformed replacements never remove the last usable certificate.
                    process.send_signal(signal.SIGHUP)
                    second=await_status(lambda s:s['process_id']!=first['process_id'] and s['acme']['phase']=='ready')
                    self.assertNotEqual(first['process_id'],second['process_id']); probe()
                    self.assertFalse((root/'account.json').exists(), 'unneeded CA registration contacted despite a usable certificate')
                finally:
                    process.terminate()
                    try: process.wait(timeout=8)
                    except subprocess.TimeoutExpired: process.kill(); process.wait()

if __name__=='__main__': unittest.main(verbosity=2)
