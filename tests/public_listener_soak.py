#!/usr/bin/env python3
"""Owned, bounded four-listener churn fixture; no production endpoints.

Runs for eight seconds with sixteen clients on loopback ports. Each request
must reach its own scoped origin while the same listener definitions survive
repeated authorized config publications. This is a correctness smoke, not a
throughput or production load benchmark.
"""
from __future__ import annotations
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get('HANGANG_BIN', ROOT / 'target/debug/hangang'))
TOKEN = 'owned-public-listener-soak'
DURATION = 8.0
CLIENTS = 16
NAMES = ('default', 'named-https', 'named-http', 'direct-https')


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__('localhost', timeout=3)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def free_ports(count):
    held=[]
    try:
        for _ in range(count):
            sock=socket.socket()
            sock.bind(('127.0.0.1',0))
            held.append(sock)
        return [sock.getsockname()[1] for sock in held]
    finally:
        for sock in held: sock.close()


def origin(body):
    class Handler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'
        def do_GET(self):
            payload=body.encode()
            self.send_response(200)
            self.send_header('Content-Type','text/plain')
            self.send_header('Content-Length',str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        def log_message(self,*_args): pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    server.daemon_threads=True
    thread=threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    return server,thread


def api(socket_path, method, path, document=None, revision=None):
    connection=UnixConnection(socket_path)
    headers={'Authorization':'Bearer '+TOKEN}
    if document is not None:
        headers['Content-Type']='application/json'
        headers['If-Match']=f'"{revision}"'
    try:
        connection.request(method,path,body=json.dumps(document) if document is not None else None,headers=headers)
        response=connection.getresponse();body=response.read()
        if response.status!=200:
            raise AssertionError(f'admin {method} returned {response.status}')
        return json.loads(body)
    finally:connection.close()


def listener_signature(listeners):
    return [(item['id'],item['listen'],tuple(cert['id'] for cert in item.get('certificates',[])))
            for item in listeners]


def run():
    if not BINARY.is_file():raise RuntimeError('set HANGANG_BIN to a built test binary')
    servers=[];child=None
    with tempfile.TemporaryDirectory(prefix='hangang-public-listener-soak-') as directory:
        folder=Path(directory)
        os.chmod(folder,0o700)
        try:
            for name in NAMES:
                servers.append(origin('scope:'+name))
            ports=free_ports(4)
            cert_file=folder/'cert.pem';key_file=folder/'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                            '-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost',
                            '-keyout',str(key_file),'-out',str(cert_file)],
                           check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            os.chmod(key_file,0o600)
            certs=lambda ident:[{'id':ident,'hosts':[],'default':True,
                                  'cert_file':str(cert_file),'key_file':str(key_file)}]
            listeners=[{'id':'named-https','listen':f'127.0.0.1:{ports[1]}','certificates':certs('one')},
                       {'id':'named-http','listen':f'127.0.0.1:{ports[2]}'},
                       {'id':'direct-https','listen':f'127.0.0.1:{ports[3]}','certificates':certs('two')}]
            routes=[]
            for index,name in enumerate(NAMES):
                route={'id':'route-'+name,'path_prefix':'/scope',
                       'backends':[f'http://127.0.0.1:{servers[index][0].server_port}']}
                if name!='default':route['listener_ids']=[name]
                routes.append(route)
            document={'revision':1,'certificates':[],'cache':None,'http':routes,'tcp':[],
                      'public_http':listeners}
            config=folder/'hangang.json';config.write_text(json.dumps(document)+'\n')
            os.chmod(config,0o600)
            admin=folder/'admin.sock'
            with (folder/'child.log').open('wb') as log:
                child=subprocess.Popen([str(BINARY),'--config',str(config),
                                        '--listen',f'127.0.0.1:{ports[0]}',
                                        '--admin-socket',str(admin),'--threads','2',
                                        '--lua-workers','1','--drain-seconds','1',
                                        '--max-header-bytes','32768'],
                                       env={**os.environ,'HANGANG_ADMIN_TOKEN':TOKEN},
                                       stdout=subprocess.DEVNULL,stderr=log)
                deadline=time.monotonic()+8
                while True:
                    if child.poll() is not None:raise AssertionError(f'child exited {child.returncode} before readiness')
                    try:
                        active=api(admin,'GET','/v1/config')
                        if active['revision']==1:break
                    except (OSError,AssertionError,ValueError):pass
                    if time.monotonic()>deadline:raise AssertionError('admin readiness deadline')
                    time.sleep(.05)
                assert listener_signature(active['public_http'])==listener_signature(listeners)
                stable_listeners=active['public_http']
                context=ssl.create_default_context(cafile=str(cert_file))
                stop=threading.Event();errors=[];lock=threading.Lock();counts=[0]*4
                def worker(number):
                    index=number%4
                    name=NAMES[index]
                    connection=None
                    while not stop.is_set():
                        try:
                            if connection is None:
                                connection=(http.client.HTTPSConnection('localhost',ports[index],timeout=2,context=context)
                                            if index in (1,3) else
                                            http.client.HTTPConnection('127.0.0.1',ports[index],timeout=2))
                            connection.request('GET','/scope',headers={'Host':'localhost'})
                            response=connection.getresponse();body=response.read()
                            if response.status!=200 or body!=('scope:'+name).encode():
                                raise AssertionError(f'scope/body mismatch on listener index {index}: status {response.status}')
                            with lock:counts[index]+=1
                        except Exception as error:
                            with lock:errors.append(f'client {number}: {type(error).__name__}: {error}')
                            stop.set()
                        time.sleep(.05)
                    if connection is not None:connection.close()
                workers=[threading.Thread(target=worker,args=(index,),daemon=True) for index in range(CLIENTS)]
                for thread in workers:thread.start()
                start=time.monotonic();publications=0
                while time.monotonic()-start<DURATION and not stop.is_set():
                    time.sleep(.35)
                    candidate=api(admin,'GET','/v1/config')
                    assert candidate['public_http']==stable_listeners
                    revision=candidate['revision']
                    candidate['http'][0]['priority']=publications%2
                    applied=api(admin,'PUT','/v1/config',candidate,revision)
                    assert applied['revision']==revision+1
                    assert applied['public_http']==stable_listeners
                    publications+=1
                stop.set()
                for thread in workers:thread.join(timeout=3)
                if any(thread.is_alive() for thread in workers):raise AssertionError('client did not stop')
                if errors:raise AssertionError(errors[0])
                if not all(counts):raise AssertionError('one or more listeners received no requests')
                if publications<3:raise AssertionError('configuration did not churn')
                print(f'PASS owned public listener soak: {CLIENTS} clients, {publications} publications, '
                      f'{sum(counts)} scoped requests, zero mismatches')
        finally:
            if child is not None and child.poll() is None:
                child.terminate()
                try:child.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    child.kill();child.wait(timeout=3)
            for server,thread in servers:
                server.shutdown();server.server_close();thread.join(timeout=2)

if __name__=='__main__':run()
