#!/usr/bin/env python3
"""Owned loopback gateway: traffic records must reflect the accepting listener.

Run with HANGANG_BIN pointing at the built gateway. No production services or
published ports are contacted. The predecessor binary must fail this test.
"""
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT=Path(__file__).resolve().parents[1]
BINARY=Path(os.environ.get('HANGANG_BIN',ROOT/'target/debug/hangang')).resolve()


def free_port(exclude):
    while True:
        with socket.socket() as item:
            item.bind(('127.0.0.1',0));port=item.getsockname()[1]
        if port not in exclude:
            exclude.add(port);return port


def get(port,path,headers=None):
    client=http.client.HTTPConnection('127.0.0.1',port,timeout=8)
    try:
        client.request('GET',path,headers=headers or {})
        response=client.getresponse();return response.status,response.read()
    finally:client.close()


def records(admin,token):
    status,body=get(admin,'/v1/traffic?limit=128',{'Authorization':'Bearer '+token})
    assert status==200,(status,body[:200])
    return json.loads(body)['records']


def await_record(admin,token,path,expected_status):
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
        found=[row for row in records(admin,token) if row['path']==path]
        if found:
            assert len(found)==1,found
            assert found[0]['status']==expected_status,found[0]
            return found[0]
        time.sleep(.05)
    raise AssertionError('traffic record absent: '+path)


def assert_listener(row,kind,identifier):
    assert row['listener']=={'kind':kind,'id':identifier},row


def main():
    if not BINARY.is_file():raise RuntimeError('build gateway or set HANGANG_BIN')
    arrived=threading.Event();release=threading.Event()
    class Origin(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith('/hit/hold'):
                arrived.set()
                if not release.wait(5):raise RuntimeError('held request timeout')
            body=b'owned-origin'
            self.send_response(200);self.send_header('Content-Length',str(len(body)))
            self.end_headers();self.wfile.write(body)
        def log_message(self,*_args):pass

    origin=ThreadingHTTPServer(('127.0.0.1',0),Origin)
    origin.daemon_threads=True
    threading.Thread(target=origin.serve_forever,daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix='hangang-traffic-listener-') as directory:
            root=Path(directory);used={origin.server_port}
            ports={name:free_port(used) for name in ('default','alpha','beta','admin')}
            config={'http':[{'id':'shared-route','path_prefix':'/hit',
                             'listener_ids':['default','alpha','beta'],
                             'backends':[f'http://127.0.0.1:{origin.server_port}']}],
                    'public_http':[{'id':name,'listen':f'127.0.0.1:{ports[name]}',
                                    'enabled':True,'certificates':[]}
                                   for name in ('alpha','beta')]}
            state=root/'config.json';state.write_text(json.dumps(config))
            token=secrets.token_hex(24)
            with (root/'gateway.log').open('wb') as log:
                child=subprocess.Popen([str(BINARY),'--config',str(state),
                    '--listen',f"127.0.0.1:{ports['default']}",
                    '--admin',f"127.0.0.1:{ports['admin']}",
                    '--threads','2','--lua-workers','1','--max-requests','1',
                    '--drain-seconds','1'],
                    env={**os.environ,'HANGANG_ADMIN_TOKEN':token},stdout=log,stderr=log)
                try:
                    deadline=time.monotonic()+10
                    while True:
                        if child.poll() is not None:raise RuntimeError('owned gateway exited before readiness')
                        try:
                            status,_=get(ports['admin'],'/v1/config',{'Authorization':'Bearer '+token})
                            if status==200:break
                        except OSError:pass
                        if time.monotonic()>deadline:raise RuntimeError('owned readiness deadline')
                        time.sleep(.05)
                    cases=(('default','/hit/default'),('alpha','/hit/alpha'),('beta','/hit/beta'))
                    for name,path in cases:
                        status,_=get(ports[name],path,{'X-Hangang-Listener':'beta',
                            'X-Listener-Id':'default','X-Forwarded-Listener':'alpha'})
                        assert status==200,(name,status)
                        row=await_record(ports['admin'],token,path,200)
                        assert row['route_id']=='shared-route',row
                        assert_listener(row,'default' if name=='default' else 'public',
                                        'default' if name=='default' else name)
                    for name in ('default','alpha','beta'):
                        path='/missing/'+name
                        status,_=get(ports[name],path,{'X-Hangang-Listener':'default'})
                        assert status==404,(name,status)
                        row=await_record(ports['admin'],token,path,404)
                        assert row['route_id'] is None,row
                        assert_listener(row,'default' if name=='default' else 'public',
                                        'default' if name=='default' else name)
                    holder={}
                    def hold():holder['result']=get(ports['alpha'],'/hit/hold')
                    thread=threading.Thread(target=hold,daemon=True);thread.start()
                    assert arrived.wait(3),'origin never received held request'
                    status,_=get(ports['beta'],'/hit/rejected',{'X-Hangang-Listener':'alpha'})
                    assert status==503,status
                    row=await_record(ports['admin'],token,'/hit/rejected',503)
                    assert_listener(row,'public','beta')
                    release.set();thread.join(5)
                    assert not thread.is_alive() and holder['result'][0]==200,holder
                    row=await_record(ports['admin'],token,'/hit/hold',200)
                    assert_listener(row,'public','alpha')
                finally:
                    release.set();child.terminate()
                    try:child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.kill();child.wait(timeout=5)
    finally:
        release.set();origin.shutdown();origin.server_close()
    print('Owned listener traffic scope and admission recording: passed')


if __name__=='__main__':main()
