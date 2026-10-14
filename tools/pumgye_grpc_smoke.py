#!/usr/bin/env python3
"""Isolated actual Pumgye + Hangang client; mutates only a disposable policy DB."""
import argparse
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--server',required=True,type=Path)
    parser.add_argument('--client',required=True,type=Path)
    args=parser.parse_args()
    def port():
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0))
            return sock.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix='hangang-pumgye-grpc-owned-') as temporary:
        root=Path(temporary)
        root.chmod(0o700)
        def run(*argv):
            subprocess.run(argv,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        def cert(name,usage=None):
            run('openssl','req','-new','-newkey','rsa:2048','-nodes','-keyout',str(root/f'{name}.key'),'-out',str(root/f'{name}.csr'),'-subj',f'/CN={name}')
            if usage:
                ext=root/f'{name}.ext'
                ext.write_text(f'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage={usage}\nsubjectAltName=DNS:pumgye.example.test\n')
                run('openssl','x509','-req','-in',str(root/f'{name}.csr'),'-CA',str(root/'ca.pem'),'-CAkey',str(root/'ca.key'),'-CAcreateserial','-days','1','-extfile',str(ext),'-out',str(root/f'{name}.pem'))
            else:
                run('openssl','req','-x509','-key',str(root/'ca.key'),'-in',str(root/'ca.csr'),'-days','1','-out',str(root/'ca.pem'),'-addext','basicConstraints=critical,CA:TRUE')
        cert('ca');cert('server','serverAuth');cert('client','clientAuth')
        management,native,grpc_port=port(),port(),port()
        env=dict(os.environ,PUMGYE_ADMIN_TOKEN=secrets.token_hex(24),PUMGYE_DECISION_TOKEN=secrets.token_hex(24))
        initial={'version':1,'information_classes':['public'],'services':{'orders':{'permissions':['read'],'require_guard':True,'roles':{'reader':{'permissions':['read'],'information_classes':['public'],'minimum_aal':1}},'users':{'fixture':['reader']},'networks':[{'cidr':'192.0.2.0/24','roles':['reader']}]}}}
        policy=root/'policy.json';policy.write_text(json.dumps({'revision':1,'policy':initial}))
        config=root/'client.json';config.write_text(json.dumps({'transport':'grpc','decision_address':f'localhost:{grpc_port}','management_address':f'127.0.0.1:{management}','decision_token_env':'PUMGYE_DECISION_TOKEN','admin_token_env':'PUMGYE_ADMIN_TOKEN','timeout_ms':1000,'tls':{'server_name':'pumgye.example.test','ca':str(root/'ca.pem'),'certificate':str(root/'client.pem'),'key':str(root/'client.key')}}))
        argv=[str(args.server.resolve()),'--listen',f'127.0.0.1:{management}','--decision-listen',f'127.0.0.1:{native}','--grpc-listen',f'0.0.0.0:{grpc_port}','--database',str(root/'policy.sqlite3'),'--policy',str(policy),'--tls-cert',str(root/'server.pem'),'--tls-key',str(root/'server.key'),'--client-ca',str(root/'ca.pem')]
        with (root/'server.log').open('wb') as log:
            process=subprocess.Popen(argv,env=env,stdout=log,stderr=log)
            try:
                ready=False
                for _ in range(100):
                    if process.poll() is not None:
                        raise RuntimeError('owned server exited before readiness')
                    try:
                        with socket.create_connection(('127.0.0.1',grpc_port),timeout=.1):
                            ready=True
                            break
                    except OSError:time.sleep(.05)
                assert ready,'owned gRPC listener deadline'
                subprocess.run([str(args.client.resolve()),str(config)],env=env,check=True,timeout=20)
            finally:
                process.terminate()
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:process.kill();process.wait()


if __name__=='__main__':main()
