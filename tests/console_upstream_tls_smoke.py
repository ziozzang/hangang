#!/usr/bin/env python3
"""hangang-console reaching the authority's admin API over TLS (--upstream-ca).

Real authority with an admin TLS listener (owned private CA, IP SAN
127.0.0.1) and the real console with --upstream https://127.0.0.1:<port>
--upstream-ca. Checks: requests pass through the console; --upstream-ca with
a plaintext upstream is refused; a CA that does not sign the authority's
certificate is refused (the forwarded request answers 502, an identity check 401); the CA file is re-read when it changes (swap to
the wrong CA, then back). Run after cargo build --bin hangang --bin
hangang-console (HANGANG_BIN_DIR overrides target/debug). No operational
credentials.
"""
import json, os, pathlib, secrets, socket, ssl, subprocess, tempfile, time, urllib.request, urllib.error
ROOT=pathlib.Path(__file__).resolve().parents[1]
BIN=pathlib.Path(os.environ.get('HANGANG_BIN_DIR',ROOT/'target/debug'))

def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def openssl(*args):subprocess.run(['openssl',*args],check=True,capture_output=True)
def ca(root,name):
    openssl('req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-keyout',str(root/f'{name}.key'),'-out',str(root/f'{name}.pem'),'-days','2','-subj',f'/CN={name}','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign')
def request(origin,path,headers=None,context=None):
    req=urllib.request.Request(origin+path,headers=headers or {})
    try:
        with urllib.request.urlopen(req,timeout=5,context=context) as r:return r.status
    except urllib.error.HTTPError as e:return e.code
def ready(origin,process,context=None):
    for _ in range(200):
        if process.poll() is not None:raise RuntimeError('owned server exited')
        try:
            if urllib.request.urlopen(origin+'/ui/',timeout=.2,context=context).status==200:return
        except OSError:pass
        time.sleep(.05)
    raise RuntimeError('owned server readiness timeout')
def eventually(check,seconds=30):
    deadline=time.time()+seconds
    while time.time()<deadline:
        if check():return
        time.sleep(.5)
    raise AssertionError('condition not reached')

def main():
    system=secrets.token_hex(32);children=[]
    with tempfile.TemporaryDirectory(prefix='hangang-console-upstream-tls-') as tmp:
        root=pathlib.Path(tmp);root.chmod(0o700)
        ca(root,'ca');ca(root,'other')
        openssl('req','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-keyout',str(root/'admin.key'),'-out',str(root/'admin.csr'),'-subj','/CN=admin')
        (root/'ext.cnf').write_text('subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n')
        openssl('x509','-req','-in',str(root/'admin.csr'),'-CA',str(root/'ca.pem'),'-CAkey',str(root/'ca.key'),'-CAcreateserial','-out',str(root/'admin.pem'),'-days','2','-extfile',str(root/'ext.cnf'))
        (root/'admin.key').chmod(0o600)
        public,admin,console=port(),port(),port();authority=f'https://127.0.0.1:{admin}';origin=f'http://127.0.0.1:{console}'
        env={**os.environ,'HANGANG_ADMIN_TOKEN':system}
        log=open(root/'servers.log','wb')
        plugins=root/'plugins.json';plugins.write_text(json.dumps({'plugins':[]}));plugins.chmod(0o600)
        trust=root/'upstream-ca.pem';trust.write_bytes((root/'ca.pem').read_bytes())
        try:
            parent=subprocess.Popen([str(BIN/'hangang'),'--config',str(root/'config.json'),'--listen',f'127.0.0.1:{public}','--admin',f'127.0.0.1:{admin}','--admin-tls-cert',str(root/'admin.pem'),'--admin-tls-key',str(root/'admin.key'),'--threads','2','--lua-workers','1'],env=env,stdout=log,stderr=log);children.append(parent)
            ready(authority,parent,ssl.create_default_context(cafile=str(root/'ca.pem')))
            # --upstream-ca needs an HTTPS upstream.
            check=subprocess.run([str(BIN/'hangang-console'),'--upstream',f'http://127.0.0.1:{admin}','--upstream-ca',str(trust),'--plugins',str(plugins),'--check'],env=env,capture_output=True)
            assert check.returncode!=0 and b'requires an HTTPS upstream' in check.stderr,check
            con=subprocess.Popen([str(BIN/'hangang-console'),'--listen',f'127.0.0.1:{console}','--upstream',authority+'/','--upstream-ca',str(trust),'--plugins',str(plugins)],env=env,stdout=log,stderr=log);children.append(con);ready(origin,con)
            auth={'Authorization':'Bearer '+system}
            assert request(origin,'/v1/status',auth)==200
            setup=lambda:request(origin,'/v1/auth/setup')
            assert setup()==200
            # The CA is re-read: the wrong CA refuses the authority, the right one restores it.
            trust.write_bytes(b'not a certificate')
            time.sleep(11);assert setup()==200,'a broken CA keeps the current trust'
            trust.write_bytes((root/'other.pem').read_bytes())
            eventually(lambda:setup()==502)
            trust.write_bytes((root/'ca.pem').read_bytes())
            eventually(lambda:setup()==200)
            # A console trusting only the other CA cannot reach the authority.
            con.terminate();con.wait(timeout=5)
            trust.write_bytes((root/'other.pem').read_bytes())
            con=subprocess.Popen([str(BIN/'hangang-console'),'--listen',f'127.0.0.1:{console}','--upstream',authority+'/','--upstream-ca',str(trust),'--plugins',str(plugins)],env=env,stdout=log,stderr=log);children.append(con);ready(origin,con)
            assert setup()==502 and request(origin,'/v1/status',auth)==401
            print('PASS: console to the admin API over TLS with a private CA; plaintext with a CA refused; the wrong CA refused; CA changes re-read.')
        finally:
            for child in reversed(children):
                if child.poll() is None:
                    child.terminate()
                    try:child.wait(timeout=5)
                    except subprocess.TimeoutExpired:child.kill();child.wait()
            log.close()
if __name__=='__main__':main()
