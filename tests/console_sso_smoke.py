#!/usr/bin/env python3
"""Real Hangang authority + console SSO; an owned HOP1 identity fixture controls revocation.
Run after cargo build --bin hangang --bin hangang-console. No operational credentials.
"""
import json, os, pathlib, secrets, socket, struct, subprocess, tempfile, threading, time, urllib.request, urllib.error
ROOT=pathlib.Path(__file__).resolve().parents[1]

def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def request(origin,path,method='GET',data=None,headers=None):
    h={'Content-Type':'application/json',**(headers or {})};req=urllib.request.Request(origin+path,data=None if data is None else json.dumps(data).encode(),headers=h,method=method)
    try:
        with urllib.request.urlopen(req,timeout=5) as r:return r.status,json.loads(r.read() or b'{}')
    except urllib.error.HTTPError as e:
        raw=e.read()
        try:body=json.loads(raw)
        except ValueError:body={}
        return e.code,body

def exact(s,n):
    b=b''
    while len(b)<n:
        chunk=s.recv(n-len(b))
        if not chunk:raise EOFError
        b+=chunk
    return b
class Identity:
    def __init__(self,key):
        self.key=key;self.live=True;self.user='u_fixture';self.count=0;self.s=socket.socket();self.s.bind(('127.0.0.1',0));self.port=self.s.getsockname()[1];self.s.listen();threading.Thread(target=self.accept,daemon=True).start()
    def accept(self):
        while True:
            try:s,_=self.s.accept()
            except OSError:return
            threading.Thread(target=self.serve,args=(s,),daemon=True).start()
    def serve(self,s):
        try:
            magic,i,n=struct.unpack('!4sQI',exact(s,16));assert magic==b'HOP1' and i==0;assert exact(s,n)==self.key.encode();s.sendall(struct.pack('!4sQI',b'HOP1',0,1)+b'\1')
            while True:
                magic,i,n=struct.unpack('!4sQI',exact(s,16));data=exact(s,n);count=struct.unpack('!H',data[:2])[0];pos=2;headers={}
                for _ in range(count):
                    nl,vl=struct.unpack('!HI',data[pos:pos+6]);pos+=6;name=data[pos:pos+nl].decode();pos+=nl;value=data[pos:pos+vl];pos+=vl;headers[name]=value
                assert headers['cookie']==b'__Host-hopae=fixture-native-handle';self.count+=1
                pairs=[(b'x-forwarded-user',self.user.encode())];reply=struct.pack('!HH',200 if self.live else 403,len(pairs))
                for name,value in pairs:reply+=struct.pack('!HI',len(name),len(value))+name+value
                reply+=struct.pack('!I',0);s.sendall(struct.pack('!4sQI',b'HOP1',i,len(reply))+reply)
        except (OSError,EOFError):pass
        finally:s.close()

def ready(origin,process):
    for _ in range(200):
        if process.poll() is not None:raise RuntimeError('owned server exited')
        try:
            if urllib.request.urlopen(origin+'/ui/',timeout=.2).status==200:return
        except OSError:pass
        time.sleep(.05)
    raise RuntimeError('owned server readiness timeout')

def main():
    system=secrets.token_hex(32);key=secrets.token_hex(32);identity=Identity(key);children=[]
    with tempfile.TemporaryDirectory(prefix='hangang-sso-proof-') as tmp:
        root=pathlib.Path(tmp);root.chmod(0o700);public,admin,console=port(),port(),port();authority=f'http://127.0.0.1:{admin}';origin=f'http://127.0.0.1:{console}'
        env={**os.environ,'HANGANG_ADMIN_TOKEN':system,'FIXTURE_HOPAE_KEY':key,'FIXTURE_SYSTEM_KEY':system}
        log=open(root/'servers.log','wb')
        try:
            parent=subprocess.Popen([str(ROOT/'target/debug/hangang'),'--config',str(root/'config.json'),'--listen',f'127.0.0.1:{public}','--admin',f'127.0.0.1:{admin}','--threads','2','--lua-workers','1'],env=env,stdout=log,stderr=log);children.append(parent);ready(authority,parent)
            status,_=request(authority,'/v1/auth/bootstrap','POST',{'username':'operator','password':'owned fixture secure password'},{'Authorization':'Bearer '+system});assert status==201
            status,password_session=request(authority,'/v1/auth/login','POST',{'username':'operator','password':'owned fixture secure password'});assert status==200
            assert request(authority,'/v1/auth/sso-lease','POST',{'username':'operator'},{'Authorization':'Bearer '+password_session['token']})[0]==403,'ordinary administrators must not impersonate mapped accounts'
            plugins=root/'plugins.json';plugins.write_text(json.dumps({'plugins':[]}));plugins.chmod(0o600)
            config=root/'sso.json';config.write_text(json.dumps({'public_url':origin+'/','native_address':f'127.0.0.1:{identity.port}','gateway_key_env':'FIXTURE_HOPAE_KEY','upstream_token_env':'FIXTURE_SYSTEM_KEY','accounts':{'u_fixture':'operator'}}));config.chmod(0o600)
            adapter=subprocess.Popen([str(ROOT/'target/debug/hangang-console'),'--listen',f'127.0.0.1:{console}','--upstream',authority,'--plugins',str(plugins),'--hopae-sso',str(config)],env=env,stdout=log,stderr=log);children.append(adapter);ready(origin,adapter)
            headers={'Cookie':'__Host-hopae=fixture-native-handle','Origin':origin,'X-Hangang-SSO':'1'}
            assert request(origin,'/v1/auth/sso/config')[0]==200
            assert request(origin,'/v1/auth/sso/exchange','POST',{}, {'Cookie':headers['Cookie'],'Origin':'https://evil.example.test','X-Hangang-SSO':'1'})[0]==403
            assert request(origin,'/v1/auth/sso/exchange','POST',{}, {'Origin':origin,'X-Hangang-SSO':'1'})[0]==401
            status,session=request(origin,'/v1/auth/sso/exchange','POST',{},headers);assert status==200 and session['user']['username']=='operator' and session['user']['role']=='admin';assert session['token'].startswith('hsso_')
            authorized={'Authorization':'Bearer '+session['token'],'Cookie':headers['Cookie']}
            assert request(origin,'/v1/auth/me',headers=authorized)[0]==200
            assert request(authority,'/v1/auth/me',headers=authorized)[0]==401,'opaque SSO bearer must not bypass the broker'
            assert request(origin,'/v1/auth/sso-lease','POST',{'username':'operator'},authorized)[0]==404
            assert request(origin,'/v1/auth/me',headers={'Authorization':authorized['Authorization']})[0]==401
            identity.live=False;assert request(origin,'/v1/status',headers=authorized)[0]==401;identity.live=True
            identity.user='u_unmapped';assert request(origin,'/v1/auth/sso/exchange','POST',{},headers)[0]==401;identity.user='u_fixture'
            assert request(origin,'/v1/auth/logout','POST',{},authorized)[0]==204
            assert request(origin,'/v1/auth/me',headers=authorized)[0]==401
            print('PASS: real Hangang account SSO, explicit mapping, native per-request revocation, same-origin exchange, opaque-bearer isolation and logout.')
        finally:
            for child in reversed(children):
                child.terminate()
                try:child.wait(timeout=5)
                except subprocess.TimeoutExpired:child.kill();child.wait()
            identity.s.close();log.close()
if __name__=='__main__':main()
