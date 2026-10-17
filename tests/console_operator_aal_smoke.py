#!/usr/bin/env python3
"""Real Hangang authority + console with Hopae operator assurance (Hopae ADR-0021).

An owned HOP1 identity fixture answers like Hopae with a signed operator
assertion (Ed25519, pinned public key) whose level, factor and freshness each case sets.
Checks: sign-in refused without the phishing-resistant factor (step-up
answer), admitted with it; mutations need the policy; a sensitive action needs
a fresh factor; a forged assertion is refused; Hopae's own step-up answer is
relayed; the session endpoint shows the assurance; the step-up landing stays
inside /ui/; the break-glass local login is audited and can be disabled.
Run after cargo build --bin hangang --bin hangang-console (HANGANG_BIN_DIR
overrides target/debug). No operational credentials.
"""
import base64, json, os, pathlib, secrets, socket, struct, subprocess, tempfile, threading, time, urllib.request, urllib.error
ROOT=pathlib.Path(__file__).resolve().parents[1]
BIN=pathlib.Path(os.environ.get('HANGANG_BIN_DIR',ROOT/'target/debug'))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
KEY=Ed25519PrivateKey.generate();FORGED=Ed25519PrivateKey.generate()
def pubkey(key):return base64.b64encode(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()

def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*a,**k):return None
OPENER=urllib.request.build_opener(NoRedirect)
def request(origin,path,method='GET',data=None,headers=None):
    h={'Content-Type':'application/json',**(headers or {})};req=urllib.request.Request(origin+path,data=None if data is None else json.dumps(data).encode(),headers=h,method=method)
    try:
        with OPENER.open(req,timeout=5) as r:
            raw=r.read()
            try:return r.status,json.loads(raw or b'{}')
            except ValueError:return r.status,{}
    except urllib.error.HTTPError as e:
        raw=e.read()
        try:body=json.loads(raw)
        except ValueError:body={}
        return e.code,{**body,'_location':e.headers.get('location')}
def b64(b):return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
def assertion(key,claims):
    payload=b64(json.dumps(claims).encode());sig=b64(key.sign(b'hopae-operator-assertion.v2.'+payload.encode()))
    return f'v2.{payload}.{sig}'
def exact(s,n):
    b=b''
    while len(b)<n:
        chunk=s.recv(n-len(b))
        if not chunk:raise EOFError
        b+=chunk
    return b
class Identity:
    """Hopae over HOP1, answering with a signed operator assertion."""
    def __init__(self,key,host):
        self.key=key;self.host=host;self.factor='webauthn';self.factor_age=10;self.satisfied=True;self.step_up=False;self.forge=False
        self.s=socket.socket();self.s.bind(('127.0.0.1',0));self.port=self.s.getsockname()[1];self.s.listen();threading.Thread(target=self.accept,daemon=True).start()
    def accept(self):
        while True:
            try:s,_=self.s.accept()
            except OSError:return
            threading.Thread(target=self.serve,args=(s,),daemon=True).start()
    def claims(self):
        now=int(time.time())
        return {'v':2,'kid':'op-1','aud':'hangang-console','app':'console','host':self.host,'sub':'u_fixture','sid':'s_fixture','aal':2 if self.factor else 1,'factor':self.factor,'factor_at':now-self.factor_age if self.factor else None,'high_assurance':False,'auth_time':now-600,'require_aal':2,'require_factor':'webauthn','satisfied':self.satisfied,'grace':False,'iat':now,'exp':now+60}
    def serve(self,s):
        try:
            magic,i,n=struct.unpack('!4sQI',exact(s,16));assert magic==b'HOP1' and i==0;assert exact(s,n)==self.key.encode();s.sendall(struct.pack('!4sQI',b'HOP1',0,1)+b'\1')
            while True:
                magic,i,n=struct.unpack('!4sQI',exact(s,16));exact(s,n)
                if self.step_up:
                    status,pairs=401,[(b'x-hopae-reason',b'step_up_required')]
                else:
                    a=assertion(FORGED if self.forge else KEY,self.claims())
                    status,pairs=200,[(b'x-forwarded-user',b'u_fixture'),(b'x-hopae-operator-assertion',a.encode())]
                reply=struct.pack('!HH',status,len(pairs))
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
    system=secrets.token_hex(32);gateway=secrets.token_hex(32);children=[]
    with tempfile.TemporaryDirectory(prefix='hangang-operator-aal-') as tmp:
        root=pathlib.Path(tmp);root.chmod(0o700);public,admin,console=port(),port(),port();authority=f'http://127.0.0.1:{admin}';origin=f'http://127.0.0.1:{console}'
        identity=Identity(gateway,'127.0.0.1')
        env={**os.environ,'HANGANG_ADMIN_TOKEN':system,'FIXTURE_HOPAE_KEY':gateway,'FIXTURE_SYSTEM_KEY':system}
        log=open(root/'servers.log','wb');audit=root/'console-audit.jsonl'
        def start_console(*extra):
            p=subprocess.Popen([str(BIN/'hangang-console'),'--listen',f'127.0.0.1:{console}','--upstream',authority,'--plugins',str(plugins),'--hopae-sso',str(config),'--audit-log',str(audit),'--operator-audit-db',str(root/'operator-audit.db'),*extra],env=env,stdout=log,stderr=log);children.append(p);ready(origin,p);return p
        try:
            parent=subprocess.Popen([str(BIN/'hangang'),'--config',str(root/'config.json'),'--listen',f'127.0.0.1:{public}','--admin',f'127.0.0.1:{admin}','--threads','2','--lua-workers','1'],env=env,stdout=log,stderr=log);children.append(parent);ready(authority,parent)
            assert request(authority,'/v1/auth/bootstrap','POST',{'username':'operator','password':'owned fixture secure password'},{'Authorization':'Bearer '+system})[0]==201
            plugins=root/'plugins.json';plugins.write_text(json.dumps({'plugins':[]}));plugins.chmod(0o600)
            config=root/'sso.json';config.write_text(json.dumps({'public_url':origin+'/','native_address':f'127.0.0.1:{identity.port}','gateway_key_env':'FIXTURE_HOPAE_KEY','upstream_token_env':'FIXTURE_SYSTEM_KEY','accounts':{'u_fixture':'operator'},
                'operator_policy':{'assertion_public_keys':{"op-1":pubkey(KEY)},'minimum_aal':2,'require_factor':'webauthn','sensitive_max_age_seconds':300}}));config.chmod(0o600)
            adapter=start_console()
            headers={'Cookie':'__Host-hopae=fixture-native-handle','Origin':origin,'X-Hangang-SSO':'1'}
            # A TOTP-only operator: sign-in answers with the step-up location.
            identity.factor='totp';identity.satisfied=False
            status,body=request(origin,'/v1/auth/sso/exchange','POST',{},headers);assert status==403 and body['error']=='operator_step_up_required' and body['step_up_url'].startswith('/ui/step-up?return='),body
            # Hopae itself wants a step-up: relayed the same way.
            identity.step_up=True;status,body=request(origin,'/v1/auth/sso/exchange','POST',{},headers);assert status==403 and body['error']=='operator_step_up_required',body;identity.step_up=False
            # A forged assertion is refused outright.
            identity.factor='webauthn';identity.satisfied=True;identity.forge=True
            assert request(origin,'/v1/auth/sso/exchange','POST',{},headers)[0]==401;identity.forge=False
            # Passkey: admitted, the session shows the assurance.
            status,session=request(origin,'/v1/auth/sso/exchange','POST',{},headers);assert status==200 and session['assurance']['factor']=='webauthn',session
            authorized={'Authorization':'Bearer '+session['token'],'Cookie':headers['Cookie']}
            status,info=request(origin,'/v1/auth/sso/session',headers=authorized);assert status==200 and info['method']=='hopae' and info['assurance']['aal']==2 and info['policy']['minimum_aal']==2,info
            assert request(origin,'/v1/status',headers=authorized)[0]==200
            # A sensitive change with a stale factor: re-authenticate; fresh: passes the gate.
            identity.factor_age=400
            status,body=request(origin,'/v1/config','PUT',{},authorized);assert status==403 and body['error']=='operator_reauthentication_required',body
            status,body=request(origin,'/v1/routes','POST',{},authorized);assert body.get('error') not in ('operator_reauthentication_required','operator_step_up_required'),body
            identity.factor_age=10
            status,body=request(origin,'/v1/config','PUT',{},authorized);assert body.get('error')!='operator_reauthentication_required',body
            # The operator's factor degrades mid-session: even reads stop.
            identity.factor='totp';identity.satisfied=False
            assert request(origin,'/v1/status',headers=authorized)[0]==403;identity.factor='webauthn';identity.satisfied=True
            # The step-up landing returns inside /ui/ only.
            assert request(origin,'/ui/step-up?return=%2Fui%2F%23routes')[1]['_location']=='/ui/?sso=hopae#routes'
            assert request(origin,'/ui/step-up?return=https%3A%2F%2Fevil.example%2F')[1]['_location']=='/ui/?sso=hopae'
            # Break-glass: local login works and is audited.
            status,local=request(origin,'/v1/auth/login','POST',{'username':'operator','password':'owned fixture secure password'});assert status==200
            status,info=request(origin,'/v1/auth/sso/session',headers={'Authorization':'Bearer '+local['token']});assert info['method']=='local' and info['break_glass'] is True,info
            request(origin,'/v1/routes','POST',{},{'Authorization':'Bearer '+local['token']})
            adapter.terminate();adapter.wait(timeout=5)
            # Disabled: the local login and local sessions are refused.
            start_console('--disable-local-login')
            status,body=request(origin,'/v1/auth/login','POST',{'username':'operator','password':'owned fixture secure password'});assert status==403 and body['error']=='local_login_disabled',body
            assert request(origin,'/v1/status',headers={'Authorization':'Bearer '+local['token']})[0]==401
            events=[json.loads(l)['event'] for l in audit.read_text().splitlines()]
            for e in ['console.sso_login','console.step_up_required','console.break_glass_login','console.break_glass_change','console.change']:
                assert e in events,(e,events)
            outcomes=[json.loads(l).get('outcome') for l in audit.read_text().splitlines() if json.loads(l)['event']=='console.break_glass_login']
            assert 'success' in outcomes and 'disabled' in outcomes,outcomes
            # The operator audit store (kept across the restart) through the admin API.
            status,session=request(origin,'/v1/auth/sso/exchange','POST',{},headers);assert status==200,session
            authorized={'Authorization':'Bearer '+session['token'],'Cookie':headers['Cookie']}
            status,page=request(origin,'/v1/console/operator-audit?limit=500',headers=authorized);assert status==200,page
            stored=[r['event'] for r in page['records']]
            for e in ['console.sso_login','console.step_up_required','console.break_glass_login','console.break_glass_change','console.change']:
                assert e in stored,(e,stored)
            assert all(isinstance(r['id'],int) and r['time_unix_ms']>0 for r in page['records'])
            assert any(r['event']=='console.break_glass_login' and r.get('account')=='operator' and r['outcome']=='success' for r in page['records']),page
            status,first=request(origin,'/v1/console/operator-audit?limit=2',headers=authorized);assert status==200 and len(first['records'])==2 and first['next_before'],first
            status,more=request(origin,f"/v1/console/operator-audit?limit=2&before={first['next_before']}",headers=authorized);assert status==200 and more['records'][0]['id']<first['records'][1]['id'],more
            assert request(origin,'/v1/console/operator-audit')[0]==401
            assert request(origin,'/v1/console/operator-audit?limit=0',headers=authorized)[0]==400
            assert request(origin,'/v1/console/operator-audit','POST',{},authorized)[0]==405
            assert (root/'operator-audit.db').stat().st_mode&0o777==0o600
            print('PASS: operator assurance at sign-in, mutation and sensitive-action freshness; forged assertions refused; step-up relayed; break-glass audited and disableable; the operator audit store is read through the admin API.')
        finally:
            for child in reversed(children):
                if child.poll() is None:
                    child.terminate()
                    try:child.wait(timeout=5)
                    except subprocess.TimeoutExpired:child.kill();child.wait()
            identity.s.close();log.close()
if __name__=='__main__':main()
