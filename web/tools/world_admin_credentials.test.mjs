import {test} from 'node:test';
import assert from 'node:assert/strict';
import {applicationAuthorization,redact} from './world_admin_credentials.mjs';
test('legacy default and explicit fixed composition scheme',()=>{
  assert.equal(applicationAuthorization({key:'payload'}),'Bearer payload');
  assert.equal(applicationAuthorization({key:'payload',credentialScheme:'bearer'}),'Bearer payload');
  assert.equal(applicationAuthorization({key:'payload',credentialScheme:'hopae_compose'}),'Hopae-Compose payload');
});
test('raw schemes and malformed payload refuse without reflection',()=>{
  for(const credentialScheme of ['Basic','raw','Hopae-Compose','Bearer credential'])assert.throws(()=>applicationAuthorization({key:'sensitive-sentinel',credentialScheme}),/^Error: unsupported application credential scheme$/);
  for(const key of ['', 'Bearer payload','value\r\nsecret', 'x'.repeat(4097)])assert.throws(()=>applicationAuthorization({key}),/^Error: invalid application credential payload$/);
});
test('errors redact envelope, provider credentials, caller and password',()=>{
  const secrets=['local-sentinel','remote-sentinel','caller-sentinel','envelope-sentinel','password-sentinel'];
  const safe=redact(secrets.join(' '),secrets);
  for(const secret of secrets)assert.ok(!safe.includes(secret));
  assert.equal(safe,'[redacted] [redacted] [redacted] [redacted] [redacted]');
});
