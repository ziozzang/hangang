import { test, expect } from '@playwright/test';
async function fixture(page, failure=0) {
 const calls=[];let state={revision:0,source:'disabled',enabled:false,config:{transport:'disabled'}};
 await page.route('**/*',async route=>{
  const r=route.request(), p=new URL(r.url()).pathname, m=r.method();if(p.startsWith('/ui/'))return route.continue();
  const body=r.postDataJSON();calls.push({p,m,body,etag:r.headers()['if-match']});
  if(p==='/v1/auth/setup')return route.fulfill({status:404,body:'not found'});
  if(p==='/v1/status')return route.fulfill({json:{revision:1,http_routes:0,tcp_routes:0,uptime_seconds:2,state:{ready:true},metrics:{}}});
  if(p==='/v1/events')return route.fulfill({status:503,body:'fixture no stream'});
  if(p==='/v1/update/status')return route.fulfill({json:{enabled:false,phase:'idle'}});
  if(p==='/v1/docker/connection/test')return route.fulfill({json:{ok:true}});
  if(p==='/v1/docker/resolve')return route.fulfill({json:{http_backend:'http://192.0.2.4:8080',tcp_backend:'192.0.2.4:8080'}});
  if(p==='/v1/docker/connection'){
   if(m==='PUT'&&failure)return route.fulfill({status:failure,json:{detail:'owned failure'}});
   if(m==='PUT')state={revision:state.revision+1,source:'managed',enabled:body.transport!=='disabled',config:body};
   if(m==='DELETE')state={revision:state.revision+1,source:'cli',enabled:true,config:{transport:'unix',socket_path:'/run/default.sock'}};
   return route.fulfill({json:state});
  }
  return route.fulfill({status:404,body:'not found'});
 });
 await page.goto('/ui/');await page.locator('#token-input').fill('fixture-admin');await page.locator('#login-submit').click();await expect(page.locator('#login-dialog')).toBeHidden();await page.locator('[data-view="docker"]').click();await expect(page.locator('#docker-connection-source')).toContainText('revision 0');return calls;
}
async function unix(page){await page.locator('#docker-connection-transport').selectOption('unix');await page.locator('#docker-connection-socket_path').fill('/run/owned/docker.sock');}
test('Docker test does not save, writes use CAS, resolution and restore default have dedicated actions',async({page})=>{
 const calls=await fixture(page);await unix(page);await page.locator('#docker-connection-test').click();await expect(page.locator('#docker-connection-message')).toContainText('has not been saved');expect(calls.filter(x=>x.m==='PUT')).toHaveLength(0);
 await page.locator('#docker-connection-save').click();await expect(page.locator('#docker-connection-source')).toContainText('revision 1');expect(calls.find(x=>x.m==='PUT')).toMatchObject({etag:'"0"',body:{transport:'unix',socket_path:'/run/owned/docker.sock'}});
 for(const [key,value] of Object.entries({container:'api',network:'edge',port:'8080'}))await page.locator(`#docker-inspect-${key}`).fill(value);
 await page.locator('#docker-inspect-submit').click();await expect(page.locator('#docker-inspect-result')).toContainText('docker://api/edge/8080');
 await page.locator('#docker-connection-transport').selectOption('disabled');await page.locator('#docker-connection-save').click();await expect(page.locator('#docker-connection-state')).toHaveText('Docker connection disabled');await expect(page.locator('#docker-inspect-result')).toHaveText('');
 await page.locator('#docker-connection-reset').click();await expect(page.locator('#docker-connection-socket_path')).toHaveValue('/run/default.sock');expect(calls.find(x=>x.m==='DELETE').etag).toBe('"2"');
});
test('Docker HTTPS validation and locale navigation preserve unsaved file references',async({page})=>{
 const calls=await fixture(page);await page.locator('#docker-connection-transport').selectOption('https');
 for(const [key,value] of Object.entries({url:'http://docker.example.test:2375',ca_file:'/data/ca.pem',client_cert_file:'/data/cert.pem',client_key_file:'/data/key.pem'}))await page.locator(`#docker-connection-${key}`).fill(value);
 await page.locator('#docker-connection-test').click();await expect(page.locator('#docker-connection-message')).toContainText('HTTPS origin');expect(calls.filter(x=>x.p.endsWith('/connection/test'))).toHaveLength(0);
 await page.locator('#docker-connection-url').fill('https://docker.example.test:2376');await page.locator('#locale-select').selectOption('ko');await expect(page.locator('#docker-panel-title')).toContainText('연결');await page.locator('[data-view="status"]').click();await page.locator('[data-view="docker"]').click();await expect(page.locator('#docker-connection-client_key_file')).toHaveValue('/data/key.pem');await expect(page.locator('#docker-connection-url')).toHaveValue('https://docker.example.test:2376');
 await page.locator('#docker-connection-test').click();await expect(page.locator('#docker-connection-message')).toContainText('아직 저장하지');expect(calls.find(x=>x.p.endsWith('/connection/test')).body).toMatchObject({transport:'https',url:'https://docker.example.test:2376',client_key_file:'/data/key.pem'});
});
test('Docker revision conflict keeps the draft',async({page})=>{await fixture(page,412);await unix(page);await page.locator('#docker-connection-save').click();await expect(page.locator('#docker-connection-message')).toContainText('changed elsewhere');await expect(page.locator('#docker-connection-socket_path')).toHaveValue('/run/owned/docker.sock');});
test('Docker expired authorization scrubs form and logs out',async({page})=>{await fixture(page,401);await unix(page);await page.locator('#docker-connection-save').click();await expect(page.locator('#login-dialog')).toBeVisible();await expect(page.locator('#docker-connection-socket_path')).toHaveValue('');await expect(page.locator('#docker-inspect-result')).toHaveText('');});
