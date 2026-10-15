import {test,expect} from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
const directories={hopae:process.env.HANGANG_TEST_HOPAE_PLUGIN,guard:process.env.HANGANG_TEST_SUMUNJANG_PLUGIN};
const policy={mode:'enforce',auto_block:false,window_secs:60,threshold:100,block_ttl_secs:600,allow:['192.0.2.0/24'],weights:{honeypot:10,scanner:5,auth_failure:2,invalid_request:1}};
async function setup(page,{native=true,holdPublish=false,holdMe=false}={}){
  const calls=[];let revision=7,role='admin',releasePublish,releaseMe;const publishing=new Promise(resolve=>releasePublish=resolve),mounting=new Promise(resolve=>releaseMe=resolve);
  const packages=Object.entries(directories).map(([id,dir])=>{const manifest=JSON.parse(fs.readFileSync(path.join(dir,'manifest.json')));for(const [name,hash]of Object.entries(manifest.assets))expect(crypto.createHash('sha256').update(fs.readFileSync(path.join(dir,name))).digest('hex')).toBe(hash);return {...manifest,entry:`/ui/plugins/${id}/index.js`,api_base:`/v1/plugins/${id}`,authentication:'hangang'};});
  await page.route('**/*',async route=>{
    const req=route.request(),p=new URL(req.url()).pathname;
    const match=p.match(/^\/ui\/plugins\/(hopae|guard)\/(index.js|panel.html|style.css)$/);
    if(match)return route.fulfill({body:fs.readFileSync(path.join(directories[match[1]],match[2])),contentType:match[2].endsWith('.js')?'text/javascript':match[2].endsWith('.css')?'text/css':'text/html'});
    if(p.startsWith('/ui/'))return route.continue();
    calls.push({path:p,method:req.method(),body:req.postData()});
    if(p==='/v1/auth/setup')return route.fulfill({status:404,body:''});
    if(p==='/v1/auth/logout')return route.fulfill({status:204});
    if(p==='/v1/plugins')return route.fulfill({json:{api_version:1,plugins:packages}});
    if(p==='/v1/status')return route.fulfill({json:{revision:1,http_routes:0,tcp_routes:0,metrics:{},uptime_seconds:1,state:{}}});
    if(p.startsWith('/v1/plugins/hopae/')){
      const key=p.slice('/v1/plugins/hopae/'.length);
      if(key==='me'){if(holdMe)await mounting;const result=await route.fulfill({json:{role}});if(holdMe)calls.push({released:true});return result;}
      if(key.endsWith('/publish')){if(holdPublish)await publishing;return route.fulfill({json:{revision:++revision}});}
      if(key==='status')return route.fulfill({json:{store:{users:17,live_sessions:2,events:3},providers:[{provider_id:'fixture-provider',kind:'fixture',enabled:true,health:'healthy'}]}});
      return route.fulfill({json:{revision,configuration:{profiles:[]}}});
    }
    if(p.startsWith('/v1/plugins/guard/')){
      const key=p.slice('/v1/plugins/guard/'.length);
      if(key==='kubernetes/authority')return route.fulfill({json:{enabled:native,available:true,remaining_ms:753,resource_version:'fixture-rv'}});
      if(key==='policy/document')return route.fulfill({json:{revision:'fixture-rev',policy}});
      if(key==='status')return route.fulfill({json:{mode:'enforce',capacity:{candidates:12345,max_candidates:20000,blocks:2,max_blocks:100},stats:{accepted:55555,dropped_capacity:3,block_capacity_rejections:4}}});
      if(key==='candidates'||key==='blocks')return route.fulfill({json:[]});
    }
    return route.fulfill({status:404,body:''});
  });
  await page.goto('/ui/');await page.getByLabel('Administrator token').fill('fixture-token');await page.getByRole('button',{name:'Connect',exact:true}).click();await expect(page.locator('#login-dialog')).toBeHidden();return {calls,releasePublish,releaseMe,revoke:()=>{role='viewer';}};
}
test.describe('actual production plugin package locale lifecycle',()=>{
 test.skip(!directories.hopae||!directories.guard,'Supply reviewed real Hopae and generated Sumunjang plugin package paths');
 test('native source composite and cached cards localize KO→EN without owner calls or remount',async({page})=>{
   await page.clock.install();const {calls}=await setup(page);await page.locator('#locale-select').selectOption('ko');await page.locator('[data-view="plugin-guard"]').click();const root=page.locator('#view-plugin-guard .plugin-root');await expect(root.locator('#native-authority-status')).toContainText('Kubernetes 네이티브');await expect(root.locator('#candidate-capacity')).toContainText('최대');const observedTime=await root.locator('#status-time').textContent();
   await page.locator('[data-view="status"]').click();await page.clock.fastForward(60000);const before=calls.filter(c=>c.path.startsWith('/v1/plugins/guard/')).length;await page.locator('#locale-select').selectOption('en');await expect(root.locator('#native-authority-status')).toContainText('Kubernetes native IP policy source');await expect(root.locator('#candidate-capacity')).toContainText('Maximum');await expect(root.locator('#drop-card')).toContainText('Capacity dropped');await expect(root.locator('#status-time')).toContainText('Status checked:');await expect(root.locator('#native-authority-status')).toContainText('753 ms');expect(calls.filter(c=>c.path.startsWith('/v1/plugins/guard/')).length).toBe(before);
   await page.locator('#locale-select').selectOption('ko');await expect(root.locator('#native-authority-status')).toContainText('Kubernetes 네이티브');expect(calls.filter(c=>c.path.startsWith('/v1/plugins/guard/')).length).toBe(before);await expect(root.locator('#status-time')).toHaveText(observedTime);
 });
 test('Sum policy/allow/raw drafts and DOM identity survive repeated locale changes',async({page})=>{
   const {calls}=await setup(page,{native:false});await page.locator('[data-view="plugin-guard"]').click();const root=page.locator('#view-plugin-guard .plugin-root');await expect(root.locator('#native-authority-status')).toContainText('local database');await root.locator('#tab-policy').click();await root.locator('#policy-threshold').fill('777');await root.locator('details:has(#policy-json) summary').click();await root.locator('#policy-json').fill('{ invalid private draft');await page.evaluate(()=>window.originalEditor=document.querySelector('#view-plugin-guard #policy-json'));const before=calls.filter(c=>c.path.startsWith('/v1/plugins/guard/')).length;
   for(const locale of ['ko','en','ko','en'])await page.locator('#locale-select').selectOption(locale);
   await expect(root.locator('#policy-threshold')).toHaveValue('777');await expect(root.locator('#policy-json')).toHaveValue('{ invalid private draft');expect(await page.evaluate(()=>window.originalEditor===document.querySelector('#view-plugin-guard #policy-json'))).toBe(true);expect(calls.filter(c=>c.path.startsWith('/v1/plugins/guard/')).length).toBe(before);expect(calls.some(c=>c.method==='PUT')).toBe(false);await page.evaluate(()=>window.oldGuardRoot=document.querySelector('#view-plugin-guard .plugin-root'));await page.locator('#logout-button').click();await page.locator('#locale-select').selectOption('ko');expect(await page.evaluate(()=>window.oldGuardRoot.textContent)).toBe('');expect(calls.filter(c=>c.path.startsWith('/v1/plugins/guard/')).length).toBe(before);
 });
 test('Hop editor, unsaved composite and tabs localize in place without requests',async({page})=>{
   const {calls}=await setup(page);await page.locator('[data-view="plugin-hopae"]').click();const root=page.locator('#view-plugin-hopae .plugin-root');await root.locator('[data-tab="profiles"]').click();await expect(root.locator('textarea')).toBeVisible();await root.locator('textarea').fill('{ invalid draft');await page.evaluate(()=>window.originalEditor=document.querySelector('#view-plugin-hopae textarea'));const before=calls.filter(c=>c.path.startsWith('/v1/plugins/hopae/')).length;
   await page.locator('#locale-select').selectOption('ko');await expect(root.locator('[data-tab="profiles"]')).toHaveText('인증 프로필');await expect(root.locator('[role="status"]')).toContainText('저장하지 않은 초안');await expect(root.locator('textarea')).toHaveAttribute('aria-label','인증 프로필 설정');await page.locator('#locale-select').selectOption('en');await expect(root.locator('[role="status"]')).toContainText('Unsaved draft');await expect(root.locator('textarea')).toHaveValue('{ invalid draft');expect(await page.evaluate(()=>window.originalEditor===document.querySelector('#view-plugin-hopae textarea'))).toBe(true);expect(calls.filter(c=>c.path.startsWith('/v1/plugins/hopae/')).length).toBe(before);
   await page.evaluate(()=>window.oldRoot=document.querySelector('#view-plugin-hopae .plugin-root'));await page.locator('#logout-button').click();await page.locator('#locale-select').selectOption('ko');await expect(page.locator('[data-console-plugin]')).toHaveCount(0);expect(await page.evaluate(()=>window.oldRoot.textContent)).toBe('');
 });
 test('Hop pending publication labels localize without replay, state loss or editor replacement',async({page})=>{
   const {calls,releasePublish}=await setup(page,{holdPublish:true});await page.locator('[data-view="plugin-hopae"]').click();const root=page.locator('#view-plugin-hopae .plugin-root');await root.locator('[data-tab="profiles"]').click();await expect(root.locator('textarea')).toBeVisible();await root.locator('textarea').fill('{"profiles":[]}');await root.getByRole('button',{name:'Save profiles',exact:true}).click();await expect.poll(()=>calls.filter(c=>c.path?.endsWith('/publish')).length).toBe(1);const before=calls.length;
   await page.locator('#locale-select').selectOption('ko');await expect(root.locator('[role="status"]')).toContainText('게시 중');await expect(root.locator('textarea')).toBeDisabled();await page.locator('#locale-select').selectOption('en');await expect(root.locator('[role="status"]')).toContainText('Publishing');expect(calls.length).toBe(before);releasePublish();await expect(root.locator('[role="status"]')).toContainText('Saved revision: 8');await page.locator('#locale-select').selectOption('ko');await expect(root.locator('[role="status"]')).toContainText('저장한 리비전: 8');await expect(root.locator('textarea')).toHaveValue('{"profiles":[]}');expect(calls.filter(c=>c.path?.endsWith('/publish')).length).toBe(1);
 });
 test('host locale during real pending mount and after abort cannot revive the old root',async({page})=>{
   const errors=[];page.on('pageerror',e=>errors.push(e.name));const {calls,releaseMe}=await setup(page,{holdMe:true});await page.locator('[data-view="plugin-hopae"]').click();await expect.poll(()=>calls.some(c=>c.path==='/v1/plugins/hopae/me')).toBe(true);await page.locator('#locale-select').selectOption('ko');await expect(page.locator('#view-plugin-hopae [data-tab="status"]')).toHaveText('상태');await page.evaluate(()=>window.oldRoot=document.querySelector('#view-plugin-hopae .plugin-root'));await page.locator('#logout-button').click();await page.locator('#locale-select').selectOption('en');releaseMe();await expect.poll(()=>calls.some(c=>c.released)).toBe(true);expect(await page.evaluate(()=>window.oldRoot.textContent)).toBe('');expect(errors).toEqual([]);
 });
 test('native Hop role loss scrubs drafts and locale changes cannot restore write controls',async({page})=>{
   const {calls,revoke}=await setup(page);await page.locator('[data-view="plugin-hopae"]').click();const root=page.locator('#view-plugin-hopae .plugin-root');await root.locator('[data-tab="profiles"]').click();await expect(root.locator('textarea')).toBeVisible();await root.locator('textarea').fill('{ private draft');revoke();await root.getByRole('button',{name:'Refresh',exact:true}).click();await expect(root.locator('textarea')).toBeDisabled();const before=calls.length;await page.locator('#locale-select').selectOption('ko');await page.locator('#locale-select').selectOption('en');await expect(root.locator('textarea')).not.toHaveValue('{ private draft');await expect(root.getByRole('button',{name:'Save profiles',exact:true})).toBeDisabled();expect(calls.length).toBe(before);
 });

});
