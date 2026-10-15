// Actual owned Kubernetes console: no intercepted API responses or fixture UI server.
import fs from 'node:fs';
import {applicationAuthorization,redact} from './world_admin_credentials.mjs';
import http from 'node:http';
import https from 'node:https';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const execute=promisify(execFile);
import { randomBytes } from 'node:crypto';
import { chromium, expect } from '@playwright/test';
const config=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
const password=randomBytes(24).toString('hex');
const sensitive=[config.token,password,config.application?.key,...(config.redactionSecrets??[])];
let authorization;
try{if(config.application)authorization=applicationAuthorization(config.application);}catch(error){console.error(redact(String(error),sensitive));process.exit(1);}
function exchange(transport,options){
  return new Promise((resolve,reject)=>{
    const req=transport.get(options,res=>{let body='';res.setEncoding('utf8');res.on('data',chunk=>body+=chunk);res.on('end',()=>resolve({status:res.statusCode,body}));});
    req.setTimeout(3000,()=>req.destroy(new Error('owned request deadline')));req.on('error',reject);
  });
}
async function protectedStatus(expected){
  const before=JSON.parse((await exchange(http,{hostname:'127.0.0.1',port:config.application.backendPort,path:'/__count'})).body).count;
  const response=await exchange(https,{hostname:'127.0.0.1',port:config.application.gatewayPort,servername:'app.example.test',ca:fs.readFileSync(config.application.ca),path:'/secure',headers:{Host:'app.example.test',Authorization:authorization}});
  const after=JSON.parse((await exchange(http,{hostname:'127.0.0.1',port:config.application.backendPort,path:'/__count'})).body).count;
  expect(after).toBe(before+(response.status===200?1:0));
  if(expected!==null)expect(response.status).toBe(expected);
  return response.status;
}
const browser=await chromium.launch({headless:true});
let phase='initial-navigation';
const browserEvents=[];
const diagnosticStart=performance.now();
function diagnosticPath(url){
  const path=new URL(url).pathname;
  return ['/v1/auth/sso/config','/v1/auth/setup','/v1/auth/me','/v1/auth/login','/v1/auth/logout','/v1/status','/ui/'].includes(path)||/^\/ui\/[a-z0-9_-]+\.js$/.test(path)?path:null;
}
function recordBrowser(kind,request,status){const path=diagnosticPath(request.url());if(path){browserEvents.push({kind,path,status,atMs:Math.round(performance.now()-diagnosticStart)});if(browserEvents.length>40)browserEvents.shift();}}
try {
  const page=await browser.newPage();
  page.on('request',request=>recordBrowser('request',request,null));
  page.on('response',response=>recordBrowser('response',response.request(),response.status()));
  page.on('requestfailed',request=>recordBrowser('requestfailed',request,null));
  page.on('pageerror',error=>{browserEvents.push({kind:'pageerror',name:error.name,atMs:Math.round(performance.now()-diagnosticStart)});if(browserEvents.length>40)browserEvents.shift();});
  await page.goto(config.base+'/ui/');
  phase='initial-login-dialog';
  await expect(page.locator('#login-dialog')).toBeVisible();
  await expect(page.locator('#login-description')).not.toHaveText('Checking administrator access…');
  await expect(page.locator('#setup-login-fields')).toBeVisible();
  await page.locator('#setup-token').fill(config.token);
  await page.locator('#setup-username').fill('browser-owner');
  await page.locator('#setup-password').fill(password);
  await page.locator('#setup-confirm').fill(password);
  phase='first-administrator-bootstrap';
  await page.locator('#login-submit').click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  phase='pumgye-console';
  await page.locator('.sidebar a[data-view="pumgye"]').click();
  await expect(page.locator('#pumgye-authority-panel')).toBeVisible();
  await expect(page.locator('#pumgye-matrix tr')).toHaveCount(2);
  if (config.resourceCatalog) {
    await expect(page.locator('#pumgye-resources tr')).toHaveCount(1);
    await expect(page.locator('#pumgye-resources')).toContainText('db:orders');
    await expect(page.locator('#pumgye-resources')).toContainText('select → read');
  }
  await page.locator('#pumgye-subject').fill('browser-guest');
  await page.locator('#pumgye-assignment-roles').fill('guest');
  await page.locator('#pumgye-assignment-form button').click();
  await page.locator('#pumgye-publish').click();
  await expect(page.locator('#pumgye-message')).toHaveText('Authorization policy published.');
  if(config.pumgyeResponsive){
    phase='pumgye-responsive-390';
    try {
      await page.setViewportSize({width:390,height:900});
      await expect(page.locator('#pumgye-source-summary')).toBeVisible();
      const bounds=await page.evaluate(()=>({viewport:document.documentElement.clientWidth,width:document.documentElement.scrollWidth,
        panels:[...document.querySelectorAll('#view-pumgye .pumgye-panel')].map(el=>{const r=el.getBoundingClientRect(),s=getComputedStyle(el);return {left:r.left,right:r.right,padding:[s.paddingTop,s.paddingRight,s.paddingBottom,s.paddingLeft].map(parseFloat)};}),
        controls:[...document.querySelectorAll('#view-pumgye .pumgye-table-wrap,#view-pumgye input,#view-pumgye select,#view-pumgye textarea,#view-pumgye button')].filter(el=>el.getClientRects().length&&(el.classList.contains('pumgye-table-wrap')||!el.closest('.pumgye-table-wrap'))).map(el=>{const r=el.getBoundingClientRect();return {id:el.id,left:r.left,right:r.right};})}));
      expect(bounds.viewport).toBe(390);expect(bounds.width).toBeLessThanOrEqual(390);
      expect(bounds.panels.length).toBeGreaterThanOrEqual(3);
      for(const panel of bounds.panels){expect(panel.left).toBeGreaterThanOrEqual(0);expect(panel.right).toBeLessThanOrEqual(391);for(const padding of panel.padding)expect(padding).toBeGreaterThan(0);}
      expect(bounds.controls.length).toBeGreaterThan(0);
      for(const control of bounds.controls){expect(control.left,control.id).toBeGreaterThanOrEqual(0);expect(control.right,control.id).toBeLessThanOrEqual(391);}
      const table=page.locator('#view-pumgye .pumgye-table-wrap').first();
      await expect(table).toHaveAttribute('role','region');await expect(table).toHaveAttribute('tabindex','0');
      expect((await table.getAttribute('aria-label'))?.length).toBeGreaterThan(0);
      await table.focus();await expect(table).toBeFocused();
      const scrollable=await table.evaluate(el=>el.scrollWidth>el.clientWidth);
      expect(scrollable).toBe(true);await page.keyboard.press('ArrowRight');
      await expect.poll(()=>table.evaluate(el=>el.scrollLeft)).toBeGreaterThan(0);
      await table.evaluate(el=>el.scrollLeft=0);
      console.log('PASS: actual embedded Pumgye UI at390px has no document overflow, padded panels, bounded form/table wrappers and keyboard-scrollable authorization region');
    } finally {await page.setViewportSize({width:1280,height:900});}
    phase='pumgye-responsive-desktop-restored';
  }
  await page.locator('.sidebar a[data-view="plugin-'+config.plugin+'"]').click();
  const root=page.locator('#view-plugin-'+config.plugin+' .plugin-root');
  await expect(root.locator('#tab-blocks')).toBeVisible();
  phase='network-console';
  if(config.nativeSource){
    await expect(root.locator('#native-authority-status')).toContainText('Kubernetes native IP policy source');
    for(const selector of ['#block-form button[type="submit"]','#allow-save','#policy-form button[type="submit"]','#rules-save','#lua-save','#geoip-reload'])await expect(root.locator(selector)).toBeDisabled();
    const source=config.nativeSource;
    async function patchSource(blocks){
      const result=await execute(source.kubectl,['-n',source.namespace,'get','sumunjangpolicy',source.name,'-o','json']);
      expect(JSON.parse(result.stdout).metadata.uid).toBe(source.uid);
      await execute(source.kubectl,['-n',source.namespace,'patch','sumunjangpolicy',source.name,'--type=merge','-p',JSON.stringify({spec:{blocks}})]);
    }
    await patchSource([{network:'127.0.0.1/32',expires_at:Math.floor(Date.now()/1000)+600,reason:'owned source browser qualification'}]);
    await expect.poll(()=>protectedStatus(null),{timeout:15000}).toBe(403);
    await patchSource([]);
    await expect.poll(()=>protectedStatus(null),{timeout:15000}).toBe(200);
    await root.locator('#refresh').click();
    await expect(root.locator('#native-authority-status')).toContainText('Kubernetes native IP policy source');
    await expect(root.locator('#block-form button[type="submit"]')).toBeDisabled();
    console.log('PASS: actual source-owned console stays read-only while operator CRD block/unblock controls final403/200 with backend non-dispatch');
  } else {
    await root.locator('#tab-blocks').click();
    await root.locator('#network').fill('127.0.0.1/32');
    await root.locator('#reason').fill('owned browser qualification');
    await root.locator('#block-form button[type="submit"]').click();
    await expect(root.locator('#blocks-rows')).toContainText('127.0.0.1/32');
    await root.locator('#blocks-rows tr').filter({hasText:'127.0.0.1/32'}).locator('button').click();
    await expect(root.locator('#blocks-rows')).not.toContainText('127.0.0.1/32');
  }
  phase='hopae-console';
  if(config.hopae){
    await page.locator('.sidebar a[data-view="plugin-hopae"]').click();
    const hop=page.locator('#view-plugin-hopae .plugin-root');
    await expect(hop).toContainText('Managed with your Hangang administrator session.');
    await expect(hop.locator('.error')).toHaveText('');
    await hop.locator('[data-tab="profiles"]').click();
    await expect(hop).toContainText('orders');
    await expect(hop.locator('.error')).toHaveText('');
    if(config.application){
      const editor=hop.getByRole('textbox',{name:'Authentication profile configuration'});
      const original=await editor.inputValue();
      expect(JSON.parse(original).profiles.some(profile=>profile.service_id==='orders')).toBe(true);
      await protectedStatus(200);
      const staleContext=await browser.newContext();
      const stalePage=await staleContext.newPage();
      await stalePage.goto(config.base+'/ui/');
      await expect(stalePage.locator('#login-dialog')).toBeVisible();
      await expect(stalePage.locator('#login-username')).toBeVisible();
      await stalePage.locator('#login-username').fill('browser-owner');
      await stalePage.locator('#login-password').fill(password);
      await stalePage.locator('#login-submit').click();
      await expect(stalePage.locator('#login-dialog')).toBeHidden();
      await stalePage.locator('.sidebar a[data-view="plugin-hopae"]').click();
      const staleHop=stalePage.locator('#view-plugin-hopae .plugin-root');
      await staleHop.locator('[data-tab="profiles"]').click();
      const staleEditor=staleHop.getByRole('textbox',{name:'Authentication profile configuration'});
      await expect(staleEditor).toHaveValue(original);
      const staleRevision=await staleHop.locator('p').filter({hasText:/^Revision: /}).innerText();
      const publish=async value=>{
        const status=hop.getByRole('status');
        const base=Number((await status.innerText()).match(/Base revision: ([1-9]\d*)/)?.[1]);
        expect(Number.isSafeInteger(base)&&base>0).toBe(true);
        await editor.fill(value);
        const published=page.waitForResponse(response=>response.url().endsWith('/authentication/profiles/publish')&&response.request().method()==='POST');
        await hop.getByRole('button',{name:'Save profiles',exact:true}).click();
        const response=await published;
        expect(response.status()).toBe(200);
        expect(response.request().postDataJSON().revision).toBe(base);
        expect((await response.json()).revision).toBe(base+1);
        await expect(status).toHaveText('Saved revision: '+(base+1)+' · Base revision: '+(base+1));
        await expect(hop.locator('.error')).toHaveText('');
      };
      await publish('null');
      await expect(editor).toHaveValue('null');
      await protectedStatus(401);
      const conflict=stalePage.waitForResponse(response=>response.url().endsWith('/authentication/profiles/publish')&&response.request().method()==='POST');
      await staleHop.getByRole('button',{name:'Save profiles',exact:true}).click();
      expect((await conflict).status()).toBe(409);
      await expect(staleHop.getByRole('status')).toContainText('Revision conflict; refresh to compare with the latest revision. Draft retained.');
      await expect(staleEditor).toHaveValue(original);
      await expect(staleHop.locator('.error')).toHaveText('');
      await expect(staleHop.locator('p').filter({hasText:/^Revision: /})).toHaveText(staleRevision);
      await protectedStatus(401);
      await staleContext.close();
      console.log('PASS: independently signed-in stale administrator cannot overwrite profile revocation; actual CAS conflict preserves denied requests');
      if(config.hopaeRestart){
        const {kubectl,namespace}=config.hopaeRestart;
        if(!/^owned-world-[a-f0-9]{12}$/.test(namespace)||!kubectl.startsWith('/'))throw new Error('invalid owned restart scope');
        await execute(kubectl,['-n',namespace,'rollout','restart','deployment/hopae'],{timeout:15000});
        await execute(kubectl,['-n',namespace,'rollout','status','deployment/hopae','--timeout=120s'],{timeout:135000});
        const reconnectStatuses=[];
        await expect.poll(async()=>{
          const status=await protectedStatus(null);
          reconnectStatuses.push(status);
          return status;
        },{timeout:15000,intervals:[200,500,1000]}).toBe(401);
        expect(reconnectStatuses.every(status=>status===401||status===503)).toBe(true);
        // Reload the actual authority document after replacing its process.
        await hop.locator('[data-tab="status"]').click();
        await expect(hop.getByRole('heading',{name:'Providers',exact:true})).toBeVisible();
        await hop.locator('[data-tab="profiles"]').click();
        await expect(editor).toHaveValue('null');
        console.log('PASS: Hopae profile revocation survives actual K8s Pod replacement despite unchanged bootstrap configuration');
      }
      await publish(original);
      // Publication commits the profile; native peer/source readiness may still
      // refuse safely while connections recover. Preserve every request budget
      // and require zero backend effects before considering a refused response.
      const restoreDeadline=Date.now()+15000;
      const restoreStatuses=[];
      for(;;){
        if(Date.now()>=restoreDeadline)throw new Error('owned profile restoration deadline');
        const restored=await protectedStatus(null);
        restoreStatuses.push(restored);
        if(restored===200)break;
        expect(restored).toBe(503); // Other statuses fail immediately, without polling.
        if(Date.now()>=restoreDeadline)throw new Error('owned profile restoration deadline');
        await new Promise(resolve=>setTimeout(resolve,200));
      }
      console.log('PASS: real Hopae browser profile revocation and bounded restoration; every refusal has zero backend effects; restore statuses '+restoreStatuses.join(','));
    }
    console.log('PASS: actual remote Hopae administrator mTLS delegation and profile view under the Hangang login');
  }
  phase='final-logout';
  await page.locator('#logout-button').click();
  await expect(page.locator('#login-dialog')).toBeVisible();
  await expect(page.locator('#pumgye-document')).toHaveValue('');
  console.log('PASS: actual browser first-administrator bootstrap and ID/password login, owning Pumgye guest publication, real Sumunjang menu and owning policy block/unblock, and logout clearing');
} catch(error) { console.error('Owned browser diagnostic '+JSON.stringify({phase,events:browserEvents}));console.error(redact(error.stack??String(error),sensitive)); process.exitCode=1; } finally {await browser.close();}
