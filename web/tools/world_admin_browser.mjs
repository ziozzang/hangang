// Actual owned Kubernetes console: no intercepted API responses or fixture UI server.
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const execute=promisify(execFile);
import { randomBytes } from 'node:crypto';
import { chromium, expect } from '@playwright/test';
const config=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
const password=randomBytes(24).toString('hex');
function exchange(transport,options){
  return new Promise((resolve,reject)=>{
    const req=transport.get(options,res=>{let body='';res.setEncoding('utf8');res.on('data',chunk=>body+=chunk);res.on('end',()=>resolve({status:res.statusCode,body}));});
    req.setTimeout(3000,()=>req.destroy(new Error('owned request deadline')));req.on('error',reject);
  });
}
async function protectedStatus(expected){
  const before=JSON.parse((await exchange(http,{hostname:'127.0.0.1',port:config.application.backendPort,path:'/__count'})).body).count;
  const response=await exchange(https,{hostname:'127.0.0.1',port:config.application.gatewayPort,servername:'app.example.test',ca:fs.readFileSync(config.application.ca),path:'/secure',headers:{Host:'app.example.test',Authorization:'Bearer '+config.application.key}});
  if(expected!==null)expect(response.status).toBe(expected);
  const after=JSON.parse((await exchange(http,{hostname:'127.0.0.1',port:config.application.backendPort,path:'/__count'})).body).count;
  expect(after).toBe(before+(response.status===200?1:0));
  return response.status;
}
const browser=await chromium.launch({headless:true});
try {
  const page=await browser.newPage();
  await page.goto(config.base+'/ui/');
  await expect(page.locator('#login-dialog')).toBeVisible();
  await expect(page.locator('#login-description')).not.toHaveText('Checking administrator access…');
  await expect(page.locator('#setup-login-fields')).toBeVisible();
  await page.locator('#setup-token').fill(config.token);
  await page.locator('#setup-username').fill('browser-owner');
  await page.locator('#setup-password').fill(password);
  await page.locator('#setup-confirm').fill(password);
  await page.locator('#login-submit').click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  await page.locator('.sidebar a[data-view="pumgye"]').click();
  await expect(page.locator('#pumgye-authority-panel')).toBeVisible();
  await expect(page.locator('#pumgye-matrix tr')).toHaveCount(2);
  await page.locator('#pumgye-subject').fill('browser-guest');
  await page.locator('#pumgye-assignment-roles').fill('guest');
  await page.locator('#pumgye-assignment-form button').click();
  await page.locator('#pumgye-publish').click();
  await expect(page.locator('#pumgye-message')).toHaveText('Authorization policy published.');
  await page.locator('.sidebar a[data-view="plugin-'+config.plugin+'"]').click();
  const root=page.locator('#view-plugin-'+config.plugin+' .plugin-root');
  await expect(root.locator('#tab-blocks')).toBeVisible();
  await root.locator('#tab-blocks').click();
  await root.locator('#network').fill('127.0.0.1/32');
  await root.locator('#reason').fill('owned browser qualification');
  await root.locator('#block-form button[type="submit"]').click();
  await expect(root.locator('#blocks-rows')).toContainText('127.0.0.1/32');
  await root.locator('#blocks-rows tr').filter({hasText:'127.0.0.1/32'}).locator('button').click();
  await expect(root.locator('#blocks-rows')).not.toContainText('127.0.0.1/32');
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
        const revision=await hop.locator('p').filter({hasText:/^Revision: /}).innerText();
        await editor.fill(value);
        await hop.getByRole('button',{name:'Save profiles',exact:true}).click();
        await expect(hop.locator('p').filter({hasText:/^Revision: /})).not.toHaveText(revision);
        await expect(hop.locator('.error')).toHaveText('');
      };
      await publish('null');
      await expect(editor).toHaveValue('null');
      await protectedStatus(401);
      const conflict=stalePage.waitForResponse(response=>response.url().endsWith('/authentication/profiles/publish')&&response.request().method()==='POST');
      await staleHop.getByRole('button',{name:'Save profiles',exact:true}).click();
      expect((await conflict).status()).toBe(409);
      await expect(staleHop.locator('.error')).not.toHaveText('');
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
      await protectedStatus(200);
      console.log('PASS: real Hopae browser profile revocation/restoration changes protected requests immediately; refused request never reaches application');
    }
    console.log('PASS: actual remote Hopae administrator mTLS delegation and profile view under the Hangang login');
  }
  await page.locator('#logout-button').click();
  await expect(page.locator('#login-dialog')).toBeVisible();
  await expect(page.locator('#pumgye-document')).toHaveValue('');
  console.log('PASS: actual browser first-administrator bootstrap and ID/password login, owning Pumgye guest publication, real Sumunjang menu/block/unblock and logout clearing');
} catch(error) { console.error(String(error).replaceAll(config.token,'[redacted]').replaceAll(password,'[redacted]').replaceAll(config.application?.key??'unused-secret-placeholder','[redacted]')); process.exitCode=1; } finally {await browser.close();}
