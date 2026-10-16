import { test, expect } from '@playwright/test';

const plugin = id => ({id,name:'Discovery '+id,entry:`/ui/plugins/${id}/index.js`,api_base:`/v1/plugins/${id}`,authentication:'hangang'});
async function fixture(page, { ids=['guard','hopae'], viewer=false, duplicate=false }={}) {
  const calls=[];
  await page.route('**/*', async r => {
    const p=new URL(r.request().url()).pathname;calls.push(p);
    if(p.startsWith('/ui/plugins/')) {
      if(p.endsWith('style.css'))return r.fulfill({contentType:'text/css',body:''});
      return r.fulfill({contentType:'text/javascript',body:`export async function mount(h){window.lifecycle??={mount:0,pause:0,resume:0,dispose:0};window.lifecycle.mount++; const {data}=await h.api('status');h.root.textContent=data.message;return {pause(){window.lifecycle.pause++},resume(){window.lifecycle.resume++},dispose(){window.lifecycle.dispose++;h.root.replaceChildren()}}}`});
    }
    if(p.startsWith('/ui/'))return r.continue();
    if(p==='/v1/auth/setup')return r.fulfill({json:{bootstrap_required:false}});
    if(p==='/v1/auth/login')return r.fulfill({json:{token:'fixture-session',user:{id:1,username:'reader',role:viewer?'viewer':'admin'}}});
    if(p==='/v1/auth/me')return r.fulfill({json:{user:{id:1,username:'reader',role:viewer?'viewer':'admin'}}});
    if(p==='/v1/auth/logout')return r.fulfill({status:204});
    if(p==='/v1/status')return r.fulfill({json:{revision:1,http_routes:0,tcp_routes:0,metrics:{},state:{},uptime_seconds:1}});
    if(p==='/v1/plugins')return r.fulfill({json:{api_version:1,plugins:(duplicate?[...ids,ids[0]]:ids).map(plugin)}});
    if(/^\/v1\/plugins\/[a-z-]+\/status$/.test(p))return r.fulfill({json:{message:'Authorized fixture content'}});
    if(p==='/v1/config')return r.fulfill({json:{revision:1,http:[],tcp:[],pumgye:{version:1,services:{},resources:{}}}});
    return r.fulfill({status:404,body:''});
  });
  return calls;
}
async function login(page, hash='') {
  await page.goto('/ui/'+hash);
  await page.locator('#login-username').fill('reader');await page.locator('#login-password').fill('fixture-password');await page.getByRole('button',{name:'Sign in',exact:true}).click();
  await expect(page.locator('#login-dialog')).toBeHidden();
}
for(const ids of [['guard','hopae'],['hopae','guard']])test(`host order independent of discovery ${ids}`,async({page})=>{
  await fixture(page,{ids});await login(page);
  await expect(page.locator('.sidebar a[data-console-plugin]')).toHaveCount(2);
  expect(await page.locator('.sidebar .nav-link').evaluateAll(links=>links.filter(a=>['policies','plugin-hopae','plugin-guard'].includes(a.dataset.view)).map(a=>a.dataset.view))).toEqual(['policies','plugin-hopae','plugin-guard']);
  await expect(page.locator('[data-view="plugin-hopae"]')).toContainText('Identity · Hopae');
  await page.locator('#locale-select').selectOption('ko');await expect(page.locator('[data-view="plugin-guard"]')).toContainText('네트워크 신뢰 · 수문장');
  await page.locator('#command-open').click();await page.locator('#command-search').fill('Guard');await expect(page.locator('.command-result')).toContainText('수문장');
});
test('duplicate discovery cannot partially install or execute plugins',async({page})=>{
  const calls=await fixture(page,{duplicate:true});await login(page);
  await expect(page.locator('#global-alert')).toContainText('Invalid console plugin discovery');
  await expect(page.locator('[data-console-plugin]')).toHaveCount(0);expect(calls.some(p=>p.startsWith('/ui/plugins/'))).toBe(false);
});
test('installed deep link waits for discovery; Back Forward and logout preserve lifecycle',async({page})=>{
  const calls=await fixture(page);await login(page,'#plugin-hopae');await expect(page.locator('#view-plugin-hopae')).toContainText('Authorized fixture content');
  await expect(page.locator('[data-view="plugin-hopae"]')).toHaveAttribute('aria-current','page');
  await page.locator('[data-view="status"]').click();await expect(page.locator('#view-plugin-hopae')).toBeHidden();
  await page.goBack();await expect(page.locator('#view-plugin-hopae')).toBeVisible();expect(await page.evaluate(()=>window.lifecycle.mount)).toBe(1);
  await page.goForward();await expect(page.locator('#view-plugin-hopae')).toBeHidden();
  await page.goBack();await page.reload();await expect(page.locator('#view-plugin-hopae')).toContainText('Authorized fixture content');
  expect(calls.filter(p=>p==='/v1/plugins/hopae/status').length).toBe(2);
  await page.locator('#logout-button').click();await expect(page.locator('[data-console-plugin]')).toHaveCount(0);expect(await page.evaluate(()=>window.lifecycle.dispose)).toBe(1);
});
test('uninstalled and unknown nested destinations canonicalize without module execution',async({page})=>{
  const calls=await fixture(page,{ids:[]});await login(page,'#plugin-hopae/sessions');await expect(page).toHaveURL(/#status$/);expect(calls.some(p=>p.startsWith('/ui/plugins/'))).toBe(false);
});
test('viewer direct destination never discovers or imports administrator modules',async({page})=>{
  const calls=await fixture(page,{viewer:true});await login(page,'#plugin-hopae');await expect(page).toHaveURL(/#status$/);expect(calls.includes('/v1/plugins')).toBe(false);expect(calls.some(p=>p.startsWith('/ui/plugins/'))).toBe(false);await expect(page.locator('[data-view="pumgye"]')).toBeHidden();
});
test('legacy Pumgye addresses redirect into the Policies section',async({page})=>{
  await fixture(page);await login(page,'#pumgye/resources');await expect(page).toHaveURL(/#policies$/);
  await page.evaluate(()=>location.hash='#pumgye/policy');await expect(page).toHaveURL(/#policies\/advanced$/);
  await page.evaluate(()=>location.hash='#pumgye/%2e%2e');await expect(page).toHaveURL(/#policies$/);
});

test('installed module unsupported subpage canonicalizes to installed root',async({page})=>{
  await fixture(page);await login(page,'#plugin-hopae/sessions');await expect(page).toHaveURL(/#plugin-hopae$/);await expect(page.locator('#view-plugin-hopae')).toContainText('Authorized fixture content');
});
test('unknown installed capabilities follow stable IDs without prototype labels',async({page})=>{
  await fixture(page,{ids:['zeta','constructor','guard','alpha','hopae']});await login(page);
  expect(await page.locator('.sidebar [data-console-plugin]').evaluateAll(a=>a.map(x=>x.dataset.consolePlugin))).toEqual(['hopae','guard','alpha','constructor','zeta']);
  await expect(page.locator('[data-view="plugin-constructor"]')).toContainText('Discovery constructor');
});
test('390px navigation remains keyboard operable and within the host viewport',async({page})=>{
  await page.setViewportSize({width:390,height:900});await fixture(page);await login(page);
  const link=page.locator('[data-view="plugin-hopae"]');await link.focus();await link.press('Enter');await expect(page.locator('#view-plugin-hopae')).toBeVisible();await expect(link).toHaveAttribute('aria-current','page');
  expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  await page.locator('#command-open').click();await page.locator('#command-search').fill('품계');await page.locator('#command-search').press('Enter');await expect(page).toHaveURL(/#policies$/);
});

test('localized command search reaches only administrator-owned section routes',async({page})=>{
  await fixture(page);await login(page);await page.locator('#locale-select').selectOption('ko');await page.locator('#command-open').click();await page.locator('#command-search').fill('resources');await expect(page.locator('.command-result')).toContainText('정책');await page.locator('#command-search').press('Enter');await expect(page).toHaveURL(/#policies$/);
});
test('viewer command search cannot offer administrator section destinations',async({page})=>{
  await fixture(page,{viewer:true});await login(page);await page.locator('#command-open').click();await page.locator('#command-search').fill('resources');await expect(page.locator('.command-result')).toHaveCount(0);
});
