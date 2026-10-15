import {test,expect} from '@playwright/test';
const subject='s_'+'a'.repeat(48);
async function setup(page,{source='native',workload=false,conflict=false}={}){
  const calls=[];let document={revision:7,policy:{version:1,information_classes:['internal'],services:{orders:{permissions:['read'],roles:{reader:{permissions:['read'],information_classes:['internal'],minimum_aal:1}},users:{[subject]:['reader']},...(workload?{workload_users:{[subject]:['reader']}}:{}),networks:[{cidr:'192.0.2.0/24',roles:['reader']}],require_guard:true}},resources:{'db:orders':{service:'orders',information_class:'internal',actions:{select:'read'},minimum_aal:2}}}};
  await page.route('**/*',async route=>{
    const request=route.request(),path=new URL(request.url()).pathname;
    if(path.startsWith('/ui/'))return route.continue();
    calls.push({path,method:request.method(),headers:request.headers(),body:request.postData()&&request.postDataJSON()});
    if(path==='/v1/auth/setup')return route.fulfill({status:404,body:''});
    if(path==='/v1/auth/logout')return route.fulfill({status:204});
    if(path==='/v1/status')return route.fulfill({json:{revision:3,http_routes:0,tcp_routes:0,uptime_seconds:1,metrics:{}}});
    if(path==='/v1/plugins')return route.fulfill({json:{api_version:1,plugins:[]}});
    if(path==='/v1/config')return route.fulfill({json:{revision:3,http:[],tcp:[],pumgye_authority:{decision_address:'127.0.0.1:9085',management_address:'127.0.0.1:9084',decision_token_env:'FIXTURE_DECISION',admin_token_env:'FIXTURE_ADMIN'}}});
    if(path==='/v1/pumgye/policy'){
      if(request.method()==='PUT'){
        if(conflict)return route.fulfill({status:409,json:{detail:'fixture revision conflict'},contentType:'application/problem+json'});
        document={...request.postDataJSON(),revision:document.revision+1};
      }
      return route.fulfill({json:document,headers:{etag:`"${document.revision}"`,'x-hangang-config-revision':'"3"'}});
    }
    if(path==='/v1/pumgye/status')return route.fulfill({json:{healthy:true,policy_source:source,source_state:source==='native'?'native':'fresh',policy_revision:document.revision}});
    if(path==='/v1/pumgye/audit')return route.fulfill({json:[]});
    return route.fulfill({status:404,body:''});
  });
  await page.goto('/ui/');await page.getByLabel('Administrator token').fill('fixture-admin');await page.getByRole('button',{name:'Connect',exact:true}).click();await expect(page.locator('#login-dialog')).toBeHidden();await page.locator('.sidebar [data-view="pumgye"]').click();await expect(page.locator('#pumgye-matrix tr')).toHaveCount(workload?3:2);
  return {calls,writes:()=>calls.filter(c=>c.path==='/v1/pumgye/policy'&&c.method==='PUT')};
}
async function assign(page,id=subject,roles='reader'){
  await page.locator('#pumgye-kind').selectOption('workload');await page.locator('#pumgye-subject').fill(id);await page.locator('#pumgye-assignment-roles').fill(roles);await page.locator('#pumgye-assignment-form button').click();
}
const policy=page=>page.locator('#pumgye-document').inputValue().then(JSON.parse);
test('same subject has independent User and Workload assignments through owning CAS',async({page})=>{
  const {writes}=await setup(page);await assign(page);await expect(page.locator('[data-assignment-kind="workload"]')).toContainText(subject);await expect(page.locator('[data-assignment-kind="user"]')).toContainText(subject);
  await page.locator('#pumgye-publish').click();await expect(page.locator('#pumgye-message')).toHaveText('Authorization policy published.');const first=writes()[0];expect(first.headers['if-match']).toBe('"7"');expect(first.headers['x-hangang-config-revision']).toBe('"3"');expect(first.body.policy.services.orders.users[subject]).toEqual(['reader']);expect(first.body.policy.services.orders.workload_users[subject]).toEqual(['reader']);expect(first.body.policy.services.orders.roles.reader.minimum_aal).toBe(1);expect(first.body.policy.resources['db:orders'].minimum_aal).toBe(2);
  await page.locator('[data-assignment-kind="workload"] button').click();let p=await policy(page);expect(p.services.orders).not.toHaveProperty('workload_users');expect(p.services.orders.users[subject]).toEqual(['reader']);
  await page.locator('#pumgye-publish').click();await expect.poll(()=>writes().length).toBe(2);await expect(page.locator('#pumgye-message')).toHaveText('Authorization policy published.');expect(writes()[1].body.policy.services.orders).not.toHaveProperty('workload_users');
  await assign(page);await page.locator('[data-assignment-kind="user"] button').click();p=await policy(page);expect(p.services.orders.users).toEqual({});expect(p.services.orders.workload_users[subject]).toEqual(['reader']);
  await page.locator('#pumgye-publish').click();await expect.poll(()=>writes().length).toBe(3);await expect(page.locator('#pumgye-message')).toHaveText('Authorization policy published.');expect(writes()[2].headers['if-match']).toBe('"9"');expect(writes()[2].body.policy.services.orders.workload_users[subject]).toEqual(['reader']);
  await page.locator('#pumgye-kind').selectOption('user');await page.locator('#pumgye-subject').fill(subject);await page.locator('#pumgye-assignment-roles').fill('guest');await page.locator('#pumgye-assignment-form button').click();p=await policy(page);expect(p.services.orders.users[subject]).toEqual(['guest']);expect(p.services.orders.workload_users[subject]).toEqual(['reader']);expect(p.services.orders.networks).toEqual([{cidr:'192.0.2.0/24',roles:['reader']}]);
});
test('malformed canonical subjects and unknown kind never mutate either namespace',async({page})=>{
  const {writes}=await setup(page);const before=await page.locator('#pumgye-document').inputValue();
  for(const bad of ['s_'+'A'.repeat(48),'s_'+'a'.repeat(47),'s_'+'a'.repeat(49),'x_'+'a'.repeat(48),' '+subject,subject+' ',subject+'\u2028','s_'+'０'.repeat(48)]){await assign(page,bad);await expect(page.locator('#pumgye-message')).toContainText('exactly 48 lowercase hexadecimal');expect(await page.locator('#pumgye-document').inputValue()).toBe(before);}
  await page.evaluate(()=>{const s=document.querySelector('#pumgye-kind');s.add(new Option('unknown','unknown'));s.value='unknown';document.querySelector('#pumgye-assignment-form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));});await expect(page.locator('#pumgye-message')).toContainText('supported assignment kind');expect(writes()).toHaveLength(0);
});
test('guest remains an explicit zero-permission Workload assignment; unknown role refuses',async({page})=>{
  await setup(page);await assign(page,subject,'guest');let p=await policy(page);expect(p.services.orders.workload_users[subject]).toEqual(['guest']);expect(p.services.orders.users[subject]).toEqual(['reader']);await expect(page.locator('#pumgye-workload-help')).toContainText('guest roles have no permissions');const before=await page.locator('#pumgye-document').inputValue();await assign(page,subject,'invented');await expect(page.locator('#pumgye-message')).toContainText('existing role or guest');expect(await page.locator('#pumgye-document').inputValue()).toBe(before);
});
test('source-managed Workload rows cannot mutate even via dispatched form events',async({page})=>{
  const {writes}=await setup(page,{source:'kubernetes',workload:true});const before=await page.locator('#pumgye-document').inputValue();await expect(page.locator('#pumgye-kind')).toBeDisabled();await expect(page.locator('[data-assignment-kind="workload"] button')).toBeDisabled();await expect(page.locator('#pumgye-publish')).toBeDisabled();await page.evaluate(()=>document.querySelector('#pumgye-assignment-form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));expect(await page.locator('#pumgye-document').inputValue()).toBe(before);expect(writes()).toHaveLength(0);
});
test('failed CAS retains Workload draft across navigation and canceled refresh; logout scrubs it',async({page})=>{
  const {writes}=await setup(page,{conflict:true});await assign(page);const before=await page.locator('#pumgye-document').inputValue();await page.locator('#pumgye-publish').click();await expect(page.locator('#pumgye-message')).toContainText('Configuration changed');expect(writes()).toHaveLength(1);await page.locator('.sidebar [data-view="status"]').click();await page.locator('.sidebar [data-view="pumgye"]').click();expect(await page.locator('#pumgye-document').inputValue()).toBe(before);page.once('dialog',d=>d.dismiss());await page.locator('#pumgye-refresh').click();expect(await page.locator('#pumgye-document').inputValue()).toBe(before);await page.locator('#logout-button').click();await expect(page.locator('#pumgye-document')).toHaveValue('');await expect(page.locator('#pumgye-matrix tr')).toHaveCount(0);await expect(page.locator('#pumgye-subject')).toHaveValue('');
});
test('structured Workload add and remove preserve invalid raw editor work',async({page})=>{
  await setup(page,{workload:true});await page.locator('#pumgye-document').fill('{invalid');await page.locator('[data-assignment-kind="workload"] button').click();await expect(page.locator('#pumgye-document')).toHaveValue('{invalid');await expect(page.locator('#pumgye-message')).toContainText('Correct the authorization policy JSON');await assign(page);await expect(page.locator('#pumgye-document')).toHaveValue('{invalid');await expect(page.locator('#pumgye-message')).toContainText('Correct the authorization policy JSON');
});
for(const locale of ['en','ko'])test(`Workload controls and matrix fit390px and localize without translating subjects ${locale}`,async({page})=>{
  await page.setViewportSize({width:390,height:900});await setup(page,{workload:true});await page.locator('#locale-select').selectOption(locale);await expect(page.locator('#pumgye-kind option[value="workload"]')).toHaveText(locale==='ko'?'워크로드':'Workload');await expect(page.locator('[data-assignment-kind="workload"] td').first()).toHaveText(locale==='ko'?'워크로드':'Workload');await expect(page.locator('[data-assignment-kind="workload"]')).toContainText(subject);await expect(page.locator('#pumgye-workload-help')).toContainText('AAL0');expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);const bounds=await page.locator('#pumgye-assignment-form').boundingBox();expect(bounds.x+bounds.width).toBeLessThanOrEqual(390);
});

test('ordinary User edits leave the optional empty Workload map absent',async({page})=>{
  await setup(page);await page.locator('#pumgye-subject').fill('fixture-second-user');await page.locator('#pumgye-assignment-roles').fill('reader');await page.locator('#pumgye-assignment-form button').click();const p=await policy(page);expect(p.services.orders.users['fixture-second-user']).toEqual(['reader']);expect(p.services.orders).not.toHaveProperty('workload_users');
});

test('detached Workload row callbacks cannot mutate a newer render or a new session',async({page})=>{
  await setup(page,{workload:true});await page.evaluate(()=>window.oldRenderButton=document.querySelector('[data-assignment-kind="workload"] button'));await assign(page,subject,'guest');let before=await page.locator('#pumgye-document').inputValue();await page.evaluate(()=>window.oldRenderButton.click());expect(await page.locator('#pumgye-document').inputValue()).toBe(before);
  await page.evaluate(()=>window.oldSessionButton=document.querySelector('[data-assignment-kind="workload"] button'));await page.locator('#logout-button').click();await expect(page.locator('#login-dialog')).toBeVisible();await page.locator('#token-input').fill('fixture-next-admin');await page.getByRole('button',{name:'Connect',exact:true}).click();await expect(page.locator('#login-dialog')).toBeHidden();await page.locator('.sidebar [data-view="pumgye"]').click();await expect(page.locator('[data-assignment-kind="workload"]')).toHaveCount(1);before=await page.locator('#pumgye-document').inputValue();await page.evaluate(()=>window.oldSessionButton.click());expect(await page.locator('#pumgye-document').inputValue()).toBe(before);
});
