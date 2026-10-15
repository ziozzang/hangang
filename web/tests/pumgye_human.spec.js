import {test,expect} from '@playwright/test';
const subject='s_'+'a'.repeat(48);
async function setup(page,{source='native',workload=false,conflict=false,api=false}={}){
  const calls=[];let document={revision:7,policy:{version:1,information_classes:['internal'],services:{orders:{permissions:['read'],roles:{reader:{permissions:['read'],information_classes:['internal'],minimum_aal:1}},users:{[subject]:['reader']},...(workload?{workload_users:{[subject]:['reader']}}:{}),networks:[{cidr:'192.0.2.0/24',roles:['reader']}],require_guard:true}},resources:{'db:orders':{service:'orders',information_class:'internal',actions:{select:'read'},minimum_aal:2}}}};
  if(api){const v=document.policy.services.orders;v.authorization_context='kubernetes_api';v.users={'k8sapi:owned-reader':['reader']};v.networks=[];v.require_guard=false;v.roles.reader.minimum_aal=0;document.policy.kubernetes_authorization={version:1,principals:[],routes:[]};}
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
  await page.goto('/ui/');await page.getByLabel('Administrator token').fill('fixture-admin');await page.getByRole('button',{name:'Connect',exact:true}).click();await expect(page.locator('#login-dialog')).toBeHidden();await page.locator('.sidebar [data-view="pumgye"]').click();await expect(page.locator('#pumgye-matrix tr')).toHaveCount(api?1:workload?3:2);
  return {calls,writes:()=>calls.filter(c=>c.path==='/v1/pumgye/policy'&&c.method==='PUT')};
}
const human='human1:'+'b'.repeat(64);
const policy=page=>page.locator('#pumgye-document').inputValue().then(JSON.parse);
async function assign(page,id=human,roles='reader') {
 await page.locator('#pumgye-kind').selectOption('human');await page.locator('#pumgye-subject').fill(id);await page.locator('#pumgye-assignment-roles').fill(roles);await page.locator('#pumgye-assignment-form button').click();
}
test('Human CAS assignments are separate from legacy users and preserve Workload and resource policy',async({page})=>{
 const {writes}=await setup(page,{workload:true});const initial=await policy(page);initial.services.orders.users[human]=['reader'];await page.locator('#pumgye-document').fill(JSON.stringify(initial));await assign(page,human,'guest');
 await expect(page.locator('[data-assignment-kind="human"]')).toContainText(human);await page.locator('#pumgye-publish').click();await expect(page.locator('#pumgye-message')).toHaveText('Authorization policy published.');const first=writes()[0];expect(first.headers['if-match']).toBe('"7"');expect(first.headers['x-hangang-config-revision']).toBe('"3"');expect(first.body.policy.services.orders.human_users[human]).toEqual(['guest']);expect(first.body.policy.services.orders.users[human]).toEqual(['reader']);
 await page.locator('[data-assignment-kind="human"] button').click();const after=await policy(page);expect(after.services.orders).not.toHaveProperty('human_users');expect(after.services.orders.users[human]).toEqual(['reader']);expect(after.services.orders.workload_users[subject]).toEqual(['reader']);expect(after.resources).toEqual(initial.resources);expect(after.services.orders.networks).toEqual(initial.services.orders.networks);
});
test('Human canonical subject validation and unknown roles cannot rewrite the draft',async({page})=>{
 await setup(page);const before=await page.locator('#pumgye-document').inputValue();
 for(const bad of ['human1:'+'A'.repeat(64),'human1:'+'b'.repeat(63),'human1:'+'b'.repeat(65),human+'\u2028',' '+human,human+' ','human1:'+'０'.repeat(64),subject]) {await assign(page,bad);await expect(page.locator('#pumgye-message')).toContainText('exactly 64 lowercase hexadecimal');expect(await page.locator('#pumgye-document').inputValue()).toBe(before);}
 await assign(page,human,'invented');await expect(page.locator('#pumgye-message')).toContainText('existing role or guest');expect(await page.locator('#pumgye-document').inputValue()).toBe(before);
});
test('API context forbids Human assignment even through dispatched submit',async({page})=>{
 await setup(page,{api:true});await expect(page.locator('#pumgye-kind option[value="human"]')).toBeDisabled();const before=await page.locator('#pumgye-document').inputValue();await page.evaluate(()=>{document.querySelector('#pumgye-kind').value='human';document.querySelector('#pumgye-assignment-form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));});await expect(page.locator('#pumgye-message')).toContainText('supported by this service');expect(await page.locator('#pumgye-document').inputValue()).toBe(before);
});
test('source ownership forbids Human mutations',async({page})=>{
 const {writes}=await setup(page,{source:'kubernetes'});const before=await page.locator('#pumgye-document').inputValue();await page.evaluate(()=>{document.querySelector('#pumgye-kind').value='human';document.querySelector('#pumgye-subject').value='human1:'+'b'.repeat(64);document.querySelector('#pumgye-assignment-form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));});expect(await page.locator('#pumgye-document').inputValue()).toBe(before);expect(writes()).toHaveLength(0);
});
for(const locale of ['en','ko'])test(`Human matrix stays canonical and fits390px in ${locale}`,async({page})=>{
 await page.setViewportSize({width:390,height:900});await setup(page);await assign(page);await page.locator('#locale-select').selectOption(locale);await expect(page.locator('#pumgye-kind option[value="human"]')).toHaveText(locale==='ko'?'사람':'Human');await expect(page.locator('[data-assignment-kind="human"] td').first()).toHaveText(locale==='ko'?'사람':'Human');await expect(page.locator('[data-assignment-kind="human"]')).toContainText(human);await expect(page.locator('#pumgye-human-help')).toContainText('AAL1');expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
});

test('invalid raw JSON and stale Human remove handlers cannot overwrite current edits',async({page})=>{
 await setup(page);await assign(page);await page.evaluate(()=>window.oldHumanButton=document.querySelector('[data-assignment-kind="human"] button'));
 await assign(page,human,'guest');const fresh=await page.locator('#pumgye-document').inputValue();await page.evaluate(()=>window.oldHumanButton.click());expect(await page.locator('#pumgye-document').inputValue()).toBe(fresh);
 await page.locator('#pumgye-document').fill('{invalid');await page.locator('[data-assignment-kind="human"] button').click();await expect(page.locator('#pumgye-document')).toHaveValue('{invalid');await assign(page);await expect(page.locator('#pumgye-document')).toHaveValue('{invalid');await expect(page.locator('#pumgye-message')).toContainText('Correct the authorization policy JSON');
});
