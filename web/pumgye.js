import { t } from './i18n.js';
let generation = 0;
let context = null;
let document = null;
let etag = null;
let draft = null;
let dirty = false;
const $ = (id) => window.document.getElementById(id);
const text = (value) => window.document.createTextNode(value);
function message(value) { $('pumgye-message').textContent = value; }
function edit() { draft = JSON.parse($('pumgye-document').value); dirty = true; render(); }
function render() {
  $('pumgye-document').value = JSON.stringify(draft, null, 2);
  const select = $('pumgye-service'); const selected = select.value;
  select.replaceChildren();
  for (const id of Object.keys(draft.services || {})) { const option = window.document.createElement('option'); option.value = id; option.textContent = id; select.append(option); }
  if (draft.services?.[selected]) select.value = selected;
  renderMatrix();
}
function renderMatrix() {
  const table = $('pumgye-matrix'); table.replaceChildren();
  const service = draft?.services?.[$('pumgye-service').value];
  if (!service) return;
  for (const [kind, rows] of [['User', Object.entries(service.users || {})], ['Network', (service.networks || []).map(n => [n.cidr, n.roles])]]) {
    for (const [id, roles] of rows) {
      const tr = window.document.createElement('tr');
      for (const value of [t(kind), id, roles.join(', ')]) { const td = window.document.createElement('td'); td.append(text(value)); tr.append(td); }
      const td = window.document.createElement('td'); const button = window.document.createElement('button'); button.type = 'button'; button.className = 'button button-quiet'; button.textContent = t('Remove');
      button.addEventListener('click', () => { if (kind === 'User') delete service.users[id]; else service.networks = service.networks.filter(n => n.cidr !== id); dirty = true; render(); }); td.append(button); tr.append(td); table.append(tr);
    }
  }
  $('pumgye-roles').textContent = JSON.stringify(service.roles, null, 2);
}
export function resetPumgye() { generation++; context = null; document = null; etag = null; draft = null; dirty = false; for (const id of ['pumgye-document','pumgye-subject']) if ($(id)) $(id).value=''; if ($('pumgye-matrix')) $('pumgye-matrix').replaceChildren(); if ($('pumgye-roles')) $('pumgye-roles').textContent=''; }
export async function loadPumgye(host) {
  context = host; const own = ++generation;
  const result = await host.api('/v1/config'); if (own !== generation) return;
  document = result.data; etag = result.etag || `"${document.revision}"`;
  draft = structuredClone(document.pumgye || { version:1, information_classes:['public','internal','confidential','restricted'], services:{} }); dirty=false; render(); message(t('Unassigned users are guests with no permissions. User and network rights must both allow access.'));
}
$('pumgye-service').addEventListener('change', renderMatrix);
$('pumgye-document').addEventListener('change', () => { try { edit(); message(t('Draft updated. Publish to apply.')); } catch (e) { dirty=true; message(e.message); } });
$('pumgye-refresh').addEventListener('click', () => { if (dirty && !confirm(t('Discard unsaved authorization changes?'))) return; if (context) loadPumgye(context).catch(e=>message(e.message)); });
$('pumgye-service-form').addEventListener('submit', (event) => {
  event.preventDefault(); if (!draft) return; const id=$('pumgye-new-service').value.trim(); if (!id || draft.services[id]) return message(t('Choose a new service ID.'));
  draft.services[id]={ permissions:['read','write'], roles:{reader:{permissions:['read'],information_classes:['public'],inherits:[],minimum_aal:1},writer:{permissions:['write'],information_classes:['public'],inherits:['reader'],minimum_aal:2}},users:{},networks:[],require_guard:true };
  dirty=true; render(); $('pumgye-service').value=id; renderMatrix();
});
$('pumgye-assignment-form').addEventListener('submit', event => {
  event.preventDefault(); const service=draft?.services?.[$('pumgye-service').value]; if (!service) return;
  const id=$('pumgye-subject').value.trim(); const roles=$('pumgye-assignment-roles').value.split(',').map(x=>x.trim()).filter(Boolean);
  if (!id || !roles.length || roles.some(role=>role!=='guest' && !Object.hasOwn(service.roles,role))) return message(t('Use an existing role or guest.'));
  if ($('pumgye-kind').value==='user') Object.defineProperty(service.users,id,{value:roles,enumerable:true,writable:true,configurable:true});
  else { service.networks=service.networks.filter(n=>n.cidr!==id);service.networks.push({cidr:id,roles}); }
  dirty=true;render();message(t('Draft updated. Publish to apply.'));
});
$('pumgye-publish').addEventListener('click', async () => {
  if (!context || !document) return; const own=generation; const button=$('pumgye-publish');button.disabled=true;
  try {
    const policy=JSON.parse($('pumgye-document').value);
    const next=structuredClone(document);next.pumgye=policy;
    const result=await context.api('/v1/config',{method:'PUT',headers:{'If-Match':etag},json:next});
    if (own!==generation) return;document=result.data;etag=result.etag || `"${document.revision}"`;draft=structuredClone(document.pumgye);dirty=false;render();message(t('Authorization policy published.'));
  } catch (e) { if (own===generation) message(e.status===409?t('Configuration changed. Reload before publishing.'):e.message); }
  finally {button.disabled=false;}
});
