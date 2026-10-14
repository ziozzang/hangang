import { t } from './i18n.js';
let generation = 0;
let context = null;
let document = null;
let etag = null;
let draft = null;
let dirty = false;
let independent = false;
let authorityRevision = null;
let sourceManaged = false;
let sourceOwner = 'native';
function sourceControls() {
  $('pumgye-document').readOnly = sourceManaged;
  $('pumgye-publish').disabled = sourceManaged;
  for (const id of ['pumgye-service-form','pumgye-assignment-form']) for (const element of $(id).elements) element.disabled = sourceManaged;
}
const $ = (id) => window.document.getElementById(id);
const text = (value) => window.document.createTextNode(value);
function message(value) { $('pumgye-message').textContent = value; }
function sourceSummary(status) {
  const states = {
    native: 'Native policy source', starting: 'Kubernetes source starting',
    collecting: 'Kubernetes source collecting', fresh: 'Kubernetes source fresh',
    expired: 'Kubernetes source expired', collection_failed: 'Kubernetes source collection failed',
    candidate_rejected: 'Kubernetes policy candidate rejected', persistence_failed: 'Policy persistence failed',
  };
  const state = Object.hasOwn(states, status.source_state) ? states[status.source_state] : 'Source state unreported';
  const available = status.healthy === true ? 'Authority available' : 'Authority unavailable';
  const parts = [t('Status at last refresh'), t(state), t(available)];
  if (Number.isSafeInteger(status.policy_revision) && status.policy_revision >= 0)
    parts.push(t('Applied policy revision {revision}', { revision: status.policy_revision }));
  if (Number.isSafeInteger(status.source_lease_remaining_ms) && status.source_lease_remaining_ms >= 0)
    parts.push(t('Source lease remaining {milliseconds} ms', { milliseconds: status.source_lease_remaining_ms }));
  $('pumgye-source-summary').textContent = parts.join(' · ');
}
function edit() { if (sourceManaged) return; draft = JSON.parse($('pumgye-document').value); dirty = true; render(); }
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
      const td = window.document.createElement('td'); const button = window.document.createElement('button'); button.type = 'button'; button.className = 'button button-quiet'; button.textContent = t('Remove'); button.disabled = sourceManaged;
      button.addEventListener('click', () => { if (sourceManaged) return; if (kind === 'User') delete service.users[id]; else service.networks = service.networks.filter(n => n.cidr !== id); dirty = true; render(); }); td.append(button); tr.append(td); table.append(tr);
    }
  }
  $('pumgye-roles').textContent = JSON.stringify(service.roles, null, 2);
}
export function resetPumgye() { sourceOwner = 'native'; sourceManaged = false; sourceControls(); generation++; context = null; document = null; etag = null; draft = null; dirty = false; independent=false; authorityRevision=null; if ($('pumgye-authority-panel')) $('pumgye-authority-panel').hidden=true; for (const id of ['pumgye-document','pumgye-subject']) if ($(id)) $(id).value=''; if ($('pumgye-matrix')) $('pumgye-matrix').replaceChildren(); if ($('pumgye-roles')) $('pumgye-roles').textContent=''; for (const id of ['pumgye-source-summary','pumgye-authority-status','pumgye-audit']) if ($(id)) $(id).textContent=''; }
export async function loadPumgye(host) {
  context = host; const own = ++generation; sourceManaged = true; sourceControls();
  $('pumgye-source-summary').textContent = t('Checking authority');
  $('pumgye-authority-status').textContent = '';
  $('pumgye-audit').textContent = '';
  let result;
  try { result = await host.api('/v1/config'); }
  catch (error) { if (own === generation) $('pumgye-source-summary').textContent = t('Authority unavailable'); throw error; }
  if (own !== generation) return;
  independent = Boolean(result.data.pumgye_authority);
  $('pumgye-authority-panel').hidden = !independent;
  if (independent) {
    let results;
    try {
      results = await Promise.all([host.api('/v1/pumgye/policy'),host.api('/v1/pumgye/status'),host.api('/v1/pumgye/audit')]);
    } catch (error) {
      if (own === generation) $('pumgye-source-summary').textContent = t('Authority unavailable');
      throw error;
    }
    const [policy, status, audit] = results;
    if (own !== generation) return;
    document=policy.data;etag=policy.etag || `"${document.revision}"`;authorityRevision=policy.response.headers.get('x-hangang-config-revision');
    sourceOwner = ['native', 'kubernetes'].includes(status.data.policy_source) ? status.data.policy_source : 'unknown';
    sourceManaged = sourceOwner !== 'native';
    sourceSummary(status.data);
    $('pumgye-authority-status').textContent=JSON.stringify(status.data,null,2);
    $('pumgye-audit').textContent=JSON.stringify(audit.data,null,2);
  } else { sourceOwner = 'native'; sourceManaged = false; document = result.data; etag = result.etag || `"${document.revision}"`; authorityRevision=null; }
  draft = structuredClone((independent?document.policy:document.pumgye) || { version:1, information_classes:['public','internal','confidential','restricted'], services:{} }); dirty=false; sourceControls(); render(); message(sourceManaged ? t(sourceOwner === 'kubernetes' ? 'Kubernetes owns this policy. Change the source RBAC or its mapping, then refresh.' : 'Policy source ownership is unreported. Native editing is disabled.') : t('Unassigned users are guests with no permissions. User and network rights must both allow access.'));
}
$('pumgye-service').addEventListener('change', renderMatrix);
$('pumgye-document').addEventListener('change', () => { try { edit(); message(t('Draft updated. Publish to apply.')); } catch (e) { dirty=true; message(e.message); } });
$('pumgye-refresh').addEventListener('click', () => { if (dirty && !confirm(t('Discard unsaved authorization changes?'))) return; if (context) loadPumgye(context).catch(e=>message(e.message)); });
$('pumgye-service-form').addEventListener('submit', (event) => {
  event.preventDefault(); if (sourceManaged || !draft) return; const id=$('pumgye-new-service').value.trim(); if (!id || draft.services[id]) return message(t('Choose a new service ID.'));
  draft.services[id]={ permissions:['read','write'], roles:{reader:{permissions:['read'],information_classes:['public'],inherits:[],minimum_aal:1},writer:{permissions:['write'],information_classes:['public'],inherits:['reader'],minimum_aal:2}},users:{},networks:[],require_guard:true };
  dirty=true; render(); $('pumgye-service').value=id; renderMatrix();
});
$('pumgye-assignment-form').addEventListener('submit', event => {
  event.preventDefault(); if (sourceManaged) return; const service=draft?.services?.[$('pumgye-service').value]; if (!service) return;
  const id=$('pumgye-subject').value.trim(); const roles=$('pumgye-assignment-roles').value.split(',').map(x=>x.trim()).filter(Boolean);
  if (!id || !roles.length || roles.some(role=>role!=='guest' && !Object.hasOwn(service.roles,role))) return message(t('Use an existing role or guest.'));
  if ($('pumgye-kind').value==='user') Object.defineProperty(service.users,id,{value:roles,enumerable:true,writable:true,configurable:true});
  else { service.networks=service.networks.filter(n=>n.cidr!==id);service.networks.push({cidr:id,roles}); }
  dirty=true;render();message(t('Draft updated. Publish to apply.'));
});
$('pumgye-publish').addEventListener('click', async () => {
  if (sourceManaged || !context || !document) return; const own=generation; const button=$('pumgye-publish');button.disabled=true;
  try {
    const policy=JSON.parse($('pumgye-document').value);
    const next=independent?{revision:document.revision,policy}:structuredClone(document);if (!independent) next.pumgye=policy;
    const headers={'If-Match':etag};if (independent) {if (!authorityRevision) throw new Error(t('Reload before publishing.'));headers['x-hangang-config-revision']=authorityRevision;}
    const result=await context.api(independent?'/v1/pumgye/policy':'/v1/config',{method:'PUT',headers,json:next});
    if (own!==generation) return;document=result.data;if (independent) authorityRevision=result.response.headers.get('x-hangang-config-revision');etag=result.etag || `"${document.revision}"`;draft=structuredClone(independent?document.policy:document.pumgye);dirty=false;render();message(t('Authorization policy published.'));
  } catch (e) { if (own===generation) message(e.status===409?t('Configuration changed. Reload before publishing.'):e.message); }
  finally { if (own === generation) button.disabled=sourceManaged; }
});
