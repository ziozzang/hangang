import { t } from './i18n.js';
let generation = 0;
let matrixGeneration = 0;
let context = null;
let document = null;
let etag = null;
let draft = null;
let dirty = false;
let independent = false;
let authorityRevision = null;
let sourceManaged = false;
let sourceOwner = 'native';
let publishing = false;
let outcomeUnknown = false;
function sourceControls() {
  $('pumgye-document').readOnly = sourceManaged;
  $('pumgye-publish').disabled = sourceManaged || publishing || outcomeUnknown;
  $('pumgye-refresh').disabled = publishing;
  for (const id of ['pumgye-service-form','pumgye-assignment-form']) for (const element of $(id).elements) element.disabled = sourceManaged;
}
const $ = (id) => window.document.getElementById(id);
const text = (value) => window.document.createTextNode(value);
function message(value) { $('pumgye-message').textContent = value; }
function assignmentDraft() {
  try {
    const current = JSON.parse($('pumgye-document').value);
    if (!current || typeof current !== 'object' || Array.isArray(current)) throw new Error();
    return current;
  } catch { message(t('Correct the authorization policy JSON before changing assignments.')); return null; }
}
const apiContext = service => service?.authorization_context === 'kubernetes_api';
const ordinaryContext = service => service?.authorization_context === undefined || service.authorization_context === 'network_and_guard';
const assignmentMap = value => value && typeof value === 'object' && !Array.isArray(value);

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
  const catalog = $('pumgye-resources'); catalog.replaceChildren();
  for (const [id, resource] of Object.entries(draft.resources || {})) {
    const tr = window.document.createElement('tr');
    for (const value of [id, resource.service, resource.information_class,
      Object.entries(resource.actions || {}).map(([action, permission]) => `${action} → ${permission}`).join(', '), resource.minimum_aal ?? 0]) {
      const td = window.document.createElement('td'); td.textContent = String(value); tr.append(td);
    }
    catalog.append(tr);
  }
}
function renderMatrix() {
  const matrix = ++matrixGeneration, own = generation, serviceId = $('pumgye-service').value;
  const table = $('pumgye-matrix'); table.replaceChildren();
  const service = draft?.services?.[serviceId];
  const api = apiContext(service), ordinary = ordinaryContext(service);
  const kinds = $('pumgye-kind');
  for (const option of kinds.options) option.disabled = api ? option.value !== 'kubernetes_api' : !ordinary || option.value === 'kubernetes_api';
  if (kinds.selectedOptions[0]?.disabled) kinds.value = api ? 'kubernetes_api' : ordinary ? 'user' : '';
  const requirement = service ? (api ? 'Kubernetes API context: only mapped API subjects apply. Network and Workload assignments are not accepted. API identities carry AAL0; mapping labels are not authentication.' : !ordinary ? 'Unsupported authorization context. Edit the policy JSON before changing assignments.' : service.require_guard ? 'Enforced Sumunjang allow evidence is required. Observe mode or unavailable evidence refuses access.' : 'Enforced Sumunjang allow evidence is not required. User and network permissions still apply; an explicit network denial refuses access.') : '';
  $('pumgye-guard-requirement').textContent = requirement ? t(requirement) : '';
  if (requirement) $('pumgye-guard-requirement').dataset.i18n = requirement;
  else delete $('pumgye-guard-requirement').dataset.i18n;
  if (!service) return;
  for (const [kind, rows] of [[api ? 'Kubernetes API' : 'User', Object.entries(service.users || {})], ['Workload', Object.entries(service.workload_users || {})], ['Network', (service.networks || []).map(n => [n.cidr, n.roles])]]) {
    for (const [id, roles] of rows) {
      const tr = window.document.createElement('tr'); tr.dataset.assignmentKind = kind === 'Kubernetes API' ? 'kubernetes_api' : kind.toLowerCase();
      for (const [column, value] of [t(kind), id, roles.join(', ')].entries()) { const td = window.document.createElement('td'); if (column === 0) td.dataset.i18n = kind; td.append(text(value)); tr.append(td); }
      const td = window.document.createElement('td'); const button = window.document.createElement('button'); button.type = 'button'; button.className = 'button button-quiet'; button.textContent = t('Remove'); button.dataset.i18n = 'Remove'; button.disabled = sourceManaged;
      button.addEventListener('click', () => {
        if (sourceManaged || own !== generation || matrix !== matrixGeneration) return;
        const current = assignmentDraft(); if (!current) return;
        const active = current.services?.[serviceId]; if (!active) return;
        if (kind === 'User' || kind === 'Workload' || kind === 'Kubernetes API') {
          const field = kind === 'Workload' ? 'workload_users' : 'users';
          if (!assignmentMap(active[field]) || !Object.hasOwn(active[field], id)) return;
          delete active[field][id];
          if (kind === 'Workload' && !Object.keys(active[field]).length) delete active[field];
        } else { if (!Array.isArray(active.networks)) return; active.networks = active.networks.filter(n => n.cidr !== id); }
        draft = current; dirty = true; render();
      }); td.append(button); tr.append(td); table.append(tr);
    }
  }
  $('pumgye-roles').textContent = JSON.stringify(service.roles, null, 2);
}
export function resetPumgye() { publishing = false; outcomeUnknown = false; sourceOwner = 'native'; sourceManaged = false; sourceControls(); generation++; context = null; document = null; etag = null; draft = null; dirty = false; independent=false; authorityRevision=null; if ($('pumgye-kind')) $('pumgye-kind').value='user'; if ($('pumgye-new-context')) $('pumgye-new-context').value='network_and_guard'; if ($('pumgye-authority-panel')) $('pumgye-authority-panel').hidden=true; for (const id of ['pumgye-document','pumgye-subject','pumgye-new-service','pumgye-assignment-roles']) if ($(id)) $(id).value=''; if ($('pumgye-service')) $('pumgye-service').replaceChildren(); if ($('pumgye-matrix')) $('pumgye-matrix').replaceChildren(); if ($('pumgye-resources')) $('pumgye-resources').replaceChildren(); if ($('pumgye-roles')) $('pumgye-roles').textContent=''; if ($('pumgye-guard-requirement')) { $('pumgye-guard-requirement').textContent=''; delete $('pumgye-guard-requirement').dataset.i18n; } for (const id of ['pumgye-source-summary','pumgye-authority-status','pumgye-audit','pumgye-message']) if ($(id)) $(id).textContent=''; }
export async function loadPumgye(host, { resume = false } = {}) {
  // A navigation resume retains the exact draft and its base revisions in memory.
  // Only explicit Refresh may replace it, including invalid raw JSON.
  if (resume && document) { context = host; return; }
  if (publishing) return;
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
  draft = structuredClone((independent?document.policy:document.pumgye) || { version:1, information_classes:['public','internal','confidential','restricted'], services:{} }); dirty=false; outcomeUnknown=false; sourceControls(); render(); message(sourceManaged ? t(sourceOwner === 'kubernetes' ? 'Kubernetes owns this policy. Change the source RBAC or its mapping, then refresh.' : 'Policy source ownership is unreported. Native editing is disabled.') : t('Unassigned subjects are guests with no permissions. The service authorization context determines which evidence applies.'));
}
$('pumgye-service').addEventListener('change', renderMatrix);
$('pumgye-document').addEventListener('input', () => { if (!sourceManaged) dirty = true; });
$('pumgye-document').addEventListener('change', () => { try { edit(); message(t('Draft updated. Publish to apply.')); } catch (e) { dirty=true; message(e.message); } });
$('pumgye-refresh').addEventListener('click', () => { if (dirty && !confirm(t('Discard unsaved authorization changes?'))) return; if (context) loadPumgye(context).catch(e=>message(e.message)); });
$('pumgye-service-form').addEventListener('submit', (event) => {
  event.preventDefault(); if (sourceManaged || !draft) return;
  const current = assignmentDraft(); if (!current) return;
  const id=$('pumgye-new-service').value.trim(), selectedContext=$('pumgye-new-context').value;
  if (!assignmentMap(current.services) || !id || Object.hasOwn(current.services,id)) return message(t('Choose a new service ID.'));
  if (!['network_and_guard','kubernetes_api'].includes(selectedContext)) return message(t('Choose an assignment kind supported by this service authorization context.'));
  const api = selectedContext === 'kubernetes_api', informationClass = current.information_classes?.[0];
  if (typeof informationClass !== 'string') return message(t('Correct the authorization policy JSON before changing assignments.'));
  const service={ permissions:['read','write'], roles:{reader:{permissions:['read'],information_classes:[informationClass],inherits:[],minimum_aal:api?0:1},writer:{permissions:['write'],information_classes:[informationClass],inherits:['reader'],minimum_aal:api?0:2}},users:{},networks:[],require_guard:!api };
  if (api) service.authorization_context='kubernetes_api';
  Object.defineProperty(current.services,id,{value:service,enumerable:true,writable:true,configurable:true});
  draft=current;
  dirty=true; render(); $('pumgye-service').value=id; renderMatrix();
});
$('pumgye-assignment-form').addEventListener('submit', event => {
  event.preventDefault(); if (sourceManaged) return;
  const kind = $('pumgye-kind').value;
  if (!['user', 'workload', 'network', 'kubernetes_api'].includes(kind)) return message(t('Choose a supported assignment kind.'));
  // Never replace invalid raw editor work with the last valid structured draft.
  const current = assignmentDraft(); if (!current) return;
  const service = current?.services?.[$('pumgye-service').value]; if (!service) return;
  if (apiContext(service) ? kind !== 'kubernetes_api' : !ordinaryContext(service) || kind === 'kubernetes_api') return message(t('Choose an assignment kind supported by this service authorization context.'));
  const raw = $('pumgye-subject').value;
  const id = kind === 'workload' || kind === 'kubernetes_api' ? raw : raw.trim();
  if (kind === 'kubernetes_api' && (id.length > 128 || !/^k8sapi:[A-Za-z0-9_.:-]+$/.test(id))) return message(t('Kubernetes API subject must start with k8sapi: and use at most 128 ASCII letters, digits, dots, colons, underscores or hyphens.'));
  if (kind === 'workload' && (id.length !== 50 || !/^s_[0-9a-f]{48}$/.test(id))) return message(t('Workload subject must be s_ followed by exactly 48 lowercase hexadecimal characters.'));
  const roles = $('pumgye-assignment-roles').value.split(',').map(x => x.trim()).filter(Boolean);
  if (!id || !roles.length || roles.some(role => role !== 'guest' && !Object.hasOwn(service.roles || {}, role))) return message(t('Use an existing role or guest.'));
  draft = current;
  if (kind === 'user' || kind === 'workload' || kind === 'kubernetes_api') {
    const field = kind === 'workload' ? 'workload_users' : 'users';
    if (!Object.hasOwn(service, field)) Object.defineProperty(service, field, { value: {}, enumerable: true, writable: true, configurable: true });
    if (!assignmentMap(service[field])) return message(t('Correct the authorization policy JSON before changing assignments.'));
    Object.defineProperty(service[field], id, { value: roles, enumerable: true, writable: true, configurable: true });
  } else { if (!Array.isArray(service.networks)) return message(t('Correct the authorization policy JSON before changing assignments.')); service.networks = service.networks.filter(n => n.cidr !== id); service.networks.push({ cidr: id, roles }); }
  dirty = true; render(); message(t('Draft updated. Publish to apply.'));
});
$('pumgye-publish').addEventListener('click', async () => {
  if (sourceManaged || publishing || outcomeUnknown || !context || !document) return; const own=generation;
  const submitted = $('pumgye-document').value;
  let requested = false; publishing = true; sourceControls();
  try {
    const policy=JSON.parse(submitted);
    const next=independent?{revision:document.revision,policy}:structuredClone(document);if (!independent) next.pumgye=policy;
    const headers={'If-Match':etag};if (independent) {if (!authorityRevision) throw new Error(t('Reload before publishing.'));headers['x-hangang-config-revision']=authorityRevision;}
    requested = true;
    const result=await context.api(independent?'/v1/pumgye/policy':'/v1/config',{method:'PUT',headers,json:next});
    if (own!==generation) return;document=result.data;if (independent) authorityRevision=result.response.headers.get('x-hangang-config-revision');etag=result.etag || `"${document.revision}"`;if ($('pumgye-document').value === submitted) { draft=structuredClone(independent?document.policy:document.pumgye);dirty=false;render();message(t('Authorization policy published.')); }
    else { dirty=true; message(t('Authorization policy published. Newer draft edits are still unsaved.')); }
  } catch (e) { if (own===generation) {
      outcomeUnknown = requested && (!e.status || e.status >= 500);
      message(outcomeUnknown ? t('Outcome unknown; refresh to reconcile before publishing again.') : e.status===409?t('Configuration changed. Reload before publishing.'):e.message);
    } }
  finally { if (own === generation) { publishing=false; sourceControls(); } }
});
