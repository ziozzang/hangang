// Identities ▸ Credential projections (Hangang ADR 0014): projection plans per
// service from Hopae `authentication/projections`, connector circuits from
// Hopae `status`, and the plan editor with CAS publish and a reason.
import { can, hopae, failure, sectionPage, notConnected, capabilities, panel, outcomeBanner, button, aalBadge } from './common.js';
import { changeList, loadDraft, saveDraft, dropDraft, publish } from './editor.js';

const DRAFT = 'projections';
const CIRCUIT = Object.freeze({ closed: 'healthy', open: 'deny', half_open: 'stale', quarantined: 'error', unavailable: 'unavailable' });
const CREDENTIALS = Object.freeze(['identity_header', 'bearer_reference']);

function circuitBadge(cx, circuit) {
  const safe = Object.hasOwn(CIRCUIT, circuit) ? circuit : 'unavailable';
  return cx.ui.statusBadge(cx.t, CIRCUIT[safe], `identities.circuit.${safe}`);
}

function planEntities(cx, config) {
  const { t } = cx;
  const out = {};
  for (const plan of config?.plans || []) {
    out[`${plan.service} › ${plan.resource}:${plan.action} → ${plan.audience}`] = {
      'identities.projection.field.minimum_aal': t('identities.aal', { aal: plan.minimum_aal }),
      'identities.projection.field.credential': t(`identities.projection.credential.${CREDENTIALS.includes(plan.credential?.type) ? plan.credential.type : 'identity_header'}`),
      ...(plan.credential?.type === 'bearer_reference' ? { 'identities.projection.field.secret_ref': plan.credential.secret_ref } : {}),
    };
  }
  return out;
}

function planRow(cx, plan, { readOnly, onChange, onRemove }) {
  const { t, ui } = cx;
  const row = ui.el('tr', { class: 'zt-plan' });
  const input = (name, value, label, extra = {}) => { const node = ui.el('input', { name, value: value ?? '', disabled: readOnly, spellcheck: false, autocomplete: 'off', maxLength: 128, required: true, ...extra }); node.setAttribute('aria-label', t(label)); return ui.el('td', {}, node); };
  const aal = ui.el('select', { name: 'minimum_aal', disabled: readOnly }, [0, 1, 2].map(value => ui.el('option', { value: String(value), text: t('identities.aal', { aal: value }), selected: plan.minimum_aal === value })));
  aal.setAttribute('aria-label', t('identities.projection.field.minimum_aal'));
  const credential = ui.el('select', { name: 'credential', disabled: readOnly }, CREDENTIALS.map(value => ui.el('option', { value, text: t(`identities.projection.credential.${value}`), selected: (plan.credential?.type || 'identity_header') === value })));
  credential.setAttribute('aria-label', t('identities.projection.field.credential'));
  const secret = ui.el('input', { name: 'secret_ref', value: plan.credential?.secret_ref || '', disabled: readOnly || credential.value !== 'bearer_reference', spellcheck: false, autocomplete: 'off', maxLength: 128 });
  secret.setAttribute('aria-label', t('identities.projection.field.secret_ref'));
  row.append(input('service', plan.service, 'identities.projection.field.service'), input('audience', plan.audience, 'identities.projection.field.audience'), input('resource', plan.resource, 'identities.projection.field.resource'), input('action', plan.action, 'identities.projection.field.action'),
    ui.el('td', {}, aal), ui.el('td', {}, credential, ' ', secret),
    ui.el('td', {}, readOnly ? null : ui.el('button', { type: 'button', class: 'button button-quiet', text: t('identities.projection.remove'), on: { click: onRemove } })));
  const emit = () => {
    secret.disabled = readOnly || credential.value !== 'bearer_reference';
    const value = name => row.querySelector(`[name=${name}]`).value.trim();
    onChange({ service: value('service'), audience: value('audience'), minimum_aal: Number(aal.value), resource: value('resource'), action: value('action'), credential: credential.value === 'bearer_reference' ? { type: 'bearer_reference', secret_ref: secret.value.trim() } : { type: 'identity_header' } });
  };
  row.addEventListener('input', emit); row.addEventListener('change', emit);
  return row;
}

export async function renderProjections(cx, root) {
  const { t, ui } = cx;
  const caps = await capabilities(cx);
  if (cx.signal.aborted) return;
  const { content } = sectionPage(cx, root, { active: 'projections', title: t('identities.page.projections'), owner: t('identities.projections.owner') });
  if (!caps.installed || !can(caps, 'authentication/projections')) { content.append(notConnected(cx, caps, 'authentication/projections')); return; }
  const body = ui.el('div', { class: 'zt-content' }, ui.loadingState(t));
  content.append(body);
  let document, runtime = null, runtimeFailed = false;
  try {
    const [projections, status] = await Promise.allSettled([hopae(cx, 'authentication/projections'), can(caps, 'status') ? hopae(cx, 'status') : Promise.reject(Object.assign(new Error('status'), { status: 404 }))]);
    if (projections.status === 'rejected') throw projections.reason;
    document = projections.value.data || { revision: 0, configuration: null };
    if (status.status === 'fulfilled') runtime = status.value.data?.authentication_gateway || null; else runtimeFailed = true;
  } catch (error) { ui.clear(body, failure(cx, error, () => cx.navigate('#identities/projections?retry=' + Date.now()))); return; }
  if (cx.signal.aborted) return;
  const revision = Number(document.revision) || 0;
  const base = document.configuration || null;
  const connectors = Array.isArray(runtime?.connectors) ? runtime.connectors : [];
  // Services: every projected service plus every service with a verifier connector.
  const services = [...new Set([...(base?.plans || []).map(plan => plan.service), ...connectors.map(row => row.service_id)])].sort();
  const cards = ui.el('div', { class: 'zt-service-grid' });
  if (!services.length) cards.append(ui.emptyState(t, { title: 'identities.projections.empty', body: 'identities.projections.empty.body' }));
  for (const service of services) {
    const plans = (base?.plans || []).filter(plan => plan.service === service);
    const circuits = connectors.filter(row => row.service_id === service);
    const worst = circuits.find(row => row.circuit === 'open' || row.circuit === 'quarantined') || circuits.find(row => row.circuit !== 'closed') || circuits[0];
    cards.append(ui.el('article', { class: 'zt-card zt-service', attrs: { 'aria-label': service } },
      ui.el('div', { class: 'zt-card-head' }, ui.el('a', { href: `#policies/services/${encodeURIComponent(service)}`, class: 'zt-stack' }, ui.el('strong', { text: service }), ui.el('span', { class: 'kit-muted', text: t('identities.projections.plans', { count: plans.length }) })), worst ? circuitBadge(cx, worst.circuit) : ui.el('span', { class: 'kit-tag', text: t('identities.projections.no_connector') })),
      circuits.length ? ui.el('ul', { class: 'zt-circuits' }, circuits.map(row => ui.el('li', {}, ui.el('span', { text: t(row.connector === 'kubernetes-tokenreview' ? 'identities.profile.connector.kubernetes' : row.connector === 'api-relay' ? 'identities.profile.connector.api_relay' : 'identities.projections.connector.other') }), circuitBadge(cx, row.circuit), ui.el('span', { class: 'kit-muted', text: t('identities.projections.capacity', { count: row.available_capacity ?? 0 }) })))) : null,
      plans.length ? ui.el('ul', { class: 'zt-plan-list' }, plans.map(plan => ui.el('li', {}, ui.el('code', { class: 'kit-mono', text: `${plan.resource}:${plan.action}` }), ' → ', ui.el('span', { text: plan.audience }), ' ', aalBadge(cx, plan.minimum_aal), ' ', ui.el('span', { class: 'kit-tag', text: t(`identities.projection.credential.${CREDENTIALS.includes(plan.credential?.type) ? plan.credential.type : 'identity_header'}`) })))) : ui.el('p', { class: 'kit-muted', text: t('identities.projections.no_plans') })));
  }
  const strip = ui.el('div', { class: 'zt-authority' },
    ui.el('span', { class: 'zt-authority-item' }, ui.el('span', { class: 'kit-muted', text: t('identities.authority.owner') }), ' ', ui.el('strong', { text: t('ui.owner.hopae') })),
    ui.el('span', { class: 'zt-authority-item', text: t('ui.revision', { revision }) }),
    document.digest ? ui.el('span', { class: 'zt-authority-item' }, ui.el('span', { class: 'kit-muted', text: t('identities.authority.digest') }), ' ', ui.hashChip(t, document.digest)) : null,
    runtimeFailed ? ui.statusBadge(t, 'unavailable', 'identities.projections.circuits.unavailable') : runtime ? ui.statusBadge(t, runtime.available ? 'healthy' : 'unavailable', runtime.available ? 'identities.authority.runtime.ready' : 'identities.authority.runtime.unavailable') : ui.statusBadge(t, 'disabled', 'identities.projections.gateway.off'));
  // Editor.
  const canPublish = can(caps, 'authentication/projections/publish');
  const status = ui.el('div', { class: 'zt-notes' });
  const stored = loadDraft(DRAFT);
  let draft = { plans: structuredClone(base?.plans || []) };
  if (stored?.base === revision && stored.draft) { draft = stored.draft; status.append(ui.el('p', { class: 'zt-banner', attrs: { role: 'status' } }, ui.el('span', { text: t('identities.draft.restored') }), ' ', button(cx, 'identities.draft.discard', () => { dropDraft(DRAFT); cx.navigate('#identities/projections?fresh=' + Date.now()); }))); }
  else if (stored && stored.base !== revision) dropDraft(DRAFT);
  const tbody = ui.el('tbody');
  const counter = ui.el('span', { class: 'zt-change-count', attrs: { 'aria-live': 'polite' } });
  const publishButton = ui.el('button', { type: 'button', class: 'button button-primary', text: t('identities.publish.review'), disabled: true });
  const preview = ui.el('div');
  const changed = () => {
    const diff = changeList(cx, planEntities(cx, base), planEntities(cx, draft));
    counter.textContent = t('identities.publish.changes', { count: diff.count });
    publishButton.disabled = !diff.count || !canPublish;
    ui.clear(preview, diff.element);
    if (diff.count) saveDraft(DRAFT, revision, draft); else dropDraft(DRAFT);
  };
  const renderRows = () => {
    ui.clear(tbody, draft.plans.map((plan, index) => planRow(cx, plan, { readOnly: !canPublish, onChange: next => { draft.plans[index] = next; changed(); }, onRemove: () => { draft.plans.splice(index, 1); renderRows(); changed(); } })));
    if (!draft.plans.length) tbody.append(ui.el('tr', {}, ui.el('td', { colSpan: 7 }, ui.el('p', { class: 'kit-muted', text: t('identities.projections.no_plans') }))));
  };
  const form = ui.el('form', { class: 'zt-plan-form' }, ui.el('table', { class: 'zt-keys zt-plans' }, ui.el('caption', { class: 'kit-visually-hidden', text: t('identities.projections.editor') }),
    ui.el('thead', {}, ui.el('tr', {}, ['identities.projection.field.service', 'identities.projection.field.audience', 'identities.projection.field.resource', 'identities.projection.field.action', 'identities.projection.field.minimum_aal', 'identities.projection.field.credential', 'identities.session.col.actions'].map(key => ui.el('th', { scope: 'col', text: t(key) })))), tbody));
  form.addEventListener('submit', event => event.preventDefault());
  publishButton.addEventListener('click', async () => {
    if (!form.reportValidity()) return;
    const configuration = draft.plans.length || base ? { revision: revision + 1, plans: draft.plans } : null;
    const result = await publish(cx, { route: 'authentication/projections/publish', revision, configuration, diff: changeList(cx, planEntities(cx, base), planEntities(cx, draft)), target: t('identities.projections.target'), status });
    if (!result) return;
    dropDraft(DRAFT);
    ui.clear(status, outcomeBanner(cx, 'committed', 'identities.publish.done', { revision: revision + 1, operation: result.operation || '—' }));
    setTimeout(() => cx.navigate('#identities/projections?published=' + Date.now()), 1200);
  });
  renderRows(); changed();
  const editor = panel(cx, 'identities.projections.editor', ui.el('div', { class: 'zt-content' }, ui.el('p', { class: 'kit-muted', text: t('identities.projections.editor.help') }), form, panel(cx, 'identities.publish.preview', preview)), {
    actions: canPublish ? [counter, button(cx, 'identities.projection.add', () => { draft.plans.push({ service: '', audience: '', minimum_aal: 1, resource: '', action: '', credential: { type: 'identity_header' } }); renderRows(); changed(); }), publishButton] : [ui.disabledAction(t, 'identities.publish.review', 'identities.gap.not_declared')],
  });
  ui.clear(body, strip, status, panel(cx, 'identities.projections.services', cards), editor);
}
