// Access simulator: Pumgye POST /v1/explain through the Hangang broker. The
// form state lives in the URL so a result can be shared and re-run; Pumgye
// structured errors are placed on the offending field.
import { policyState } from './store.js';
import { contextOf, kindsFor } from './model.js';

const GUARD = Object.freeze(['enforced_allow', 'observe', 'deny', 'unavailable']);
const FIELD_FOR_PATH = Object.freeze({ 'case.subject.id': 'subject', 'case.subject.kind': 'kind', 'case.subject': 'subject', 'case.ip': 'ip', 'case.aal': 'aal', 'case.guard': 'guard', 'case.permission': 'permission', 'case.information_class': 'information_class', 'case.resource': 'resource', 'case.action': 'action' });

function params(detail) {
  const out = {};
  for (const [key, value] of Object.entries(detail || {})) {
    if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) out[key] = value ?? '—';
    else if (Array.isArray(value) && value.every(item => typeof item !== 'object')) out[key] = value.join(', ');
  }
  return out;
}

function stageExtra(cx, entry) {
  const { t, ui } = cx;
  const detail = entry.detail || {};
  const chips = (values, kind = '') => ui.el('span', { class: 'zt-chips' }, values.map(value => ui.el('span', { class: `kit-tag ${kind}`, text: value })));
  if (entry.stage === 'subject' && Array.isArray(detail.roles)) return ui.el('div', { class: 'zt-trace-extra' }, ui.el('span', { class: 'kit-muted', text: t('policies.sim.roles') }), chips(detail.roles));
  if (entry.stage === 'network' && detail.matched) return ui.el('div', { class: 'zt-trace-extra' }, ui.el('span', { class: 'kit-muted', text: t('policies.sim.matched') }), ui.el('code', { class: 'kit-mono', text: detail.matched.cidr }), chips(detail.matched.roles || []),
    Array.isArray(detail.shadowed) && detail.shadowed.length ? ui.el('small', { class: 'kit-muted', text: t('policies.sim.shadowed', { count: detail.shadowed.length }) }) : null);
  if (entry.stage === 'role_expansion' && detail.effective) return ui.el('div', { class: 'zt-trace-extra' }, ui.el('span', { class: 'kit-muted', text: t('policies.sim.effective') }), chips(detail.effective.permissions || []), chips(detail.effective.information_classes || [], 'zt-class-chip'));
  return null;
}

export function explainResult(cx, response) {
  const { t, ui } = cx;
  const result = response.result || {};
  const outcome = result.outcome || {};
  const kind = outcome.allow ? 'allow' : outcome.reason_code === 'pumgye.unavailable' ? 'unavailable' : 'deny';
  const snapshot = response.snapshot || {};
  const head = ui.el('div', { class: 'zt-sim-head' },
    ui.statusBadge(t, kind, `decision.result.${kind}`),
    ui.el('strong', { class: 'kit-mono', text: outcome.decision ?? t('policies.sim.no_decision') }),
    ui.el('span', { class: 'kit-tag', text: t('policies.sim.snapshot', { source: t(`policies.sim.source.${snapshot.source === 'candidate' ? 'candidate' : 'published'}`), revision: snapshot.revision ?? '—' }) }),
    response.audit_id ? ui.el('small', { class: 'kit-muted', text: t('policies.sim.audit', { id: response.audit_id }) }) : null);
  const why = ui.el('p', { class: 'kit-why' }, ui.el('strong', { text: t('decision.why') }), ' ', outcome.message_key ? t(outcome.message_key) : '—');
  const fix = outcome.allow ? null : ui.el('p', { class: 'kit-fix' }, ui.el('strong', { text: t('decision.fix') }), ' ', outcome.hint_key ? t(outcome.hint_key) : t('decision.fix.unknown'));
  const parts = [head, why, fix];
  if (result.obligations?.required_aal) parts.push(ui.el('p', { class: 'kit-muted', text: t('policies.sim.required_aal', { aal: result.obligations.required_aal }) }));
  if (result.comparison) {
    const published = result.comparison.published || {};
    parts.push(ui.el('p', { class: `zt-banner${result.comparison.changed ? ' zt-banner-warn' : ''}`, text: t(result.comparison.changed ? 'policies.sim.changed' : 'policies.sim.unchanged', { before: published.decision ?? '—', after: outcome.decision ?? '—' }) }));
  }
  const trace = (result.trace || []).map(entry => ({
    stage: entry.stage, result: entry.result,
    label: t(entry.label_key || `pumgye.stage.${entry.stage}`),
    text: entry.code ? t(entry.code, params(entry.detail)) : '',
    deciding: entry.stage === outcome.deciding_stage,
    extra: stageExtra(cx, entry),
  }));
  parts.push(ui.el('h2', { class: 'zt-subhead', text: t('policies.sim.trace') }), trace.length ? ui.traceTimeline(t, trace) : ui.el('p', { class: 'kit-muted', text: t('policies.sim.no_trace') }));
  return ui.el('section', { class: `panel zt-request is-simulation zt-sim-result`, dataset: { decision: outcome.decision ?? 'none' }, attrs: { 'aria-live': 'polite' } }, parts);
}

/** Places Pumgye structured error details on fields; returns unplaced messages. */
function placeErrors(cx, form, error) {
  const { t } = cx;
  const body = error?.payload?.error;
  if (!body) return [error?.message || t('policies.sim.failed')];
  const loose = [];
  for (const detail of body.details || []) {
    const name = FIELD_FOR_PATH[detail.path];
    const control = name && form.elements[name];
    const message = t(detail.message_key || detail.code);
    if (control) {
      control.setAttribute('aria-invalid', 'true');
      const holder = control.closest('.kit-field') || control.parentElement;
      holder.querySelector('.kit-field-error')?.remove();
      holder.append(cx.ui.el('small', { class: 'kit-field-error', text: message }));
    } else loose.push(`${detail.path}: ${message}`);
  }
  if (!(body.details || []).length) loose.push(t(body.message_key || body.code));
  return loose;
}

export async function renderSimulator(cx, id, service, policy, params) {
  const { t, ui } = cx;
  const state = policyState();
  const wrap = ui.el('div', { class: 'zt-sim' });
  if (!state.independent) { wrap.append(ui.emptyState(t, { title: 'policies.sim.unavailable', body: 'policies.sim.unavailable.body' })); return wrap; }
  const kinds = kindsFor(service);
  const api = contextOf(service) === 'kubernetes_api';
  const resources = Object.entries(policy.resources || {}).filter(([, resource]) => resource.service === id);
  const value = name => params.get(name) || '';
  const kind = kinds.includes(value('kind')) ? value('kind') : kinds[0];
  const mode = api || kind !== 'user' ? 'resource' : (value('mode') === 'resource' ? 'resource' : 'permission');
  const resource = resources.some(([name]) => name === value('resource')) ? value('resource') : resources[0]?.[0] || '';
  const actions = Object.keys(policy.resources?.[resource]?.actions || {});
  const form = ui.el('form', { class: 'panel zt-panel zt-sim-form', attrs: { 'aria-label': t('policies.tab.simulate') } });
  const kindField = ui.field(t, { label: 'policies.col.kind', name: 'kind', value: kind, options: kinds.map(option => ({ value: option, label: `policies.kind.${option}` })) });
  const subject = ['user', 'human'].includes(kind) ? ui.subjectPicker(t, cx.api, { label: 'policies.col.subject', name: 'subject', value: value('subject'), help: 'policies.sim.subject.help' }) : ui.field(t, { label: 'policies.col.subject', name: 'subject', value: value('subject'), maxLength: 128 });
  const modeField = ui.field(t, { label: 'policies.sim.target', name: 'mode', value: mode, options: (api || kind !== 'user' ? ['resource'] : ['permission', 'resource']).map(option => ({ value: option, label: `policies.sim.target.${option}` })) });
  const target = mode === 'permission'
    ? [ui.field(t, { label: 'policies.col.permission', name: 'permission', value: value('permission'), options: (service.permissions || []).map(option => ({ value: option, text: option })) }),
       ui.field(t, { label: 'policies.col.class', name: 'information_class', value: value('information_class'), options: (policy.information_classes || []).map(option => ({ value: option, text: option })) })]
    : resources.length
      ? [ui.field(t, { label: 'policies.resource.id', name: 'resource', value: resource, options: resources.map(([option]) => ({ value: option, text: option })) }),
         ui.field(t, { label: 'policies.col.action', name: 'action', value: value('action'), options: actions.map(option => ({ value: option, text: option })) })]
      : [ui.el('p', { class: 'kit-muted', text: t('policies.sim.no_resources') })];
  const evidence = api ? [] : [
    ui.field(t, { label: 'policies.sim.ip', name: 'ip', value: value('ip') || '192.0.2.10', maxLength: 45 }),
    ui.field(t, { label: 'policies.sim.guard', name: 'guard', value: value('guard') || 'enforced_allow', options: GUARD.map(option => ({ value: option, label: `policies.sim.guard.${option}` })) }),
  ];
  const aal = ui.field(t, { label: 'policies.sim.aal', name: 'aal', value: value('aal') || (api || kind === 'workload' ? '0' : '1'), options: [0, 1, 2, 3].map(option => ({ value: String(option), label: `policies.aal.option.${option}` })) });
  const sources = [{ value: 'published', label: 'policies.sim.source.published' }];
  if (state.draft) sources.push({ value: 'candidate', label: 'policies.sim.source.candidate' });
  const snapshot = ui.field(t, { label: 'policies.sim.snapshot_label', name: 'snapshot', value: value('snapshot') === 'candidate' && state.draft ? 'candidate' : 'published', options: sources });
  const errors = ui.el('div', { class: 'kit-field-error', attrs: { role: 'alert' } });
  form.append(ui.el('div', { class: 'zt-form-grid' }, kindField, subject, modeField, target, evidence, aal, snapshot), errors,
    ui.el('div', { class: 'button-row' }, ui.el('button', { type: 'submit', class: 'button button-primary', text: t('policies.sim.run') })));
  // Changing the subject kind, target mode or resource re-renders the dependent fields.
  for (const name of ['kind', 'mode', 'resource']) form.elements[name]?.addEventListener('change', () => cx.navigate(cx.hashFor('policies', ['services', id], collect(false))));
  function collect(run) {
    const next = new URLSearchParams({ tab: 'simulate' });
    for (const name of ['kind', 'subject', 'mode', 'permission', 'information_class', 'resource', 'action', 'ip', 'guard', 'aal', 'snapshot']) { const control = form.elements[name]; if (control?.value) next.set(name, control.value.trim()); }
    if (run) next.set('run', '1');
    return next;
  }
  form.addEventListener('submit', event => { event.preventDefault(); cx.navigate(cx.hashFor('policies', ['services', id], collect(true))); });
  wrap.append(ui.el('p', { class: 'zt-banner', attrs: { role: 'note' }, text: t('policies.sim.note') }), form);
  if (params.get('run') === '1') {
    const output = ui.el('div', { attrs: { 'aria-live': 'polite' } }, ui.loadingState(t));
    wrap.append(output);
    const subjectId = form.elements.subject.value.trim();
    const testCase = { label: 'console', subject: { id: subjectId, kind }, service: id };
    if (mode === 'permission') { testCase.permission = form.elements.permission?.value; testCase.information_class = form.elements.information_class?.value; }
    else { testCase.resource = form.elements.resource?.value; testCase.action = form.elements.action?.value; }
    if (!api) { testCase.ip = form.elements.ip.value.trim(); testCase.guard = form.elements.guard.value; }
    testCase.aal = Number(form.elements.aal.value);
    const body = { case: testCase, trace: true };
    if (form.elements.snapshot.value === 'candidate' && state.draft) body.snapshot = { source: 'candidate', base_revision: state.revision, policy: state.draft };
    try {
      const { data } = await cx.api('/v1/pumgye/explain', { method: 'POST', json: body });
      if (cx.signal.aborted) return wrap;
      ui.clear(output, explainResult(cx, data));
    } catch (error) {
      if (error?.status === 401) throw error;
      const loose = placeErrors(cx, form, error);
      ui.clear(output, error?.status === 409 ? ui.errorState(t, { owner: 'ui.owner.pumgye', message: t('policies.sim.stale'), retry: () => cx.navigate('#policies?refresh=1') }) : error?.status === 429 ? ui.errorState(t, { owner: 'ui.owner.pumgye', message: t('policies.sim.rate_limited') }) : loose.length ? ui.errorState(t, { owner: 'ui.owner.pumgye', message: loose.join(' · ') }) : '');
    }
  }
  return wrap;
}
