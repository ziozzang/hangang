// Devices & Workloads section (ADR 0020 §6): shared helpers and data sources.
// Workload principals come from Hopae (Kubernetes ServiceAccount identity,
// Hopae docs/KUBERNETES_WORKLOAD.md) through its console package broker, their
// grants and re-grant proposals from Pumgye model v2 through the Hangang
// broker (`/v1/pumgye/v2/*`), protected routes from Hangang itself
// (`/v1/kubernetes/protection`). Every source is optional: a missing one is
// stated, never guessed.
import { capabilities as hopaeCapabilities, can as hopaeCan, hopae } from '../identities/common.js';

export const PAGES = Object.freeze(['workloads', 'routes', 'devices']);
const PAGE_ICONS = Object.freeze({ workloads: '⬡', routes: '⛨', devices: '▭' });
export const STATUSES = Object.freeze(['active', 'retired']);
/** Hopae routes this section reads; undeclared ones are listed as manifest gaps. */
export const HOPAE_ROUTES = Object.freeze(['subjects/workloads/snapshot', 'subjects/lifecycle']);
const FEED_PAGES = 10, FEED_LIMIT = 200;

export { hopaeCapabilities, hopaeCan };

export function sectionPage(cx, root, { active, crumbs = [], title, owner, actions = [] }) {
  const { t, ui } = cx;
  const view = cx.page(root, { crumbs: [{ label: t('nav.workloads'), href: '#workloads' }, ...crumbs], title, owner, actions });
  const nav = ui.el('nav', { class: 'zt-subnav', attrs: { 'aria-label': t('workloads.subnav') } });
  nav.append(ui.el('ul', {}, PAGES.map(name => {
    const link = ui.el('a', { href: `#workloads/${name}`, dataset: { page: name } }, ui.el('span', { class: 'zt-subnav-icon', text: PAGE_ICONS[name], attrs: { 'aria-hidden': 'true' } }), ui.el('span', { text: t(`workloads.page.${name}`) }));
    if (name === active) link.setAttribute('aria-current', 'page');
    return ui.el('li', {}, link);
  })));
  view.content.before(nav);
  return view;
}

export function toMs(value) { return Number.isFinite(value) && value > 0 ? (value > 1e12 ? value : value * 1000) : null; }
export function timeOrDash(cx, value) {
  const ms = toMs(value);
  return ms ? cx.ui.timeCell(cx.t, ms) : cx.ui.el('span', { class: 'kit-muted', text: cx.t('workloads.none') });
}
const NUMBER = () => new Intl.NumberFormat(document.documentElement.lang || undefined);
export function number(value) { return Number.isFinite(value) ? NUMBER().format(value) : '—'; }

export function facts(cx, rows) {
  const { t, ui } = cx;
  return ui.el('dl', { class: 'zt-dl' }, rows.filter(([, value]) => value !== null && value !== undefined && value !== '').map(([key, value]) => [ui.el('dt', { text: t(key) }), ui.el('dd', {}, value instanceof Node ? value : String(value))]));
}
export function panel(cx, titleKey, body, { actions = [], params, className = '' } = {}) {
  const { t, ui } = cx;
  return ui.el('section', { class: `panel zt-panel ${className}`.trim(), attrs: { 'aria-label': t(titleKey, params) } },
    ui.el('div', { class: 'zt-panel-head' }, ui.el('h2', { text: t(titleKey, params) }), actions.length ? ui.el('div', { class: 'button-row' }, actions) : null), body);
}
export function mono(cx, value, { copy = false } = {}) {
  const { t, ui } = cx;
  if (!value) return ui.el('span', { class: 'kit-muted', text: t('workloads.none') });
  const code = ui.el('code', { class: 'kit-mono zt-break', text: value });
  return copy ? ui.el('span', { class: 'zt-id' }, code, ui.copyButton(t, value)) : code;
}
export function statusBadge(cx, status) {
  return status === 'retired' ? cx.ui.statusBadge(cx.t, 'disabled', 'workloads.status.retired') : status === 'active' ? cx.ui.statusBadge(cx.t, 'healthy', 'workloads.status.active') : cx.ui.statusBadge(cx.t, 'unknown', 'workloads.status.unknown');
}
export function workloadHref(principal) { return `#workloads/w/${encodeURIComponent(principal)}`; }

/** Localized sentence for a failed call; never the raw backend text. */
export function errorText(t, error) {
  const status = error?.status ?? 0;
  const payload = error?.payload && typeof error.payload === 'object' ? error.payload : {};
  const code = typeof payload.error?.code === 'string' ? payload.error.code : '';
  if (code === 'pumgye.error.revision_conflict' || (status === 409 && !code && /revision/i.test(String(payload.detail || '')))) return t('workloads.error.conflict');
  if (code === 'pumgye.error.regrant_unknown') return t('workloads.error.regrant_unknown');
  if (code === 'pumgye.error.no_v2_document') return t('workloads.error.no_v2');
  if (status === 409) return t('workloads.error.kubernetes_owned');
  if (status === 429) return t('workloads.error.busy');
  if (status === 400) return t('workloads.error.invalid');
  if (status === 403) return t('workloads.error.forbidden');
  if (status === 404) return t('workloads.error.not_available');
  if (status === 502 || status === 503 || status === 0) return t('workloads.error.unavailable');
  return t('workloads.error.generic', { status });
}

/**
 * Hopae workload principals. Prefer the durable registry snapshot; Hopae
 * console package 0.1.10 does not declare it, so the lifecycle feed with
 * `include_workloads` is folded instead (retained events only, bounded pages).
 */
export async function hopaeWorkloads(cx, caps) {
  const out = { source: null, items: new Map(), complete: true, error: null, gaps: HOPAE_ROUTES.filter(route => !hopaeCan(caps, route)) };
  if (!caps.installed) { out.error = { status: 0, missing: true }; return out; }
  try {
    if (hopaeCan(caps, 'subjects/workloads/snapshot')) {
      out.source = 'snapshot';
      let cursor = null;
      for (let page = 0; page < FEED_PAGES; page += 1) {
        const { data } = await hopae(cx, 'subjects/workloads/snapshot', { json: { cursor, limit: FEED_LIMIT } });
        for (const item of data?.items || []) if (item?.principal) out.items.set(item.principal, { ...item, legacy_subject_refs: item.legacy_subject_refs || [] });
        cursor = data?.next_cursor || null;
        if (!cursor) break;
      }
      out.complete = !cursor;
    } else if (hopaeCan(caps, 'subjects/lifecycle')) {
      out.source = 'feed';
      let cursor = null, more = true;
      for (let page = 0; page < FEED_PAGES && more; page += 1) {
        const { data } = await hopae(cx, 'subjects/lifecycle', { json: { ...(cursor ? { cursor } : {}), limit: FEED_LIMIT, include_workloads: true } });
        for (const change of data?.changes || []) foldChange(out.items, change);
        cursor = data?.next_cursor || cursor;
        more = Boolean(data?.more) && (data?.changes || []).length > 0;
      }
      out.complete = !more;
    }
  } catch (error) { if (error?.status === 401) throw error; out.error = error; }
  return out;
}

function foldChange(items, change) {
  const w = change?.workload;
  if (!w?.principal) return;
  const at = toMs(change.at);
  const record = items.get(w.principal) || { principal: w.principal, legacy_subject_refs: [], first_seen_at: null, last_seen_at: null };
  for (const key of ['subject_ref', 'spiffe_id', 'cluster', 'namespace', 'service_account', 'service_account_uid', 'service']) if (w[key]) record[key] = w[key];
  if (change.change === 'workload_retired') { record.status = 'retired'; record.retired_at = at; record.cause = w.cause || null; record.replacement = w.replacement || null; }
  else if (record.status !== 'retired') record.status = change.status === 'retired' ? 'retired' : 'active';
  if (change.change === 'workload_legacy_mapped' && w.legacy_subject_ref && !record.legacy_subject_refs.includes(w.legacy_subject_ref)) record.legacy_subject_refs.push(w.legacy_subject_ref);
  if (at && change.change !== 'workload_retired') { record.first_seen_at = record.first_seen_at ? Math.min(record.first_seen_at, at) : at; record.last_seen_at = Math.max(record.last_seen_at || 0, at); }
  items.set(w.principal, record);
}

/** Pumgye model v2: principals, legacy mappings, re-grant proposals and bindings. */
export async function pumgyeWorkloads(cx) {
  const out = { workloads: null, policy: null, revision: null, error: null, policyError: null };
  const settle = promise => promise.then(answer => ({ ok: answer.data }), error => { if (error?.status === 401) throw error; return { error }; });
  const [workloads, policy] = await Promise.all([settle(cx.api('/v1/pumgye/v2/workloads')), settle(cx.api('/v1/pumgye/v2/policy'))]);
  if (workloads.error) out.error = workloads.error; else out.workloads = { principals: workloads.ok?.principals || [], legacy: workloads.ok?.legacy_mappings || {}, proposals: workloads.ok?.regrant_proposals || [] };
  if (policy.error) out.policyError = policy.error; else out.policy = { revision: policy.ok?.revision ?? null, bindings: Array.isArray(policy.ok?.policy?.bindings) ? policy.ok.policy.bindings : [] };
  // Re-grant base: Pumgye's `policy_revision` on /v2/workloads (same answer as
  // the proposals) when present, else the v2 document revision.
  const listed = workloads.ok?.policy_revision;
  out.revision = Number.isSafeInteger(listed) && listed >= 0 ? listed : Number.isSafeInteger(out.policy?.revision) ? out.policy.revision : null;
  return out;
}

/**
 * One row per principal from both owners. Hopae is authoritative for
 * observation times; Pumgye adds its retired state, legacy mappings and grants.
 */
export function mergeWorkloads(hopaeData, pumgyeData) {
  const rows = new Map();
  for (const [principal, item] of hopaeData.items) rows.set(principal, { ...item, sources: ['hopae'] });
  for (const item of pumgyeData.workloads?.principals || []) {
    const row = rows.get(item.principal) || { principal: item.principal, legacy_subject_refs: [], sources: [] };
    for (const key of ['subject_ref', 'spiffe_id', 'cluster', 'namespace', 'service_account', 'service_account_uid', 'cause', 'replacement']) if (item[key] && !row[key]) row[key] = item[key];
    if (item.status === 'retired') row.status = 'retired';
    else row.status ||= item.status;
    row.sources = [...row.sources, 'pumgye'];
    rows.set(item.principal, row);
  }
  for (const [legacy, principal] of Object.entries(pumgyeData.workloads?.legacy || {})) {
    const row = rows.get(principal);
    if (row && !row.legacy_subject_refs.includes(legacy)) row.legacy_subject_refs = [...row.legacy_subject_refs, legacy];
  }
  const bindings = pumgyeData.policy?.bindings || null;
  const proposals = pumgyeData.workloads?.proposals || [];
  for (const row of rows.values()) {
    row.grants = bindings ? grantsFor(bindings, row) : null;
    row.proposals = proposals.filter(proposal => proposal.evidence?.principal === row.principal);
  }
  return [...rows.values()].sort((a, b) => (a.namespace || '').localeCompare(b.namespace || '') || (a.service_account || '').localeCompare(b.service_account || '') || (a.status === 'retired') - (b.status === 'retired'));
}

/** Bindings naming the principal, its SPIFFE ID or one of its legacy Pod-bound subjects. */
export function grantsFor(bindings, row) {
  const out = [];
  for (const binding of bindings) {
    for (const subject of binding.subjects || []) {
      if (subject?.kind !== 'workload') continue;
      const match = subject.ref === row.principal ? 'principal' : row.spiffe_id && subject.ref === row.spiffe_id ? 'spiffe' : row.legacy_subject_refs.includes(subject.ref) ? 'legacy' : null;
      if (match) { out.push({ binding, match }); break; }
    }
  }
  return out;
}
