// Devices & Workloads ▸ Protected routes: Hangang's Kubernetes route
// protection report (docs/KUBERNETES_PROTECTION.md): Ingress protection
// state, ProtectionPolicy acceptance, withheld routes with their reason,
// snapshot staleness and client address preservation. Read-only; the
// Kubernetes objects are the authority.
import { sectionPage, number, facts, panel, errorText } from './common.js';

export const INGRESS_STATES = Object.freeze(['protected', 'unprotected', 'withheld']);
export const REASONS = Object.freeze(['ProtectionRequired', 'Invalid', 'Conflicted', 'InvalidIdentityProfile', 'RefNotPermitted', 'GuardUnavailable', 'ClientAddressUnavailable', 'Pending', 'Unsupported', 'TargetNotFound', 'Accepted']);
/** Operator flag that enables protection (shown verbatim, not translated). */
const PROTECTION_FLAG = '--kubernetes-protection-config';
/** Operator settings field for client address preservation. */
const CLIENT_ADDRESS_SETTING = 'client_address';
const STATE_BADGE = Object.freeze({ protected: 'healthy', unprotected: 'stale', withheld: 'deny' });

function reasonText(cx, reason) {
  if (!reason) return cx.t('workloads.none');
  return REASONS.includes(reason) ? cx.t(`workloads.reason.${reason}`) : cx.t('workloads.reason.other', { reason });
}

/** Snapshot age against the bound: a meter, the numbers and the fail-closed state. */
function stalenessGauge(cx, freshness) {
  const { t, ui } = cx;
  if (!freshness) return panel(cx, 'workloads.routes.staleness', ui.el('p', { class: 'kit-muted', text: t('workloads.routes.staleness.unknown') }));
  const age = Number(freshness.snapshot_age_seconds) || 0, max = Number(freshness.max_snapshot_staleness_seconds) || 0;
  const ratio = max ? Math.min(1, age / max) : 0;
  const level = freshness.protected_fail_closed ? 'deny' : ratio >= 0.5 ? 'stale' : 'healthy';
  const meter = ui.el('meter', { class: `zt-staleness zt-staleness-${level}`, min: 0, max: max || 1, low: max * 0.5, high: max * 0.8, optimum: 0, value: Math.min(age, max || age), attrs: { 'aria-label': t('workloads.routes.staleness.meter', { age: number(age), max: number(max) }) } });
  return panel(cx, 'workloads.routes.staleness', ui.el('div', { class: 'zt-content' },
    ui.el('div', { class: 'zt-staleness-row' }, meter, ui.statusBadge(t, level, freshness.protected_fail_closed ? 'workloads.routes.fail_closed' : level === 'stale' ? 'workloads.routes.aging' : 'workloads.routes.fresh')),
    facts(cx, [
      ['workloads.routes.snapshot_age', t('workloads.seconds', { count: number(age) })],
      ['workloads.routes.max_staleness', t('workloads.seconds', { count: number(max) })],
      ['workloads.routes.stale_refusals', number(Number(freshness.stale_refusals) || 0)],
    ]),
    ui.el('p', { class: 'kit-help', text: t(freshness.protected_fail_closed ? 'workloads.routes.fail_closed.body' : 'workloads.routes.staleness.note') })));
}

function gatewayPanel(cx, report) {
  const { t, ui } = cx;
  const yes = (value, okKey, offKey) => ui.statusBadge(t, value ? 'healthy' : 'disabled', value ? okKey : offKey);
  return panel(cx, 'workloads.routes.gateway', facts(cx, [
    ['workloads.routes.require_protection', yes(report.require_protection, 'workloads.routes.required', 'workloads.routes.optional')],
    ['workloads.routes.client_address', ui.el('span', { class: 'zt-stack' }, yes(report.client_address_preserved, 'workloads.routes.preserved', 'workloads.routes.not_preserved'), report.client_address_message ? ui.el('span', { class: 'kit-mono kit-muted zt-break zt-backend-message', text: report.client_address_message }) : null)],
    ['workloads.routes.client_mode', ui.el('span', { class: 'kit-muted' }, t('workloads.routes.client_mode.not_reported'), ' ', ui.el('code', { class: 'kit-mono', text: CLIENT_ADDRESS_SETTING }))],
    ['workloads.routes.guard', yes(report.guard_configured && report.guard_enforcing, 'workloads.routes.guard.enforcing', report.guard_configured ? 'workloads.routes.guard.not_enforcing' : 'workloads.routes.guard.absent')],
  ]));
}

export async function renderRoutes(cx, root, params) {
  const { t, ui } = cx;
  const { content } = sectionPage(cx, root, { active: 'routes', title: t('workloads.page.routes'), owner: t('workloads.routes.owner') });
  const holder = ui.el('div', { class: 'zt-content' }, ui.loadingState(t));
  content.append(holder);
  let answer;
  try { answer = (await cx.api('/v1/kubernetes/protection')).data || {}; }
  catch (error) {
    if (error?.status === 401) throw error;
    if (cx.signal.aborted) return;
    ui.clear(holder, error?.status === 404 ? ui.emptyState(t, { title: 'workloads.routes.not_supported', body: 'workloads.routes.not_supported.body' }) : ui.errorState(t, { owner: 'ui.owner.host', message: errorText(t, error), retry: () => cx.reload() }));
    return;
  }
  if (cx.signal.aborted) return;
  const report = answer.report;
  if (!answer.enabled || !report) {
    ui.clear(holder, ui.emptyState(t, { title: 'workloads.routes.disabled', body: 'workloads.routes.disabled.body', action: ui.el('code', { class: 'kit-mono', text: PROTECTION_FLAG }) }), answer.freshness ? stalenessGauge(cx, answer.freshness) : null);
    return;
  }
  const counts = report.counts || {};
  const state = INGRESS_STATES.includes(params.get('state')) ? params.get('state') : '';
  const ingresses = Array.isArray(report.ingresses) ? report.ingresses : [];
  const policies = Array.isArray(report.policies) ? report.policies : [];
  const tiles = ui.el('div', { class: 'zt-whatif-tiles' }, [['workloads.routes.kpi.protected', counts.protected, ''], ['workloads.routes.kpi.unprotected', counts.unprotected, counts.unprotected ? 'is-warn' : ''], ['workloads.routes.kpi.withheld', counts.withheld, counts.withheld ? 'is-deny' : ''], ['workloads.routes.kpi.invalid', counts.invalid_policies, counts.invalid_policies ? 'is-deny' : ''], ['workloads.routes.kpi.conflicted', counts.conflicted_policies, counts.conflicted_policies ? 'is-deny' : '']]
    .map(([label, value, tone]) => ui.el('div', { class: `zt-whatif-tile ${tone}`.trim() }, ui.el('span', { class: 'zt-kpi-value', text: number(Number(value) || 0) }), ui.el('span', { class: 'kit-muted', text: t(label) }))));
  const banners = [];
  if (answer.freshness?.protected_fail_closed) banners.push(ui.el('p', { class: 'zt-banner zt-banner-danger', attrs: { role: 'alert' }, text: t('workloads.routes.fail_closed.banner') }));
  if (counts.withheld) banners.push(ui.el('p', { class: 'zt-banner zt-banner-warn', attrs: { role: 'note' }, text: t('workloads.routes.withheld.banner', { count: counts.withheld }) }));
  if (!report.require_protection && counts.unprotected) banners.push(ui.el('p', { class: 'zt-banner', attrs: { role: 'note' }, text: t('workloads.routes.migration.banner', { count: counts.unprotected }) }));
  const chips = ui.el('nav', { class: 'zt-filter-chips', attrs: { 'aria-label': t('workloads.routes.filter') } }, ['', ...INGRESS_STATES].map(value => {
    const next = new URLSearchParams(); if (value) next.set('state', value);
    const count = value ? ingresses.filter(row => row.state === value).length : ingresses.length;
    return ui.el('a', { href: cx.hashFor('workloads', ['routes'], next), class: 'kit-tag', attrs: value === state ? { 'aria-current': 'true' } : {}, text: t('workloads.routes.chip', { label: t(value ? `workloads.routes.state.${value}` : 'workloads.filter.any'), count }) });
  }));
  const rows = ingresses.filter(row => !state || row.state === state).sort((a, b) => (a.state === 'withheld' ? 0 : 1) - (b.state === 'withheld' ? 0 : 1) || `${a.namespace}/${a.name}`.localeCompare(`${b.namespace}/${b.name}`));
  const ingressTable = ui.dataTable(t, {
    id: 'workloads-ingresses', caption: 'workloads.routes.ingresses.caption', owner: 'ui.owner.host', sortable: 'none', rowKey: row => `${row.namespace}/${row.name}`,
    columns: [
      { key: 'ingress', label: 'workloads.routes.col.ingress', render: row => ui.el('span', { class: 'zt-stack' }, ui.el('strong', { text: row.name }), ui.el('span', { class: 'kit-muted', text: t('workloads.routes.namespace', { namespace: row.namespace }) })) },
      { key: 'state', label: 'workloads.routes.col.state', render: row => ui.statusBadge(t, STATE_BADGE[row.state] || 'unknown', INGRESS_STATES.includes(row.state) ? `workloads.routes.state.${row.state}` : 'workloads.status.unknown') },
      { key: 'published', label: 'workloads.routes.col.published', render: row => ui.el('span', { text: t(row.published ? 'workloads.routes.published.yes' : 'workloads.routes.published.no') }) },
      { key: 'policy', label: 'workloads.routes.col.policy', render: row => row.policy ? ui.el('code', { class: 'kit-mono', text: row.policy }) : ui.el('span', { class: 'kit-muted', text: t('workloads.none') }) },
      { key: 'reason', label: 'workloads.routes.col.reason', render: row => row.reason ? ui.el('span', { class: 'zt-stack zt-reason-cell' }, ui.el('strong', { text: reasonText(cx, row.reason) }), row.message ? ui.el('span', { class: 'kit-mono kit-muted zt-break zt-backend-message', text: row.message }) : null) : ui.el('span', { class: 'kit-muted', text: t('workloads.none') }), title: row => row.message || '' },
    ],
    empty: { title: ingresses.length ? 'workloads.routes.ingresses.no_match' : 'workloads.routes.ingresses.empty' },
    fetchPage: async ({ cursor }) => { const offset = Number(cursor || 0); return { items: rows.slice(offset, offset + 50), nextCursor: offset + 50 < rows.length ? String(offset + 50) : null }; },
  });
  const policyTable = ui.dataTable(t, {
    id: 'workloads-policies', caption: 'workloads.routes.policies.caption', owner: 'ui.owner.host', sortable: 'none', rowKey: row => `${row.namespace}/${row.name}`,
    columns: [
      { key: 'policy', label: 'workloads.routes.col.protection_policy', render: row => ui.el('span', { class: 'zt-stack' }, ui.el('strong', { text: row.name }), ui.el('span', { class: 'kit-muted', text: t('workloads.routes.namespace', { namespace: row.namespace }) })) },
      { key: 'accepted', label: 'workloads.routes.col.accepted', render: row => ui.statusBadge(t, row.accepted ? 'healthy' : 'deny', row.accepted ? 'workloads.routes.condition.true' : 'workloads.routes.condition.false') },
      { key: 'reason', label: 'workloads.routes.col.reason', render: row => ui.el('span', { text: reasonText(cx, row.reason) }) },
    ],
    empty: { title: 'workloads.routes.policies.empty' },
    fetchPage: async () => ({ items: [...policies].sort((a, b) => Number(a.accepted) - Number(b.accepted) || `${a.namespace}/${a.name}`.localeCompare(`${b.namespace}/${b.name}`)), nextCursor: null }),
  });
  policyTable.element.classList.add('zt-static');
  for (const table of [ingressTable, policyTable]) cx.signal.addEventListener('abort', () => table.destroy(), { once: true });
  ui.clear(holder, ...banners, tiles, ui.el('div', { class: 'zt-grid-2' }, stalenessGauge(cx, answer.freshness), gatewayPanel(cx, report)),
    panel(cx, 'workloads.routes.ingresses', ui.el('div', {}, chips, ingressTable.element)),
    panel(cx, 'workloads.routes.policies', ui.el('div', {}, policyTable.element, ui.el('p', { class: 'kit-help', text: t('workloads.routes.policies.note') }))),
    report.truncated ? ui.el('p', { class: 'kit-help', text: t('workloads.routes.truncated', { count: report.truncated }) }) : null,
    ui.el('p', { class: 'kit-help', text: t('workloads.routes.scope') }));
  await Promise.all([ingressTable.reload(), policyTable.reload()]);
}
