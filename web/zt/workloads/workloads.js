// Devices & Workloads ▸ Workloads: Kubernetes workload principals
// (ServiceAccount identity) with their Pumgye grants, and the workload detail
// with identity, grants, recent decisions and Pod-bound re-grant proposals.
import { decisionColumns, decisionFetcher } from '../access.js';
import { formDialog, outcomeBanner } from '../network/common.js';
import { sectionPage, hopaeCapabilities, hopaeWorkloads, pumgyeWorkloads, mergeWorkloads, statusBadge, timeOrDash, number, facts, panel, mono, workloadHref, errorText, STATUSES, HOPAE_ROUTES } from './common.js';

const CAUSES = Object.freeze(['deleted', 'uid_changed']);

/** Per-render cache: the list and detail read the same owners. */
const LOADS = new WeakMap();
function load(cx) {
  if (!LOADS.has(cx.signal)) LOADS.set(cx.signal, (async () => {
    const caps = await hopaeCapabilities(cx);
    const [hopaeData, pumgyeData] = await Promise.all([hopaeWorkloads(cx, caps), pumgyeWorkloads(cx)]);
    return { caps, hopaeData, pumgyeData, rows: mergeWorkloads(hopaeData, pumgyeData) };
  })());
  return LOADS.get(cx.signal);
}

/** Owner notes: which source answered, what is partial and which Hopae routes are not declared. */
function sourceNotes(cx, { caps, hopaeData, pumgyeData }) {
  const { t, ui } = cx;
  const notes = [];
  if (!caps.installed) notes.push(['warn', t('workloads.source.hopae_missing')]);
  else if (hopaeData.error) notes.push(['warn', t('workloads.source.hopae_failed', { reason: errorText(t, hopaeData.error) })]);
  else if (hopaeData.source === 'feed') notes.push(['info', t(hopaeData.complete ? 'workloads.source.feed' : 'workloads.source.feed_partial')]);
  else if (hopaeData.source === 'snapshot' && !hopaeData.complete) notes.push(['info', t('workloads.source.snapshot_partial')]);
  else if (!hopaeData.source) notes.push(['warn', t('workloads.source.hopae_routes')]);
  if (pumgyeData.error) notes.push(['warn', t('workloads.source.pumgye_failed', { reason: errorText(t, pumgyeData.error) })]);
  else if (pumgyeData.policyError) notes.push(['warn', t('workloads.source.policy_failed', { reason: errorText(t, pumgyeData.policyError) })]);
  const box = ui.el('div', { class: 'zt-notes zt-workload-sources' }, notes.map(([kind, text]) => ui.el('p', { class: `zt-banner${kind === 'warn' ? ' zt-banner-warn' : ''}`, attrs: { role: 'note' }, text })));
  if (caps.installed && hopaeData.gaps.length) box.append(ui.el('div', { class: 'zt-gaps' }, ui.el('span', { class: 'kit-muted', text: t('workloads.gap.title') }), ' ',
    hopaeData.gaps.map(route => ui.disabledAction(t, `workloads.gap.route.${route.replace(/\//g, '_')}`, 'workloads.gap.hopae'))));
  return box;
}

function grantsCell(cx, row) {
  const { t, ui } = cx;
  if (!row.grants) return ui.el('span', { class: 'kit-muted', text: t('workloads.none') });
  const direct = row.grants.filter(grant => grant.match !== 'legacy').length, legacy = row.grants.length - direct;
  return ui.el('span', { class: 'zt-stack' }, ui.el('span', { class: 'zt-num', text: number(direct) }), legacy ? ui.el('span', { class: 'kit-muted', text: t('workloads.grants.legacy_count', { count: legacy }) }) : null);
}

function identityCell(cx, row) {
  const { t, ui } = cx;
  const name = row.namespace && row.service_account ? t('workloads.ns_sa', { namespace: row.namespace, service_account: row.service_account }) : t('workloads.unnamed');
  return ui.el('a', { class: 'zt-stack', href: workloadHref(row.principal) }, ui.el('strong', { text: name }), ui.el('span', { class: 'kit-entity-id', text: `${row.principal.slice(0, 16)}…` }));
}

export async function renderWorkloads(cx, root, params) {
  const { t, ui } = cx;
  const { content } = sectionPage(cx, root, { active: 'workloads', title: t('workloads.page.workloads'), owner: t('workloads.owner') });
  const holder = ui.el('div', { class: 'zt-content' }, ui.loadingState(t));
  content.append(holder);
  const data = await load(cx);
  if (cx.signal.aborted) return;
  const status = STATUSES.includes(params.get('status')) ? params.get('status') : '';
  const q = (params.get('q') || '').trim().toLowerCase().slice(0, 256);
  const namespace = (params.get('namespace') || '').trim().slice(0, 253);
  const namespaces = [...new Set(data.rows.map(row => row.namespace).filter(Boolean))].sort();
  const form = ui.el('form', { class: 'zt-filters', attrs: { role: 'search' } },
    ui.field(t, { label: 'workloads.filter.q', name: 'q', value: params.get('q') || '', help: 'workloads.filter.q.help' }),
    ui.field(t, { label: 'workloads.filter.namespace', name: 'namespace', value: namespace, options: [{ value: '', label: 'workloads.filter.any' }, ...namespaces.map(value => ({ value, text: value }))] }),
    ui.field(t, { label: 'workloads.filter.status', name: 'status', value: status, options: [{ value: '', label: 'workloads.filter.any' }, ...STATUSES.map(value => ({ value, label: `workloads.status.${value}` }))] }),
    ui.el('div', { class: 'button-row zt-filter-actions' }, ui.el('button', { type: 'submit', class: 'button', text: t('workloads.filter.apply') })));
  form.addEventListener('submit', event => {
    event.preventDefault();
    const next = new URLSearchParams();
    for (const name of ['q', 'namespace', 'status']) { const value = form.elements[name].value.trim(); if (value) next.set(name, value); }
    cx.navigate(cx.hashFor('workloads', ['workloads'], next));
  });
  const rows = data.rows.filter(row => (!status || row.status === status) && (!namespace || row.namespace === namespace)
    && (!q || [row.principal, row.spiffe_id, row.subject_ref, row.namespace, row.service_account, ...row.legacy_subject_refs].some(value => String(value || '').toLowerCase().includes(q))));
  const counts = { total: data.rows.length, active: data.rows.filter(row => row.status === 'active').length, retired: data.rows.filter(row => row.status === 'retired').length, legacy: data.rows.filter(row => row.legacy_subject_refs.length).length, proposals: data.pumgyeData.workloads?.proposals.length ?? null };
  const tiles = ui.el('div', { class: 'zt-whatif-tiles zt-workload-kpis' }, [['workloads.kpi.total', counts.total], ['workloads.kpi.active', counts.active], ['workloads.kpi.retired', counts.retired], ['workloads.kpi.legacy', counts.legacy], ['workloads.kpi.proposals', counts.proposals]]
    .map(([label, value]) => ui.el('div', { class: 'zt-whatif-tile' }, ui.el('span', { class: 'zt-kpi-value', text: value === null ? '—' : number(value) }), ui.el('span', { class: 'kit-muted', text: t(label) }))));
  const table = ui.dataTable(t, {
    id: 'workloads-list', caption: 'workloads.list.caption', owner: 'ui.owner.hopae', sortable: 'none', rowKey: row => row.principal,
    columns: [
      { key: 'identity', label: 'workloads.col.identity', render: row => identityCell(cx, row) },
      { key: 'spiffe', label: 'workloads.col.spiffe', render: row => mono(cx, row.spiffe_id), title: row => row.spiffe_id || '' },
      { key: 'status', label: 'workloads.col.status', render: row => ui.el('span', { class: 'zt-stack' }, statusBadge(cx, row.status), row.status === 'retired' && CAUSES.includes(row.cause) ? ui.el('span', { class: 'kit-muted', text: t(`workloads.cause.${row.cause}`) }) : null) },
      { key: 'seen', label: 'workloads.col.last_seen', render: row => timeOrDash(cx, row.last_seen_at) },
      { key: 'legacy', label: 'workloads.col.legacy', render: row => ui.el('span', { class: 'zt-num', text: number(row.legacy_subject_refs.length) }) },
      { key: 'grants', label: 'workloads.col.grants', render: row => grantsCell(cx, row) },
      { key: 'cluster', label: 'workloads.col.cluster', hidden: true, render: row => ui.el('span', { text: row.cluster || t('workloads.none') }) },
    ],
    empty: { title: data.rows.length ? 'workloads.list.no_match' : 'workloads.list.empty', body: data.rows.length ? 'workloads.list.no_match.body' : 'workloads.list.empty.body' },
    onRowOpen: row => cx.navigate(workloadHref(row.principal)),
    fetchPage: async ({ cursor }) => { const offset = Number(cursor || 0); return { items: rows.slice(offset, offset + 50), nextCursor: offset + 50 < rows.length ? String(offset + 50) : null }; },
  });
  cx.signal.addEventListener('abort', () => table.destroy(), { once: true });
  ui.clear(holder, sourceNotes(cx, data), tiles, form, table.element, ui.el('p', { class: 'kit-help', text: t('workloads.list.note') }));
  await table.reload();
}

function grantRows(cx, grants) {
  const { t, ui } = cx;
  const table = ui.dataTable(t, {
    id: 'workload-grants', caption: 'workloads.grants.caption', owner: 'ui.owner.pumgye', sortable: 'none', rowKey: grant => grant.binding.id,
    columns: [
      { key: 'binding', label: 'workloads.grant.col.binding', render: grant => ui.el('code', { class: 'kit-mono', text: grant.binding.id }) },
      { key: 'effect', label: 'workloads.grant.col.effect', render: grant => ui.statusBadge(t, grant.binding.effect === 'deny' ? 'deny' : 'allow', grant.binding.effect === 'deny' ? 'workloads.grant.deny' : 'workloads.grant.allow') },
      { key: 'grants', label: 'workloads.grant.col.what', render: grant => ui.el('span', { text: grant.binding.role ? t('workloads.grant.role', { role: grant.binding.role }) : grant.binding.permissions === 'all' ? t('workloads.grant.all') : (grant.binding.permissions || []).join(', ') }) },
      { key: 'scope', label: 'workloads.grant.col.scope', render: grant => scopeCell(cx, grant.binding.scope) },
      { key: 'match', label: 'workloads.grant.col.match', render: grant => ui.el('span', { class: `kit-tag${grant.match === 'legacy' ? ' kit-tag-warn' : ''}`, text: t(`workloads.grant.match.${grant.match}`) }) },
      { key: 'expires', label: 'workloads.grant.col.expires', render: grant => grant.binding.conditions?.expires_at ? timeOrDash(cx, Date.parse(grant.binding.conditions.expires_at)) : ui.el('span', { class: 'kit-muted', text: t('workloads.grant.never') }) },
      { key: 'reason', label: 'workloads.grant.col.reason', render: grant => ui.el('span', { text: grant.binding.metadata?.reason || t('workloads.none') }) },
    ],
    empty: { title: 'workloads.grants.empty', body: 'workloads.grants.empty.body' },
    fetchPage: async () => ({ items: grants, nextCursor: null }),
  });
  table.element.classList.add('zt-static');
  cx.signal.addEventListener('abort', () => table.destroy(), { once: true });
  table.reload();
  return table.element;
}

function scopeCell(cx, scope) {
  const { t, ui } = cx;
  const services = scope?.services;
  if (services === 'all' || !Array.isArray(services)) return ui.el('span', { text: t('workloads.grant.all_services') });
  return ui.el('span', { class: 'zt-chips' }, services.slice(0, 4).map(service => ui.el('a', { class: 'kit-tag', href: `#policies/services/${encodeURIComponent(service)}`, text: service })), services.length > 4 ? ui.el('span', { class: 'kit-muted', text: t('workloads.more', { count: services.length - 4 }) }) : null);
}

function recentDecisions(cx, row) {
  const { t, ui } = cx;
  const params = new URLSearchParams();
  if (row.subject_ref) params.append('subject', row.subject_ref);
  if (!params.has('subject')) return panel(cx, 'workloads.decisions.title', ui.el('p', { class: 'kit-muted', text: t('workloads.decisions.no_subject') }));
  const table = ui.dataTable(t, { id: 'workload-decisions', caption: 'entity.decisions.caption', owner: 'ui.owner.exporter', columns: decisionColumns(cx), rowKey: event => event.event_id, onRowOpen: event => cx.navigate(cx.hashFor('access', ['requests', event.request_id])), empty: { title: 'entity.decisions.empty' }, fetchPage: decisionFetcher(cx, params, { limit: 10 }) });
  cx.signal.addEventListener('abort', () => table.destroy(), { once: true });
  table.reload();
  return panel(cx, 'workloads.decisions.title', ui.el('div', {}, table.element, ui.el('p', { class: 'kit-help', text: t('workloads.decisions.note') })), { actions: [ui.el('a', { class: 'button button-quiet', href: cx.hashFor('access', ['decisions'], params), text: t('entity.decisions.open') })] });
}

function proposalsPanel(cx, row, data, status) {
  const { t, ui } = cx;
  if (data.pumgyeData.error) return panel(cx, 'workloads.regrant.title', ui.el('p', { class: 'kit-muted', text: errorText(t, data.pumgyeData.error) }));
  const proposals = row.proposals;
  if (!proposals.length) return panel(cx, 'workloads.regrant.title', ui.emptyState(t, { title: 'workloads.regrant.empty', body: row.legacy_subject_refs.length ? 'workloads.regrant.empty.mapped' : 'workloads.regrant.empty.body' }));
  const selected = new Set(proposals.map(proposal => proposal.id));
  const list = ui.el('ul', { class: 'zt-regrants' }, proposals.map(proposal => {
    const id = `rg-${proposal.id}`;
    const box = ui.el('input', { type: 'checkbox', id, checked: true, value: proposal.id, on: { change: event => { if (event.target.checked) selected.add(proposal.id); else selected.delete(proposal.id); sync(); } } });
    const binding = proposal.binding || {};
    return ui.el('li', { class: 'zt-card zt-regrant' }, ui.el('label', { htmlFor: id, class: 'zt-regrant-head' }, box, ui.el('span', { class: 'zt-stack' },
      ui.el('strong', { text: binding.role ? t('workloads.grant.role', { role: binding.role }) : binding.permissions === 'all' ? t('workloads.grant.all') : (binding.permissions || []).join(', ') }),
      ui.el('span', { class: 'kit-muted' }, t('workloads.regrant.from'), ' ', ui.el('code', { class: 'kit-mono', text: proposal.evidence?.legacy_binding || '—' })))),
    facts(cx, [['workloads.regrant.legacy_subject', mono(cx, proposal.evidence?.legacy_subject)], ['workloads.regrant.new_binding', mono(cx, binding.id)], ['workloads.grant.col.scope', scopeCell(cx, binding.scope)], ['workloads.grant.col.effect', t(binding.effect === 'deny' ? 'workloads.grant.deny' : 'workloads.grant.allow')]]));
  }));
  const revision = data.pumgyeData.policy?.revision;
  const apply = ui.el('button', { type: 'button', class: 'button button-primary', text: t('workloads.regrant.apply', { count: selected.size }) });
  const sync = () => { apply.textContent = t('workloads.regrant.apply', { count: selected.size }); apply.disabled = !selected.size || !Number.isFinite(revision); };
  sync();
  apply.addEventListener('click', async () => {
    const ids = [...selected];
    const approvalId = `zt-approval-${Math.random().toString(36).slice(2, 8)}`;
    const approval = ui.el('label', { class: 'kit-field', htmlFor: approvalId }, ui.el('span', { class: 'kit-field-label', text: t('workloads.regrant.approval') }), ui.el('input', { id: approvalId, name: 'approval_ref', maxLength: 128, autocomplete: 'off' }), ui.el('small', { class: 'kit-help', text: t('workloads.regrant.approval.help') }));
    const result = await formDialog(cx, {
      title: 'workloads.regrant.dialog', intro: t('workloads.regrant.effect', { count: ids.length, revision }), confirm: String(ids.length), confirmLabel: 'workloads.regrant.confirm',
      fields: [{ node: approval, name: 'approval_ref' }],
      submit: async values => {
        const json = { base_revision: revision, proposals: ids, reason: values.reason, ...(values.approval_ref ? { approval_ref: values.approval_ref } : {}) };
        try { return (await cx.api('/v1/pumgye/v2/workloads/regrants/apply', { method: 'POST', json, headers: { 'x-hangang-change-reason': encodeURIComponent(values.reason) } })).data; }
        catch (error) { throw Object.assign(error, { message: errorText(t, error) }); }
      },
    });
    if (!result) return;
    ui.clear(status, outcomeBanner(cx, 'committed', 'workloads.regrant.done', { count: result.applied ?? ids.length, revision: result.revision ?? '—' }));
    setTimeout(() => cx.navigate(`${location.hash.split('?')[0]}?updated=${Date.now()}`), 900);
  });
  return panel(cx, 'workloads.regrant.title', ui.el('div', { class: 'zt-content' }, ui.el('p', { class: 'zt-banner', attrs: { role: 'note' }, text: t('workloads.regrant.note') }), list,
    ui.el('div', { class: 'button-row' }, Number.isFinite(revision) ? apply : ui.disabledAction(t, 'workloads.regrant.apply_short', 'workloads.regrant.no_revision'))), { params: { count: proposals.length } });
}

export async function renderWorkload(cx, root, principal) {
  const { t, ui } = cx;
  const { content, heading } = sectionPage(cx, root, { active: 'workloads', crumbs: [{ label: t('workloads.page.workloads'), href: '#workloads/workloads' }, { label: principal.slice(0, 20) }], title: t('workloads.detail.title'), owner: t('workloads.detail.owner') });
  const holder = ui.el('div', { class: 'zt-content' }, ui.loadingState(t));
  const status = ui.el('div', { class: 'zt-notes' });
  content.append(status, holder);
  const data = await load(cx);
  if (cx.signal.aborted) return;
  const row = data.rows.find(entry => entry.principal === principal);
  if (!row) { ui.clear(holder, sourceNotes(cx, data), ui.emptyState(t, { title: 'workloads.detail.missing', body: 'workloads.detail.missing.body', action: ui.el('a', { class: 'button button-quiet', href: '#workloads/workloads', text: t('workloads.page.workloads') }) })); return; }
  if (row.namespace && row.service_account) heading.textContent = t('workloads.ns_sa', { namespace: row.namespace, service_account: row.service_account });
  const replacement = row.replacement ? ui.el('a', { class: 'kit-mono', href: workloadHref(row.replacement), text: `${row.replacement.slice(0, 20)}…` }) : null;
  const banners = [];
  if (row.status === 'retired') banners.push(ui.el('p', { class: 'zt-banner zt-banner-warn', attrs: { role: 'note' }, text: t(row.cause === 'uid_changed' ? 'workloads.detail.retired.uid_changed' : 'workloads.detail.retired') }));
  if (row.legacy_subject_refs.length) banners.push(ui.el('p', { class: 'zt-banner', attrs: { role: 'note' }, text: t('workloads.detail.legacy', { count: row.legacy_subject_refs.length }) }));
  const identity = panel(cx, 'workloads.identity.title', facts(cx, [
    ['workloads.identity.status', ui.el('span', {}, statusBadge(cx, row.status), row.status === 'retired' && CAUSES.includes(row.cause) ? ui.el('span', { class: 'kit-muted' }, ' · ', t(`workloads.cause.${row.cause}`)) : null)],
    ['workloads.identity.principal', mono(cx, row.principal, { copy: true })],
    ['workloads.identity.spiffe', mono(cx, row.spiffe_id, { copy: true })],
    ['workloads.identity.subject', mono(cx, row.subject_ref, { copy: true })],
    ['workloads.identity.cluster', row.cluster || null],
    ['workloads.identity.namespace', row.namespace || null],
    ['workloads.identity.service_account', row.service_account || null],
    ['workloads.identity.uid', row.service_account_uid ? mono(cx, row.service_account_uid) : null],
    ['workloads.identity.service', row.service || null],
    ['workloads.identity.first_seen', row.first_seen_at ? timeOrDash(cx, row.first_seen_at) : null],
    ['workloads.identity.last_seen', timeOrDash(cx, row.last_seen_at)],
    ['workloads.identity.retired_at', row.retired_at ? timeOrDash(cx, row.retired_at) : null],
    ['workloads.identity.replacement', replacement],
    ['workloads.identity.sources', row.sources.map(source => t(`ui.owner.${source}`)).join(' · ')],
  ]));
  const legacy = panel(cx, 'workloads.legacy.title', row.legacy_subject_refs.length ? ui.el('div', {}, ui.el('ul', { class: 'zt-chips zt-legacy' }, row.legacy_subject_refs.slice(0, 64).map(ref => ui.el('li', {}, ui.el('code', { class: 'kit-tag kit-mono', text: ref })))), ui.el('p', { class: 'kit-help', text: t('workloads.legacy.note') })) : ui.el('p', { class: 'kit-muted', text: t('workloads.legacy.none') }), { params: { count: row.legacy_subject_refs.length } });
  const grants = row.grants ? panel(cx, 'workloads.grants.title', grantRows(cx, row.grants), { params: { count: row.grants.length } }) : panel(cx, 'workloads.grants.title', ui.el('p', { class: 'kit-muted', text: t('workloads.grants.unavailable') }), { params: { count: 0 } });
  ui.clear(holder, sourceNotes(cx, data), ...banners, ui.el('div', { class: 'zt-grid-2' }, identity, legacy), grants, proposalsPanel(cx, row, data, status), recentDecisions(cx, row));
}

export { HOPAE_ROUTES };
