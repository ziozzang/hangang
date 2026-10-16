// Network ▸ ASN ▸ bundle and proposals (Sumunjang docs/ASN_PROPOSALS.md,
// package 0.2.0 on broker contract v2). ASN is classification metadata, never
// proof of abuse: nothing activates an ASN-wide block automatically. Every
// proposal moves through draft → pending → approved → active by explicit,
// audited actions with a compare-and-set on its revision.
import { can, guard, sectionPage, capabilities, notConnected, panel, facts, button, formDialog, outcomeBanner, failure, errorText, fieldErrors, timeOrDash, number, ipLink, asnText, suspicionBadge, isCidr, toMs } from './common.js';

export const PROPOSAL_STATES = Object.freeze(['draft', 'pending', 'approved', 'rejected', 'active', 'expired', 'withdrawn']);
const OPEN = new Set(['draft', 'pending', 'approved', 'active']);
const STATE_KIND = Object.freeze({ draft: 'pending', pending: 'challenge', approved: 'allow', active: 'deny', rejected: 'refused', expired: 'disabled', withdrawn: 'disabled' });
export const SCOPES = Object.freeze(['asn', 'prefixes', 'aggregates']);
const WARNINGS = Object.freeze([['observe mode', 'observe'], ['allowlist entries', 'allowlist'], ['network zones', 'zones'], ['scope contains very large', 'large']]);
const EXPIRY_DAYS = Object.freeze([1, 7, 14, 30]);

/** Bundle/proposal routes come with Sumunjang package 0.2.0 (contract v2). */
export function asnWorkflow(caps) { return can(caps, 'asn/proposals', 'GET') && can(caps, 'asn/proposals/*', 'GET'); }

export function asnTabs(cx, caps, active) {
  const { t, ui } = cx;
  const tabs = [['pools', '#network/asn'], ...(asnWorkflow(caps) ? [['bundle', '#network/asn/bundle'], ['proposals', '#network/asn/proposals']] : [])];
  return ui.el('nav', { class: 'zt-tabs', attrs: { 'aria-label': t('network.asn.tabs') } }, tabs.map(([name, href]) => ui.el('a', { href, text: t(`network.asn.tab.${name}`), attrs: { 'aria-current': name === active ? 'page' : false } })));
}

export function stateBadge(cx, state) {
  const safe = PROPOSAL_STATES.includes(state) ? state : 'draft';
  return cx.ui.statusBadge(cx.t, STATE_KIND[safe], `network.proposal.state.${safe}`);
}

function actor(cx, ref) {
  const name = typeof ref === 'string' ? ref : ref?.name;
  if (!name) return cx.t('network.none');
  return name === 'admin-credential' ? cx.t('network.proposal.actor.credential') : name;
}

async function viewerName(cx) {
  try { return (await cx.api('/v1/auth/me')).data?.user?.username || null; } catch (error) { if (error?.status === 401) throw error; return null; }
}

// ---------------------------------------------------------------- bundle

function diffReport(cx, diff) {
  const { t, ui } = cx;
  if (!diff) return null;
  const sample = (list, render) => (Array.isArray(list) && list.length ? ui.el('ul', { class: 'zt-chips' }, list.slice(0, 12).map(render)) : null);
  return ui.el('div', { class: 'zt-diff-report' },
    ui.el('div', { class: 'zt-whatif-tiles' }, [['network.bundle.diff.before', diff.prefixes_before], ['network.bundle.diff.after', diff.prefixes_after], ['network.bundle.diff.added', diff.added], ['network.bundle.diff.removed', diff.removed], ['network.bundle.diff.reassigned', diff.reassigned]]
      .map(([label, value]) => ui.el('div', { class: 'zt-whatif-tile' }, ui.el('span', { class: 'zt-kpi-value', text: number(value ?? 0) }), ui.el('span', { class: 'kit-muted', text: t(label) })))),
    sample(diff.samples?.added, row => ui.el('li', { class: 'kit-tag kit-tag-add' }, ui.el('span', { class: 'kit-mono' }, '+ ', row.network), ' ', ui.el('span', { text: asnText(cx, row.asn) }))),
    sample(diff.samples?.removed, row => ui.el('li', { class: 'kit-tag kit-tag-warn' }, ui.el('span', { class: 'kit-mono' }, '− ', row.network), ' ', ui.el('span', { text: asnText(cx, row.asn) }))),
    sample(diff.samples?.reassigned, row => ui.el('li', { class: 'kit-tag' }, ui.el('span', { class: 'kit-mono', text: row.network }), ' ', ui.el('span', { text: t('network.bundle.diff.moved', { from: row.from, to: row.to }) }))),
    Array.isArray(diff.top_asns) && diff.top_asns.length ? ui.el('p', { class: 'kit-muted', text: t('network.bundle.diff.top', { list: diff.top_asns.slice(0, 5).map(row => `AS${row.asn} +${row.added}/−${row.removed}`).join(', ') }) }) : null);
}

export async function renderAsnBundle(cx, root) {
  const { t, ui } = cx;
  const caps = await capabilities(cx);
  if (cx.signal.aborted) return;
  const { content } = sectionPage(cx, root, { active: 'asn', crumbs: [{ label: t('network.page.asn'), href: '#network/asn' }, { label: t('network.asn.tab.bundle') }], title: t('network.bundle.title'), owner: t('network.bundle.owner') });
  content.append(asnTabs(cx, caps, 'bundle'));
  if (!caps.installed || !can(caps, 'asn/bundle', 'GET')) { content.append(notConnected(cx, caps, 'asn/bundle')); return; }
  const status = ui.el('div', { class: 'zt-notes' });
  const holder = ui.el('div', { class: 'zt-content' }, ui.loadingState(t));
  content.append(status, holder);
  let data;
  try { ({ data } = await guard(cx, 'asn/bundle')); }
  catch (error) { ui.clear(holder, failure(cx, error, () => cx.navigate(`#network/asn/bundle?retry=${Date.now()}`))); return; }
  if (cx.signal.aborted) return;
  const current = data?.current || null;
  const fetch = data?.fetch || {};
  const fetchStatus = fetch.status || {};
  const report = result => {
    const answer = result?.data || {};
    ui.clear(status, outcomeBanner(cx, 'committed', answer.changed === false ? 'network.bundle.unchanged' : 'network.bundle.installed', { version: answer.version ?? '—', operation: result?.operation || '—' }), answer.diff ? panel(cx, 'network.bundle.diff.title', diffReport(cx, answer.diff)) : null);
  };
  const actionsRow = root.querySelector('.zt-actions');
  if (actionsRow) {
    const refresh = async () => {
      const result = await formDialog(cx, { title: 'network.bundle.refresh.title', intro: t(fetch.url_configured ? 'network.bundle.refresh.effect' : 'network.bundle.refresh.no_url'), confirmLabel: 'network.bundle.refresh', submit: values => guard(cx, 'asn/refresh', { json: {}, reason: values.reason }) });
      if (result) report(result);
    };
    const upload = async () => {
      const id = `zt-bundle-${Math.random().toString(36).slice(2, 6)}`;
      const input = ui.el('input', { id, type: 'file', name: 'bundle', accept: '.json,application/json', required: true });
      const summary = ui.el('p', { class: 'kit-muted', attrs: { 'aria-live': 'polite' } });
      let envelope = null;
      input.addEventListener('change', async () => {
        envelope = null; summary.textContent = '';
        const file = input.files?.[0];
        if (!file) return;
        // The broker forwards at most 1 MiB; larger bundles use the CLI or the URL.
        if (file.size > 1024 * 1024) { input.setCustomValidity(t('network.bundle.upload.too_large')); summary.textContent = t('network.bundle.upload.too_large'); return; }
        try { envelope = JSON.parse(await file.text()); input.setCustomValidity(''); summary.textContent = t('network.bundle.upload.ready', { name: file.name, size: number(Math.ceil(file.size / 1024)) }); }
        catch { input.setCustomValidity(t('network.bundle.upload.invalid')); summary.textContent = t('network.bundle.upload.invalid'); }
      });
      const field = ui.el('label', { class: 'kit-field', htmlFor: id }, ui.el('span', { class: 'kit-field-label', text: t('network.bundle.upload.file') }), input, ui.el('small', { class: 'kit-help', text: t('network.bundle.upload.help') }), summary);
      const result = await formDialog(cx, { title: 'network.bundle.upload.title', intro: t('network.bundle.upload.effect'), fields: [{ node: field }], confirmLabel: 'network.bundle.upload',
        submit: values => guard(cx, 'asn/bundle', { method: 'PUT', json: envelope, reason: values.reason }) });
      if (result) report(result);
    };
    const rollback = async () => {
      const target = `v${current.version}`;
      const result = await formDialog(cx, { title: 'network.bundle.rollback.title', intro: t('network.bundle.rollback.effect', { version: current.version }), confirm: target, confirmLabel: 'network.bundle.rollback', danger: true,
        submit: values => guard(cx, 'asn/bundle/rollback', { json: { expected_version: current.version, reason: values.reason }, reason: values.reason }) });
      if (result) report(result);
    };
    const action = (route, method, label, handler, kind) => can(caps, route, method) ? button(cx, label, handler, { kind }) : ui.disabledAction(t, label, 'network.gap.not_declared');
    actionsRow.append(action('asn/refresh', 'POST', 'network.bundle.refresh', refresh), action('asn/bundle', 'PUT', 'network.bundle.upload', upload, 'primary'),
      current && (data.history || []).some(entry => entry.state !== 'rolled_back') ? action('asn/bundle/rollback', 'POST', 'network.bundle.rollback', rollback, 'danger') : null);
  }
  const provenance = current?.provenance && typeof current.provenance === 'object' ? Object.entries(current.provenance) : [];
  ui.clear(holder,
    current ? panel(cx, 'network.bundle.current', facts(cx, [
      ['network.bundle.version', ui.el('strong', { text: t('network.bundle.version_value', { version: current.version }) })],
      ['network.bundle.source', current.source || null],
      ['network.bundle.prefixes', current.prefixes === null || current.prefixes === undefined ? null : number(current.prefixes)],
      ['network.bundle.created', timeOrDash(cx, current.created_at)],
      ['network.bundle.installed_at', timeOrDash(cx, current.installed_at)],
      ['network.bundle.sha256', current.sha256 ? ui.hashChip(t, current.sha256) : null],
      ['network.bundle.signature', ui.statusBadge(t, data.key_configured ? 'healthy' : 'stale', data.key_configured ? 'network.bundle.key.configured' : 'network.bundle.key.missing')],
      ['network.bundle.provenance', provenance.length ? ui.el('dl', { class: 'zt-dl zt-provenance' }, provenance.map(([key, value]) => [ui.el('dt', { class: 'kit-mono', text: key }), ui.el('dd', { text: String(value) })])) : null],
    ])) : ui.emptyState(t, { title: 'network.bundle.none', body: 'network.bundle.none.body' }),
    panel(cx, 'network.bundle.fetch', facts(cx, [
      ['network.bundle.fetch.url', t(fetch.url_configured ? 'network.bundle.fetch.url.on' : 'network.bundle.fetch.url.off')],
      ['network.bundle.fetch.interval', fetch.url_configured ? t('network.seconds', { count: fetch.interval_secs ?? 0 }) : null],
      ['network.bundle.fetch.last_success', fetchStatus.last_success ? timeOrDash(cx, fetchStatus.last_success) : null],
      ['network.bundle.fetch.last_attempt', fetchStatus.last_attempt ? timeOrDash(cx, fetchStatus.last_attempt) : null],
      ['network.bundle.fetch.counts', t('network.bundle.fetch.counts_value', { attempts: number(fetchStatus.attempts ?? 0), failures: number(fetchStatus.failures ?? 0) })],
      ['network.bundle.fetch.last_error', fetchStatus.last_error ? ui.el('span', { class: 'kit-mono zt-provider-error', text: fetchStatus.last_error }) : null],
    ])),
    panel(cx, 'network.bundle.history', Array.isArray(data.history) && data.history.length ? ui.el('ul', { class: 'zt-status-list' }, data.history.map(entry => ui.el('li', {},
      ui.el('strong', { text: t('network.bundle.version_value', { version: entry.version }) }), ' ', ui.statusBadge(t, entry.state === 'rolled_back' ? 'stale' : 'disabled', entry.state === 'rolled_back' ? 'network.bundle.state.rolled_back' : 'network.bundle.state.previous'),
      ' ', timeOrDash(cx, entry.installed_at), entry.source ? ui.el('span', { class: 'kit-muted' }, ' · ', entry.source) : null))) : ui.el('p', { class: 'kit-muted', text: t('network.bundle.history.none') })),
    ui.el('p', { class: 'zt-banner', attrs: { role: 'note' }, text: t('network.bundle.note') }));
}

// ---------------------------------------------------------------- impact

/** Impact of a scope (preview or stored proposal); counts and samples only. */
// One sentence over the same three verdicts as the samples table (now, after
// activation in the current mode, with enforcement), from the complete counts.
function impactSummary(cx, mode, preview) {
  const current = preview.current_mode || {}, already = current.already_denied ?? 0, change = current.allow_to_deny ?? 0, kept = current.unchanged_allow ?? 0;
  return cx.t('network.proposal.impact.mode', { mode: cx.t(`network.mode.${mode === 'enforce' ? 'enforce' : 'observe'}`), total: number(already + change + kept), already: number(already), change: number(change), kept: number(kept), enforce: number(preview.enforce?.allow_to_deny ?? 0) });
}

export function impactView(cx, impact, { decisionLog = null } = {}) {
  const { t, ui } = cx;
  if (!impact || typeof impact !== 'object') return ui.emptyState(t, { title: 'network.proposal.impact.none' });
  const estimated = impact.estimated || {};
  const tracked = impact.tracked || {};
  const preview = impact.preview || {};
  const collisions = impact.collisions || {};
  const tiles = ui.el('div', { class: 'zt-whatif-tiles' }, [
    ['network.proposal.impact.networks', impact.networks, ''], ['network.proposal.impact.ipv4', estimated.ipv4_addresses, ''], ['network.proposal.impact.ipv6', estimated.ipv6_slash64s, ''],
    ['network.proposal.impact.tracked', tracked.addresses, ''], ['network.proposal.impact.current_change', preview.current_mode?.allow_to_deny, 'is-deny'], ['network.proposal.impact.enforce_change', preview.enforce?.allow_to_deny, 'is-deny'],
  ].map(([label, value, tone]) => ui.el('div', { class: `zt-whatif-tile ${tone}`.trim() }, ui.el('span', { class: 'zt-kpi-value', text: number(value ?? 0) }), ui.el('span', { class: 'kit-muted', text: t(label) }))));
  const warnings = (Array.isArray(impact.warnings) ? impact.warnings : []).map(text => { const match = WARNINGS.find(([prefix]) => String(text).startsWith(prefix)); return t(`network.proposal.warning.${match ? match[1] : 'other'}`); });
  const samples = Array.isArray(preview.samples) ? preview.samples : [];
  const sampleTable = samples.length ? ui.el('table', { class: 'zt-keys zt-impact-samples' }, ui.el('thead', {}, ui.el('tr', {}, ['network.proposal.sample.ip', 'network.proposal.sample.score', 'network.proposal.sample.now', 'network.proposal.sample.after', 'network.proposal.sample.enforce'].map(key => ui.el('th', { scope: 'col', text: t(key) })))),
    ui.el('tbody', {}, samples.slice(0, 20).map(row => ui.el('tr', {}, ui.el('td', {}, ipLink(cx, row.ip)), ui.el('td', { class: 'zt-num', text: number(row.score ?? 0) }), ui.el('td', {}, actionBadge(cx, row.before)), ui.el('td', {}, actionBadge(cx, row.after)), ui.el('td', {}, actionBadge(cx, row.enforce_after)))))) : ui.el('p', { class: 'kit-muted', text: t('network.proposal.sample.none') });
  const list = Array.isArray(impact.network_list) ? impact.network_list : [];
  const signals = tracked.signals || {};
  const counts = decisionLog?.counts || null;
  return ui.el('div', { class: 'zt-content zt-impact-view' },
    warnings.length ? ui.el('ul', { class: 'zt-warnings', attrs: { role: 'note' } }, warnings.map(text => ui.el('li', {}, ui.el('span', { class: 'kit-tag kit-tag-warn', text: '!' }), ' ', ui.el('span', { text })))) : null,
    tiles,
    ui.el('p', { class: 'kit-muted', text: impactSummary(cx, impact.mode, preview) }),
    ui.el('div', { class: 'zt-grid' },
      panel(cx, 'network.proposal.impact.samples', sampleTable),
      panel(cx, 'network.proposal.impact.evidence', ui.el('div', { class: 'zt-content' },
        facts(cx, [['network.proposal.impact.eligible', number(tracked.eligible ?? 0)], ['network.proposal.impact.signals', t('network.proposal.impact.signals_value', { honeypot: number(signals.honeypot ?? 0), scanner: number(signals.scanner ?? 0), auth: number(signals.auth_failure ?? 0), invalid: number(signals.invalid_request ?? 0) })],
          ['network.proposal.impact.history', impact.history ? t('network.proposal.impact.history_value', { addresses: number(impact.history.addresses ?? 0), events: number(impact.history.events ?? 0), score: number(impact.history.score ?? 0) }) : null]]),
        Array.isArray(tracked.top) && tracked.top.length ? ui.el('ul', { class: 'zt-status-list' }, tracked.top.slice(0, 8).map(row => ui.el('li', {}, ipLink(cx, row.ip), ' ', suspicionBadge(cx, row.suspicion), ui.el('span', { class: 'kit-muted', text: t('network.proposal.impact.top_value', { score: number(row.score ?? 0), events: number(row.events ?? 0) }) })))) : null))),
    panel(cx, 'network.proposal.impact.collisions', ui.el('div', { class: 'zt-content' },
      collisionList(cx, 'network.proposal.collision.allowlist', collisions.allowlist, row => [ui.el('code', { class: 'kit-mono', text: row.allow }), ' ∩ ', ui.el('code', { class: 'kit-mono', text: row.network }), row.expires_at ? ui.el('span', { class: 'kit-muted', text: t('network.proposal.collision.until', { time: new Date(toMs(row.expires_at)).toLocaleString(document.documentElement.lang || undefined) }) }) : null]),
      collisionList(cx, 'network.proposal.collision.zones', collisions.zones, row => [ui.el('a', { class: 'kit-tag zt-zone', href: `#network/zones/${encodeURIComponent(row.zone)}`, text: row.zone }), ui.el('span', { class: 'kit-muted', text: t('network.proposal.collision.prefixes', { count: row.overlapping_prefixes ?? 0 }) })]),
      collisionList(cx, 'network.proposal.collision.blocks', collisions.existing_blocks, row => [ui.el('code', { class: 'kit-mono', text: row })]))),
    panel(cx, 'network.proposal.impact.decision_log', counts ? ui.el('div', { class: 'zt-content' }, ui.el('div', { class: 'zt-whatif-tiles' }, Object.entries(counts).filter(([key, value]) => !(key === 'window_hours' && value === 168)).map(([key, value]) => ui.el('div', { class: 'zt-whatif-tile' }, ui.el('span', { class: 'zt-kpi-value', text: number(value) }), ui.el('span', { class: 'kit-muted', text: t(DECISION_COUNTS.includes(key) ? `network.proposal.log.${key}` : 'network.proposal.log.other') })))),
      ui.el('small', { class: 'kit-muted', text: t('network.proposal.log.note', { time: decisionLog.attached_at ? new Date(toMs(decisionLog.attached_at)).toLocaleString(document.documentElement.lang || undefined) : '—' }) })) : ui.el('p', { class: 'kit-muted', text: t('network.proposal.log.none') })),
    panel(cx, 'network.proposal.impact.network_list', ui.el('div', { class: 'zt-content' }, ui.el('p', { class: 'zt-asn-prefixes' }, list.slice(0, 64).map(prefix => ui.el('code', { class: 'kit-tag kit-mono', text: prefix }))),
      list.length > 64 || impact.network_list_truncated ? ui.el('p', { class: 'kit-muted', text: t('network.proposal.impact.list_more', { count: number(impact.networks ?? list.length) }) }) : null)));
}

function actionBadge(cx, action) {
  return cx.ui.statusBadge(cx.t, action === 'deny' ? 'deny' : action === 'allow' ? 'allow' : 'unknown', action === 'deny' ? 'network.verdict.deny' : action === 'allow' ? 'network.verdict.allow' : 'ui.status.unknown');
}

function collisionList(cx, title, rows, render) {
  const { t, ui } = cx;
  const list = Array.isArray(rows) ? rows : [];
  return ui.el('div', {}, ui.el('h3', { class: 'zt-subhead', text: t(title, { count: list.length }) }), list.length ? ui.el('ul', { class: 'zt-status-list' }, list.slice(0, 20).map(row => ui.el('li', {}, render(row)))) : ui.el('p', { class: 'kit-muted', text: t('network.proposal.collision.none') }));
}

// ------------------------------------------------- decision-log annotation

export const DECISION_COUNTS = Object.freeze(['window_hours', 'events', 'estimated_requests', 'deny', 'allow', 'challenge', 'unavailable', 'network_stage', 'identity_stage', 'authorization_stage', 'countries']);

/**
 * Aggregate counts for the ASN from the console's own decision-log facets
 * (last 7 days). Counts only: no addresses, subjects or requests leave the
 * console, and Sumunjang stores them as an annotation.
 */
export async function decisionLogCounts(cx, asn) {
  const now = Date.now(), hours = 168;
  const { data } = await cx.api(`/v1/observability/decisions/facets?from=${now - hours * 3_600_000}&to=${now}&asn=${encodeURIComponent(asn)}`);
  if (!data || data.state === 'disabled') return null;
  const facet = name => (Array.isArray(data.facets?.[name]) ? data.facets[name] : []);
  const sum = (rows, field) => Math.round(rows.reduce((total, row) => total + (Number(row[field]) || 0), 0));
  const outcomes = facet('outcome'), stages = facet('stage');
  const of = (rows, value) => Math.round(Number(rows.find(row => row.value === value)?.events) || 0);
  return { window_hours: hours, events: sum(outcomes, 'events'), estimated_requests: sum(outcomes, 'estimated_requests'), deny: of(outcomes, 'deny'), allow: of(outcomes, 'allow'), challenge: of(outcomes, 'challenge'), unavailable: of(outcomes, 'unavailable'),
    network_stage: of(stages, 'network'), identity_stage: of(stages, 'identity'), authorization_stage: of(stages, 'authorization'), countries: facet('country').length };
}

async function annotate(cx, proposal) {
  const counts = await decisionLogCounts(cx, proposal.asn);
  if (!counts) return null;
  return guard(cx, `asn/proposals/${proposal.id}`, { json: { action: 'annotate', expected_revision: proposal.revision, decision_log: counts } });
}

// ------------------------------------------------------------- list

export async function renderProposals(cx, root, params) {
  const { t, ui } = cx;
  const caps = await capabilities(cx);
  if (cx.signal.aborted) return;
  const { content } = sectionPage(cx, root, { active: 'asn', crumbs: [{ label: t('network.page.asn'), href: '#network/asn' }, { label: t('network.asn.tab.proposals') }], title: t('network.proposals.title'), owner: t('network.proposals.owner') });
  content.append(asnTabs(cx, caps, 'proposals'));
  if (!caps.installed || !asnWorkflow(caps)) { content.append(notConnected(cx, caps, 'asn/proposals')); return; }
  const actionsRow = root.querySelector('.zt-actions');
  if (actionsRow) actionsRow.append(can(caps, 'asn/proposals', 'POST') ? ui.el('a', { class: 'button button-primary', href: '#network/asn/proposals/new', text: t('network.proposal.new') }) : ui.disabledAction(t, 'network.proposal.new', 'network.gap.not_declared'));
  const state = PROPOSAL_STATES.includes(params.get('state')) ? params.get('state') : params.get('state') === 'open' ? 'open' : '';
  const asn = /^\d{1,10}$/.test(params.get('asn') || '') ? Number(params.get('asn')) : null;
  const chips = ui.el('nav', { class: 'zt-chips zt-filter-chips', attrs: { 'aria-label': t('network.proposals.filter') } }, ['', 'open', ...PROPOSAL_STATES].map(value => ui.el('a', { class: 'kit-tag', href: value ? `#network/asn/proposals?state=${value}` : '#network/asn/proposals', text: t(value === '' ? 'network.filter.any' : value === 'open' ? 'network.proposals.open' : `network.proposal.state.${value}`), attrs: { 'aria-current': value === state ? 'true' : false } })));
  const holder = ui.el('div', { class: 'zt-content' }, ui.loadingState(t));
  content.append(chips, holder);
  let data;
  try { ({ data } = await guard(cx, 'asn/proposals')); }
  catch (error) { ui.clear(holder, failure(cx, error, () => cx.navigate(`#network/asn/proposals?retry=${Date.now()}`))); return; }
  if (cx.signal.aborted) return;
  const rows = (Array.isArray(data?.proposals) ? data.proposals : []).filter(row => (!state || (state === 'open' ? OPEN.has(row.state) : row.state === state)) && (asn === null || row.asn === asn)).sort((a, b) => (b.created_at ?? 0) - (a.created_at ?? 0));
  const table = ui.dataTable(t, {
    id: 'network-asn-proposals', caption: 'network.proposals.caption', owner: 'ui.owner.sumunjang', sortable: 'none', rowKey: row => row.id,
    columns: [
      { key: 'asn', label: 'network.proposal.col.asn', render: row => ui.el('a', { class: 'zt-stack', href: `#network/asn/proposals/${encodeURIComponent(row.id)}` }, ui.el('strong', { text: asnText(cx, row.asn) }), ui.el('span', { class: 'kit-entity-id', text: row.id })) },
      { key: 'state', label: 'network.proposal.col.state', render: row => stateBadge(cx, row.state) },
      { key: 'scope', label: 'network.proposal.col.scope', render: row => ui.el('span', { class: 'zt-stack' }, ui.el('span', { text: t(`network.proposal.scope.${SCOPES.includes(row.scope) ? row.scope : 'asn'}`) }), ui.el('span', { class: 'kit-muted', text: t('network.proposal.networks', { count: row.networks ?? 0 }) })) },
      { key: 'approvals', label: 'network.proposal.col.approvals', render: row => ui.el('span', { class: 'zt-num', text: t('network.proposal.approvals_value', { count: row.approvals ?? 0, required: row.required_approvals ?? data.required_approvals ?? 1 }) }) },
      { key: 'tracked', label: 'network.proposal.col.tracked', render: row => ui.el('span', { class: 'zt-num', text: number(row.tracked_addresses ?? 0) }) },
      { key: 'reason', label: 'network.proposal.col.reason', render: row => ui.el('span', { text: row.reason || t('network.none') }) },
      { key: 'created', label: 'network.proposal.col.created', render: row => ui.el('span', { class: 'zt-stack' }, timeOrDash(cx, row.created_at), ui.el('span', { class: 'kit-muted', text: actor(cx, row.created_by) })) },
      { key: 'expires', label: 'network.proposal.col.expires', render: row => timeOrDash(cx, row.expires_at) },
    ],
    empty: { title: state || asn !== null ? 'network.proposals.empty.filtered' : 'network.proposals.empty', body: 'network.proposals.empty.body' },
    onRowOpen: row => cx.navigate(`#network/asn/proposals/${encodeURIComponent(row.id)}`),
    fetchPage: async ({ cursor }) => { const offset = Number(cursor || 0); return { items: rows.slice(offset, offset + 50), nextCursor: offset + 50 < rows.length ? String(offset + 50) : null }; },
  });
  cx.signal.addEventListener('abort', () => table.destroy(), { once: true });
  ui.clear(holder, ui.el('p', { class: 'zt-banner', attrs: { role: 'note' }, text: t('network.proposals.note', { count: data?.required_approvals ?? 1 }) }), table.element);
  await table.reload();
}

// ------------------------------------------------------------- wizard

export async function renderProposalNew(cx, root, params) {
  const { t, ui } = cx;
  const caps = await capabilities(cx);
  if (cx.signal.aborted) return;
  const { content } = sectionPage(cx, root, { active: 'asn', crumbs: [{ label: t('network.page.asn'), href: '#network/asn' }, { label: t('network.asn.tab.proposals'), href: '#network/asn/proposals' }, { label: t('network.proposal.new') }], title: t('network.proposal.new'), owner: t('network.proposal.new.owner') });
  if (!caps.installed || !can(caps, 'asn/proposals', 'POST') || !can(caps, 'asn/preview')) { content.append(notConnected(cx, caps, 'asn/proposals')); return; }
  const steps = ui.el('ol', { class: 'zt-steps', attrs: { 'aria-label': t('network.proposal.steps') } }, ['asn', 'scope', 'review'].map((name, index) => ui.el('li', { dataset: { step: name } }, ui.el('span', { class: 'zt-step-number', text: String(index + 1) }), ui.el('span', { text: t(`network.proposal.step.${name}`) }))));
  const status = ui.el('div', { class: 'zt-notes' });
  const body = ui.el('div', { class: 'zt-content' });
  content.append(steps, status, body);
  const state = { asn: /^\d{1,10}$/.test(params.get('asn') || '') ? Number(params.get('asn')) : null, kind: 'aggregates', prefixes: [], extra: '', catalog: null, impact: null };
  const mark = step => steps.querySelectorAll('li').forEach(item => { item.classList.toggle('is-current', item.dataset.step === step); item.setAttribute('aria-current', item.dataset.step === step ? 'step' : 'false'); });
  const scopeBody = () => {
    const prefixes = state.kind === 'prefixes' ? state.prefixes : state.kind === 'aggregates' ? state.extra.split(/[\n,]/).map(value => value.trim()).filter(Boolean) : [];
    return { kind: state.kind, ...(prefixes.length ? { prefixes } : {}) };
  };
  // Step 1: ASN.
  function stepAsn() {
    mark('asn');
    const form = ui.el('form', { class: 'zt-filters zt-wizard' });
    const field = ui.field(t, { label: 'network.proposal.field.asn', name: 'asn', value: state.asn === null ? '' : String(state.asn), pattern: '\\d{1,10}', maxLength: 10, help: 'network.proposal.help.asn' });
    field.querySelector('input').required = true;
    const evidence = ui.el('div');
    form.append(field, ui.el('div', { class: 'button-row zt-filter-actions' }, ui.el('button', { type: 'submit', class: 'button button-primary', text: t('network.proposal.next') })));
    form.addEventListener('submit', async event => {
      event.preventDefault();
      if (!form.reportValidity()) return;
      state.asn = Number(form.elements.asn.value);
      state.catalog = null;
      if (can(caps, 'asn/catalog/query')) {
        try { state.catalog = ((await guard(cx, 'asn/catalog/query', { json: { asn: state.asn, limit: 1000 } })).data?.entries || []).flatMap(entry => entry.prefixes || []); }
        catch (error) { if (error?.status === 401) throw error; }
      }
      stepScope();
    });
    ui.clear(body, panel(cx, 'network.proposal.step.asn', ui.el('div', { class: 'zt-content' }, ui.el('p', { class: 'kit-muted', text: t('network.proposal.asn.intro') }), form, evidence)));
    form.elements.asn.focus();
  }
  // Step 2: scope with preview.
  function stepScope() {
    mark('scope');
    const form = ui.el('form', { class: 'zt-editor zt-wizard' });
    const choices = ui.el('fieldset', { class: 'zt-mode-choice' }, ui.el('legend', { text: t('network.proposal.field.scope') }),
      SCOPES.map(kind => ui.el('label', { class: 'zt-choice' }, ui.el('input', { type: 'radio', name: 'kind', value: kind, checked: state.kind === kind }), ui.el('span', { class: 'zt-stack' }, ui.el('strong', { text: t(`network.proposal.scope.${kind}`) }), ui.el('span', { class: 'kit-muted', text: t(`network.proposal.scope.${kind}.help`) })))));
    const prefixBox = ui.el('div', { class: 'zt-content' });
    const preview = ui.el('div', { attrs: { 'aria-live': 'polite' } }, ui.el('p', { class: 'kit-muted', text: t('network.proposal.preview.idle') }));
    const renderPrefixBox = () => {
      if (state.kind === 'prefixes') {
        const list = state.catalog || [];
        ui.clear(prefixBox, list.length ? ui.el('fieldset', { class: 'zt-checks zt-prefix-choices' }, ui.el('legend', { text: t('network.proposal.prefixes.pick', { count: list.length }) }),
          list.slice(0, 512).map(prefix => ui.el('label', {}, ui.el('input', { type: 'checkbox', name: 'prefix', value: prefix, checked: state.prefixes.includes(prefix) }), ui.el('span', { class: 'kit-mono', text: prefix })))) : ui.el('p', { class: 'kit-muted', text: t('network.proposal.prefixes.none') }));
      } else if (state.kind === 'aggregates') {
        const id = `zt-aggregates-${Math.random().toString(36).slice(2, 6)}`;
        ui.clear(prefixBox, ui.el('label', { class: 'kit-field zt-field-wide', htmlFor: id }, ui.el('span', { class: 'kit-field-label', text: t('network.proposal.field.aggregates') }), ui.el('textarea', { id, name: 'extra', rows: 3, class: 'kit-mono', value: state.extra, spellcheck: false }), ui.el('small', { class: 'kit-help', text: t('network.proposal.help.aggregates') })));
      } else ui.clear(prefixBox, ui.el('p', { class: 'zt-banner zt-banner-warn', attrs: { role: 'note' }, text: t('network.proposal.scope.asn.warning', { count: (state.catalog || []).length }) }));
    };
    const read = () => {
      state.kind = form.querySelector('input[name=kind]:checked')?.value || 'aggregates';
      state.prefixes = [...form.querySelectorAll('input[name=prefix]:checked')].map(box => box.value);
      state.extra = form.elements.extra?.value ?? state.extra;
    };
    form.addEventListener('change', event => { const kindChanged = event.target.name === 'kind'; read(); if (kindChanged) renderPrefixBox(); state.impact = null; });
    const runPreview = async () => {
      read();
      const bad = scopeBody().prefixes?.find(prefix => !isCidr(prefix));
      if (bad) { ui.clear(preview, outcomeBanner(cx, 'refused', 'network.literal', { value: t('network.zone.error.prefix', { prefix: bad }) })); return false; }
      ui.clear(preview, ui.loadingState(t));
      try {
        state.impact = (await guard(cx, 'asn/preview', { json: { asn: state.asn, scope: scopeBody() } })).data?.impact || null;
        ui.clear(preview, impactView(cx, state.impact));
        return true;
      } catch (error) {
        if (error?.status === 401) throw error;
        ui.clear(preview, ui.el('div', { class: 'zt-dialog-error', attrs: { role: 'alert' } }, ui.el('p', { text: errorText(t, error) }), fieldErrors(cx, error)));
        return false;
      }
    };
    form.addEventListener('submit', event => event.preventDefault());
    form.append(choices, prefixBox, ui.el('div', { class: 'button-row' }, button(cx, 'network.proposal.back', stepAsn), button(cx, 'network.proposal.preview', runPreview), ui.el('button', { type: 'button', class: 'button button-primary', text: t('network.proposal.next'), on: { click: async () => { if (state.impact || await runPreview()) stepReview(); } } })));
    renderPrefixBox();
    ui.clear(body, panel(cx, 'network.proposal.step.scope', form, { params: {} }), panel(cx, 'network.proposal.preview.title', preview, { params: { asn: state.asn } }));
  }
  // Step 3: reason and expiry → draft.
  function stepReview() {
    mark('review');
    const form = ui.el('form', { class: 'zt-filters zt-wizard' });
    const reasonId = `zt-proposal-reason-${Math.random().toString(36).slice(2, 6)}`;
    const reason = ui.el('textarea', { id: reasonId, name: 'reason', rows: 3, maxLength: 256, required: true });
    form.append(ui.el('label', { class: 'kit-field zt-field-wide', htmlFor: reasonId }, ui.el('span', { class: 'kit-field-label', text: t('network.proposal.field.reason') }), reason, ui.el('small', { class: 'kit-help', text: t('network.proposal.help.reason') })),
      ui.field(t, { label: 'network.proposal.field.expires', name: 'expires', value: '7', options: EXPIRY_DAYS.map(days => ({ value: String(days), label: `network.proposal.expires.${days}` })), help: 'network.proposal.help.expires' }),
      ui.el('div', { class: 'button-row zt-filter-actions' }, button(cx, 'network.proposal.back', stepScope), ui.el('button', { type: 'submit', class: 'button button-primary', text: t('network.proposal.create') })));
    const errors = ui.el('div', { attrs: { 'aria-live': 'assertive' } });
    form.addEventListener('submit', async event => {
      event.preventDefault();
      if (!form.reportValidity()) return;
      const text = reason.value.trim();
      const body = { asn: state.asn, scope: scopeBody(), reason: text, expires_at: Math.floor(Date.now() / 1000) + Number(form.elements.expires.value) * 86400 };
      ui.clear(errors, ui.loadingState(t));
      try {
        const { data, operation } = await guard(cx, 'asn/proposals', { json: body, reason: text });
        const proposal = data?.proposal || data;
        // Attach the console's decision-log counts for this ASN (counts only).
        if (proposal?.id && can(caps, 'asn/proposals/*', 'POST')) { try { await annotate(cx, proposal); } catch (error) { if (error?.status === 401) throw error; } }
        ui.clear(status, outcomeBanner(cx, 'committed', 'network.proposal.created', { operation: operation || '—' }));
        cx.navigate(`#network/asn/proposals/${encodeURIComponent(proposal?.id || '')}`);
      } catch (error) {
        if (error?.status === 401) throw error;
        ui.clear(errors, ui.el('div', { class: 'zt-dialog-error', attrs: { role: 'alert' } }, ui.el('p', { text: errorText(t, error) }), fieldErrors(cx, error)));
      }
    });
    ui.clear(body, panel(cx, 'network.proposal.step.review', ui.el('div', { class: 'zt-content' }, facts(cx, [['network.proposal.field.asn', asnText(cx, state.asn)], ['network.proposal.field.scope', t(`network.proposal.scope.${state.kind}`)], ['network.proposal.impact.networks', number(state.impact?.networks ?? 0)], ['network.proposal.impact.tracked', number(state.impact?.tracked?.addresses ?? 0)]]),
      ui.el('p', { class: 'zt-banner', attrs: { role: 'note' }, text: t('network.proposal.review.note') }), form, errors)));
    reason.focus();
  }
  stepAsn();
}

// ------------------------------------------------------------- detail

const TRANSITIONS = Object.freeze({
  draft: ['submit', 'analyze', 'withdraw'],
  pending: ['approve', 'reject', 'analyze', 'withdraw'],
  approved: ['activate', 'reject', 'analyze', 'withdraw'],
  active: ['withdraw'],
});
export const ACTIONS = Object.freeze(['submit', 'approve', 'reject', 'activate', 'withdraw', 'analyze', 'annotate']);

export async function renderProposal(cx, root, id) {
  const { t, ui } = cx;
  const caps = await capabilities(cx);
  if (cx.signal.aborted) return;
  const { content, heading } = sectionPage(cx, root, { active: 'asn', crumbs: [{ label: t('network.page.asn'), href: '#network/asn' }, { label: t('network.asn.tab.proposals'), href: '#network/asn/proposals' }, { label: id }], title: id, owner: t('network.proposal.owner') });
  if (!caps.installed || !asnWorkflow(caps)) { content.append(notConnected(cx, caps, 'asn/proposals/*')); return; }
  const status = ui.el('div', { class: 'zt-notes' });
  const holder = ui.el('div', { class: 'zt-content' }, ui.loadingState(t));
  content.append(status, holder);
  let proposal, viewer;
  try { [proposal, viewer] = await Promise.all([guard(cx, `asn/proposals/${id}`, { method: 'GET' }).then(answer => answer.data?.proposal || answer.data), viewerName(cx)]); }
  catch (error) { ui.clear(holder, failure(cx, error, () => cx.navigate(`${location.hash.split('?')[0]}?retry=${Date.now()}`))); return; }
  if (cx.signal.aborted) return;
  if (!proposal?.id) { ui.clear(holder, ui.emptyState(t, { title: 'network.proposal.missing', body: 'network.proposal.missing.body' })); return; }
  // Decision-log counts are attached once for open proposals that have none.
  if (OPEN.has(proposal.state) && proposal.state !== 'active' && !proposal.decision_log && can(caps, 'asn/proposals/*', 'POST')) {
    try { const answer = await annotate(cx, proposal); if (answer?.data) proposal = answer.data?.proposal || answer.data; }
    catch (error) { if (error?.status === 401) throw error; }
  }
  heading.textContent = t('network.proposal.title', { asn: proposal.asn });
  const isProposer = Boolean(viewer && proposal.created_by?.name === viewer);
  const approvedBy = (proposal.approvals || []).map(mark => mark.by?.name);
  const required = proposal.required_approvals ?? 1;
  const canAct = can(caps, 'asn/proposals/*', 'POST');
  const done = (key, result) => { ui.clear(status, outcomeBanner(cx, 'committed', key, { operation: result?.operation || '—' })); setTimeout(() => cx.navigate(`#network/asn/proposals/${encodeURIComponent(proposal.id)}?updated=${Date.now()}`), 900); };
  const act = (action, { reasonRequired = false, confirm = null, danger = false, intro } = {}) => async () => {
    const result = await formDialog(cx, { title: `network.proposal.action.${action}.title`, intro: intro || t(`network.proposal.action.${action}.effect`, { asn: proposal.asn, count: proposal.networks?.length ?? 0 }), confirm, confirmLabel: `network.proposal.action.${action}`, danger, reason: reasonRequired || action !== 'analyze',
      submit: values => guard(cx, `asn/proposals/${proposal.id}`, { json: { action, expected_revision: proposal.revision, ...(values.reason ? { reason: values.reason } : {}) }, reason: values.reason || undefined }) });
    if (result) done(`network.proposal.action.${action}.done`, result);
  };
  const actionsRow = root.querySelector('.zt-actions');
  if (actionsRow) for (const action of TRANSITIONS[proposal.state] || []) {
    const label = `network.proposal.action.${action}`;
    if (!canAct) { actionsRow.append(ui.disabledAction(t, label, 'network.gap.not_declared')); continue; }
    if (action === 'approve' && (isProposer || approvedBy.includes(viewer))) { actionsRow.append(ui.disabledAction(t, label, isProposer ? 'network.proposal.two_person.self' : 'network.proposal.two_person.again')); continue; }
    const options = { submit: {}, approve: {}, reject: { reasonRequired: true, danger: true }, analyze: {}, withdraw: { danger: true }, activate: { confirm: `AS${proposal.asn}`, danger: true } }[action];
    actionsRow.append(button(cx, label, act(action, options), { kind: action === 'activate' || action === 'approve' || action === 'submit' ? 'primary' : action === 'reject' || action === 'withdraw' ? 'danger' : 'quiet' }));
  }
  const banners = [];
  if (isProposer && ['pending', 'approved'].includes(proposal.state)) banners.push(ui.el('p', { class: 'zt-banner', attrs: { role: 'note' }, text: t('network.proposal.two_person.banner', { count: required }) }));
  if (proposal.created_by?.name === 'admin-credential') banners.push(ui.el('p', { class: 'zt-banner zt-banner-warn', attrs: { role: 'note' }, text: t('network.proposal.two_person.credential') }));
  if (proposal.state === 'approved') banners.push(ui.el('p', { class: 'zt-banner zt-banner-warn', attrs: { role: 'note' }, text: t('network.proposal.activate.note') }));
  const history = Array.isArray(proposal.history) ? proposal.history : [];
  const timeline = ui.el('ol', { class: 'kit-timeline zt-proposal-timeline' }, history.map(entry => ui.el('li', { class: `kit-stage${entry.action === 'asn.proposal.activate' ? ' is-deciding' : ''}` },
    ui.el('div', { class: 'kit-stage-head' }, ui.el('strong', { text: t(`network.proposal.event.${eventName(entry.action)}`) }), stateBadge(cx, entry.to), ui.el('span', { class: 'kit-muted' }, actor(cx, entry.by)), timeOrDash(cx, entry.at)),
    entry.reason ? ui.el('p', { class: 'zt-trace-text', text: entry.reason }) : null)));
  const activation = proposal.activation;
  ui.clear(holder, ...banners,
    ui.el('div', { class: 'zt-grid' },
      panel(cx, 'network.proposal.summary', facts(cx, [
        ['network.proposal.col.state', stateBadge(cx, proposal.state)],
        ['network.proposal.field.asn', ui.el('a', { href: `#network/asn?asn=${proposal.asn}`, text: asnText(cx, proposal.asn) })],
        ['network.proposal.field.scope', t(`network.proposal.scope.${SCOPES.includes(proposal.scope?.kind) ? proposal.scope.kind : 'asn'}`)],
        ['network.proposal.col.approvals', ui.el('span', {}, ui.el('strong', { text: t('network.proposal.approvals_value', { count: approvedBy.length, required }) }), approvedBy.length ? ui.el('span', { class: 'kit-muted' }, ' · ', approvedBy.join(', ')) : null)],
        ['network.proposal.field.reason', proposal.reason || null],
        ['network.proposal.col.created', ui.el('span', {}, timeOrDash(cx, proposal.created_at), ui.el('span', { class: 'kit-muted' }, ' · ', actor(cx, proposal.created_by)))],
        ['network.proposal.col.expires', timeOrDash(cx, proposal.expires_at)],
        ['network.proposal.revision', String(proposal.revision ?? '—')],
        ['network.proposal.activation', activation ? t('network.proposal.activation_value', { blocked: activation.blocked?.length ?? 0, skipped: activation.skipped_existing?.length ?? 0 }) : null],
        ['network.proposal.block_expires', activation ? timeOrDash(cx, activation.block_expires_at) : null],
      ])),
      panel(cx, 'network.proposal.timeline', history.length ? timeline : ui.el('p', { class: 'kit-muted', text: t('network.proposal.timeline.none') }))),
    panel(cx, 'network.proposal.impact.title', impactView(cx, proposal.impact, { decisionLog: proposal.decision_log })));
}

const EVENTS = Object.freeze(['create', 'submit', 'approve', 'reject', 'activate', 'withdraw', 'analyze', 'annotate', 'expire']);
function eventName(action) { const short = String(action || '').replace(/^asn\.proposal\./, ''); return EVENTS.includes(short) ? short : 'other'; }
