// Network ▸ IP detail (`#network/ip/:ip`): GeoIP/ASN, score and suspicion,
// matched rules, block/allow status with expiry, the explain trace (and what
// enforce would decide while observing), related Hangang decisions, actions.
import { can, guard, failure, sectionPage, capabilities, modeBanner, facts, panel, button, suspicionBadge, expiry, networkLink, asnText, blockKind, isIp, outcomeBanner, number, codeText, signalChips, exactNetwork, SIGNAL_KINDS } from './common.js';
import { explainTimeline, verdictBadge } from './trace.js';
import { blockDialog, unblockDialog, allowDialog, approveCandidates, contains } from './actions.js';
import { decisionColumns, decisionFetcher } from '../access.js';

async function settle(promise) { try { return { ok: true, value: (await promise).data }; } catch (error) { if (error?.status === 401) throw error; return { ok: false, error }; } }

/**
 * Score per minute (bars) with the threshold line, per-signal totals and an
 * honest coverage label: history is memory-only and starts at the later of
 * process start and the retention edge.
 */
function historyChart(cx, data) {
  const { t, ui } = cx;
  const buckets = Array.isArray(data?.buckets) ? data.buckets : [];
  const step = Number(data?.bucket_secs) || 60;
  const since = Number(data?.retained_since ?? data?.since) || 0, until = Number(data?.until) || Math.floor(Date.now() / 1000);
  const restarted = Number(data?.stats?.started_at) && Number(data.stats.started_at) >= since;
  const coverage = restarted ? t('network.history.since_restart', { time: ui.formatFullTime(since * 1000) }) : t('network.history.since', { hours: Math.round((Number(data?.retention_secs) || 0) / 3600) });
  const head = ui.el('p', { class: 'kit-muted' }, ui.el('span', { text: coverage }), data?.in_memory ? ui.el('span', { class: 'kit-tag', title: t('network.history.in_memory.help'), text: t('network.history.in_memory') }) : null);
  if (!buckets.length) return ui.el('div', { class: 'zt-history' }, head, ui.emptyState(t, { title: 'network.history.empty', body: 'network.history.empty.body' }));
  const slots = Math.max(1, Math.ceil((until - since) / step));
  const threshold = Number(data?.window?.threshold) || 0;
  const peak = Math.max(threshold, ...buckets.map(bucket => Number(bucket.score) || 0), 1);
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', `0 0 ${slots} 100`); svg.setAttribute('preserveAspectRatio', 'none'); svg.setAttribute('class', 'zt-history-chart'); svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', t('network.history.chart', { count: buckets.length, total: number(data?.totals?.score ?? 0) }));
  const base = document.createElementNS(ns, 'line'); base.setAttribute('x1', '0'); base.setAttribute('x2', String(slots)); base.setAttribute('y1', '100'); base.setAttribute('y2', '100'); svg.append(base);
  for (const bucket of buckets) {
    const rect = document.createElementNS(ns, 'rect');
    const height = (Number(bucket.score) || 0) / peak * 96;
    rect.setAttribute('x', String(Math.max(0, Math.floor((bucket.start - since) / step))));
    rect.setAttribute('width', String(Math.max(0.8, slots / 400)));
    rect.setAttribute('y', String(100 - height)); rect.setAttribute('height', String(height));
    const tip = document.createElementNS(ns, 'title'); tip.textContent = t('network.history.bucket', { time: ui.formatFullTime(bucket.start * 1000), score: bucket.score }); rect.append(tip);
    svg.append(rect);
  }
  if (threshold) { const line = document.createElementNS(ns, 'line'); const y = String(100 - threshold / peak * 96); line.setAttribute('x1', '0'); line.setAttribute('x2', String(slots)); line.setAttribute('y1', y); line.setAttribute('y2', y); line.setAttribute('class', 'zt-threshold'); svg.append(line); }
  const totals = data?.totals?.signals || {};
  return ui.el('div', { class: 'zt-history' }, head, svg,
    ui.el('div', { class: 'zt-history-axis' }, ui.el('span', { text: ui.formatCompactTime(since * 1000) }), ui.el('span', { text: ui.formatCompactTime(until * 1000) })),
    ui.el('div', { class: 'zt-history-legend' }, ui.el('strong', { text: t('network.history.total', { score: number(data?.totals?.score ?? 0) }) }), SIGNAL_KINDS.map(kind => ui.el('span', { text: t('network.signal.count', { name: t(`network.signal.${kind}`), count: number(totals[kind] ?? 0) }) })),
      threshold ? ui.el('span', { class: 'kit-muted', text: t('network.history.threshold', { threshold }) }) : null),
    // Table alternative for the chart (screen readers, exact values).
    ui.el('details', { class: 'zt-history-table' }, ui.el('summary', { text: t('network.history.table') }), ui.el('table', { class: 'zt-keys' }, ui.el('thead', {}, ui.el('tr', {}, ui.el('th', { scope: 'col', text: t('network.history.col.minute') }), ui.el('th', { scope: 'col', text: t('network.history.col.score') }), SIGNAL_KINDS.map(kind => ui.el('th', { scope: 'col', text: t(`network.signal.${kind}.short`) })))),
      ui.el('tbody', {}, buckets.slice(-60).reverse().map(bucket => ui.el('tr', {}, ui.el('td', {}, ui.timeCell(t, bucket.start * 1000)), ui.el('td', { text: String(bucket.score) }), SIGNAL_KINDS.map(kind => ui.el('td', { text: String(bucket.signals?.[kind] ?? 0) }))))))));
}

export async function renderIpDetail(cx, root, ip) {
  const { t, ui } = cx;
  const caps = await capabilities(cx);
  if (cx.signal.aborted) return;
  const { content } = sectionPage(cx, root, { active: null, crumbs: [{ label: t('network.ip.crumb') }, { label: ip }], title: ip, owner: t('network.ip.owner') });
  if (!isIp(ip)) { content.append(ui.emptyState(t, { title: 'entity.ip.invalid.title', body: 'entity.ip.invalid.body' })); return; }
  const actionsRow = root.querySelector('.zt-actions');
  const status = ui.el('div', { class: 'zt-notes' });
  const body = ui.el('div', { class: 'zt-content' }, ui.loadingState(t));
  const params = new URLSearchParams({ ip });
  const decisions = ui.dataTable(t, { id: 'network-ip-decisions', caption: 'entity.decisions.caption', owner: 'ui.owner.exporter', columns: decisionColumns(cx), rowKey: event => event.event_id, onRowOpen: event => cx.navigate(cx.hashFor('access', ['requests', event.request_id])), empty: { title: 'entity.decisions.empty' }, fetchPage: decisionFetcher(cx, params, { limit: 20 }) });
  cx.signal.addEventListener('abort', () => decisions.destroy(), { once: true });
  content.append(status, body, panel(cx, 'entity.decisions.title', decisions.element, { actions: [ui.el('a', { class: 'button button-quiet', href: cx.hashFor('access', ['decisions'], params), text: t('entity.decisions.open') })] }));
  decisions.reload();
  if (!caps.installed) {
    // Without Sumunjang the page still shows Hangang's own GeoIP and decisions.
    const geo = await settle(cx.api(`/v1/geoip/lookup?ip=${encodeURIComponent(ip)}`));
    ui.clear(body, ui.el('p', { class: 'zt-banner', attrs: { role: 'note' }, text: t('network.ip.no_sumunjang') }), geo.ok ? facts(cx, [['entity.ip.country', geo.value?.country || geo.value?.country_code || t('entity.ip.country.unknown')]]) : null);
    return;
  }
  const [lookup, explain, blocks, candidates, policy, history, allowlist] = await Promise.all([
    settle(guard(cx, 'lookup', { json: { ip } })), settle(guard(cx, 'explain', { json: { ip } })), settle(guard(cx, 'blocks')), settle(guard(cx, 'candidates')), settle(guard(cx, 'policy/document')),
    can(caps, 'history/query') ? settle(guard(cx, 'history/query', { json: { ip } })) : Promise.resolve(null),
    can(caps, 'allowlist', 'GET') ? settle(guard(cx, 'allowlist')) : Promise.resolve(null),
  ]);
  if (cx.signal.aborted) return;
  if (!lookup.ok && !explain.ok) { ui.clear(body, failure(cx, explain.error, () => cx.navigate(location.hash.split('?')[0] + '?retry=' + Date.now()))); return; }
  const geo = lookup.value?.geoip || {};
  const inspection = lookup.value?.inspection || {};
  const result = explain.ok ? explain.value : null;
  const covering = (blocks.ok && Array.isArray(blocks.value) ? blocks.value : []).filter(block => contains(block.network, ip)).sort((a, b) => Number(b.network.split('/')[1]) - Number(a.network.split('/')[1]));
  const candidate = (candidates.ok && Array.isArray(candidates.value) ? candidates.value : []).find(entry => entry.ip === ip) || null;
  const allowStage = result?.stages?.find(stage => stage.stage === 'allowlist');
  const allowEntry = allowStage?.matched ? allowStage.network : (policy.ok ? (policy.value.policy?.allow || []).find(network => contains(network, ip)) : null);
  // Expiry and reason of the matching entry when Sumunjang reports allowlist metadata.
  const allowMeta = allowlist?.ok ? (allowlist.value?.entries || []).filter(entry => contains(entry.network, ip)).sort((a, b) => Number(Boolean(a.expired)) - Number(Boolean(b.expired)))[0] || null : null;
  const mode = policy.ok ? policy.value.policy?.mode : result?.evaluated?.mode;
  // Matched rules come from the same explain evaluation as the trace (the
  // enforce view while observing); the lookup snapshot is only a fallback.
  const evaluation = result?.enforce_preview || result;
  const rulesStage = evaluation?.stages?.find(stage => stage.stage === 'rules');
  const ruleChip = (rule, extra) => ui.el('a', { class: `kit-tag${extra ? ` ${extra}` : ''}`, href: `#network/rules?rule=${encodeURIComponent(rule.id)}`, text: rule.id, dataset: { rule: rule.id } });
  const matchedRules = rulesStage
    ? ui.el('span', { class: 'zt-chips zt-matched-rules', dataset: { source: 'explain' } },
      (rulesStage.matched || []).map(rule => ruleChip(rule, rule.winner ? 'is-winner' : '')),
      (rulesStage.expired || []).map(rule => ui.el('span', { class: 'zt-chips' }, ruleChip(rule, 'is-expired'), ui.el('span', { class: 'kit-tag kit-tag-warn', text: t('network.expiry.expired') }))),
      !(rulesStage.matched || []).length && !(rulesStage.expired || []).length ? ui.el('span', { class: 'kit-muted', text: t('network.none') }) : null)
    : result
      ? ui.el('span', { class: 'kit-muted', text: t('network.ip.rules_not_reached') })
      : ui.el('span', { class: 'zt-chips zt-matched-rules', dataset: { source: 'lookup' } }, (inspection.matched_rules || []).map(id => ruleChip({ id })), ui.el('span', { class: 'kit-muted', text: t('network.ip.rules_snapshot') }));
  // Header verdict.
  const verdict = result ? ui.el('div', { class: 'zt-verdict' }, verdictBadge(cx, result.verdict), ui.el('span', { text: codeText(t, result.reason_code, result.params) }),
    result.enforce_preview ? ui.el('span', { class: 'zt-preview-verdict' }, ui.el('span', { class: 'kit-muted', text: t('network.ip.enforce_would') }), ' ', verdictBadge(cx, result.enforce_preview.verdict === 'observe' ? (result.enforce_preview.decision?.action || 'allow') : result.enforce_preview.verdict)) : null) : null;
  // Status: block and allowlist.
  const blockRows = covering.length ? ui.el('ul', { class: 'zt-status-list' }, covering.map(block => ui.el('li', {}, ui.statusBadge(t, 'deny', `network.block.kind.${blockKind(block)}`), ' ', networkLink(cx, block.network), ' ', expiry(cx, block.expires_at), blockKind(block) === 'manual' && block.reason ? ui.el('span', { class: 'kit-muted', text: block.reason }) : null))) : ui.el('p', { class: 'kit-muted', text: t('network.ip.not_blocked') });
  const allowRow = allowEntry || allowMeta ? ui.el('p', { class: allowMeta?.expired ? 'is-expired' : '' }, ui.statusBadge(t, allowMeta?.expired ? 'stale' : 'allow', allowMeta?.expired ? 'network.allow.expired' : 'network.allow.listed'), ' ', networkLink(cx, allowMeta?.network || allowEntry), ' ',
    allowMeta?.expires_at ? expiry(cx, allowMeta.expires_at) : ui.el('span', { class: 'kit-muted', text: t('network.expiry.never') }), allowMeta?.reason ? ui.el('span', { class: 'kit-muted' }, ' · ', allowMeta.reason) : null) : ui.el('p', { class: 'kit-muted', text: t('network.ip.not_allowed') });
  const summary = ui.el('div', { class: 'zt-grid' },
    panel(cx, 'network.ip.location', facts(cx, [
      ['network.ip.country', geo.country_name ? `${geo.country_name} (${geo.country_code || '—'})` : geo.country_code || t('entity.ip.country.unknown')],
      ['network.ip.city', geo.city || null],
      ['network.ip.accuracy', Number.isFinite(geo.accuracy_radius_km) ? t('network.ip.accuracy_value', { km: geo.accuracy_radius_km }) : null],
      ['network.ip.asn', ui.el('span', {}, ui.el('span', { text: asnText(cx, geo.asn ?? inspection.asn ?? result?.geoip?.asn) }), geo.asn_organization ? ui.el('span', { class: 'kit-muted' }, ' · ', geo.asn_organization) : null)],
    ])),
    panel(cx, 'network.ip.risk', facts(cx, [
      ['network.ip.suspicion', suspicionBadge(cx, inspection.suspicion)],
      ['network.ip.score', t('network.ip.score_value', { total: number(inspection.score ?? 0), signal: number(inspection.signal_score ?? 0), rules: number(inspection.static_rule_score ?? 0) })],
      ['network.ip.threshold', policy.ok ? number(policy.value.policy?.threshold) : null],
      ['network.ip.events', candidate ? t('network.ip.events_value', { count: number(candidate.events), first: ui.formatFullTime((candidate.first_seen || 0) * 1000), last: ui.formatFullTime((candidate.last_seen || 0) * 1000) }) : t('network.ip.no_events')],
      ['network.ip.signals', candidate?.signals ? signalChips(cx, candidate.signals) : null],
      ['network.ip.matched_rules', matchedRules],
    ]), { actions: [] }),
    panel(cx, 'network.ip.status', ui.el('div', { class: 'zt-content' }, ui.el('h3', { class: 'zt-subhead', text: t('network.ip.blocks') }), blockRows, ui.el('h3', { class: 'zt-subhead', text: t('network.ip.allowlist') }), allowRow)));
  const historyPanel = history ? panel(cx, 'network.ip.history', history.ok ? historyChart(cx, history.value) : failure(cx, history.error)) : ui.el('p', { class: 'zt-gap', attrs: { role: 'note' } }, ui.el('span', { class: 'kit-info', text: 'ⓘ', attrs: { 'aria-hidden': 'true' } }), ' ', ui.el('span', { text: t('network.gap.history') }));
  // Explain trace (published) and, while observing, what enforce would decide.
  let trace;
  if (result) {
    const tabs = ui.el('div', { class: 'zt-trace-tabs', attrs: { role: 'tablist', 'aria-label': t('network.ip.trace') } });
    const holder = ui.el('div', { attrs: { role: 'tabpanel' } }, explainTimeline(cx, result));
    const views = [['published', result], ...(result.enforce_preview ? [['enforce', result.enforce_preview]] : [])];
    views.forEach(([name, value], index) => {
      const tab = ui.el('button', { type: 'button', class: 'zt-trace-tab', text: t(`network.ip.trace.${name}`), attrs: { role: 'tab', 'aria-selected': String(index === 0) } });
      tab.addEventListener('click', () => { tabs.querySelectorAll('[role=tab]').forEach(other => other.setAttribute('aria-selected', String(other === tab))); ui.clear(holder, explainTimeline(cx, value)); });
      tabs.append(tab);
    });
    trace = panel(cx, 'network.ip.trace', ui.el('div', { class: 'zt-content' }, views.length > 1 ? tabs : null, holder, facts(cx, [['network.ip.evaluated', t('network.ip.evaluated_value', { revision: result.evaluated?.revision ?? '—', policy: result.evaluated?.policy_revision ?? '—' })]])));
  } else trace = panel(cx, 'network.ip.trace', failure(cx, explain.error));
  ui.clear(body, modeBanner(cx, { mode }), verdict, summary, historyPanel, trace);
  // State-appropriate actions.
  if (actionsRow) {
    const done = (key, result_) => { ui.clear(status, outcomeBanner(cx, 'committed', key, { operation: result_?.operation || '—' })); setTimeout(() => cx.navigate(`#network/ip/${encodeURIComponent(ip)}?updated=${Date.now()}`), 900); };
    const action = (route, method, label, handler, kind) => can(caps, route, method) ? button(cx, label, handler, { kind }) : ui.disabledAction(t, label, 'network.gap.not_declared');
    const exact = covering.find(block => block.network === `${ip}/${ip.includes(':') ? 128 : 32}`);
    if (candidate?.eligible && !covering.length) actionsRow.append(action('candidates/approve', 'POST', 'network.threats.approve', async () => { const results = await approveCandidates(cx, [ip]); if (results?.[0]?.kind === 'committed') done('network.threats.approved_one', results[0]); }, 'danger'));
    if (exact) actionsRow.append(action('blocks', 'DELETE', 'network.unblock', async () => { const r = await unblockDialog(cx, exact); if (r) done('network.unblock.done', r); }));
    else if (!allowEntry) actionsRow.append(action('blocks', 'POST', 'network.block', async () => { const r = await blockDialog(cx, { network: ip, mode, fixed: true }); if (r) done('network.block.done', r); }, 'danger'));
    const allowRoute = can(caps, 'allowlist', 'POST') ? ['allowlist', 'POST'] : ['policy/document', 'PUT'];
    if ((allowMeta?.network || allowEntry) === exactNetwork(ip)) actionsRow.append(action(allowRoute[0], allowRoute[0] === 'allowlist' ? 'DELETE' : 'PUT', 'network.unallow', async () => { const r = await allowDialog(cx, { network: ip, remove: true }); if (r) done('network.unallow.done', r); }));
    else if (!allowEntry) actionsRow.append(action(allowRoute[0], allowRoute[1], 'network.allow', async () => { const r = await allowDialog(cx, { network: ip, fixed: true }); if (r) done('network.allow.done', r); }));
  }
}
