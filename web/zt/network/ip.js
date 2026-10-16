// Network ▸ IP detail (`#network/ip/:ip`): GeoIP/ASN, score and suspicion,
// matched rules, block/allow status with expiry, the explain trace (and what
// enforce would decide while observing), related Hangang decisions, actions.
import { can, guard, failure, sectionPage, capabilities, modeBanner, facts, panel, button, suspicionBadge, expiry, networkLink, asnText, blockKind, isIp, outcomeBanner, number, codeText } from './common.js';
import { explainTimeline, verdictBadge } from './trace.js';
import { zoneBadges } from './zones.js';
import { blockDialog, unblockDialog, allowDialog, approveCandidates, contains } from './actions.js';
import { decisionColumns, decisionFetcher } from '../access.js';

async function settle(promise) { try { return { ok: true, value: (await promise).data }; } catch (error) { if (error?.status === 401) throw error; return { ok: false, error }; } }

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
  const [lookup, explain, blocks, candidates, policy] = await Promise.all([
    settle(guard(cx, 'lookup', { json: { ip } })), settle(guard(cx, 'explain', { json: { ip } })), settle(guard(cx, 'blocks')), settle(guard(cx, 'candidates')), settle(guard(cx, 'policy/document')),
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
  const mode = policy.ok ? policy.value.policy?.mode : result?.evaluated?.mode;
  // Zone labels (Sumunjang 0.1.7 explain `zone` stage); zones never change the decision.
  const zoneStage = result?.stages?.find(stage => stage.stage === 'zone') || result?.enforce_preview?.stages?.find(stage => stage.stage === 'zone') || null;
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
  const allowRow = allowEntry ? ui.el('p', {}, ui.statusBadge(t, 'allow', 'network.allow.listed'), ' ', networkLink(cx, allowEntry), ' ', ui.el('span', { class: 'kit-muted', text: t('network.expiry.never') })) : ui.el('p', { class: 'kit-muted', text: t('network.ip.not_allowed') });
  const summary = ui.el('div', { class: 'zt-grid' },
    panel(cx, 'network.ip.location', facts(cx, [
      ['network.ip.country', geo.country_name ? `${geo.country_name} (${geo.country_code || '—'})` : geo.country_code || t('entity.ip.country.unknown')],
      ['network.ip.city', geo.city || null],
      ['network.ip.accuracy', Number.isFinite(geo.accuracy_radius_km) ? t('network.ip.accuracy_value', { km: geo.accuracy_radius_km }) : null],
      ['network.ip.zones', zoneStage ? zoneBadges(cx, zoneStage.zones) : null],
      ['network.ip.asn', ui.el('span', {}, ui.el('span', { text: asnText(cx, geo.asn ?? inspection.asn ?? result?.geoip?.asn) }), geo.asn_organization ? ui.el('span', { class: 'kit-muted' }, ' · ', geo.asn_organization) : null)],
    ])),
    panel(cx, 'network.ip.risk', facts(cx, [
      ['network.ip.suspicion', suspicionBadge(cx, inspection.suspicion)],
      ['network.ip.score', t('network.ip.score_value', { total: number(inspection.score ?? 0), signal: number(inspection.signal_score ?? 0), rules: number(inspection.static_rule_score ?? 0) })],
      ['network.ip.threshold', policy.ok ? number(policy.value.policy?.threshold) : null],
      ['network.ip.events', candidate ? t('network.ip.events_value', { count: number(candidate.events), first: ui.formatFullTime((candidate.first_seen || 0) * 1000), last: ui.formatFullTime((candidate.last_seen || 0) * 1000) }) : t('network.ip.no_events')],
      ['network.ip.matched_rules', matchedRules],
    ]), { actions: [] }),
    panel(cx, 'network.ip.status', ui.el('div', { class: 'zt-content' }, ui.el('h3', { class: 'zt-subhead', text: t('network.ip.blocks') }), blockRows, ui.el('h3', { class: 'zt-subhead', text: t('network.ip.allowlist') }), allowRow)));
  const history = ui.el('p', { class: 'zt-gap', attrs: { role: 'note' } }, ui.el('span', { class: 'kit-info', text: 'ⓘ', attrs: { 'aria-hidden': 'true' } }), ' ', ui.el('span', { text: t('network.gap.history') }));
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
  ui.clear(body, modeBanner(cx, { mode }), verdict, summary, history, trace);
  // State-appropriate actions.
  if (actionsRow) {
    const done = (key, result_) => { ui.clear(status, outcomeBanner(cx, 'committed', key, { operation: result_?.operation || '—' })); setTimeout(() => cx.navigate(`#network/ip/${encodeURIComponent(ip)}?updated=${Date.now()}`), 900); };
    const action = (route, method, label, handler, kind) => can(caps, route, method) ? button(cx, label, handler, { kind }) : ui.disabledAction(t, label, 'network.gap.not_declared');
    const exact = covering.find(block => block.network === `${ip}/${ip.includes(':') ? 128 : 32}`);
    if (candidate?.eligible && !covering.length) actionsRow.append(action('candidates/approve', 'POST', 'network.threats.approve', async () => { const results = await approveCandidates(cx, [ip]); if (results?.[0]?.kind === 'committed') done('network.threats.approved_one', results[0]); }, 'danger'));
    if (exact) actionsRow.append(action('blocks', 'DELETE', 'network.unblock', async () => { const r = await unblockDialog(cx, exact); if (r) done('network.unblock.done', r); }));
    else if (!allowEntry) actionsRow.append(action('blocks', 'POST', 'network.block', async () => { const r = await blockDialog(cx, { network: ip, mode, fixed: true }); if (r) done('network.block.done', r); }, 'danger'));
    if (allowEntry === `${ip}/${ip.includes(':') ? 128 : 32}`) actionsRow.append(action('policy/document', 'PUT', 'network.unallow', async () => { const r = await allowDialog(cx, { network: ip, remove: true }); if (r) done('network.unallow.done', r); }));
    else if (!allowEntry) actionsRow.append(action('policy/document', 'PUT', 'network.allow', async () => { const r = await allowDialog(cx, { network: ip, fixed: true }); if (r) done('network.allow.done', r); }));
  }
}
