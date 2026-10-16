// Network ▸ Overview: mode banner with what enforcement would change, KPI
// tiles that link to their lists, network-stage decision trend from the
// Hangang decision log, top countries and ASNs, recent policy changes.
import { can, guard, sectionPage, capabilities, notConnected, modeBanner, panel, number, blockKind, BLOCK_KINDS, asnText, failure } from './common.js';

async function settle(promise) { try { return { ok: true, value: (await promise).data }; } catch (error) { if (error?.status === 401) throw error; return { ok: false, error }; } }

function trend(cx, points) {
  const { t, ui } = cx;
  const buckets = new Map();
  for (const point of points) {
    const entry = buckets.get(point.start_ms) || { total: 0, deny: 0 };
    const value = point.estimated_requests ?? point.events ?? 0;
    entry.total += value;
    if (point.outcome === 'deny') entry.deny += value;
    buckets.set(point.start_ms, entry);
  }
  const series = [...buckets.entries()].sort((a, b) => a[0] - b[0]).map(([, entry]) => entry.deny);
  const peak = series.length ? Math.max(...series) : 0;
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', '0 0 100 24'); svg.setAttribute('preserveAspectRatio', 'none'); svg.setAttribute('aria-hidden', 'true'); svg.classList.add('zt-sparkline');
  if (series.length > 1) {
    const line = document.createElementNS(ns, 'polyline');
    line.setAttribute('points', series.map((value, index) => `${(index / (series.length - 1)) * 100},${22 - (peak ? value / peak : 0) * 20}`).join(' '));
    svg.append(line);
  }
  const total = series.reduce((sum, value) => sum + value, 0);
  return ui.el('a', { class: 'zt-kpi zt-kpi-wide', href: '#access/decisions?stage=network&outcome=deny' }, ui.el('span', { class: 'zt-kpi-label', text: t('network.overview.trend') }), svg,
    ui.el('small', { class: 'kit-muted', text: series.length ? t('network.overview.trend.summary', { total: number(total), peak: number(peak), count: series.length }) : t('network.overview.trend.empty') }));
}

function kpi(cx, { label, value, href, note, tone = '' }) {
  const { t, ui } = cx;
  return ui.el('a', { class: `zt-kpi ${tone}`.trim(), href }, ui.el('span', { class: 'zt-kpi-label', text: t(label) }), ui.el('strong', { class: 'zt-kpi-value', text: value }), note ? ui.el('small', { class: 'kit-muted', text: note }) : null);
}

function topList(cx, { title, entries, empty }) {
  const { t, ui } = cx;
  const list = ui.el('ol', { class: 'zt-top' });
  for (const entry of entries.slice(0, 5)) list.append(ui.el('li', {}, ui.el('a', { href: entry.href }, ui.el('span', { class: 'zt-top-label', text: entry.label }), ui.el('span', { class: 'zt-top-count', text: entry.count }))));
  return panel(cx, title, entries.length ? list : ui.emptyState(t, { title: empty }));
}

export async function renderNetworkOverview(cx, root) {
  const { t, ui } = cx;
  const caps = await capabilities(cx);
  if (cx.signal.aborted) return;
  const { content } = sectionPage(cx, root, { active: 'overview', title: t('network.page.overview'), owner: t('network.overview.owner') });
  if (!caps.installed) { content.append(notConnected(cx, caps, 'status')); return; }
  content.append(ui.loadingState(t));
  const now = Date.now();
  const window = `from=${now - 86_400_000}&to=${now}&stage=network`;
  const [policy, candidates, blocks, rules, audit, facets, series] = await Promise.all([
    settle(guard(cx, 'policy/document')), settle(guard(cx, 'candidates')), settle(guard(cx, 'blocks')), settle(guard(cx, 'rules')),
    can(caps, 'audit/query') ? settle(guard(cx, 'audit/query', { json: { limit: 5 } })) : Promise.resolve({ ok: false }),
    settle(cx.api(`/v1/observability/decisions/facets?${window}&outcome=deny`)), settle(cx.api(`/v1/observability/decisions/timeseries?${window}`)),
  ]);
  if (cx.signal.aborted) return;
  if (!policy.ok) { ui.clear(content, failure(cx, policy.error, () => cx.navigate('#network/overview?retry=' + Date.now()))); return; }
  const mode = policy.value.policy?.mode;
  const list = candidates.ok && Array.isArray(candidates.value) ? candidates.value : [];
  const active = blocks.ok && Array.isArray(blocks.value) ? blocks.value : [];
  // What enforcement would change, from Sumunjang's own evaluation of tracked addresses.
  const preview = ui.el('div', { class: 'zt-enforce-preview', attrs: { 'aria-live': 'polite' } });
  if (mode === 'observe' && list.length && can(caps, 'explain/batch')) {
    preview.append(ui.loadingState(t));
    settle(guard(cx, 'explain/batch', { json: { ips: list.slice(0, 1024).map(entry => entry.ip), candidate: { policy: { ...policy.value.policy, mode: 'enforce' } } } })).then(answer => {
      if (cx.signal.aborted) return;
      if (!answer.ok) { ui.clear(preview, ui.el('p', { class: 'kit-muted', text: t('network.overview.preview.unavailable') })); return; }
      const summary = answer.value.summary || {};
      const denied = (answer.value.results || []).filter(entry => entry.candidate?.action === 'deny');
      ui.clear(preview, ui.el('p', {}, ui.el('strong', { text: t('network.overview.preview.title') }), ' ', ui.el('span', { text: t('network.overview.preview.body', { count: number(summary.allow_to_deny ?? denied.length), total: number(summary.total ?? list.length) }) })),
        denied.length ? ui.el('ul', { class: 'zt-chips zt-preview-list' }, denied.slice(0, 8).map(entry => ui.el('a', { class: 'kit-tag', href: `#network/ip/${encodeURIComponent(entry.ip)}`, text: entry.ip }))) : null);
    });
  } else if (mode === 'observe') preview.append(ui.el('p', { class: 'kit-muted', text: t('network.overview.preview.nothing') }));
  const counts = Object.fromEntries(BLOCK_KINDS.map(kind => [kind, 0]));
  for (const block of active) counts[blockKind(block)] += 1;
  const eligible = list.filter(entry => entry.eligible).length;
  const kpis = ui.el('div', { class: 'zt-kpis' },
    kpi(cx, { label: 'network.overview.kpi.queue', value: candidates.ok ? number(eligible) : t('ui.status.unavailable'), href: '#network/threats?eligible=1', note: candidates.ok ? t('network.overview.kpi.queue.note', { count: number(list.length) }) : null, tone: eligible ? 'is-warn' : '' }),
    kpi(cx, { label: 'network.overview.kpi.blocks', value: blocks.ok ? number(active.length) : t('ui.status.unavailable'), href: '#network/blocks', note: blocks.ok ? BLOCK_KINDS.filter(kind => counts[kind]).map(kind => t('network.overview.kpi.blocks.kind', { kind: t(`network.block.kind.${kind}`), count: counts[kind] })).join(' · ') || null : null }),
    kpi(cx, { label: 'network.overview.kpi.allow', value: number((policy.value.policy?.allow || []).length), href: '#network/blocks/allowlist' }),
    kpi(cx, { label: 'network.overview.kpi.rules', value: rules.ok ? number(rules.value?.rules?.length ?? 0) : t('ui.status.unavailable'), href: '#network/rules' }),
    series.ok && series.value?.state !== 'disabled' ? trend(cx, series.value?.points || []) : kpi(cx, { label: 'network.overview.trend', value: t(series.ok ? 'system.decisions.disabled' : 'ui.status.unavailable'), href: '#system' }));
  // Top countries from Hangang's network-stage denials; top ASNs from Sumunjang evidence.
  const countries = (facets.ok ? facets.value?.facets?.country || [] : []).map(entry => ({ label: entry.value, count: number(entry.estimated_requests ?? entry.events), href: `#access/decisions?stage=network&outcome=deny&country=${encodeURIComponent(entry.value)}` }));
  const asns = new Map();
  for (const entry of list) if (Number.isFinite(entry.asn)) { const value = asns.get(entry.asn) || { ips: 0, score: 0 }; value.ips += 1; value.score += entry.score ?? 0; asns.set(entry.asn, value); }
  const asnEntries = [...asns.entries()].sort((a, b) => b[1].score - a[1].score).map(([asn, value]) => ({ label: asnText(cx, asn), count: t('network.overview.asn.count', { count: value.ips }), href: `#network/threats?asn=${asn}` }));
  const changes = audit.ok ? (audit.value?.entries || []) : [];
  const recent = panel(cx, 'network.overview.changes', changes.length ? ui.el('ul', { class: 'zt-changes' }, changes.map(entry => ui.el('li', {}, ui.el('a', { href: '#audit?source=sumunjang' },
    ui.statusBadge(t, ['committed', 'refused', 'uncertain'].includes(entry.result) ? entry.result : 'unknown', `network.outcome.${['committed', 'refused', 'uncertain'].includes(entry.result) ? entry.result : 'uncertain'}`),
    ui.el('span', { class: 'zt-change-main', text: t(`network.audit.action.${['policy.document.replace', 'policy.replace', 'blocks.add', 'blocks.remove', 'candidates.approve', 'rules.replace', 'rules.lua.replace', 'geoip.reload', 'update.check', 'kubernetes.authority.publish', 'startup.import'].includes(entry.action) ? entry.action : 'other'}`, { target: entry.target || '—' }) }),
    ui.el('span', { class: 'zt-change-time' }, ui.timeCell(t, entry.time_ms || (entry.time || 0) * 1000)))))) : ui.emptyState(t, { title: audit.ok ? 'network.overview.changes.empty' : 'network.overview.changes.unavailable' }));
  const action = ui.el('a', { class: 'button button-quiet', href: '#network/policy', text: t('network.overview.mode.change') });
  ui.clear(content, modeBanner(cx, policy.value.policy, { action }), preview, kpis, ui.el('div', { class: 'zt-grid' },
    topList(cx, { title: 'network.overview.top.countries', entries: countries, empty: facets.ok ? 'network.overview.top.empty' : 'network.overview.top.unavailable' }),
    topList(cx, { title: 'network.overview.top.asns', entries: asnEntries, empty: 'network.overview.top.empty' }),
    recent));
}
