// Overview: authority health, decision KPIs and top lists. Every tile links to
// the pre-filtered list that produced it; failed sources render as
// unavailable, never as zero. Refreshes every 30 s while visible.
import { loadAuditRecords } from './audit.js';

const WINDOWS = Object.freeze({ '1h': 3_600_000, '24h': 86_400_000, '7d': 7 * 86_400_000 });
const REFRESH_MS = 30_000;

async function settle(promise) { try { return { ok: true, value: (await promise).data }; } catch (error) { if (error?.status === 401) throw error; return { ok: false, error }; } }

function card(cx, { label, owner, kind, lines = [], href }) {
  const { t, ui } = cx;
  const body = ui.el(href ? 'a' : 'div', { class: 'zt-card', href: href || undefined },
    ui.el('div', { class: 'zt-card-head' }, ui.el('strong', { text: t(label) }), ui.statusBadge(t, kind)),
    ui.el('small', { class: 'kit-muted', text: t('ui.entity.owner', { owner: t(owner) }) }),
    lines.map(line => ui.el('span', { class: 'zt-card-line' }, line)));
  return body;
}

function counts(facets, name) {
  const map = new Map();
  for (const entry of facets?.facets?.[name] || []) map.set(entry.value, entry);
  return map;
}

function topList(cx, { title, entries, href, render }) {
  const { t, ui } = cx;
  const list = ui.el('ol', { class: 'zt-top' });
  for (const entry of entries.slice(0, 5)) {
    list.append(ui.el('li', {}, ui.el('a', { href: href(entry) }, ui.el('span', { class: 'zt-top-label' }, render(entry)), ui.el('span', { class: 'zt-top-count', text: new Intl.NumberFormat(document.documentElement.lang || undefined).format(entry.estimated_requests ?? entry.events) }))));
  }
  return ui.el('section', { class: 'panel zt-panel' }, ui.el('h2', { text: t(title) }), entries.length ? list : ui.emptyState(t, { title: 'overview.top.empty' }));
}

/** Deny-rate sparkline with a textual summary; the decision log is its table alternative. */
function sparkline(cx, points, href) {
  const { t, ui } = cx;
  const buckets = new Map();
  for (const point of points) {
    const entry = buckets.get(point.start_ms) || { total: 0, deny: 0 };
    entry.total += point.estimated_requests ?? point.events ?? 0;
    if (point.outcome === 'deny') entry.deny += point.estimated_requests ?? point.events ?? 0;
    buckets.set(point.start_ms, entry);
  }
  const series = [...buckets.entries()].sort((a, b) => a[0] - b[0]).map(([, entry]) => entry.total ? entry.deny / entry.total : 0);
  const peak = series.length ? Math.max(...series) : 0;
  const summary = t('overview.sparkline.summary', { count: series.length, peak: new Intl.NumberFormat(document.documentElement.lang || undefined, { style: 'percent', maximumFractionDigits: 1 }).format(peak) });
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', '0 0 100 24'); svg.setAttribute('preserveAspectRatio', 'none'); svg.setAttribute('aria-hidden', 'true'); svg.classList.add('zt-sparkline');
  if (series.length > 1) {
    const line = document.createElementNS(ns, 'polyline');
    line.setAttribute('points', series.map((value, index) => `${(index / (series.length - 1)) * 100},${22 - (peak ? value / peak : 0) * 20}`).join(' '));
    svg.append(line);
  }
  return ui.el('a', { class: 'zt-kpi zt-kpi-wide', href }, ui.el('span', { class: 'zt-kpi-label', text: t('overview.sparkline') }), svg, ui.el('small', { class: 'kit-muted', text: series.length ? summary : t('overview.top.empty') }));
}

export async function renderOverview(cx, root) {
  const { t, ui } = cx;
  const windowSelect = ui.field(t, { label: 'overview.window', name: 'window', value: cx.parse().params.get('window') || '24h', options: Object.keys(WINDOWS).map(value => ({ value, label: `access.range.${value}` })) });
  const refreshed = ui.el('span', { class: 'kit-muted', attrs: { 'aria-live': 'polite' } });
  const { content } = cx.page(root, { crumbs: [{ label: t('nav.overview') }], title: t('nav.overview'), owner: t('overview.owner'), actions: [windowSelect, refreshed] });
  windowSelect.querySelector('select').addEventListener('change', event => {
    const params = new URLSearchParams(); if (event.target.value !== '24h') params.set('window', event.target.value);
    cx.navigate(cx.hashFor('overview', [], params));
  });
  const range = cx.parse().params.get('window') || '24h';
  const span = WINDOWS[range] ?? WINDOWS['24h'];
  const filtered = extra => { const params = new URLSearchParams({ range: range === '1h' || range === '7d' ? range : '24h', ...extra }); if (params.get('range') === '24h') params.delete('range'); return cx.hashFor('access', ['decisions'], params); };

  async function draw() {
    const now = Date.now();
    const window = `from=${now - span}&to=${now}`;
    const [status, observability, pumgye, plugins, all, denies, series, audit] = await Promise.all([
      settle(cx.api('/v1/status')), settle(cx.api('/v1/observability/status')), settle(cx.api('/v1/pumgye/status')), settle(cx.api('/v1/plugins')),
      settle(cx.api(`/v1/observability/decisions/facets?${window}`)), settle(cx.api(`/v1/observability/decisions/facets?${window}&outcome=deny`)),
      settle(cx.api(`/v1/observability/decisions/timeseries?${window}`)),
      loadAuditRecords(cx).catch(() => ({ records: [], failures: [] })),
    ]);
    if (cx.signal.aborted) return;
    const installed = new Set((plugins.ok ? plugins.value?.plugins || [] : []).map(plugin => plugin.id));
    const pluginCard = async (id, label, owner) => {
      if (!plugins.ok) return card(cx, { label, owner, kind: 'unavailable', lines: [t('overview.source.unavailable')] });
      if (!installed.has(id)) return card(cx, { label, owner, kind: 'disabled', lines: [t('overview.plugin.missing')] });
      const health = await settle(cx.api(`/v1/plugins/${id}/status`));
      return card(cx, { label, owner, kind: health.ok ? 'healthy' : 'unavailable', href: `#plugin-${id}`, lines: [health.ok ? t('overview.plugin.reachable') : t('overview.source.unavailable')] });
    };
    const exporter = observability.ok ? observability.value : null;
    const exporterCard = !observability.ok ? card(cx, { label: 'overview.card.exporter', owner: 'ui.owner.exporter', kind: 'unavailable', lines: [t('overview.source.unavailable')], href: '#system' })
      : exporter.state === 'disabled' ? card(cx, { label: 'overview.card.exporter', owner: 'ui.owner.exporter', kind: 'disabled', lines: [t('overview.exporter.disabled')], href: '#system' })
      : card(cx, { label: 'overview.card.exporter', owner: 'ui.owner.exporter', kind: exporter.exporter?.connected ? 'healthy' : 'unavailable', href: '#system', lines: [
        t('overview.exporter.drops', { count: Object.values(exporter.counters?.dropped || {}).reduce((sum, value) => sum + (Number(value) || 0), 0) }),
        t('overview.exporter.profile', { profile: t(`system.profile.${exporter.profile}`) }),
        exporter.store?.newest_event_ms ? ui.freshnessBadge(t, exporter.store.newest_event_ms, 5 * 60_000) : ui.freshnessBadge(t, 0)] });
    const health = ui.el('div', { class: 'zt-cards', attrs: { 'aria-label': t('overview.health') } },
      card(cx, { label: 'overview.card.hangang', owner: 'ui.owner.host', kind: status.ok ? 'healthy' : 'unavailable', href: '#system', lines: status.ok ? [t('ui.revision', { revision: status.value?.revision ?? '—' })] : [t('overview.source.unavailable')] }),
      await pluginCard('hopae', 'overview.card.hopae', 'ui.owner.hopae'),
      await pluginCard('guard', 'overview.card.sumunjang', 'ui.owner.sumunjang'),
      card(cx, { label: 'overview.card.pumgye', owner: 'ui.owner.pumgye', kind: pumgye.ok ? 'healthy' : 'unavailable', href: '#pumgye', lines: pumgye.ok ? [t('ui.revision', { revision: pumgye.value?.revision ?? pumgye.value?.policy_revision ?? '—' })] : [t('overview.source.unavailable')] }),
      exporterCard);
    if (cx.signal.aborted) return;
    const kpis = ui.el('section', { class: 'zt-kpis', attrs: { 'aria-label': t('overview.kpis') } });
    const disabled = exporter?.state === 'disabled';
    if (!all.ok || disabled) {
      kpis.append(disabled ? ui.emptyState(t, { title: 'access.disabled.title', body: 'access.disabled.body', action: ui.el('a', { class: 'button', href: '#system', text: t('access.disabled.action') }) }) : ui.errorState(t, { owner: 'ui.owner.exporter', message: all.error?.message, retry: () => draw() }));
    } else {
      const outcomes = counts(all.value, 'outcome');
      const value = name => outcomes.get(name)?.estimated_requests ?? 0;
      const total = ['allow', 'deny', 'challenge', 'error', 'unavailable'].reduce((sum, name) => sum + value(name), 0);
      const tile = (label, number, extra, href) => ui.el('a', { class: 'zt-kpi', href }, ui.el('span', { class: 'zt-kpi-label', text: t(label) }), ui.el('strong', { class: 'zt-kpi-value', text: number }), ui.el('small', { class: 'kit-muted', text: extra }));
      const percent = part => total ? new Intl.NumberFormat(document.documentElement.lang || undefined, { style: 'percent', maximumFractionDigits: 1 }).format(part / total) : '—';
      const number = n => new Intl.NumberFormat(document.documentElement.lang || undefined).format(n);
      const source = t('overview.kpi.source', { window: t(`access.range.${range}`) });
      kpis.append(
        tile('overview.kpi.decisions', number(total), t('overview.kpi.estimate'), filtered({})),
        tile('overview.kpi.denied', percent(value('deny')), source, filtered({ outcome: 'deny' })),
        tile('overview.kpi.challenged', percent(value('challenge')), source, filtered({ outcome: 'challenge' })),
        tile('overview.kpi.unavailable', number(value('unavailable')), source, filtered({ outcome: 'unavailable' })));
    }
    if (series.ok && !disabled) kpis.append(sparkline(cx, series.value?.points || [], filtered({ outcome: 'deny' })));
    const lists = ui.el('div', { class: 'zt-grid' });
    if (denies.ok && !disabled) {
      lists.append(
        topList(cx, { title: 'overview.top.reasons', entries: denies.value?.facets?.reason || [], href: entry => filtered({ outcome: 'deny', reason: entry.value }), render: entry => ui.reasonText(t, entry.value) }),
        topList(cx, { title: 'overview.top.routes', entries: denies.value?.facets?.route || [], href: entry => filtered({ outcome: 'deny', route: entry.value }), render: entry => entry.value }),
        topList(cx, { title: 'overview.top.countries', entries: denies.value?.facets?.country || [], href: entry => filtered({ outcome: 'deny', country: entry.value }), render: entry => entry.value }));
    }
    const recent = ui.el('section', { class: 'panel zt-panel' }, ui.el('h2', { text: t('overview.changes') }));
    const records = audit.records.slice(0, 5);
    if (records.length) recent.append(ui.el('ol', { class: 'zt-top' }, records.map(record => ui.el('li', {}, ui.el('a', { href: '#audit' }, ui.el('span', { class: 'zt-top-label', text: `${t(`audit.source.${record.source}`)} · ${record.actor} · ${record.action}` }), ui.el('span', { class: 'kit-muted', text: new Intl.DateTimeFormat(document.documentElement.lang || undefined, { timeStyle: 'short', dateStyle: 'short' }).format(record.time) }))))));
    else recent.append(ui.emptyState(t, { title: 'overview.changes.empty' }));
    if (audit.failures?.length) recent.append(ui.el('p', { class: 'zt-banner', text: t('audit.partial', { sources: audit.failures.map(source => t(`audit.source.${source}`)).join(', ') }) }));
    lists.append(recent);
    ui.clear(content, health, kpis, lists);
    refreshed.textContent = t('overview.refreshed', { time: new Intl.DateTimeFormat(document.documentElement.lang || undefined, { timeStyle: 'medium' }).format(new Date()) });
  }
  await draw();
  const timer = setInterval(() => { if (!document.hidden && !cx.signal.aborted) draw().catch(() => {}); }, REFRESH_MS);
  cx.signal.addEventListener('abort', () => clearInterval(timer), { once: true });
}
