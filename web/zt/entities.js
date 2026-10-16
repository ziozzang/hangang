// Entity routes (user, address, service), the System section and the task
// sections whose full pages arrive in later phases (ADR 0020 P1/P2).
import { decisionColumns, decisionFetcher } from './access.js';

const LINKS = Object.freeze({
  identities: [{ href: '#plugin-hopae', label: 'section.link.hopae', plugin: 'hopae' }, { href: '#users', label: 'section.link.console_accounts' }],
  policies: [{ href: '#pumgye/services', label: 'section.link.pumgye_services' }, { href: '#pumgye/resources', label: 'section.link.pumgye_resources' }, { href: '#pumgye/policy', label: 'section.link.pumgye_policy' }],
  network: [{ href: '#plugin-guard', label: 'section.link.sumunjang', plugin: 'guard' }, { href: '#security', label: 'section.link.gateway_protections' }],
  workloads: [{ href: '#http', label: 'section.link.http_routes' }, { href: '#tcp', label: 'section.link.tcp_routes' }],
});
const OPENERS = Object.freeze({
  identities: { label: 'section.open.user', route: ['users'], pattern: '.{1,1024}' },
  network: { label: 'section.open.ip', route: ['ip'], pattern: '[0-9A-Fa-f:.]{2,45}' },
  policies: { label: 'section.open.service', route: ['services'], pattern: '[A-Za-z0-9_.:-]{1,128}' },
});

function recentDecisions(cx, params, caption) {
  const { t, ui } = cx;
  const table = ui.dataTable(t, { caption, owner: 'ui.owner.exporter', columns: decisionColumns(cx), rowKey: event => event.event_id, empty: { title: 'entity.decisions.empty' }, fetchPage: decisionFetcher(cx, params, { limit: 20 }) });
  cx.signal.addEventListener('abort', () => table.destroy(), { once: true });
  const all = ui.el('a', { class: 'button button-quiet', href: cx.hashFor('access', ['decisions'], params), text: t('entity.decisions.open') });
  return { section: ui.el('section', { class: 'panel zt-panel' }, ui.el('div', { class: 'zt-panel-head' }, ui.el('h2', { text: t('entity.decisions.title') }), all), table.element), table };
}

export async function renderUser(cx, root, id) {
  const { t, ui } = cx;
  const { content, heading } = cx.page(root, { crumbs: [{ label: t('nav.identities'), href: '#identities' }, { label: t('entity.user.crumb') }, { label: id }], title: id, owner: t('entity.user.owner') });
  const summary = ui.el('div', { class: 'zt-entity-summary' }, ui.loadingState(t));
  const params = new URLSearchParams({ subject: id });
  const { section, table } = recentDecisions(cx, params, 'entity.decisions.caption');
  content.append(summary, ui.el('nav', { class: 'button-row', attrs: { 'aria-label': t('entity.user.related') } }, ui.el('a', { class: 'button button-quiet', href: '#plugin-hopae', text: t('entity.user.hopae') })), section);
  const [resolved] = await Promise.all([cx.resolver.resolve(id), table.reload()]);
  if (cx.signal.aborted) return;
  const lines = [];
  if (resolved.state === 'resolved') {
    if (resolved.display) heading.textContent = resolved.display;
    lines.push([t('entity.user.principal'), resolved.principal ? t(`decision.principal.${resolved.principal}`) : '—'], [t('entity.user.status'), resolved.status || '—'], [t('entity.user.provider'), resolved.provider || '—']);
  } else {
    lines.push([t('entity.user.resolution'), t(resolved.state === 'unknown' ? 'entity.user.unknown' : 'entity.user.unresolved')]);
  }
  ui.clear(summary, ui.el('dl', { class: 'zt-dl' }, lines.map(([key, value]) => [ui.el('dt', { text: key }), ui.el('dd', { text: value })])),
    ui.el('p', { class: 'kit-muted' }, ui.el('span', { text: t('entity.user.id') }), ' ', ui.el('code', { text: id }), ui.copyButton(t, id)),
    ui.el('p', { class: 'kit-muted', text: t('entity.user.forward_lookup') }));
}

export async function renderIp(cx, root, ip) {
  const { t, ui } = cx;
  const { content } = cx.page(root, { crumbs: [{ label: t('nav.network'), href: '#network' }, { label: t('entity.ip.crumb') }, { label: ip }], title: ip, owner: t('entity.ip.owner') });
  if (!/^[0-9A-Fa-f:.]{2,45}$/.test(ip)) { content.append(ui.emptyState(t, { title: 'entity.ip.invalid.title', body: 'entity.ip.invalid.body' })); return; }
  const geo = ui.el('div', { class: 'zt-entity-summary' }, ui.loadingState(t));
  const { section, table } = recentDecisions(cx, new URLSearchParams({ ip }), 'entity.decisions.caption');
  content.append(geo, ui.el('nav', { class: 'button-row', attrs: { 'aria-label': t('entity.ip.related') } }, ui.el('a', { class: 'button button-quiet', href: '#plugin-guard', text: t('entity.ip.sumunjang') })), section);
  const [lookup] = await Promise.allSettled([cx.api(`/v1/geoip/lookup?ip=${encodeURIComponent(ip)}`), table.reload()]);
  if (cx.signal.aborted) return;
  if (lookup.status === 'fulfilled') {
    const data = lookup.value.data || {};
    const country = data.country ?? data.country_code ?? null;
    ui.clear(geo, ui.el('dl', { class: 'zt-dl' }, ui.el('dt', { text: t('entity.ip.country') }), ui.el('dd', { text: country || t('entity.ip.country.unknown') })));
  } else ui.clear(geo, ui.errorState(t, { owner: 'ui.owner.host', message: lookup.reason?.message }));
}

export async function renderService(cx, root, id) {
  const { t, ui } = cx;
  const { content } = cx.page(root, { crumbs: [{ label: t('nav.policies'), href: '#policies' }, { label: t('entity.service.crumb') }, { label: id }], title: id, owner: t('entity.service.owner') });
  const { section, table } = recentDecisions(cx, new URLSearchParams({ service: id }), 'entity.decisions.caption');
  content.append(ui.el('nav', { class: 'button-row', attrs: { 'aria-label': t('entity.service.related') } }, ui.el('a', { class: 'button button-quiet', href: '#pumgye/services', text: t('entity.service.pumgye') })), section);
  await table.reload();
}

/** Sections whose dedicated pages are later phases: entity search and links. */
export async function renderSection(cx, root, name) {
  const { t, ui } = cx;
  const { content } = cx.page(root, { crumbs: [{ label: t(`nav.${name}`) }], title: t(`nav.${name}`), owner: t(`section.${name}.owner`) });
  content.append(ui.emptyState(t, { title: `section.${name}.planned`, body: `section.${name}.body` }));
  const opener = OPENERS[name];
  if (opener) {
    const form = ui.el('form', { class: 'zt-search', attrs: { role: 'search' } });
    const control = ui.field(t, { label: opener.label, name: 'id', pattern: opener.pattern, maxLength: 1024 });
    form.append(control, ui.el('button', { type: 'submit', class: 'button', text: t('section.open') }));
    form.addEventListener('submit', event => { event.preventDefault(); if (!form.reportValidity()) return; const value = form.elements.id.value.trim(); if (value) cx.navigate(cx.hashFor(name, [...opener.route, value])); });
    content.append(form);
  }
  let installed = new Set();
  try { installed = new Set(((await cx.api('/v1/plugins')).data?.plugins || []).map(plugin => plugin.id)); } catch (error) { if (error?.status === 401) throw error; }
  if (cx.signal.aborted) return;
  const links = (LINKS[name] || []).filter(link => !link.plugin || installed.has(link.plugin));
  if (links.length) content.append(ui.el('nav', { class: 'zt-links', attrs: { 'aria-label': t('section.links') } }, ui.el('h2', { text: t('section.links') }), ui.el('ul', {}, links.map(link => ui.el('li', {}, ui.el('a', { href: link.href, text: t(link.label) }))))));
}

function definition(cx, entries) {
  const { t, ui } = cx;
  return ui.el('dl', { class: 'zt-dl' }, entries.map(([key, value]) => [ui.el('dt', { text: t(key) }), ui.el('dd', {}, value instanceof Node ? value : String(value ?? '—'))]));
}

/** Components, decision events/exporter and privacy profile. Raw JSON only here. */
export async function renderSystem(cx, root) {
  const { t, ui } = cx;
  const { content } = cx.page(root, { crumbs: [{ label: t('nav.system') }], title: t('nav.system'), owner: t('system.owner') });
  const [status, observability, plugins] = await Promise.allSettled([cx.api('/v1/status'), cx.api('/v1/observability/status'), cx.api('/v1/plugins')]);
  for (const result of [status, observability, plugins]) if (result.status === 'rejected' && result.reason?.status === 401) throw result.reason;
  if (cx.signal.aborted) return;
  const components = ui.el('section', { class: 'panel zt-panel' }, ui.el('h2', { text: t('system.components') }));
  if (status.status === 'fulfilled') components.append(definition(cx, [['system.hangang.revision', status.value.data?.revision], ['system.hangang.version', status.value.data?.version]]));
  else components.append(ui.errorState(t, { owner: 'ui.owner.host', message: status.reason?.message }));
  if (plugins.status === 'fulfilled') {
    const list = plugins.value.data?.plugins || [];
    components.append(ui.el('h3', { text: t('system.packages') }), list.length ? ui.el('ul', { class: 'zt-packages' }, list.map(plugin => ui.el('li', {}, ui.el('strong', { text: plugin.name || plugin.id }), ' ', ui.el('span', { class: 'kit-mono', text: [plugin.id, plugin.version].filter(Boolean).join(' ') })))) : ui.el('p', { class: 'kit-muted', text: t('system.packages.none') }));
  }
  const decisions = ui.el('section', { class: 'panel zt-panel' }, ui.el('h2', { text: t('system.decisions') }));
  if (observability.status === 'fulfilled') {
    const data = observability.value.data || {};
    if (data.state === 'disabled') decisions.append(ui.statusBadge(t, 'disabled', 'system.decisions.disabled'), ui.el('p', { class: 'kit-muted', text: t('system.decisions.disabled.help') }));
    else {
      const dropped = Object.entries(data.counters?.dropped || {}).map(([reason, count]) => `${t(`system.drop.${reason}`)} ${count}`).join(' · ');
      decisions.append(definition(cx, [
        ['system.profile', t(`system.profile.${data.profile}`)],
        ['system.exporter', ui.statusBadge(t, data.exporter?.connected ? 'healthy' : 'unavailable')],
        ['system.rings', t('system.rings.value', { queued: data.rings?.queued ?? 0, deny: data.rings?.deny_slots ?? 0, allow: data.rings?.allow_slots ?? 0 })],
        ['system.dropped', dropped || '0'],
        ['system.keys', t('system.keys.value', { epoch: data.keys?.current_epoch ?? '—', count: data.keys?.epochs ?? 0 })],
        ['system.store', data.store?.state === 'unavailable' ? ui.statusBadge(t, 'unavailable') : t('system.store.value', { rows: data.store?.rows ?? 0 })],
      ]));
    }
  } else decisions.append(ui.errorState(t, { owner: 'ui.owner.exporter', message: observability.reason?.message }));
  const raw = ui.el('details', { class: 'panel zt-raw' }, ui.el('summary', { text: t('system.raw') }),
    ui.el('pre', { class: 'kit-mono', text: JSON.stringify({ status: status.value?.data ?? null, observability: observability.value?.data ?? null }, null, 2) }));
  content.append(components, decisions, raw);
}
