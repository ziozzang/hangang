// Zero Trust task sections (ADR 0020 P0): routing, page skeleton and section
// lifecycle. Pages render through the shared kit with key-based messages.
import { ui } from '../kit/ui.js';
import { createTranslator, loadCatalogs } from '../kit/i18n.js';
import { getLocale } from '../i18n.js';
import { renderOverview } from './overview.js';
import { renderDecisionLog, renderRequest } from './access.js';
import { renderAudit } from './audit.js';
import { renderSection, renderSystem } from './entities.js';
import { renderIdentities } from './identities/index.js';
import { renderPolicies, resetPolicies } from './policies/index.js';
import { renderNetwork } from './network/index.js';
import { renderWorkloadsSection } from './workloads/index.js';

export const t = createTranslator(getLocale);
export const SECTIONS = Object.freeze(['overview', 'access', 'identities', 'policies', 'network', 'workloads', 'audit', 'system']);
const SECTION_KEYS = Object.freeze({ overview: 'nav.overview', access: 'nav.access', identities: 'nav.identities', policies: 'nav.policies', network: 'nav.network', workloads: 'nav.workloads', audit: 'nav.audit', system: 'nav.system' });

let catalogs = null, generation = 0, active = null, host = null, resolver = null;

export function ztView(name) { return SECTIONS.includes(name); }
export function ztLabel(name) { return t(SECTION_KEYS[name]); }

/** Parses `#section/a/b?x=1` into parts and query parameters. */
export function parseHash(hash = location.hash) {
  const raw = hash.replace(/^#/, '');
  const [path, query = ''] = raw.split('?');
  const parts = path.split('/').map(part => { try { return decodeURIComponent(part); } catch { return null; } });
  return { section: parts[0], parts: parts.slice(1), params: new URLSearchParams(query), valid: !parts.includes(null) };
}

export function hashFor(section, parts = [], params) {
  const path = [section, ...parts.map(encodeURIComponent)].join('/');
  const query = params && [...params.keys()].length ? `?${params.toString()}` : '';
  return `#${path}${query}`;
}

/** Validated canonical hash for a section route, or null to fall back. */
export function canonicalHash(hash) {
  const parsed = parseHash(hash);
  if (!parsed.valid || !ztView(parsed.section)) return null;
  return hash;
}

async function ensureCatalogs() {
  if (!catalogs) catalogs = Promise.all([loadCatalogs('/ui/zt/messages'), loadCatalogs('/ui/zt/identities/messages'), loadCatalogs('/ui/zt/network/messages'), loadCatalogs('/ui/zt/workloads/messages')]).catch(error => { catalogs = null; throw error; });
  return catalogs;
}

/** Loads catalogs once (public assets) and localizes the section navigation. */
export async function prepareZeroTrust() {
  try { await ensureCatalogs(); relabelNavigation(); } catch { /* Sections show the error when opened. */ }
}

export function relabelNavigation() {
  document.querySelectorAll('[data-zt-label]').forEach(node => { node.textContent = t(node.dataset.ztLabel); });
}

/** Common page skeleton: breadcrumb, title, owner line, actions, content. */
export function page(root, { crumbs = [], title, owner, actions = [] }) {
  const breadcrumb = ui.el('nav', { class: 'zt-crumbs', attrs: { 'aria-label': t('ui.breadcrumb') } });
  const list = ui.el('ol');
  for (const crumb of crumbs) list.append(ui.el('li', {}, crumb.href ? ui.el('a', { href: crumb.href, text: crumb.label }) : ui.el('span', { text: crumb.label, attrs: { 'aria-current': 'page' } })));
  breadcrumb.append(list);
  const heading = ui.el('h1', { class: 'zt-title', text: title, tabIndex: -1 });
  const head = ui.el('header', { class: 'zt-head' }, breadcrumb, ui.el('div', { class: 'zt-head-row' }, ui.el('div', {}, heading, owner ? ui.el('p', { class: 'zt-owner', text: owner }) : null), ui.el('div', { class: 'button-row zt-actions' }, actions)));
  const content = ui.el('div', { class: 'zt-content' });
  ui.clear(root, head, content);
  return { content, heading };
}

function context(signal, name) {
  return Object.freeze({ t, ui, signal, api: (path, options = {}) => host.api(path, { ...options, signal }), navigate: hash => { if (location.hash === hash) loadZeroTrust(name, host); else location.hash = hash; }, reload: () => loadZeroTrust(name, host), resolver, parse: parseHash, hashFor, page });
}

/** Renders the section for the current hash. Superseded renders abort. */
export async function loadZeroTrust(name, hostContext) {
  host = hostContext;
  resolver ??= ui.subjectResolver((path, options) => host.api(path, options));
  const epoch = ++generation;
  active?.abort();
  const controller = new AbortController();
  active = controller;
  const root = document.querySelector(`#view-${name} .zt-root`);
  if (!root) return;
  ui.clear(root, ui.loadingState(t));
  try { await ensureCatalogs(); }
  catch (error) { if (epoch === generation) ui.clear(root, ui.errorState(t, { owner: 'ui.owner.host', message: error.message, retry: () => loadZeroTrust(name, host) })); return; }
  if (epoch !== generation) return;
  relabelNavigation();
  const route = parseHash();
  const cx = context(controller.signal, name);
  try {
    if (name === 'overview') await renderOverview(cx, root);
    else if (name === 'access' && route.parts[0] === 'requests' && route.parts[1]) await renderRequest(cx, root, route.parts[1]);
    else if (name === 'access') await renderDecisionLog(cx, root, route.params);
    else if (name === 'identities') await renderIdentities(cx, root, route);
    else if (name === 'network') await renderNetwork(cx, root, route);
    else if (name === 'policies') await renderPolicies(cx, root, route);
    else if (name === 'workloads') await renderWorkloadsSection(cx, root, route);
    else if (name === 'audit') await renderAudit(cx, root, route.params);
    else if (name === 'system') await renderSystem(cx, root);
    else await renderSection(cx, root, name);
  } catch (error) {
    if (controller.signal.aborted || epoch !== generation) return;
    if (error?.status === 401) throw error;
    ui.clear(root, ui.errorState(t, { owner: 'ui.owner.host', message: error.message, retry: () => loadZeroTrust(name, host) }));
  }
}

export function pauseZeroTrust() { generation += 1; active?.abort(); active = null; }

export function resetZeroTrust() {
  pauseZeroTrust(); host = null; resolver = null; resetPolicies();
  document.querySelectorAll('.zt-root').forEach(root => root.replaceChildren());
}

window.addEventListener('hangang:localechange', () => {
  if (!catalogs) return;
  relabelNavigation();
  const { section } = parseHash();
  if (host && ztView(section) && !document.querySelector(`#view-${section}`)?.hidden) loadZeroTrust(section, host);
});
