// Network section (ADR 0020 §5): shared helpers. Every call goes through the
// Sumunjang console package broker (`/v1/plugins/guard/<route>`); nothing here
// talks to Sumunjang directly.
const BASE = '/v1/plugins/guard/';
const GET_ROUTES = new Set(['status', 'policy/document', 'candidates', 'blocks', 'rules', 'update/status', 'audit', 'reasons', 'kubernetes/authority', 'kubernetes/status', 'rules/document', 'allowlist']);
export const PAGES = Object.freeze(['overview', 'threats', 'blocks', 'rules', 'policy', 'asn']);
const PAGE_ICONS = Object.freeze({ overview: '◍', threats: '⚠', blocks: '⛔', rules: '▤', policy: '⚙', asn: '⌘' });

/** Installed Sumunjang package and its declared routes (`path:METHOD`). */
export async function capabilities(cx) {
  let plugins = [];
  try { plugins = (await cx.api('/v1/plugins')).data?.plugins || []; }
  catch (error) { if (error?.status === 401) throw error; return { installed: false, failed: true, routes: null }; }
  const guard = plugins.find(plugin => plugin.id === 'guard');
  if (!guard) return { installed: false, failed: false, routes: null };
  const routes = Array.isArray(guard.routes) ? new Set(guard.routes.map(route => `${route.path}:${route.method}`)) : null;
  return { installed: true, failed: false, routes, version: guard.version || null };
}

export function can(caps, route, method) {
  if (!caps?.installed) return false;
  return !caps.routes || caps.routes.has(`${route}:${method || (GET_ROUTES.has(route) ? 'GET' : 'POST')}`);
}

/**
 * One broker call. `reason` travels in the host-only `x-hangang-change-reason`
 * header into the private operation journal; Sumunjang's bodies are unchanged.
 */
export async function guard(cx, route, { json, method, reason } = {}) {
  const headers = reason ? { 'x-hangang-change-reason': encodeURIComponent(reason) } : undefined;
  const verb = method || (GET_ROUTES.has(route) && json === undefined ? 'GET' : 'POST');
  const options = verb === 'GET' ? { headers } : { method: verb, json: json ?? {}, headers };
  const { data, response } = await cx.api(`${BASE}${route}`, options);
  return { data, operation: response?.headers?.get?.('x-hangang-plugin-operation') || null };
}

/** Localized sentence for a failed broker call; JSON-pointer errors are listed by path. */
export function errorText(t, error) {
  const status = error?.status ?? 0;
  const payload = error?.payload && typeof error.payload === 'object' ? error.payload : {};
  const detail = String(payload.detail || payload.error || error?.message || '');
  if (status === 404 && /unknown plugin$/.test(detail)) return t('network.error.not_installed');
  if (status === 404 && /not registered/.test(detail)) return t('network.error.not_declared');
  if (/uncertain/.test(detail)) return t('network.error.uncertain');
  if (status === 409 && /Kubernetes/.test(detail)) return t('network.error.kubernetes_owner');
  if (status === 409) return t('network.error.conflict');
  if (status === 400 && Array.isArray(payload.errors) && payload.errors.length) return t('network.error.invalid_fields', { count: payload.errors.length });
  if (status === 400 && /change reason/.test(detail)) return t('network.error.reason');
  if (status === 400) return t('network.error.invalid');
  if (status === 429 || (status === 503 && /capacity/.test(detail))) return t('network.error.busy');
  if (status === 502 || status === 503 || status === 0) return t('network.error.unavailable');
  if (status === 403) return t('network.error.forbidden');
  return t('network.error.generic', { status });
}

export function isUncertain(error) { return /uncertain/.test(String(error?.payload?.detail || error?.payload?.error || error?.message || '')); }

/** Field errors (JSON Pointer paths) returned by Sumunjang validation. */
export function fieldErrors(cx, error) {
  const list = Array.isArray(error?.payload?.errors) ? error.payload.errors : [];
  if (!list.length) return null;
  return cx.ui.el('ul', { class: 'zt-field-errors' }, list.slice(0, 20).map(entry => cx.ui.el('li', {}, cx.ui.el('code', { class: 'kit-mono', text: String(entry.path || '/') }), ' ', cx.ui.el('span', { text: String(entry.message || '') }))));
}

export function failure(cx, error, retry) {
  if (error?.status === 401) throw error;
  return cx.ui.errorState(cx.t, { owner: 'ui.owner.sumunjang', message: errorText(cx.t, error), retry });
}

export function notConnected(cx, caps, route) {
  const { t, ui } = cx;
  if (!caps.installed) return ui.emptyState(t, { title: caps.failed ? 'network.state.discovery_failed' : 'network.state.not_installed', body: 'network.state.not_installed.body' });
  return ui.emptyState(t, { title: 'network.state.not_declared', body: 'network.state.not_declared.body', action: ui.el('code', { class: 'kit-mono', text: route }) });
}

/** Section page with the Network sub-navigation and the mode banner slot. */
export function sectionPage(cx, root, { active, crumbs = [], title, owner, actions = [] }) {
  const { t, ui } = cx;
  const view = cx.page(root, { crumbs: [{ label: t('nav.network'), href: '#network' }, ...crumbs], title, owner, actions });
  const nav = ui.el('nav', { class: 'zt-subnav', attrs: { 'aria-label': t('network.subnav') } });
  const list = ui.el('ul');
  for (const name of PAGES) {
    const link = ui.el('a', { href: `#network/${name}`, dataset: { page: name } }, ui.el('span', { class: 'zt-subnav-icon', text: PAGE_ICONS[name], attrs: { 'aria-hidden': 'true' } }), ui.el('span', { text: t(`network.page.${name}`) }));
    if (name === active) link.setAttribute('aria-current', 'page');
    list.append(ui.el('li', {}, link));
  }
  nav.append(list);
  view.content.before(nav);
  return view;
}

/** Observe/enforce banner: observe never blocks, so it must be unmistakable. */
export function modeBanner(cx, policy, { action } = {}) {
  const { t, ui } = cx;
  const mode = policy?.mode === 'enforce' ? 'enforce' : policy?.mode === 'observe' ? 'observe' : 'unknown';
  return ui.el('div', { class: `zt-mode zt-mode-${mode}`, attrs: { role: 'status' }, dataset: { mode } },
    ui.el('span', { class: 'zt-mode-glyph', text: mode === 'enforce' ? '⛨' : mode === 'observe' ? '◎' : '?', attrs: { 'aria-hidden': 'true' } }),
    ui.el('div', { class: 'zt-stack' }, ui.el('strong', { text: t(`network.mode.${mode}`) }), ui.el('span', { text: t(`network.mode.${mode}.body`) })),
    action || null);
}

export function toMs(value) { return Number.isFinite(value) && value > 0 ? (value > 1e12 ? value : value * 1000) : null; }

export function timeOrDash(cx, value) {
  const ms = toMs(value);
  return ms ? cx.ui.timeCell(cx.t, ms) : cx.ui.el('span', { class: 'kit-muted', text: cx.t('network.none') });
}

/** "in 12 min" / "expired" countdown with the absolute time in the tooltip. */
export function expiry(cx, expiresAt, now = Date.now()) {
  const { t, ui } = cx;
  const ms = toMs(expiresAt);
  if (!ms) return ui.el('span', { class: 'kit-muted', text: t('network.expiry.never') });
  const left = ms - now;
  const minutes = Math.max(1, Math.round(left / 60_000)), hours = Math.round(minutes / 60), days = Math.round(hours / 24);
  const label = left <= 0 ? t('network.expiry.expired') : minutes < 120 ? t('network.expiry.minutes', { count: minutes }) : hours < 48 ? t('network.expiry.hours', { count: hours }) : t('network.expiry.days', { count: days });
  return ui.el('time', { class: `zt-expiry${left <= 0 ? ' is-expired' : left < 5 * 60_000 ? ' is-soon' : ''}`, dateTime: new Date(ms).toISOString(), title: ui.formatFullTime(ms), text: label });
}

const SUSPICION = Object.freeze({ normal: 'healthy', watch: 'pending', suspicious: 'challenge', high: 'deny', blocked: 'deny' });
export const SUSPICIONS = Object.freeze(Object.keys(SUSPICION));
export function suspicionBadge(cx, value) {
  const safe = Object.hasOwn(SUSPICION, value) ? value : 'normal';
  return cx.ui.statusBadge(cx.t, SUSPICION[safe], `network.suspicion.${safe}`);
}

/** Address link to the IP detail page. */
export function ipLink(cx, ip) {
  if (!ip) return cx.ui.el('span', { class: 'kit-muted', text: cx.t('network.none') });
  return cx.ui.el('a', { class: 'kit-mono zt-ip', href: `#network/ip/${encodeURIComponent(ip)}`, text: ip });
}

/** Network (CIDR) link: a host route opens the IP page. */
export function networkLink(cx, network) {
  const host = /^(.+)\/(32|128)$/.exec(network || '');
  return host ? ipLink(cx, host[1]) : cx.ui.el('code', { class: 'kit-mono', text: network || '—' });
}

export function asnText(cx, asn) {
  return Number.isFinite(asn) ? cx.t('network.asn', { asn }) : cx.t('network.asn.unknown');
}

/** Block origin from Sumunjang's reason text (core constants). */
/** Block origin as recorded by Sumunjang (`source`); blocks from before provenance are unknown. */
export const BLOCK_KINDS = Object.freeze(['manual', 'approved', 'automatic', 'kubernetes', 'unknown']);
export function blockKind(block) {
  const source = block?.source === 'auto' ? 'automatic' : block?.source;
  return BLOCK_KINDS.includes(source) ? source : 'unknown';
}

/** Address families: the exact host network of an IP. */
export function exactNetwork(ip) { return `${ip}/${ip.includes(':') ? 128 : 32}`; }

/** Actor label for Sumunjang provenance (`admin-credential` is the shared credential). */
export function actorText(cx, value) {
  if (!value) return cx.t('network.actor.unknown');
  if (value === 'admin-credential') return cx.t('network.actor.credential');
  if (value === 'system') return cx.t('network.actor.system');
  return value;
}

export const SIGNAL_KINDS = Object.freeze(['honeypot', 'scanner', 'auth_failure', 'invalid_request']);
/** Per-signal counts as compact chips; zero counts are omitted. */
export function signalChips(cx, signals) {
  const { t, ui } = cx;
  const entries = SIGNAL_KINDS.filter(kind => Number(signals?.[kind]) > 0);
  if (!entries.length) return ui.el('span', { class: 'kit-muted', text: t('network.signals.none') });
  return ui.el('span', { class: 'zt-chips zt-signals' }, entries.map(kind => ui.el('span', { class: `kit-tag zt-signal zt-signal-${kind}`, title: t(`network.signal.${kind}`), text: t('network.signal.count', { name: t(`network.signal.${kind}.short`), count: signals[kind] }) })));
}

export const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
export function isIp(value) { return IPV4.test(value) || (value.includes(':') && /^[0-9A-Fa-f:.]{2,45}$/.test(value) && !/:::/.test(value)); }
/** Canonical-looking CIDR: an IP plus a prefix within the family's width. */
export function isCidr(value) {
  const match = /^([^/]+)\/(\d{1,3})$/.exec(value || '');
  if (!match || !isIp(match[1])) return false;
  return Number(match[2]) <= (IPV4.test(match[1]) ? 32 : 128);
}
export function hostNetwork(value) { return value.includes('/') ? value : `${value}/${IPV4.test(value) ? 32 : 128}`; }

/** Modal form for writes: fields, optional typed confirmation and a required reason. */
export function formDialog(cx, { title, intro, body, fields = [], confirm, confirmLabel = 'ui.confirm.action', danger = false, reason = true, submit }) {
  const { t, ui } = cx;
  return new Promise(resolve => {
    const form = ui.el('form', { class: 'kit-confirm zt-form-dialog' });
    const status = ui.el('div', { class: 'zt-dialog-status', attrs: { 'aria-live': 'assertive' } });
    form.append(ui.el('h2', { text: t(title) }));
    if (intro) form.append(ui.el('p', { text: intro }));
    if (body) form.append(body);
    for (const spec of fields) form.append(spec.node || ui.field(t, spec));
    let typed = null;
    if (confirm) {
      const id = `zt-typed-${Math.random().toString(36).slice(2, 8)}`;
      typed = ui.el('input', { id, type: 'text', autocomplete: 'off', spellcheck: false, maxLength: 256 });
      form.append(ui.el('label', { htmlFor: id }, ui.el('span', { text: t('ui.confirm.type_target', { target: confirm }) }), typed));
    }
    let reasonBox = null;
    if (reason) {
      const id = `zt-reason-${Math.random().toString(36).slice(2, 8)}`;
      reasonBox = ui.el('textarea', { id, required: true, maxLength: 256, rows: 3 });
      form.append(ui.el('label', { htmlFor: id }, ui.el('span', { text: t('network.reason.label') }), reasonBox, ui.el('small', { class: 'kit-help', text: t('network.reason.help') })));
    }
    const ok = ui.el('button', { type: 'submit', class: `button ${danger ? 'button-danger' : 'button-primary'}`, text: t(confirmLabel), disabled: Boolean(confirm || reason) });
    const cancel = ui.el('button', { type: 'button', class: 'button button-quiet', text: t('ui.cancel') });
    form.append(status, ui.el('div', { class: 'button-row' }, cancel, ok));
    const dialog = ui.el('dialog', { class: 'kit-dialog zt-dialog' }, form);
    dialog.setAttribute('aria-label', t(title));
    let busy = false;
    const sync = () => { ok.disabled = busy || (typed && typed.value !== confirm) || (reasonBox && !reasonBox.value.trim()); };
    form.addEventListener('input', sync);
    const finish = value => { dialog.close(); dialog.remove(); resolve(value); };
    cancel.addEventListener('click', () => { if (!busy) finish(null); });
    dialog.addEventListener('cancel', event => { event.preventDefault(); if (!busy) finish(null); });
    form.addEventListener('submit', async event => {
      event.preventDefault();
      if (ok.disabled || !form.reportValidity()) return;
      const values = Object.fromEntries(fields.filter(spec => spec.name).map(spec => { const control = form.elements[spec.name]; return [spec.name, control?.type === 'checkbox' ? control.checked : control?.value.trim() ?? '']; }));
      values.reason = reasonBox ? reasonBox.value.trim() : null;
      busy = true; sync(); ui.clear(status, ui.loadingState(t));
      try { finish((submit ? await submit(values) : values) ?? values); }
      catch (error) {
        if (error?.status === 401) { finish(null); throw error; }
        busy = false; sync();
        ui.clear(status, ui.el('div', { class: 'zt-dialog-error', attrs: { role: 'alert' } }, ui.el('p', { text: errorText(t, error) }), fieldErrors(cx, error)));
      }
    });
    document.body.append(dialog);
    dialog.showModal();
    (form.querySelector('input:not([type=hidden]), select, textarea') || ok).focus();
  });
}

export function outcomeBanner(cx, kind, messageKey, params = {}) {
  const { t, ui } = cx;
  return ui.el('div', { class: `zt-outcome zt-outcome-${kind}`, attrs: { role: kind === 'committed' ? 'status' : 'alert' } }, ui.statusBadge(t, kind, `network.outcome.${kind}`), ui.el('span', { text: t(messageKey, params) }));
}

export function facts(cx, rows) {
  const { t, ui } = cx;
  return ui.el('dl', { class: 'zt-dl' }, rows.filter(([, value]) => value !== null && value !== undefined && value !== '').map(([key, value]) => [ui.el('dt', { text: t(key) }), ui.el('dd', {}, value instanceof Node ? value : String(value))]));
}

export function panel(cx, titleKey, body, { actions = [], params, className = '' } = {}) {
  const { t, ui } = cx;
  return ui.el('section', { class: `panel zt-panel ${className}`.trim(), attrs: { 'aria-label': t(titleKey, params) } },
    ui.el('div', { class: 'zt-panel-head' }, ui.el('h2', { text: t(titleKey, params) }), actions.length ? ui.el('div', { class: 'button-row' }, actions) : null), body);
}

export function button(cx, label, onClick, { kind = 'quiet', params } = {}) {
  return cx.ui.el('button', { type: 'button', class: `button button-${kind}`, text: cx.t(label, params), on: { click: onClick } });
}

/** Message for a Sumunjang reason/stage code with its `{params}`; unknown codes say so. */
export function codeText(t, code, params = {}) {
  const key = `network.code.${code}`;
  const values = Object.fromEntries(Object.entries(params || {}).map(([name, value]) => [name, value === null || value === undefined ? '—' : String(value)]));
  const text = t(key, values);
  return text === key ? t('network.code.unknown', { code: String(code) }) : text;
}

const NUMBER = () => new Intl.NumberFormat(document.documentElement.lang || undefined);
export function number(value) { return Number.isFinite(value) ? NUMBER().format(value) : '—'; }

/** Read-only filter control explaining the missing owner API in a tooltip. */
export function unavailable(cx, label, reason) {
  const { t, ui } = cx;
  const id = `zt-off-${Math.random().toString(36).slice(2, 8)}`;
  const select = ui.el('select', { id, disabled: true, attrs: { 'aria-describedby': `${id}-tip` } }, ui.el('option', { text: t('network.filter.any') }));
  return ui.el('label', { class: 'kit-field zt-field-off', htmlFor: id },
    ui.el('span', { class: 'kit-field-label' }, ui.el('span', { text: t(label) }), ' ', ui.el('span', { class: 'kit-action-off', tabIndex: 0, attrs: { 'aria-label': t(reason) } }, ui.el('span', { class: 'kit-info', text: 'ⓘ', attrs: { 'aria-hidden': 'true' } }), ui.el('span', { class: 'kit-tip', id: `${id}-tip`, text: t(reason), attrs: { role: 'tooltip' } }))),
    select);
}
