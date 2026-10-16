// Identities section (ADR 0020 §3): shared helpers. Every call goes through
// the Hopae console package broker (`/v1/plugins/hopae/<route>`), which
// signs the delegated actor assertion; nothing here talks to Hopae directly.
const BASE = '/v1/plugins/hopae/';
const GET_ROUTES = new Set(['status', 'me', 'authentication/profiles', 'authentication/projections']);
export const PAGES = Object.freeze(['users', 'sessions', 'groups', 'providers', 'authentication', 'projections']);
const PAGE_ICONS = Object.freeze({ users: '◉', sessions: '⧗', groups: '◎', providers: '⇄', authentication: '⚿', projections: '⇥' });

/** Installed Hopae package and its declared routes (`path:METHOD`), from host discovery. */
export async function capabilities(cx) {
  let plugins = [];
  try { plugins = (await cx.api('/v1/plugins')).data?.plugins || []; }
  catch (error) { if (error?.status === 401) throw error; return { installed: false, failed: true, routes: null, version: null }; }
  const hopae = plugins.find(plugin => plugin.id === 'hopae');
  if (!hopae) return { installed: false, failed: false, routes: null, version: null };
  // Hosts before route discovery report no list: every route is then tried.
  const routes = Array.isArray(hopae.routes) ? new Set(hopae.routes.map(route => `${route.path}:${route.method}`)) : null;
  return { installed: true, failed: false, routes, version: hopae.version || null, authentication: hopae.authentication || null };
}

export function can(caps, route) {
  if (!caps?.installed) return false;
  return !caps.routes || caps.routes.has(`${route}:${GET_ROUTES.has(route) ? 'GET' : 'POST'}`);
}

/**
 * One broker call. `reason` travels in the host-only `x-hangang-change-reason`
 * header (percent-encoded UTF-8) into the private operation journal; Hopae's
 * own body contracts are unchanged.
 */
export async function hopae(cx, route, { json = {}, reason } = {}) {
  const headers = reason ? { 'x-hangang-change-reason': encodeURIComponent(reason) } : undefined;
  const options = GET_ROUTES.has(route) ? { headers } : { method: 'POST', json, headers };
  const { data, response } = await cx.api(`${BASE}${route}`, options);
  return { data, operation: response?.headers?.get?.('x-hangang-plugin-operation') || null };
}

const HOPAE_CODES = new Set(['revision_conflict', 'group_not_local', 'key_in_use', 'already_member', 'not_member', 'unknown_user', 'group_not_found', 'group_deleted', 'too_many_groups', 'group_full', 'too_many_local_groups', 'invalid_request', 'invalid_profiles', 'invalid_projections', 'profiles_unavailable', 'projections_unavailable', 'rate_limited', 'store_unavailable', 'audit_unavailable', 'cursor_expired', 'invalid_cursor', 'revision_required']);

/** Localized sentence for a failed broker call; never the raw backend text. */
export function errorText(t, error) {
  const status = error?.status ?? 0;
  const payload = error?.payload && typeof error.payload === 'object' ? error.payload : {};
  const detail = String(payload.detail || error?.message || '');
  if (typeof payload.error === 'string' && HOPAE_CODES.has(payload.error)) return t(`identities.error.code.${payload.error}`);
  if (status === 404 && /unknown plugin$/.test(detail)) return t('identities.error.not_installed');
  if (status === 404 && /not registered/.test(detail)) return t('identities.error.not_declared');
  if (/uncertain/.test(detail)) return t('identities.error.uncertain');
  if (status === 409) return t('identities.error.code.revision_conflict');
  if (status === 429) return t('identities.error.code.rate_limited');
  if (status === 400 && /change reason/.test(detail)) return t('identities.error.reason');
  if (status === 502 || status === 503 || status === 0) return t('identities.error.unavailable');
  if (status === 403) return t('identities.error.forbidden');
  return t('identities.error.generic', { status });
}

export function isConflict(error) { return error?.status === 409 && (error?.payload?.error === 'revision_conflict' || !error?.payload?.error); }
export function isUncertain(error) { return /uncertain/.test(String(error?.payload?.detail || error?.message || '')); }

/** Error state owned by Hopae with a localized message and retry. */
export function failure(cx, error, retry) {
  if (error?.status === 401) throw error;
  return cx.ui.errorState(cx.t, { owner: 'ui.owner.hopae', message: errorText(cx.t, error), retry });
}

/** Empty state for a Hopae package that is missing or does not declare a route. */
export function notConnected(cx, caps, route) {
  const { t, ui } = cx;
  if (!caps.installed) return ui.emptyState(t, { title: caps.failed ? 'identities.state.discovery_failed' : 'identities.state.not_installed', body: 'identities.state.not_installed.body' });
  return ui.emptyState(t, { title: 'identities.state.not_declared', body: 'identities.state.not_declared.body', action: cx.ui.el('code', { class: 'kit-mono', text: route }) });
}

/** Section page with the Identities sub-navigation. */
export function sectionPage(cx, root, { active, crumbs = [], title, owner, actions = [] }) {
  const { t, ui } = cx;
  const view = cx.page(root, { crumbs: [{ label: t('nav.identities'), href: '#identities' }, ...crumbs], title, owner, actions });
  const nav = ui.el('nav', { class: 'zt-subnav', attrs: { 'aria-label': t('identities.subnav') } });
  const list = ui.el('ul');
  for (const name of PAGES) {
    const link = ui.el('a', { href: `#identities/${name}`, dataset: { page: name } }, ui.el('span', { class: 'zt-subnav-icon', text: PAGE_ICONS[name], attrs: { 'aria-hidden': 'true' } }), ui.el('span', { text: t(`identities.page.${name}`) }));
    if (name === active) link.setAttribute('aria-current', 'page');
    list.append(ui.el('li', {}, link));
  }
  nav.append(list);
  view.content.before(nav);
  return view;
}

/** Hopae reports Unix seconds; service credential expiry is milliseconds. */
export function toMs(value) {
  if (!Number.isFinite(value) || value <= 0) return null;
  return value > 1e12 ? value : value * 1000;
}

export function timeOrDash(cx, value) {
  const ms = toMs(value);
  return ms ? cx.ui.timeCell(cx.t, ms) : cx.ui.el('span', { class: 'kit-muted', text: cx.t('identities.none') });
}

const STATUS_KIND = Object.freeze({ active: 'healthy', disabled: 'disabled', deleted: 'stale', unknown: 'unknown' });

export function subjectStatus(cx, status) {
  const safe = Object.hasOwn(STATUS_KIND, status) ? status : 'unknown';
  return cx.ui.statusBadge(cx.t, STATUS_KIND[safe], `ui.subject.status.${safe}`);
}

/** User entity link: display name (or masked e-mail) first, opaque ID second. */
export function userLink(cx, { id, label, status }) {
  const link = cx.ui.entityLink(cx.t, { type: 'user', id, label: label || null });
  if (status && status !== 'active') link.append(cx.ui.el('span', { class: 'kit-tag', text: cx.t(`ui.subject.status.${Object.hasOwn(STATUS_KIND, status) ? status : 'unknown'}`) }));
  return link;
}

/** User link resolved lazily through the shared subject resolver. */
export function resolvedUser(cx, id) {
  const holder = cx.ui.el('span', { class: 'zt-subject' }, cx.ui.el('span', { class: 'kit-mono', text: id }));
  if (!id) return cx.ui.el('span', { class: 'kit-muted', text: cx.t('identities.none') });
  cx.resolver.resolve(id).then(result => {
    if (cx.signal.aborted) return;
    const subject = result.state === 'resolved' ? result.subject : null;
    cx.ui.clear(holder, userLink(cx, { id, label: subject && subject.status !== 'deleted' ? cx.ui.subjectLabel(subject) : null, status: subject?.status }));
  });
  return holder;
}

const SOURCES = Object.freeze(['local', 'ldap', 'oidc']);
/** Group source badge: Local, LDAP or OpenID Connect plus the provider. */
export function sourceBadge(cx, source, provider) {
  const safe = SOURCES.includes(source) ? source : 'unknown';
  return cx.ui.el('span', { class: `zt-source zt-source-${safe}` }, cx.ui.el('span', { text: cx.t(`identities.group.source.${safe}`) }), provider ? cx.ui.el('span', { class: 'kit-muted', text: provider }) : null);
}

/** AAL chip: AAL 0 machine, 1 single factor, 2 multi-factor. */
export function aalBadge(cx, aal) {
  if (!Number.isFinite(aal)) return cx.ui.el('span', { class: 'kit-muted', text: cx.t('identities.none') });
  return cx.ui.el('span', { class: `zt-aal zt-aal-${Math.min(3, Math.max(0, aal))}`, title: cx.t(`identities.aal.help.${Math.min(3, Math.max(0, aal))}`), text: cx.t('identities.aal', { aal }) });
}

const FACTORS = Object.freeze(['totp', 'webauthn', 'external', 'recovery', 'federated', 'password', 'otp', 'certificate', 'bearer']);
export function factorList(cx, factors) {
  const list = Array.isArray(factors) ? factors.filter(value => typeof value === 'string') : [];
  if (!list.length) return cx.ui.el('span', { class: 'kit-muted', text: cx.t('identities.factor.none') });
  return cx.ui.el('span', { class: 'zt-chips' }, list.map(factor => cx.ui.el('span', { class: 'kit-tag', text: FACTORS.includes(factor) ? cx.t(`identities.factor.${factor}`) : factor })));
}

/** Read-only form control with an explanation of the missing owner API. */
export function unavailableField(cx, label, reason) {
  const { t, ui } = cx;
  const id = `zt-off-${Math.random().toString(36).slice(2, 8)}`;
  const select = ui.el('select', { id, disabled: true, attrs: { 'aria-describedby': `${id}-tip` } }, ui.el('option', { text: t('identities.filter.any') }));
  return ui.el('label', { class: 'kit-field zt-field-off', htmlFor: id },
    ui.el('span', { class: 'kit-field-label' }, ui.el('span', { text: t(label) }), ' ', ui.el('span', { class: 'kit-action-off', tabIndex: 0, attrs: { 'aria-label': t(reason) } }, ui.el('span', { class: 'kit-info', text: 'ⓘ', attrs: { 'aria-hidden': 'true' } }), ui.el('span', { class: 'kit-tip', id: `${id}-tip`, text: t(reason), attrs: { role: 'tooltip' } }))),
    select);
}

/**
 * Modal form for writes: labelled fields, a required reason and an optional
 * typed confirmation. `submit(values)` runs inside the dialog so a refusal
 * (conflict, validation) is shown without losing the operator's input.
 */
export function formDialog(cx, { title, intro, fields = [], confirm, confirmLabel = 'ui.confirm.action', danger = false, reason = true, submit }) {
  const { t, ui } = cx;
  return new Promise(resolve => {
    const form = ui.el('form', { class: 'kit-confirm zt-form-dialog', noValidate: false });
    const status = ui.el('div', { class: 'zt-dialog-status', attrs: { 'aria-live': 'assertive' } });
    const controls = [];
    form.append(ui.el('h2', { text: t(title) }));
    if (intro) form.append(ui.el('p', { text: intro }));
    for (const spec of fields) {
      const node = spec.node || ui.field(t, spec);
      form.append(node);
      controls.push(spec);
    }
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
      form.append(ui.el('label', { htmlFor: id }, ui.el('span', { text: t('identities.reason.label') }), reasonBox, ui.el('small', { class: 'kit-help', text: t('identities.reason.help') })));
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
      const values = Object.fromEntries(controls.filter(spec => spec.name).map(spec => [spec.name, form.elements[spec.name]?.type === 'checkbox' ? form.elements[spec.name].checked : form.elements[spec.name]?.value.trim() ?? '']));
      values.reason = reasonBox ? reasonBox.value.trim() : null;
      busy = true; sync(); ui.clear(status, ui.loadingState(t));
      try {
        const result = submit ? await submit(values) : values;
        finish(result ?? values);
      } catch (error) {
        if (error?.status === 401) { finish(null); throw error; }
        busy = false; sync();
        ui.clear(status, ui.el('p', { class: 'zt-dialog-error', attrs: { role: 'alert' }, text: errorText(t, error) }));
      }
    });
    document.body.append(dialog);
    dialog.showModal();
    (form.querySelector('input:not([type=hidden]), select, textarea') || ok).focus();
  });
}

/** Result banner after a write: committed, refused or uncertain (inspect, then retry). */
export function outcomeBanner(cx, kind, messageKey, params = {}) {
  const { t, ui } = cx;
  const map = { committed: 'committed', refused: 'refused', uncertain: 'uncertain' };
  return ui.el('div', { class: `zt-outcome zt-outcome-${kind}`, attrs: { role: kind === 'committed' ? 'status' : 'alert' } }, ui.statusBadge(t, map[kind] || 'unknown', `identities.outcome.${kind}`), ui.el('span', { text: t(messageKey, params) }));
}

/** Simple definition list from [labelKey, node|string|null] rows; empty values are skipped. */
export function facts(cx, rows) {
  const { t, ui } = cx;
  return ui.el('dl', { class: 'zt-dl' }, rows.filter(([, value]) => value !== null && value !== undefined && value !== '').map(([key, value]) => [ui.el('dt', { text: t(key) }), ui.el('dd', {}, value instanceof Node ? value : String(value))]));
}

/** Panel with heading, optional actions and body. */
export function panel(cx, titleKey, body, { actions = [], id, params } = {}) {
  const { t, ui } = cx;
  return ui.el('section', { class: 'panel zt-panel', id, attrs: { 'aria-label': t(titleKey, params) } },
    ui.el('div', { class: 'zt-panel-head' }, ui.el('h2', { text: t(titleKey, params) }), actions.length ? ui.el('div', { class: 'button-row' }, actions) : null), body);
}

/** Pages through a cursor-listed Hopae read up to `pages`, keeping matching items. */
export async function scan(cx, route, { match, limit = 200, pages = 5, signal }) {
  let cursor = null, seen = 0;
  const items = [];
  for (let page = 0; page < pages; page += 1) {
    const { data } = await hopae(cx, route, { json: { limit, ...(cursor ? { cursor } : {}) } });
    if (signal?.aborted) return { items, complete: false, seen };
    const batch = Array.isArray(data?.items) ? data.items : [];
    seen += batch.length;
    items.push(...batch.filter(match));
    cursor = data?.next_cursor || null;
    if (!cursor) return { items, complete: true, seen };
  }
  return { items, complete: false, seen };
}

export function button(cx, label, onClick, { kind = 'quiet', params } = {}) {
  return cx.ui.el('button', { type: 'button', class: `button button-${kind}`, text: cx.t(label, params), on: { click: onClick } });
}
