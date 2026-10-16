// Identities ▸ Sessions: live Hopae sessions (`sessions/query`) with device,
// address, assurance and activity; terminate one with a reason.
import { can, hopae, modern, sectionPage, notConnected, timeOrDash, aalBadge, factorList, resolvedUser, formDialog, outcomeBanner, capabilities, scan, toMs } from './common.js';

/** "Chrome · macOS" from a sanitized user-agent prefix; the raw prefix stays in the tooltip. */
export function deviceLabel(t, ua) {
  if (typeof ua !== 'string' || !ua) return t('identities.session.device.unknown');
  const browser = /Edg\//.test(ua) ? 'Edge' : /OPR\//.test(ua) ? 'Opera' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : /curl\//.test(ua) ? 'curl' : null;
  const os = /iPhone|iPad/.test(ua) ? 'iOS' : /Android/.test(ua) ? 'Android' : /Mac OS X|Macintosh/.test(ua) ? 'macOS' : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : null;
  if (browser && os) return t('identities.session.device.value', { browser, os });
  return browser || os || t('identities.session.device.other');
}

function ipLink(cx, ip) {
  if (!ip) return cx.ui.el('span', { class: 'kit-muted', text: cx.t('identities.session.ip.unbound') });
  return cx.ui.el('a', { href: `#network/ip/${encodeURIComponent(ip)}`, class: 'kit-mono', text: ip });
}

export async function terminateSession(cx, session, label) {
  const { t } = cx;
  return formDialog(cx, {
    title: 'identities.session.terminate.title', intro: t('identities.session.terminate.effect', { user: label || session.user_id || '—', device: deviceLabel(t, session.ua_prefix) }),
    confirmLabel: 'identities.session.terminate', danger: true,
    submit: async values => (await hopae(cx, 'sessions/terminate', { json: { id: session.session_id }, reason: values.reason })),
  });
}

/** Columns shared by the Sessions page and the user Sessions tab. */
export function sessionColumns(cx, { showUser, canTerminate, onTerminated, label }) {
  const { t, ui } = cx;
  return [
    ...(showUser ? [{ key: 'user', label: 'identities.session.col.user', render: session => resolvedUser(cx, session.user_id) }] : []),
    { key: 'device', label: 'identities.session.col.device', render: session => ui.el('span', { class: 'zt-stack' }, ui.el('span', { text: deviceLabel(t, session.ua_prefix) }), session.hosts?.length ? ui.el('span', { class: 'kit-muted', text: t('identities.session.hosts', { count: session.hosts.length }) }) : null), title: session => session.ua_prefix || '' },
    { key: 'ip', label: 'identities.session.col.ip', render: session => ipLink(cx, session.bound_ip) },
    { key: 'aal', label: 'identities.session.col.aal', render: session => aalBadge(cx, session.aal) },
    { key: 'factors', label: 'identities.session.col.factors', render: session => factorList(cx, session.factors) },
    { key: 'provider', label: 'identities.session.col.provider', render: session => ui.el('span', { text: session.provider_id || t('identities.none') }) },
    { key: 'signed_in', label: 'identities.session.col.signed_in', render: session => timeOrDash(cx, session.auth_time ?? session.created_at) },
    { key: 'last_seen', label: 'identities.session.col.last_seen', render: session => timeOrDash(cx, session.last_seen_at) },
    { key: 'expires', label: 'identities.session.col.expires', render: session => timeOrDash(cx, session.absolute_expires_at), hidden: true },
    { key: 'actions', label: 'identities.session.col.actions', render: session => canTerminate
      ? ui.el('button', { type: 'button', class: 'button button-quiet zt-row-action', text: t('identities.session.terminate'), on: { click: async event => {
        event.stopPropagation();
        const result = await terminateSession(cx, session, label?.(session));
        if (result) onTerminated?.(session, result);
      } } })
      : ui.disabledAction(t, 'identities.session.terminate', 'identities.gap.not_declared'), title: () => '' },
  ];
}

export async function renderSessions(cx, root, params) {
  const { t, ui } = cx;
  const caps = await capabilities(cx);
  if (cx.signal.aborted) return;
  const { content } = sectionPage(cx, root, { active: 'sessions', title: t('identities.page.sessions'), owner: t('identities.sessions.owner') });
  if (!caps.installed || !can(caps, 'sessions/query')) { content.append(notConnected(cx, caps, 'sessions/query')); return; }
  const user = params.get('user') || '';
  const server = modern(caps);
  const aal = server && ['1', '2'].includes(params.get('aal')) ? params.get('aal') : '';
  const form = ui.el('form', { class: 'zt-filters', attrs: { role: 'search', 'aria-label': t('identities.sessions.filters') } },
    ui.subjectPicker(t, cx.api, { label: 'identities.sessions.filter.user', name: 'user', value: user, help: 'identities.sessions.filter.user.help' }),
    // AAL 3 is never stored on a session (Hopae ADR-0018), so the filter offers 1 and 2.
    server ? ui.field(t, { label: 'identities.sessions.filter.aal', name: 'aal', value: aal, options: [{ value: '', label: 'identities.filter.any' }, { value: '1', label: 'identities.sessions.aal.1' }, { value: '2', label: 'identities.sessions.aal.2' }] }) : null,
    ui.el('div', { class: 'button-row zt-filter-actions' }, ui.el('button', { type: 'submit', class: 'button button-primary', text: t('identities.users.apply') }), ui.el('a', { class: 'button button-quiet', href: '#identities/sessions', text: t('identities.users.reset') })));
  form.addEventListener('submit', event => {
    event.preventDefault();
    const next = new URLSearchParams();
    const value = form.elements.user.value.trim();
    if (value) next.set('user', value);
    if (form.elements.aal?.value) next.set('aal', form.elements.aal.value);
    cx.navigate(cx.hashFor('identities', ['sessions'], next));
  });
  const banner = ui.el('div', { class: 'zt-notes' });
  const status = ui.el('div');
  let table;
  const columns = sessionColumns(cx, { showUser: true, canTerminate: can(caps, 'sessions/terminate'), onTerminated: (session, result) => { ui.clear(status, outcomeBanner(cx, 'committed', result.data?.changed === false ? 'identities.session.terminated.already' : 'identities.session.terminated', { operation: result.operation || '—' })); table.refresh(); } });
  table = ui.dataTable(t, {
    id: 'identities-sessions', caption: 'identities.sessions.caption', owner: 'ui.owner.hopae', columns, sortable: 'none', rowKey: session => session.session_id,
    empty: { title: user || aal ? 'identities.sessions.empty.user' : 'identities.sessions.empty', body: 'identities.sessions.empty.body' },
    onRowOpen: session => cx.navigate(`#identities/users/${encodeURIComponent(session.user_id)}/sessions`),
    fetchPage: async ({ cursor, signal }) => {
      if (server) {
        const { data } = await hopae(cx, 'sessions/query', { json: { limit: 50, ...(user ? { user_id: user } : {}), ...(aal ? { aal: Number(aal) } : {}), ...(cursor ? { cursor } : {}) } });
        return { items: Array.isArray(data?.items) ? data.items : [], nextCursor: data?.next_cursor || null };
      }
      if (user) {
        // Older packages have no user filter: scan the newest live sessions.
        const result = await scan(cx, 'sessions/query', { match: session => session.user_id === user, signal });
        ui.clear(banner, result.complete ? null : ui.el('p', { class: 'zt-banner', attrs: { role: 'note' }, text: t('identities.scan.partial', { count: result.seen }) }));
        return { items: result.items, nextCursor: null };
      }
      const { data } = await hopae(cx, 'sessions/query', { json: { limit: 50, ...(cursor ? { cursor } : {}) } });
      return { items: Array.isArray(data?.items) ? data.items : [], nextCursor: data?.next_cursor || null };
    },
  });
  cx.signal.addEventListener('abort', () => table.destroy(), { once: true });
  content.append(form, banner, status, table.element);
  await table.reload();
}

/** Newest live session time for a user, from the session list. */
export function newest(sessions, field) {
  return sessions.reduce((best, session) => Math.max(best, toMs(session[field]) || 0), 0) || null;
}
