// Identities ▸ Users ▸ user detail (ADR 0020 §3): Profile & linked
// identities, Authentication, Sessions, Groups, Access (Pumgye grants) and
// Activity (Hopae events plus the Hangang decision log for this subject).
import { can, hopae, failure, sectionPage, capabilities, timeOrDash, subjectStatus, aalBadge, factorList, formDialog, outcomeBanner, facts, panel, scan, button, sourceBadge, errorText } from './common.js';
import { sessionColumns } from './sessions.js';
import { explainPanel } from './explain.js';
import { decisionColumns, decisionFetcher } from '../access.js';

export const TABS = Object.freeze(['profile', 'authentication', 'sessions', 'groups', 'access', 'activity']);
export const EVENT_KINDS = Object.freeze(['login.started', 'login.succeeded', 'login.failed', 'session.created', 'session.handoff', 'session.terminated', 'handle.revoked', 'identity.linked', 'identity.conflict', 'verify.denied', 'handoff.rejected', 'factor.enrollment_prepared', 'factor.enrollment_activated', 'factor.enrollment_expired', 'factor.enrollment_revoked', 'factor.totp_consumed', 'factor.external_consumed', 'factor.webauthn_registered', 'factor.webauthn_used', 'factor.webauthn_renamed', 'factor.webauthn_revoked', 'factor.webauthn_failed', 'factor.webauthn_clone_suspected', 'factor.recovery_codes_generated', 'factor.recovery_code_used', 'admin.user_disable', 'admin.user_enable', 'admin.session_terminate', 'admin.sessions_terminate', 'admin.factor_reset', 'admin.grant', 'admin.revoke', 'group.member_added', 'group.member_removed']);
const OUTCOMES = Object.freeze({ success: 'allow', failure: 'deny', info: 'unknown' });

async function resolveSubject(cx, id) {
  try { return (await hopae(cx, 'subjects/resolve', { json: { ids: [id], privacy_profile: 'standard', include_groups: true } })).data?.items?.[0] || null; }
  catch (error) {
    if (error?.status === 401) throw error;
    // A Hopae without groups refuses the unknown field.
    if (error?.status === 400) return (await hopae(cx, 'subjects/resolve', { json: { ids: [id], privacy_profile: 'standard' } })).data?.items?.[0] || null;
    throw error;
  }
}

function eventText(cx, event) {
  const kind = EVENT_KINDS.includes(event.kind) ? event.kind : null;
  return kind ? cx.t(`identities.event.${kind}`) : cx.t('identities.event.other');
}

function eventColumns(cx) {
  const { t, ui } = cx;
  return [
    { key: 'time', label: 'identities.event.col.time', render: event => timeOrDash(cx, Number(event.at)) },
    { key: 'event', label: 'identities.event.col.event', render: event => ui.el('span', { text: eventText(cx, event) }), title: event => event.kind },
    { key: 'outcome', label: 'identities.event.col.outcome', render: event => ui.statusBadge(t, OUTCOMES[event.outcome] || 'unknown', `identities.event.outcome.${Object.hasOwn(OUTCOMES, event.outcome) ? event.outcome : 'info'}`) },
    { key: 'app', label: 'identities.event.col.app', render: event => ui.el('span', { text: event.app_id || event.provider_id || t('identities.none') }) },
    { key: 'ip', label: 'identities.event.col.ip', render: event => event.client_ip ? ui.el('a', { class: 'kit-mono', href: `#network/ip/${encodeURIComponent(event.client_ip)}`, text: event.client_ip }) : ui.el('span', { class: 'kit-muted', text: t('identities.none') }) },
  ];
}

/** Bounded scan of the newest Hopae events for one user (no server filter yet). */
async function userEvents(cx, userId, filter = () => true) {
  return scan(cx, 'events/query', { match: event => event?.user_id === userId && filter(event), pages: 3, signal: cx.signal });
}

function scanNote(cx, result) {
  return result.complete ? null : cx.ui.el('p', { class: 'zt-banner', attrs: { role: 'note' }, text: cx.t('identities.scan.partial', { count: result.seen }) });
}

function staticTable(cx, { id, caption, columns, items, empty, onRowOpen }) {
  const table = cx.ui.dataTable(cx.t, { id, caption, owner: 'ui.owner.hopae', columns, sortable: 'none', rowKey: item => item.event_id || item.session_id || item.group_id || item.key || JSON.stringify(item).length, empty, onRowOpen, fetchPage: async () => ({ items, nextCursor: null }) });
  table.element.classList.add('zt-static');
  cx.signal.addEventListener('abort', () => table.destroy(), { once: true });
  table.reload();
  return table;
}

function recentDecisions(cx, id, limit) {
  const { t, ui } = cx;
  const params = new URLSearchParams({ subject: id });
  const table = ui.dataTable(t, { id: 'identities-user-decisions', caption: 'entity.decisions.caption', owner: 'ui.owner.exporter', columns: decisionColumns(cx), rowKey: event => event.event_id, onRowOpen: event => cx.navigate(cx.hashFor('access', ['requests', event.request_id])), empty: { title: 'entity.decisions.empty' }, fetchPage: decisionFetcher(cx, params, { limit }) });
  cx.signal.addEventListener('abort', () => table.destroy(), { once: true });
  table.reload();
  return panel(cx, 'entity.decisions.title', table.element, { actions: [ui.el('a', { class: 'button button-quiet', href: cx.hashFor('access', ['decisions'], params), text: t('entity.decisions.open') })] });
}

async function profileTab(cx, user, caps) {
  const { t, ui } = cx;
  const providers = user.providers || [];
  let providerInfo = new Map();
  if (providers.length && can(caps, 'status')) {
    try { providerInfo = new Map(((await hopae(cx, 'status')).data?.providers || []).map(provider => [provider.provider_id, provider])); }
    catch (error) { if (error?.status === 401) throw error; }
  }
  const linked = providers.length ? ui.el('ul', { class: 'zt-linked' }, providers.map(id => {
    const info = providerInfo.get(id);
    return ui.el('li', { class: 'zt-card' }, ui.el('div', { class: 'zt-card-head' }, ui.el('div', { class: 'zt-stack' }, ui.el('strong', { text: info?.display_name || id }), ui.el('span', { class: 'kit-entity-id', text: id })), info ? ui.statusBadge(t, info.health === 'ok' ? 'healthy' : info.health === 'degraded' ? 'stale' : 'disabled', `identities.provider.health.${['ok', 'degraded', 'disabled'].includes(info.health) ? info.health : 'unknown'}`) : null),
      ui.el('span', { class: 'kit-muted', text: info ? t(`identities.provider.kind.${['oidc', 'oauth2', 'email_link', 'password', 'ldap'].includes(info.kind) ? info.kind : 'other'}`) : t('identities.unreported') }));
  })) : ui.el('p', { class: 'kit-muted', text: t('identities.user.linked.none') });
  return [
    panel(cx, 'identities.user.profile', facts(cx, [
      ['identities.user.display_name', user.display_name],
      ['identities.user.email', user.email],
      ['identities.user.kind', user.kind ? t(`decision.principal.${user.kind}`) : null],
      ['identities.users.col.status', subjectStatus(cx, user.status)],
      ['identities.user.id', ui.el('span', {}, ui.el('code', { class: 'kit-mono', text: user.user_id || user.id }), ui.copyButton(t, user.user_id || user.id))],
      ['identities.user.human_subject', user.human_subject ? ui.el('span', {}, ui.el('code', { class: 'kit-mono zt-break', text: user.human_subject }), ui.copyButton(t, user.human_subject)) : null],
      ['identities.users.col.created', timeOrDash(cx, user.created_at)],
      ['identities.users.col.last_login', timeOrDash(cx, user.last_login_at)],
      ['identities.user.last_seen', timeOrDash(cx, user.last_seen_at)],
    ])),
    panel(cx, 'identities.user.linked', ui.el('div', { class: 'zt-content' }, linked, ui.el('p', { class: 'zt-gap', attrs: { role: 'note' } }, ui.el('span', { class: 'kit-info', text: 'ⓘ', attrs: { 'aria-hidden': 'true' } }), ' ', ui.el('span', { text: t('identities.gap.linked_identities') })))),
    recentDecisions(cx, user.user_id || user.id, 10),
  ];
}

async function authenticationTab(cx, user, caps) {
  const { t, ui } = cx;
  const id = user.user_id || user.id;
  const factorRows = ['webauthn', 'totp', 'recovery'].map(factor => ui.el('li', { class: 'zt-factor' },
    ui.el('span', { class: 'zt-factor-icon', text: factor === 'webauthn' ? '⚿' : factor === 'totp' ? '⏱' : '⎘', attrs: { 'aria-hidden': 'true' } }),
    ui.el('span', { class: 'zt-stack' }, ui.el('strong', { text: t(`identities.factor.${factor}`) }), ui.el('span', { class: 'kit-muted', text: t(`identities.factor.${factor}.help`) })),
    ui.statusBadge(t, 'unknown', 'identities.factor.unreported')));
  const factors = panel(cx, 'identities.factors.title', ui.el('div', { class: 'zt-content' }, ui.el('ul', { class: 'zt-factors' }, factorRows),
    ui.el('p', { class: 'zt-gap', attrs: { role: 'note' } }, ui.el('span', { class: 'kit-info', text: 'ⓘ', attrs: { 'aria-hidden': 'true' } }), ' ', ui.el('span', { text: t('identities.gap.factors') }))), { actions: [ui.disabledAction(t, 'identities.factors.reset', 'identities.gap.factor_reset')] });
  const observed = ui.el('div', {}, ui.loadingState(t));
  const activity = ui.el('div', {}, ui.loadingState(t));
  const test = explainPanel(cx, { subject: id });
  const out = [factors, panel(cx, 'identities.factors.observed', observed), panel(cx, 'identities.factors.activity', activity), test.element];
  (async () => {
    if (can(caps, 'sessions/query')) {
      try {
        const result = await scan(cx, 'sessions/query', { match: session => session.user_id === id, signal: cx.signal });
        if (cx.signal.aborted) return;
        const aal = result.items.reduce((best, session) => Math.max(best, Number(session.aal) || 0), 0);
        const used = [...new Set(result.items.flatMap(session => Array.isArray(session.factors) ? session.factors : []))];
        ui.clear(observed, result.items.length ? facts(cx, [['identities.factors.highest_aal', aalBadge(cx, aal)], ['identities.factors.used', factorList(cx, used)], ['identities.factors.sessions', String(result.items.length)]]) : ui.el('p', { class: 'kit-muted', text: t('identities.factors.observed.none') }), scanNote(cx, result));
      } catch (error) { ui.clear(observed, failure(cx, error)); }
    } else ui.clear(observed, ui.el('p', { class: 'kit-muted', text: t('identities.error.not_declared') }));
    if (can(caps, 'events/query')) {
      try {
        const result = await userEvents(cx, id, event => /^factor\.|^admin\.factor_reset$/.test(event.kind || ''));
        if (cx.signal.aborted) return;
        const table = staticTable(cx, { id: 'identities-factor-events', caption: 'identities.factors.activity', columns: eventColumns(cx), items: result.items, empty: { title: 'identities.factors.activity.empty', body: 'identities.factors.activity.empty.body' } });
        ui.clear(activity, scanNote(cx, result), table.element);
      } catch (error) { ui.clear(activity, failure(cx, error)); }
    } else ui.clear(activity, ui.el('p', { class: 'kit-muted', text: t('identities.error.not_declared') }));
  })();
  return out;
}

async function sessionsTab(cx, user, caps, refreshHeader) {
  const { t, ui } = cx;
  const id = user.user_id || user.id;
  if (!can(caps, 'sessions/query')) return [ui.emptyState(t, { title: 'identities.state.not_declared', body: 'identities.state.not_declared.body' })];
  const note = ui.el('div');
  const status = ui.el('div');
  let table;
  const columns = sessionColumns(cx, { showUser: false, canTerminate: can(caps, 'sessions/terminate'), label: () => user.display_name || id, onTerminated: (session, result) => { ui.clear(status, outcomeBanner(cx, 'committed', result.data?.changed === false ? 'identities.session.terminated.already' : 'identities.session.terminated', { operation: result.operation || '—' })); table.refresh(); refreshHeader?.(); } });
  table = ui.dataTable(t, {
    id: 'identities-user-sessions', caption: 'identities.sessions.caption', owner: 'ui.owner.hopae', columns, sortable: 'none', rowKey: session => session.session_id,
    empty: { title: 'identities.sessions.empty.user', body: 'identities.sessions.empty.body' },
    expand: session => facts(cx, [['identities.session.id', ui.el('span', {}, ui.el('code', { class: 'kit-mono', text: session.session_id }), ui.copyButton(t, session.session_id))], ['identities.session.ua', session.ua_prefix], ['identities.session.hosts.label', (session.hosts || []).join(', ')], ['identities.session.auth_source', session.auth_time_source ? t(session.auth_time_source === 'provider_claim' ? 'identities.session.auth_source.provider' : 'identities.session.auth_source.hopae') : null], ['identities.session.col.expires', timeOrDash(cx, session.absolute_expires_at)]]),
    fetchPage: async ({ signal }) => {
      const result = await scan(cx, 'sessions/query', { match: session => session.user_id === id, signal });
      ui.clear(note, scanNote(cx, result));
      return { items: result.items, nextCursor: null };
    },
  });
  table.element.classList.add('zt-static');
  cx.signal.addEventListener('abort', () => table.destroy(), { once: true });
  table.reload();
  return [note, status, table.element];
}

async function groupsTab(cx, user, caps) {
  const { t, ui } = cx;
  const id = user.user_id || user.id;
  if (!can(caps, 'subjects/groups')) return [ui.emptyState(t, { title: 'identities.state.not_declared', body: 'identities.state.not_declared.body' })];
  const status = ui.el('div');
  const columns = [
    { key: 'group', label: 'identities.group.col.group', render: group => ui.el('a', { class: 'zt-stack', href: `#identities/groups/${encodeURIComponent(group.group_id)}` }, ui.el('strong', { text: group.name || group.key }), ui.el('span', { class: 'kit-entity-id', text: group.group_id })) },
    { key: 'source', label: 'identities.group.col.source', render: group => sourceBadge(cx, group.source, group.provider_id) },
    { key: 'since', label: 'identities.group.member.col.since', render: group => timeOrDash(cx, group.membership?.first_seen_at) },
    { key: 'expires', label: 'identities.group.member.col.expires', render: group => group.membership?.removal_pending_at ? ui.el('span', { class: 'kit-tag kit-tag-warn', text: t('identities.group.member.pending_removal') }) : group.membership?.expires_at ? timeOrDash(cx, group.membership.expires_at) : ui.el('span', { class: 'kit-muted', text: t('identities.group.member.no_expiry') }) },
    { key: 'actions', label: 'identities.session.col.actions', title: () => '', render: group => group.source !== 'local' ? ui.el('span', { class: 'kit-muted', text: t('identities.group.read_only.short') }) : can(caps, 'groups/members/remove')
      ? ui.el('button', { type: 'button', class: 'button button-quiet zt-row-action', text: t('identities.group.member.remove'), on: { click: async event => {
        event.stopPropagation();
        const result = await formDialog(cx, { title: 'identities.group.member.remove.title', intro: t('identities.group.member.remove.effect', { user: user.display_name || id, group: group.name }), confirmLabel: 'identities.group.member.remove', danger: true,
          submit: values => hopae(cx, 'groups/members/remove', { json: { group_id: group.group_id, expected_revision: group.revision, user_id: id, reason: values.reason }, reason: values.reason }) });
        if (result) { ui.clear(status, outcomeBanner(cx, 'committed', 'identities.group.member.removed', { operation: result.operation || '—' })); table.refresh(); }
      } } }) : ui.disabledAction(t, 'identities.group.member.remove', 'identities.gap.not_declared') },
  ];
  const table = ui.dataTable(t, {
    id: 'identities-user-groups', caption: 'identities.user.groups.caption', owner: 'ui.owner.hopae', columns, sortable: 'none', rowKey: group => group.group_id,
    empty: { title: 'identities.user.groups.empty', body: 'identities.user.groups.empty.body' },
    onRowOpen: group => cx.navigate(`#identities/groups/${encodeURIComponent(group.group_id)}`),
    fetchPage: async ({ cursor }) => {
      const { data } = await hopae(cx, 'subjects/groups', { json: { id, limit: 100, ...(cursor ? { cursor } : {}) } });
      return { items: Array.isArray(data?.items) ? data.items : [], nextCursor: data?.next_cursor || null };
    },
  });
  cx.signal.addEventListener('abort', () => table.destroy(), { once: true });
  table.reload();
  const add = can(caps, 'groups/members/add') && can(caps, 'groups/search') ? button(cx, 'identities.user.groups.add', async () => {
    let groups = [];
    try { groups = ((await hopae(cx, 'groups/search', { json: { source: 'local', limit: 100 } })).data?.items || []).filter(group => group.state !== 'deleted'); }
    catch (error) { if (error?.status === 401) throw error; ui.clear(status, outcomeBanner(cx, 'refused', 'identities.literal', { value: errorText(t, error) })); return; }
    if (!groups.length) { ui.clear(status, ui.el('p', { class: 'zt-banner', attrs: { role: 'note' }, text: t('identities.user.groups.no_local') })); return; }
    const select = ui.field(t, { label: 'identities.user.groups.pick', name: 'group_id', options: groups.map(group => ({ value: group.group_id, label: 'identities.literal' })) });
    [...select.querySelectorAll('option')].forEach((option, index) => { option.textContent = groups[index].name || groups[index].key; });
    const result = await formDialog(cx, { title: 'identities.group.member.add.title', intro: t('identities.user.groups.add.effect', { user: user.display_name || id }), confirmLabel: 'identities.group.member.add',
      fields: [{ node: select, name: 'group_id' }, { label: 'identities.group.member.expires', name: 'expires', type: 'date', help: 'identities.group.member.expires.help' }],
      submit: values => { const group = groups.find(item => item.group_id === values.group_id); return hopae(cx, 'groups/members/add', { json: { group_id: group.group_id, expected_revision: group.revision, user_id: id, ...(values.expires ? { expires_at: Math.floor(new Date(`${values.expires}T23:59:59`).getTime() / 1000) } : {}), reason: values.reason }, reason: values.reason }); } });
    if (result) { ui.clear(status, outcomeBanner(cx, 'committed', 'identities.group.member.added', { operation: result.operation || '—' })); table.refresh(); }
  }, { kind: 'primary' }) : ui.disabledAction(t, 'identities.user.groups.add', 'identities.gap.not_declared');
  return [panel(cx, 'identities.user.groups.title', ui.el('div', { class: 'zt-content' }, status, table.element), { actions: [add] })];
}

/** Effective roles, classes, permissions and minimum AAL of `subjects` in a Pumgye policy. */
export function grantsFor(policy, subjects, groupRefs) {
  const rows = [];
  for (const [service, definition] of Object.entries(policy?.services || {})) {
    const roles = definition?.roles || {};
    const direct = [];
    for (const field of ['users', 'human_users', 'workload_users']) for (const subject of subjects) {
      const assigned = definition?.[field]?.[subject];
      if (Array.isArray(assigned)) direct.push(...assigned.map(role => ({ role, via: field === 'users' ? 'user' : field === 'human_users' ? 'human' : 'workload', subject })));
    }
    for (const field of ['groups', 'group_bindings']) for (const [ref, assigned] of Object.entries(definition?.[field] || {})) {
      if (groupRefs.has(ref) && Array.isArray(assigned)) direct.push(...assigned.map(role => ({ role, via: 'group', group: groupRefs.get(ref) })));
    }
    if (!direct.length) continue;
    const effective = new Set(), seen = new Set();
    const walk = role => { if (seen.has(role) || !roles[role]) return; seen.add(role); effective.add(role); for (const parent of roles[role].inherits || []) walk(parent); };
    direct.forEach(entry => walk(entry.role));
    const permissions = new Set(), classes = new Set();
    let minAal = null;
    for (const role of effective) {
      (roles[role].permissions || []).forEach(value => permissions.add(value));
      (roles[role].information_classes || []).forEach(value => classes.add(value));
      if (Number.isFinite(roles[role].minimum_aal)) minAal = minAal === null ? roles[role].minimum_aal : Math.min(minAal, roles[role].minimum_aal);
    }
    rows.push({ service, direct, permissions: [...permissions].sort(), classes: [...classes].sort(), minAal, guest: direct.every(entry => entry.role === 'guest') });
  }
  return rows;
}

async function accessTab(cx, user) {
  const { t, ui } = cx;
  const id = user.user_id || user.id;
  const body = ui.el('div', {}, ui.loadingState(t));
  const simulate = ui.el('a', { class: 'button button-primary', href: cx.hashFor('policies', ['simulate'], new URLSearchParams({ subject: id })), text: t('identities.access.simulate') });
  (async () => {
    let policy = null, revision = null;
    try {
      const config = (await cx.api('/v1/config')).data || {};
      if (config.pumgye_authority) { const answer = (await cx.api('/v1/pumgye/policy')).data || {}; policy = answer.policy; revision = answer.revision; }
      else { policy = config.pumgye; revision = config.revision; }
    } catch (error) { if (error?.status === 401) throw error; ui.clear(body, cx.ui.errorState(t, { owner: 'ui.owner.pumgye', message: t('identities.access.unavailable'), retry: null })); return; }
    if (cx.signal.aborted) return;
    if (!policy) { ui.clear(body, ui.emptyState(t, { title: 'identities.access.no_policy', body: 'identities.access.no_policy.body' })); return; }
    const groupRefs = new Map((user.groups || []).map(group => [group.group_id, group.name || group.group_id]));
    const rows = grantsFor(policy, [id, user.user_id, user.human_subject].filter(Boolean), groupRefs);
    const columns = [
      { key: 'service', label: 'identities.access.col.service', render: row => ui.entityLink(t, { type: 'service', id: row.service }) },
      { key: 'roles', label: 'identities.access.col.roles', render: row => ui.el('span', { class: 'zt-chips' }, row.direct.map(entry => ui.el('span', { class: 'kit-tag', title: entry.via === 'group' ? t('identities.access.via.group', { group: entry.group }) : t(`identities.access.via.${entry.via}`), text: entry.via === 'group' ? `${entry.role} ← ${entry.group}` : entry.role }))) },
      { key: 'classes', label: 'identities.access.col.classes', render: row => row.classes.length ? ui.el('span', { class: 'zt-chips' }, row.classes.map(value => ui.el('span', { class: 'kit-tag', text: value }))) : ui.el('span', { class: 'kit-muted', text: t('identities.none') }) },
      { key: 'permissions', label: 'identities.access.col.permissions', render: row => row.permissions.length ? ui.el('span', { text: row.permissions.join(', ') }) : ui.el('span', { class: 'kit-muted', text: t(row.guest ? 'identities.access.guest' : 'identities.none') }) },
      { key: 'aal', label: 'identities.access.col.aal', render: row => aalBadge(cx, row.minAal) },
    ];
    const table = ui.dataTable(t, { id: 'identities-user-access', caption: 'identities.access.caption', owner: 'ui.owner.pumgye', columns, sortable: 'none', rowKey: row => row.service, empty: { title: 'identities.access.empty', body: 'identities.access.empty.body' }, onRowOpen: row => cx.navigate(`#policies/services/${encodeURIComponent(row.service)}`), fetchPage: async () => ({ items: rows, nextCursor: null }) });
    table.element.classList.add('zt-static');
    cx.signal.addEventListener('abort', () => table.destroy(), { once: true });
    ui.clear(body, ui.el('p', { class: 'kit-muted', text: t('identities.access.revision', { revision: revision ?? '—' }) }), table.element);
    table.reload();
  })();
  return [panel(cx, 'identities.access.title', body, { actions: [simulate] })];
}

async function activityTab(cx, user, caps) {
  const { t, ui } = cx;
  const id = user.user_id || user.id;
  const events = ui.el('div', {}, ui.loadingState(t));
  if (can(caps, 'events/query')) (async () => {
    try {
      const result = await userEvents(cx, id);
      if (cx.signal.aborted) return;
      const table = staticTable(cx, { id: 'identities-user-events', caption: 'identities.activity.hopae', columns: eventColumns(cx), items: result.items, empty: { title: 'identities.activity.empty', body: 'identities.activity.empty.body' } });
      ui.clear(events, scanNote(cx, result), table.element);
    } catch (error) { ui.clear(events, failure(cx, error)); }
  })();
  else ui.clear(events, ui.el('p', { class: 'kit-muted', text: t('identities.error.not_declared') }));
  return [panel(cx, 'identities.activity.hopae', events), recentDecisions(cx, id, 20)];
}

export async function renderUser(cx, root, id, tab) {
  const { t, ui } = cx;
  const active = TABS.includes(tab) ? tab : 'profile';
  const caps = await capabilities(cx);
  if (cx.signal.aborted) return;
  const view = sectionPage(cx, root, { active: 'users', crumbs: [{ label: t('identities.page.users'), href: '#identities/users' }, { label: id }], title: id, owner: t('entity.user.owner') });
  const { content, heading } = view;
  const actionsRow = root.querySelector('.zt-actions');
  const head = ui.el('div', { class: 'zt-entity-summary' }, ui.loadingState(t));
  const status = ui.el('div', { class: 'zt-notes' });
  content.append(head, status);
  let user = null, unresolved = null;
  // Resolve unless discovery says the route is missing; a missing package answers 404.
  if (!caps.routes || can(caps, 'subjects/resolve')) {
    try { user = await resolveSubject(cx, id); }
    catch (error) {
      if (error?.status === 401) throw error;
      unresolved = [429, 503].includes(error?.status) ? 'entity.user.retry' : 'entity.user.unresolved';
    }
  } else unresolved = 'entity.user.unresolved';
  if (cx.signal.aborted) return;
  if (!user) user = { id, user_id: /^u_/.test(id) ? id : null, status: unresolved ? 'unresolved' : 'unknown', providers: [] };
  const label = user.status !== 'deleted' ? (user.display_name || user.email) : null;
  if (label) {
    heading.textContent = label;
    const crumb = root.querySelector('.zt-crumbs [aria-current="page"]');
    if (crumb) crumb.textContent = label;
  }
  const userId = user.user_id || id;
  // Header strip: status, kind, providers, ID, last sign-in.
  ui.clear(head, unresolved ? ui.el('p', { class: 'zt-banner', dataset: { subjectState: 'unavailable' }, text: t(unresolved) }) : null, ui.el('div', { class: 'zt-subject-state', dataset: { subjectState: user.status } },
    unresolved ? null : subjectStatus(cx, user.status),
    user.reason ? ui.el('span', { class: 'kit-muted', text: t(`ui.subject.reason.${user.reason}`) }) : null,
    user.kind ? ui.el('span', { class: 'kit-tag', text: t(`decision.principal.${user.kind}`) }) : null,
    ...(user.providers || []).map(provider => ui.el('span', { class: 'kit-tag', text: provider })),
    ui.el('span', { class: 'zt-id' }, ui.el('code', { class: 'kit-mono', text: userId }), ui.copyButton(t, userId)),
    user.last_login_at ? ui.el('span', { class: 'kit-muted' }, ui.el('span', { text: t('identities.users.col.last_login') }), ' ', timeOrDash(cx, user.last_login_at)) : null),
    user.status === 'deleted' ? ui.el('p', { class: 'zt-banner', text: t('entity.user.tombstone') }) : null);
  // State-appropriate primary actions.
  if (actionsRow && (user.status === 'active' || user.status === 'disabled')) {
    const disabled = user.status === 'disabled';
    const route = disabled ? 'users/enable' : 'users/disable';
    const run = async () => {
      const result = await formDialog(cx, {
        title: disabled ? 'identities.user.enable.title' : 'identities.user.disable.title', intro: t(disabled ? 'identities.user.enable.effect' : 'identities.user.disable.effect', { user: label || userId }),
        confirm: disabled ? null : (label || userId), confirmLabel: disabled ? 'identities.user.enable' : 'identities.user.disable', danger: !disabled,
        submit: values => hopae(cx, route, { json: { id: userId }, reason: values.reason }),
      });
      if (!result) return;
      ui.clear(status, outcomeBanner(cx, 'committed', disabled ? 'identities.user.enabled' : 'identities.user.disabled', { sessions: result.data?.sessions_terminated ?? 0, operation: result.operation || '—' }));
      setTimeout(() => cx.navigate(`${location.hash.split('?')[0]}?updated=${Date.now()}`), 900);
    };
    const endAll = async () => {
      const result = await formDialog(cx, { title: 'identities.user.end_sessions.title', intro: t('identities.user.end_sessions.effect', { user: label || userId }), confirm: label || userId, confirmLabel: 'identities.user.end_sessions', danger: true,
        submit: values => hopae(cx, 'users/sessions-terminate', { json: { id: userId }, reason: values.reason }) });
      if (result) ui.clear(status, outcomeBanner(cx, 'committed', 'identities.user.sessions_ended', { count: result.data?.terminated ?? 0, operation: result.operation || '—' }));
    };
    actionsRow.append(
      can(caps, 'users/sessions-terminate') ? button(cx, 'identities.user.end_sessions', endAll) : ui.disabledAction(t, 'identities.user.end_sessions', 'identities.gap.not_declared'),
      can(caps, route) ? button(cx, disabled ? 'identities.user.enable' : 'identities.user.disable', run, { kind: disabled ? 'primary' : 'danger' }) : ui.disabledAction(t, disabled ? 'identities.user.enable' : 'identities.user.disable', 'identities.gap.not_declared'));
  }
  // Tabs (links keep each tab deep-linkable; arrow keys move between them).
  const tabs = ui.el('nav', { class: 'zt-tabs', attrs: { 'aria-label': t('identities.user.tabs') } });
  for (const name of TABS) tabs.append(ui.el('a', { href: `#identities/users/${encodeURIComponent(id)}/${name}`, text: t(`identities.user.tab.${name}`), dataset: { tab: name }, attrs: { 'aria-current': name === active ? 'page' : false } }));
  tabs.addEventListener('keydown', event => {
    if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
    const links = [...tabs.querySelectorAll('a')], index = links.indexOf(document.activeElement);
    if (index < 0) return;
    event.preventDefault();
    links[(index + (event.key === 'ArrowRight' ? 1 : links.length - 1)) % links.length].focus();
  });
  const panelBox = ui.el('div', { class: 'zt-content zt-tab-panel', dataset: { tab: active } });
  content.append(tabs, panelBox);
  if ((user.status === 'unknown' || user.status === 'unresolved') && active !== 'activity') {
    panelBox.append(ui.emptyState(t, { title: user.status === 'unknown' ? 'identities.user.unknown' : 'identities.user.unresolved', body: 'identities.user.unknown.body', action: ui.el('a', { class: 'button button-quiet', href: `#identities/users/${encodeURIComponent(id)}/activity`, text: t('identities.user.tab.activity') }) }));
    return;
  }
  const render = { profile: profileTab, authentication: authenticationTab, sessions: sessionsTab, groups: groupsTab, access: accessTab, activity: activityTab }[active];
  panelBox.append(...await render(cx, user, caps));
}
