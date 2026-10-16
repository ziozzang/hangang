// Identities ▸ Groups (Hopae docs/GROUPS.md): local groups are written by
// administrators with `expected_revision` and a reason; LDAP and OpenID
// Connect groups are written only by their provider's sync and are read-only.
import { can, hopae, failure, sectionPage, notConnected, capabilities, timeOrDash, sourceBadge, userLink, subjectStatus, formDialog, outcomeBanner, facts, panel, button } from './common.js';

const SOURCES = Object.freeze(['local', 'ldap', 'oidc']);

function groupLink(cx, group) {
  const { ui } = cx;
  return ui.el('a', { class: 'zt-stack', href: `#identities/groups/${encodeURIComponent(group.group_id)}` }, ui.el('strong', { text: group.name || group.key || group.group_id }), ui.el('span', { class: 'kit-entity-id', text: group.key && group.key !== group.name ? group.key : group.group_id }));
}

function stateBadge(cx, group) {
  return group.state === 'deleted' ? cx.ui.statusBadge(cx.t, 'stale', 'identities.group.state.deleted') : cx.ui.statusBadge(cx.t, 'healthy', 'identities.group.state.active');
}

export async function createGroup(cx) {
  return formDialog(cx, {
    title: 'identities.group.create.title', confirmLabel: 'identities.group.create',
    fields: [
      { label: 'identities.group.field.key', name: 'key', pattern: '[A-Za-z0-9._:\\-]{1,128}', maxLength: 128, help: 'identities.group.help.key' },
      { label: 'identities.group.field.name', name: 'name', maxLength: 256 },
      { label: 'identities.group.field.description', name: 'description', maxLength: 1024 },
    ],
    submit: values => hopae(cx, 'groups/create', { json: { key: values.key, name: values.name || values.key, description: values.description, reason: values.reason }, reason: values.reason }),
  });
}

export async function renderGroups(cx, root, params) {
  const { t, ui } = cx;
  const caps = await capabilities(cx);
  if (cx.signal.aborted) return;
  const canCreate = can(caps, 'groups/create');
  const create = canCreate ? button(cx, 'identities.group.create', async () => {
    const result = await createGroup(cx);
    if (result?.data?.group) cx.navigate(`#identities/groups/${encodeURIComponent(result.data.group.group_id)}`);
  }, { kind: 'primary' }) : ui.disabledAction(t, 'identities.group.create', 'identities.gap.not_declared');
  const { content } = sectionPage(cx, root, { active: 'groups', title: t('identities.page.groups'), owner: t('identities.groups.owner'), actions: caps.installed ? [create] : [] });
  if (!caps.installed || !can(caps, 'groups/search')) { content.append(notConnected(cx, caps, 'groups/search')); return; }
  const q = params.get('q') || '', source = SOURCES.includes(params.get('source')) ? params.get('source') : '', deleted = params.get('deleted') === '1';
  const form = ui.el('form', { class: 'zt-filters', attrs: { role: 'search', 'aria-label': t('identities.groups.filters') } });
  const search = ui.field(t, { label: 'identities.groups.search', name: 'q', value: q, maxLength: 128, placeholder: 'identities.groups.search.placeholder' });
  search.classList.add('zt-field-wide');
  search.querySelector('input').type = 'search';
  const deletedId = `zt-deleted-${Math.random().toString(36).slice(2, 6)}`;
  form.append(search,
    ui.field(t, { label: 'identities.groups.filter.source', name: 'source', value: source, options: [{ value: '', label: 'identities.filter.any' }, ...SOURCES.map(value => ({ value, label: `identities.group.source.${value}` }))] }),
    ui.el('label', { class: 'zt-check', htmlFor: deletedId }, ui.el('input', { type: 'checkbox', id: deletedId, name: 'deleted', checked: deleted }), ui.el('span', { text: t('identities.groups.filter.deleted') })),
    ui.el('div', { class: 'button-row zt-filter-actions' }, ui.el('button', { type: 'submit', class: 'button button-primary', text: t('identities.users.apply') }), ui.el('a', { class: 'button button-quiet', href: '#identities/groups', text: t('identities.users.reset') })));
  form.addEventListener('submit', event => {
    event.preventDefault();
    const next = new URLSearchParams();
    if (form.elements.q.value.trim()) next.set('q', form.elements.q.value.trim());
    if (form.elements.source.value) next.set('source', form.elements.source.value);
    if (form.elements.deleted.checked) next.set('deleted', '1');
    cx.navigate(cx.hashFor('identities', ['groups'], next));
  });
  const columns = [
    { key: 'group', label: 'identities.group.col.group', render: group => groupLink(cx, group) },
    { key: 'source', label: 'identities.group.col.source', render: group => sourceBadge(cx, group.source, group.provider_id) },
    { key: 'members', label: 'identities.group.col.members', render: group => ui.el('span', { class: 'zt-num', text: String(group.members ?? 0) }) },
    { key: 'state', label: 'identities.group.col.state', render: group => stateBadge(cx, group) },
    { key: 'updated', label: 'identities.group.col.updated', render: group => timeOrDash(cx, group.updated_at) },
    { key: 'synced', label: 'identities.group.col.synced', render: group => group.source === 'local' ? ui.el('span', { class: 'kit-muted', text: t('identities.group.synced.local') }) : timeOrDash(cx, group.last_seen_at) },
  ];
  const table = ui.dataTable(t, {
    id: 'identities-groups', caption: 'identities.groups.caption', owner: 'ui.owner.hopae', columns, sortable: 'none', rowKey: group => group.group_id,
    empty: { title: q || source ? 'identities.groups.empty.search' : 'identities.groups.empty', body: 'identities.groups.empty.body' },
    onRowOpen: group => cx.navigate(`#identities/groups/${encodeURIComponent(group.group_id)}`),
    fetchPage: async ({ cursor }) => {
      const { data } = await hopae(cx, 'groups/search', { json: { limit: 50, ...(q ? { q } : {}), ...(source ? { source } : {}), ...(deleted ? { include_deleted: true } : {}), ...(cursor ? { cursor } : {}) } });
      return { items: Array.isArray(data?.items) ? data.items : [], nextCursor: data?.next_cursor || null };
    },
  });
  cx.signal.addEventListener('abort', () => table.destroy(), { once: true });
  content.append(form, table.element);
  await table.reload();
}

export async function renderGroup(cx, root, id) {
  const { t, ui } = cx;
  const caps = await capabilities(cx);
  if (cx.signal.aborted) return;
  const view = sectionPage(cx, root, { active: 'groups', crumbs: [{ label: t('identities.page.groups'), href: '#identities/groups' }, { label: id }], title: id, owner: t('identities.group.owner') });
  const { content, heading } = view;
  if (!caps.installed || !can(caps, 'groups/get')) { content.append(notConnected(cx, caps, 'groups/get')); return; }
  const summary = ui.el('div', { class: 'zt-entity-summary' }, ui.loadingState(t));
  const status = ui.el('div', { class: 'zt-notes' });
  const members = ui.el('div');
  content.append(summary, status, members);
  let group = null;
  const actionsRow = root.querySelector('.zt-actions');
  const write = async (extra, okKey) => {
    const result = await formDialog(cx, extra.dialog);
    if (!result) return;
    ui.clear(status, outcomeBanner(cx, 'committed', okKey, { operation: result.operation || '—' }));
    await load();
  };
  const columns = local => [
    { key: 'user', label: 'identities.group.member.col.user', render: member => userLink(cx, { id: member.subject?.user_id || member.subject?.id, label: member.subject?.status !== 'deleted' ? (member.subject?.display_name || member.subject?.email) : null }) },
    { key: 'status', label: 'identities.users.col.status', render: member => subjectStatus(cx, member.subject?.status) },
    { key: 'since', label: 'identities.group.member.col.since', render: member => timeOrDash(cx, member.membership?.first_seen_at) },
    { key: 'expires', label: 'identities.group.member.col.expires', render: member => member.membership?.removal_pending_at ? ui.el('span', { class: 'kit-tag kit-tag-warn', text: t('identities.group.member.pending_removal') }) : member.membership?.expires_at ? timeOrDash(cx, member.membership.expires_at) : ui.el('span', { class: 'kit-muted', text: t('identities.group.member.no_expiry') }) },
    { key: 'added_by', label: 'identities.group.member.col.added_by', render: member => ui.el('span', { text: member.membership?.reason || (local ? t('identities.none') : t('identities.group.member.synced')) }), hidden: !local },
    { key: 'actions', label: 'identities.session.col.actions', title: () => '', render: member => local && group.state !== 'deleted'
      ? (can(caps, 'groups/members/remove') ? ui.el('button', { type: 'button', class: 'button button-quiet zt-row-action', text: t('identities.group.member.remove'), on: { click: event => { event.stopPropagation(); const user = member.subject?.user_id || member.subject?.id; write({ dialog: { title: 'identities.group.member.remove.title', intro: t('identities.group.member.remove.effect', { user: member.subject?.display_name || user, group: group.name }), confirmLabel: 'identities.group.member.remove', danger: true, submit: values => hopae(cx, 'groups/members/remove', { json: { group_id: group.group_id, expected_revision: group.revision, user_id: user, reason: values.reason }, reason: values.reason }) } }, 'identities.group.member.removed'); } } }) : ui.disabledAction(t, 'identities.group.member.remove', 'identities.gap.not_declared'))
      : ui.el('span', { class: 'kit-muted', text: t('identities.group.read_only.short') }) },
  ];
  async function load() {
    let data;
    try { ({ data } = await hopae(cx, 'groups/get', { json: { group_id: id, members_limit: 0 } })); }
    catch (error) { ui.clear(summary, failure(cx, error, load)); return; }
    if (cx.signal.aborted) return;
    group = data?.group;
    if (!group) { ui.clear(summary, ui.emptyState(t, { title: 'identities.group.missing', body: 'identities.group.missing.body' })); return; }
    heading.textContent = group.name || group.key;
    const crumb = root.querySelector('.zt-crumbs [aria-current="page"]');
    if (crumb) crumb.textContent = group.name || group.key;
    const local = group.source === 'local';
    ui.clear(summary,
      ui.el('div', { class: 'zt-subject-state' }, stateBadge(cx, group), sourceBadge(cx, group.source, group.provider_id), ui.el('span', { class: 'kit-tag', text: t('ui.revision', { revision: group.revision }) })),
      local ? null : ui.el('p', { class: 'zt-banner', attrs: { role: 'note' }, text: t(group.source === 'ldap' ? 'identities.group.read_only.ldap' : 'identities.group.read_only.oidc', { provider: group.provider_id || '—' }) }),
      group.state === 'deleted' ? ui.el('p', { class: 'zt-banner zt-banner-warn', attrs: { role: 'note' }, text: t('identities.group.tombstone') }) : null,
      facts(cx, [
        ['identities.group.field.key', ui.el('code', { class: 'kit-mono', text: group.key })],
        ['identities.group.field.ref', ui.el('span', {}, ui.el('code', { class: 'kit-mono', text: group.group_id }), ui.copyButton(t, group.group_id))],
        ['identities.group.field.description', group.description || null],
        ['identities.group.col.members', String(group.members ?? 0)],
        ['identities.group.field.created', timeOrDash(cx, group.created_at)],
        ['identities.group.col.updated', timeOrDash(cx, group.updated_at)],
        [local ? null : 'identities.group.col.synced', local ? null : timeOrDash(cx, group.last_seen_at)],
        ['identities.group.field.deleted', group.deleted_at ? timeOrDash(cx, group.deleted_at) : null],
      ].filter(([key]) => key)));
    // State-appropriate actions: local and live groups only.
    if (actionsRow) {
      ui.clear(actionsRow);
      if (local && group.state !== 'deleted') {
        const action = (route, label, handler, kind) => can(caps, route) ? button(cx, label, handler, { kind }) : ui.disabledAction(t, label, 'identities.gap.not_declared');
        actionsRow.append(
          action('groups/members/add', 'identities.group.member.add', () => write({ dialog: { title: 'identities.group.member.add.title', intro: t('identities.group.member.add.effect', { group: group.name }), confirmLabel: 'identities.group.member.add',
            fields: [{ node: ui.subjectPicker(t, cx.api, { label: 'identities.group.member.user', name: 'user_id', help: 'identities.group.member.user.help' }), name: 'user_id' }, { label: 'identities.group.member.expires', name: 'expires', type: 'date', help: 'identities.group.member.expires.help' }],
            submit: values => hopae(cx, 'groups/members/add', { json: { group_id: group.group_id, expected_revision: group.revision, user_id: values.user_id, ...(values.expires ? { expires_at: Math.floor(new Date(`${values.expires}T23:59:59`).getTime() / 1000) } : {}), reason: values.reason }, reason: values.reason }) } }, 'identities.group.member.added'), 'primary'),
          action('groups/update', 'identities.group.edit', () => write({ dialog: { title: 'identities.group.edit.title', confirmLabel: 'identities.group.edit.save',
            fields: [{ label: 'identities.group.field.name', name: 'name', value: group.name || '', maxLength: 256 }, { label: 'identities.group.field.description', name: 'description', value: group.description || '', maxLength: 1024 }],
            submit: values => hopae(cx, 'groups/update', { json: { group_id: group.group_id, expected_revision: group.revision, name: values.name, description: values.description, reason: values.reason }, reason: values.reason }) } }, 'identities.group.updated')),
          action('groups/delete', 'identities.group.delete', () => write({ dialog: { title: 'identities.group.delete.title', intro: t('identities.group.delete.effect', { group: group.name, count: group.members ?? 0 }), confirm: group.name || group.key, confirmLabel: 'identities.group.delete', danger: true,
            submit: values => hopae(cx, 'groups/delete', { json: { group_id: group.group_id, expected_revision: group.revision, reason: values.reason }, reason: values.reason }) } }, 'identities.group.deleted'), 'danger'));
      }
    }
    const table = ui.dataTable(t, {
      id: `identities-group-members-${local ? 'local' : 'provider'}`, caption: 'identities.group.members.caption', owner: 'ui.owner.hopae', columns: columns(local), sortable: 'none', rowKey: member => member.subject?.id || member.subject?.user_id,
      empty: { title: 'identities.group.members.empty', body: local ? 'identities.group.members.empty.local' : 'identities.group.members.empty.provider' },
      onRowOpen: member => cx.navigate(`#identities/users/${encodeURIComponent(member.subject?.user_id || member.subject?.id)}`),
      fetchPage: async ({ cursor }) => {
        const { data: page } = await hopae(cx, 'groups/get', { json: { group_id: id, members_limit: 50, ...(cursor ? { members_cursor: cursor } : {}) } });
        return { items: Array.isArray(page?.members) ? page.members : [], nextCursor: page?.next_members_cursor || null };
      },
    });
    cx.signal.addEventListener('abort', () => table.destroy(), { once: true });
    ui.clear(members, panel(cx, 'identities.group.members.title', table.element, { params: { count: group.members ?? 0 }, actions: [ui.el('a', { class: 'button button-quiet', href: cx.hashFor('identities', ['users'], new URLSearchParams({ group: group.group_id })), text: t('identities.group.members.open') })] }));
    await table.reload();
  }
  await load();
}
