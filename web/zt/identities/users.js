// Identities ▸ Users: server-side search (Hopae `subjects/search`), the full
// listing (`users/query`), group membership (`groups/get`) and bulk disable.
// Hopae package 0.1.10 filters the listing itself (q, status, provider, MFA,
// group) and disables up to 100 users per call with per-item results.
import { can, hopae, failure, sectionPage, notConnected, timeOrDash, subjectStatus, userLink, unavailableField, outcomeBanner, errorText, isUncertain, capabilities, sourceBadge, modern, hopaeStatus } from './common.js';

const STATUSES = Object.freeze(['active', 'disabled']);
const MFA = Object.freeze(['enrolled', 'none']);
const BULK_LIMIT = 100;
const PAGE = 50;

/** One list row from any of the three sources. */
function fromUser(item) {
  return { id: item.user_id, label: item.display_name || item.username || item.primary_email || null, email: item.primary_email || null, status: item.status === 'disabled' ? 'disabled' : 'active', providers: null, groups: null, lastLogin: item.last_login_at ?? null, created: item.created_at ?? null, sessions: Number.isFinite(item.live_sessions) ? item.live_sessions : null, role: item.role || null };
}
function fromSubject(item) {
  return { id: item.user_id || item.id, label: item.display_name || item.email || null, email: item.email || null, status: item.status, providers: Array.isArray(item.providers) ? item.providers : [], groups: Array.isArray(item.groups) ? item.groups : null, lastLogin: item.last_login_at ?? null, created: item.created_at ?? null, sessions: null, role: null };
}

/** Adds providers and groups from one `subjects/resolve` call (≤100 IDs). */
async function enrich(cx, rows) {
  const ids = rows.filter(row => row.id && (row.providers === null || row.groups === null)).map(row => row.id);
  if (!ids.length) return;
  let data = null;
  try { ({ data } = await hopae(cx, 'subjects/resolve', { json: { ids: ids.slice(0, 100), include_groups: true } })); }
  catch (error) {
    if (error?.status === 401) throw error;
    // A Hopae without groups refuses the unknown field; providers still resolve.
    if (error?.status === 400) { try { ({ data } = await hopae(cx, 'subjects/resolve', { json: { ids: ids.slice(0, 100) } })); } catch (inner) { if (inner?.status === 401) throw inner; } }
  }
  const byId = new Map((Array.isArray(data?.items) ? data.items : []).map(item => [item.id, item]));
  for (const row of rows) {
    const item = byId.get(row.id);
    if (!item) continue;
    if (row.providers === null) row.providers = Array.isArray(item.providers) ? item.providers : [];
    if (row.groups === null && Array.isArray(item.groups)) row.groups = item.groups;
    if (!row.label) row.label = item.display_name || item.email || null;
  }
}

function filters(cx, params, caps, groups, apply, providers) {
  const { t, ui } = cx;
  const form = ui.el('form', { class: 'zt-filters', attrs: { role: 'search', 'aria-label': t('identities.users.filters') } });
  const search = ui.field(t, { label: 'identities.users.search', name: 'q', value: params.get('q') || '', maxLength: 128, placeholder: 'identities.users.search.placeholder', help: 'identities.users.search.help' });
  search.classList.add('zt-field-wide');
  search.querySelector('input').type = 'search';
  const groupField = ui.field(t, { label: 'identities.users.filter.group', name: 'group', value: params.get('group') || '', options: [{ value: '', label: 'identities.filter.any' }, ...groups.map(group => ({ value: group.group_id, label: 'identities.literal' }))] });
  // Group names are data, not message keys: write them as text.
  [...groupField.querySelectorAll('option')].forEach((node, index) => { if (index > 0) node.textContent = `${groups[index - 1].name || groups[index - 1].key} · ${t(`identities.group.source.${groups[index - 1].source}`)}`; });
  if (!can(caps, 'groups/search')) groupField.querySelector('select').disabled = true;
  form.append(search,
    ui.field(t, { label: 'identities.users.filter.status', name: 'status', value: params.get('status') || '', options: [{ value: '', label: 'identities.filter.any' }, ...STATUSES.map(value => ({ value, label: `ui.subject.status.${value}` }))] }),
    groupField,
    modern(caps) ? providerField(cx, params, providers) : unavailableField(cx, 'identities.users.filter.provider', 'identities.gap.provider_filter'),
    modern(caps) ? ui.field(t, { label: 'identities.users.filter.mfa', name: 'mfa', value: params.get('mfa') || '', options: [{ value: '', label: 'identities.filter.any' }, ...MFA.map(value => ({ value, label: `identities.users.mfa.${value}` }))] }) : unavailableField(cx, 'identities.users.filter.mfa', 'identities.gap.mfa_filter'),
    ui.el('div', { class: 'button-row zt-filter-actions' },
      ui.el('button', { type: 'submit', class: 'button button-primary', text: t('identities.users.apply') }),
      ui.el('button', { type: 'button', class: 'button button-quiet', text: t('identities.users.reset'), on: { click: () => apply(new URLSearchParams()) } })));
  const active = ['q', 'status', 'group', 'provider', 'mfa'].filter(name => params.get(name)).length;
  const sheet = ui.el('details', { class: 'zt-filter-sheet', open: window.matchMedia('(min-width: 721px)').matches || active > 0 }, ui.el('summary', { text: t('identities.users.filters.summary', { count: active }) }), form);
  form.addEventListener('submit', event => {
    event.preventDefault();
    if (!form.reportValidity()) return;
    const next = new URLSearchParams();
    for (const name of ['q', 'status', 'group', 'provider', 'mfa']) { const value = form.elements[name]?.value.trim(); if (value) next.set(name, value); }
    apply(next);
  });
  return sheet;
}

function providerField(cx, params, providers) {
  const { t, ui } = cx;
  const node = ui.field(t, { label: 'identities.users.filter.provider', name: 'provider', value: params.get('provider') || '', options: [{ value: '', label: 'identities.filter.any' }, ...providers.map(provider => ({ value: provider.provider_id, label: 'identities.literal' }))] });
  // Provider names are data: write them as text.
  [...node.querySelectorAll('option')].forEach((option, index) => { if (index > 0) option.textContent = providers[index - 1].display_name || providers[index - 1].provider_id; });
  return node;
}

export async function renderUsers(cx, root, params) {
  const { t, ui } = cx;
  const caps = await capabilities(cx);
  if (cx.signal.aborted) return;
  const selected = new Map();
  const bulkCount = ui.el('span', { class: 'zt-bulk-count', attrs: { 'aria-live': 'polite' } });
  const bulkDisable = ui.el('button', { type: 'button', class: 'button button-danger', text: t('identities.users.bulk.disable'), disabled: true });
  const bulkClear = ui.el('button', { type: 'button', class: 'button button-quiet', text: t('identities.users.bulk.clear'), disabled: true });
  const bulkBar = ui.el('div', { class: 'zt-bulk', attrs: { role: 'region', 'aria-label': t('identities.users.bulk.region') } }, bulkCount, can(caps, 'users/disable') ? bulkDisable : ui.disabledAction(t, 'identities.users.bulk.disable', 'identities.gap.not_declared'), bulkClear);
  const results = ui.el('div', { class: 'zt-bulk-results' });
  const { content } = sectionPage(cx, root, { active: 'users', title: t('identities.page.users'), owner: t('identities.users.owner') });
  if (!caps.installed) { content.append(notConnected(cx, caps, 'users/query')); return; }
  const groupList = [];
  if (can(caps, 'groups/search')) {
    try { const { data } = await hopae(cx, 'groups/search', { json: { limit: 100 } }); groupList.push(...(Array.isArray(data?.items) ? data.items : [])); }
    catch (error) { if (error?.status === 401) throw error; }
    if (cx.signal.aborted) return;
  }
  const apply = next => cx.navigate(cx.hashFor('identities', ['users'], next));
  const q = params.get('q') || '', status = STATUSES.includes(params.get('status')) ? params.get('status') : '', group = params.get('group') || '';
  const provider = /^[a-z0-9][a-z0-9_-]{0,31}$/.test(params.get('provider') || '') ? params.get('provider') : '', mfa = MFA.includes(params.get('mfa')) ? params.get('mfa') : '';
  const serverFilters = modern(caps);
  const providers = serverFilters ? ((await hopaeStatus(cx, caps))?.providers || []) : [];
  if (cx.signal.aborted) return;
  const notes = ui.el('div', { class: 'zt-notes' });
  if (status && !q && !group && !serverFilters) notes.append(ui.el('p', { class: 'zt-banner', attrs: { role: 'note' }, text: t('identities.users.status_needs_search') }));
  const sync = () => {
    bulkCount.textContent = selected.size ? t('identities.users.bulk.count', { count: selected.size }) : t('identities.users.bulk.none');
    bulkDisable.disabled = !selected.size; bulkClear.disabled = !selected.size;
  };
  sync();
  const checkbox = row => {
    const box = ui.el('input', { type: 'checkbox', checked: selected.has(row.id), disabled: row.status !== 'active', attrs: { 'aria-label': t('identities.users.select', { user: row.label || row.id }) } });
    box.addEventListener('change', () => { if (box.checked) selected.set(row.id, row); else selected.delete(row.id); sync(); });
    return box;
  };
  // 0.1.10 filters on the server; older packages pick the listing that can answer.
  const route = serverFilters ? 'users/query' : group ? 'groups/get' : q ? 'subjects/search' : 'users/query';
  const filtered = Boolean(q || status || group || provider || mfa);
  const groupView = { current: null };
  const columns = [
    { key: 'select', label: 'identities.users.col.select', render: checkbox, title: () => '' },
    { key: 'user', label: 'identities.users.col.user', render: row => ui.el('span', { class: 'zt-stack' }, userLink(cx, { id: row.id, label: row.label }), row.email && row.email !== row.label ? ui.el('span', { class: 'kit-muted', text: row.email }) : null) },
    { key: 'status', label: 'identities.users.col.status', render: row => subjectStatus(cx, row.status) },
    { key: 'providers', label: 'identities.users.col.providers', render: row => row.providers?.length ? ui.el('span', { class: 'zt-chips' }, row.providers.map(provider => ui.el('span', { class: 'kit-tag', text: provider }))) : ui.el('span', { class: 'kit-muted', text: t(row.providers ? 'identities.none' : 'identities.unreported') }) },
    { key: 'groups', label: 'identities.users.col.groups', render: row => row.groups?.length ? ui.el('span', { class: 'zt-chips' }, row.groups.slice(0, 3).map(item => ui.el('a', { class: 'kit-tag', href: `#identities/groups/${encodeURIComponent(item.group_id)}`, text: item.name || item.group_id })), row.groups.length > 3 ? ui.el('span', { class: 'kit-muted', text: t('identities.more', { count: row.groups.length - 3 }) }) : null) : ui.el('span', { class: 'kit-muted', text: t(row.groups ? 'identities.none' : 'identities.unreported') }) },
    { key: 'last_login', label: 'identities.users.col.last_login', render: row => timeOrDash(cx, row.lastLogin) },
    { key: 'sessions', label: 'identities.users.col.sessions', render: row => row.sessions === null ? ui.el('span', { class: 'kit-muted', text: t('identities.unreported') }) : ui.el('span', { class: 'zt-num', text: String(row.sessions) }) },
    { key: 'created', label: 'identities.users.col.created', render: row => timeOrDash(cx, row.created), hidden: true },
  ];
  const table = ui.dataTable(t, {
    id: 'identities-users', caption: 'identities.users.caption', owner: 'ui.owner.hopae', columns, sortable: 'none', rowKey: row => row.id,
    empty: { title: group && !q && !provider && !mfa ? 'identities.users.empty.group' : filtered ? 'identities.users.empty.search' : 'identities.users.empty', body: filtered ? 'identities.users.empty.search.body' : 'identities.users.empty.body' },
    onRowOpen: row => cx.navigate(`#identities/users/${encodeURIComponent(row.id)}`),
    fetchPage: async ({ cursor }) => {
      let rows = [], nextCursor = null;
      if (route === 'groups/get') {
        const { data } = await hopae(cx, route, { json: { group_id: group, members_limit: PAGE, ...(cursor ? { members_cursor: cursor } : {}) } });
        groupView.current = data?.group || null;
        rows = (Array.isArray(data?.members) ? data.members : []).map(member => fromSubject(member.subject || {})).filter(row => !status || row.status === status);
        nextCursor = data?.next_members_cursor || null;
      } else if (route === 'subjects/search') {
        const { data } = await hopae(cx, route, { json: { q, kind: 'human', limit: PAGE, ...(status ? { status } : {}), ...(cursor ? { cursor } : {}) } });
        rows = (Array.isArray(data?.items) ? data.items : []).filter(item => item.status !== 'unknown').map(fromSubject);
        nextCursor = data?.next_cursor || null;
      } else {
        const filters = serverFilters ? { ...(q ? { q } : {}), ...(status ? { status } : {}), ...(provider ? { provider } : {}), ...(mfa ? { mfa } : {}), ...(group ? { group } : {}) } : {};
        if (serverFilters && group && !groupView.current) groupView.current = groupList.find(item => item.group_id === group) || null;
        const { data } = await hopae(cx, route, { json: { limit: PAGE, ...filters, ...(cursor ? { cursor } : {}) } });
        rows = (Array.isArray(data?.items) ? data.items : []).map(fromUser);
        nextCursor = data?.next_cursor || null;
      }
      await enrich(cx, rows);
      return { items: rows, nextCursor };
    },
    onPage: () => { if (groupView.current) ui.clear(notes, ui.el('p', { class: 'zt-banner', attrs: { role: 'note' } }, ui.el('span', { text: t('identities.users.group_scope') }), ' ', ui.el('a', { href: `#identities/groups/${encodeURIComponent(groupView.current.group_id)}`, text: groupView.current.name || groupView.current.key }), ' ', sourceBadge(cx, groupView.current.source, groupView.current.provider_id))); },
  });
  cx.signal.addEventListener('abort', () => table.destroy(), { once: true });
  bulkClear.addEventListener('click', () => { selected.clear(); table.element.querySelectorAll('tbody input[type=checkbox]').forEach(box => { box.checked = false; }); sync(); });
  bulkDisable.addEventListener('click', async () => {
    const targets = [...selected.values()];
    const target = t('identities.users.bulk.target', { count: targets.length });
    const confirmed = await ui.confirmDialog(t, { title: 'identities.users.bulk.title', effect: 'identities.users.bulk.effect', target, confirmLabel: 'identities.users.bulk.confirm' });
    if (!confirmed) return;
    bulkDisable.disabled = true;
    const list = ui.el('ul', { class: 'zt-result-list' });
    ui.clear(results, ui.el('h2', { class: 'zt-subhead', text: t('identities.users.bulk.results') }), list);
    let committed = 0, refused = 0, uncertain = 0;
    const label = new Map(targets.map(row => [row.id, row]));
    const show = (id, kind, key, params) => list.append(ui.el('li', {}, userLink(cx, { id, label: label.get(id)?.label }), ' ', outcomeBanner(cx, kind, key, params)));
    if (can(caps, 'users/bulk-disable')) {
      // One audited call per 100 users; Hopae answers every item in order.
      for (let start = 0; start < targets.length; start += BULK_LIMIT) {
        const ids = targets.slice(start, start + BULK_LIMIT).map(row => row.id);
        try {
          const { data, operation } = await hopae(cx, 'users/bulk-disable', { json: { ids, reason: confirmed.reason }, reason: confirmed.reason });
          for (const item of Array.isArray(data?.items) ? data.items : []) {
            if (item.result === 'disabled' || item.result === 'unchanged') { committed += 1; selected.delete(item.id); show(item.id, 'committed', item.result === 'unchanged' ? 'identities.users.bulk.unchanged' : 'identities.users.bulk.done', { sessions: item.sessions_terminated ?? 0, operation: operation || '—' }); }
            else if (item.result === 'not_attempted') { refused += 1; show(item.id, 'refused', 'identities.users.bulk.not_attempted'); }
            else { refused += 1; show(item.id, 'refused', 'identities.literal', { value: t(`identities.users.bulk.error.${['invalid_id', 'not_found', 'self_target'].includes(item.error) ? item.error : 'other'}`) }); }
          }
          if (data?.halted) results.prepend(ui.el('p', { class: 'zt-banner zt-banner-warn', attrs: { role: 'alert' }, text: t('identities.users.bulk.halted') }));
        } catch (error) {
          if (error?.status === 401) throw error;
          const unsure = isUncertain(error) || !error?.status || error.status >= 500;
          for (const id of ids) { if (unsure) uncertain += 1; else refused += 1; show(id, unsure ? 'uncertain' : 'refused', 'identities.literal', { value: errorText(t, error) }); }
        }
      }
    } else for (const row of targets) {
      // Older packages: one call per user.
      try {
        const { data, operation } = await hopae(cx, 'users/disable', { json: { id: row.id }, reason: confirmed.reason });
        committed += 1; selected.delete(row.id);
        show(row.id, 'committed', 'identities.users.bulk.done', { sessions: data?.sessions_terminated ?? 0, operation: operation || '—' });
      } catch (error) {
        if (error?.status === 401) throw error;
        const unsure = isUncertain(error) || !error?.status || error.status >= 500;
        if (unsure) uncertain += 1; else refused += 1;
        show(row.id, unsure ? 'uncertain' : 'refused', 'identities.literal', { value: errorText(t, error) });
      }
    }
    results.prepend(outcomeBanner(cx, uncertain ? 'uncertain' : refused ? 'refused' : 'committed', 'identities.users.bulk.summary', { committed, refused, uncertain }));
    sync();
    table.refresh();
  });
  content.append(filters(cx, params, caps, groupList, apply, providers), notes, bulkBar, results, table.element);
  await table.reload();
}
