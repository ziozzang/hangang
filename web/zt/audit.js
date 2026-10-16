// Unified administrative audit: one timeline federated from the authorities'
// own journals. Each source keeps its ownership; a failed source is labelled
// and never shown as "no activity"; a source whose operation is not installed
// is shown as not connected.
const SOURCES = Object.freeze(['accounts', 'plugins', 'pumgye', 'hopae', 'sumunjang']);
const OUTCOMES = Object.freeze(['committed', 'refused', 'uncertain']);
const PLUGIN_LABELS = Object.freeze({ hopae: 'ui.owner.hopae', guard: 'ui.owner.sumunjang' });
const HOPAE_KINDS = Object.freeze(['admin.user_disable', 'admin.user_enable', 'admin.session_terminate', 'admin.sessions_terminate', 'admin.grant', 'admin.revoke', 'admin.denied']);

function outcomeFromStatus(status) {
  if (!Number.isFinite(status)) return 'uncertain';
  if (status >= 200 && status < 300) return 'committed';
  if (status >= 400 && status < 500) return 'refused';
  return 'uncertain';
}

/** What changed between two account states, as `field: before → after` parts. */
function accountChanges(t, before, after) {
  const parts = [];
  if (before?.role !== after?.role && after?.role) parts.push(t('audit.change.role', { before: before?.role ?? '—', after: after.role }));
  if (before && after && before.enabled !== after.enabled) parts.push(t(after.enabled ? 'audit.change.enabled' : 'audit.change.disabled'));
  return parts;
}

async function settle(cx, path, options) {
  try { return { ok: true, data: (await cx.api(path, options)).data }; }
  catch (error) {
    if (error?.status === 401) throw error;
    return { ok: false, missing: error?.status === 404, error };
  }
}

/** Loads one page per source and merges newest first. */
export async function loadAuditRecords(cx) {
  const { t } = cx;
  const failures = [], disconnected = [];
  const records = [];
  const [accounts, users, plugins, pumgye, hopae, sumunjang] = await Promise.all([
    settle(cx, '/v1/audit/users?limit=100'), settle(cx, '/v1/users'), settle(cx, '/v1/plugins/audit'), settle(cx, '/v1/pumgye/audit'),
    settle(cx, '/v1/plugins/hopae/events/query', { method: 'POST', json: { limit: 200 } }),
    settle(cx, '/v1/plugins/guard/audit'),
  ]);
  const names = new Map();
  if (users.ok) for (const user of users.data?.users || []) if (user && Number.isFinite(user.id)) names.set(user.id, user.username);
  const account = id => names.get(id) ?? `#${id}`;
  if (accounts.ok) {
    for (const record of accounts.data?.records || []) {
      const target = record.target_user_id ? account(record.target_user_id) : null;
      const changes = accountChanges(t, record.before, record.after);
      const summary = record.action === 'create' ? t('audit.summary.account_create', { target, role: record.after?.role ?? '—' })
        : record.action === 'delete' ? t('audit.summary.account_delete', { target })
        : record.action === 'update' ? (changes.length ? t('audit.summary.account_update', { target, changes: changes.join(', ') }) : t('audit.summary.account_password', { target }))
        : t(`audit.summary.account.${record.action}`, { count: record.affected_count ?? 0, revision: record.policy_revision ?? 0 });
      records.push({ id: `accounts:${record.id}`, source: 'accounts', time: new Date(record.time_unix_ms), actor: record.actor_user_id ? account(record.actor_user_id) : t(`audit.actor.${record.actor_kind || 'unknown'}`), action: `account.${record.action}`, target: target ? { type: 'account', id: target } : null, outcome: 'committed', summary, before: record.before, after: record.after, operation: String(record.id) });
    }
  } else failures.push('accounts');
  if (plugins.ok) {
    for (const operation of plugins.data?.operations || []) {
      const label = t(PLUGIN_LABELS[operation.plugin] || 'ui.owner.host');
      const outcome = operation.completed_at === null ? 'uncertain' : outcomeFromStatus(operation.status);
      records.push({ id: `plugins:${operation.id}`, source: 'plugins', time: new Date((operation.completed_at ?? operation.started_at) * 1000), actor: operation.actor_name, action: `${operation.method} ${operation.path}`, target: { type: 'plugin', id: operation.plugin }, outcome, summary: outcome === 'uncertain' ? t('audit.summary.plugin_uncertain', { owner: label, method: operation.method, path: operation.path }) : t('audit.summary.plugin', { owner: label, method: operation.method, path: operation.path, status: operation.status }), digest: operation.body_sha256, operation: String(operation.id) });
    }
  } else failures.push('plugins');
  if (pumgye.ok) {
    const list = Array.isArray(pumgye.data) ? pumgye.data : pumgye.data?.records || [];
    for (const receipt of list) {
      records.push({ id: `pumgye:${receipt.revision}`, source: 'pumgye', time: new Date((receipt.at_unix ?? 0) * 1000), actor: receipt.actor, action: 'publish', target: { type: 'revision', id: String(receipt.revision) }, outcome: 'committed', summary: t('audit.summary.publish', { revision: receipt.revision }), digest: receipt.sha256, operation: String(receipt.revision) });
    }
  } else failures.push('pumgye');
  // Hopae admin.* events (docs/ADMIN.md "Audit events") through the Hopae package broker.
  if (hopae.ok && Array.isArray(hopae.data?.items)) {
    for (const event of hopae.data.items) {
      if (!event || typeof event.kind !== 'string' || !HOPAE_KINDS.includes(event.kind)) continue;
      const attrs = event.attrs && typeof event.attrs === 'object' ? event.attrs : {};
      const user = typeof event.user_id === 'string' ? event.user_id : null;
      records.push({ id: `hopae:${event.event_id}`, source: 'hopae', time: new Date(Number(event.at) * 1000), actor: typeof attrs.actor === 'string' ? attrs.actor : t('audit.actor.unknown'), action: event.kind, target: user ? { type: 'user', id: user } : null, outcome: event.kind === 'admin.denied' || event.outcome === 'failure' ? 'refused' : 'committed', summary: t(`audit.summary.${event.kind}`, { user: user ?? '—', count: Number(attrs.count) || 0, role: attrs.role ?? '—', previous: attrs.previous_role ?? '—', reason: attrs.reason ?? '—', endpoint: attrs.endpoint ?? '—' }), attrs, operation: String(event.event_id) });
    }
  } else if (hopae.ok || hopae.missing) disconnected.push('hopae');
  else failures.push('hopae');
  // Sumunjang policy audit: wired to the guard package's `audit` read; until
  // that operation ships it reports not connected.
  if (sumunjang.ok && Array.isArray(sumunjang.data?.items ?? sumunjang.data?.records)) {
    for (const entry of sumunjang.data.items ?? sumunjang.data.records) {
      if (!entry || !Number.isFinite(entry.revision)) continue;
      records.push({ id: `sumunjang:${entry.revision}`, source: 'sumunjang', time: new Date(Number(entry.at ?? entry.at_unix ?? 0) * 1000), actor: typeof entry.actor === 'string' ? entry.actor : t('audit.actor.unknown'), action: typeof entry.action === 'string' ? entry.action : 'publish', target: { type: 'revision', id: String(entry.revision) }, outcome: 'committed', summary: t('audit.summary.sumunjang', { revision: entry.revision }), digest: typeof entry.sha256 === 'string' ? entry.sha256 : null, operation: String(entry.revision) });
    }
  } else if (sumunjang.ok || sumunjang.missing) disconnected.push('sumunjang');
  else failures.push('sumunjang');
  records.sort((a, b) => b.time - a.time);
  return { records, failures, disconnected };
}

function detail(cx, record) {
  const { t, ui } = cx;
  const box = ui.el('div', { class: 'zt-audit-detail' }, ui.el('p', { text: record.summary }));
  if (record.before || record.after) box.append(ui.el('h3', { text: t('audit.diff') }), ui.structuredDiff(t, record.before, record.after));
  if (record.attrs && Object.keys(record.attrs).length) box.append(ui.el('h3', { text: t('audit.attributes') }), ui.structuredDiff(t, {}, record.attrs));
  const facts = [[t('audit.col.source'), t(`audit.source.${record.source}`)], [t(`audit.record_id.${record.source}`), ui.el('code', { class: 'kit-mono', text: record.operation })], [t('audit.col.time'), ui.formatFullTime(record.time)]];
  if (record.digest) facts.push([t('audit.digest'), ui.hashChip(t, record.digest, { full: true })]);
  box.append(ui.el('dl', { class: 'zt-dl' }, facts.map(([key, value]) => [ui.el('dt', { text: key }), ui.el('dd', {}, value)])));
  return box;
}

function target(cx, record) {
  const { t, ui } = cx;
  if (!record.target) return '—';
  if (record.target.type === 'plugin') return ui.el('a', { href: `#plugin-${record.target.id}`, text: t(PLUGIN_LABELS[record.target.id] || 'ui.owner.host') });
  if (record.target.type === 'revision') return ui.el('a', { href: record.source === 'sumunjang' ? '#plugin-guard' : '#pumgye', text: t('ui.revision', { revision: record.target.id }) });
  if (record.target.type === 'user') return ui.el('a', { href: ui.entityHref('user', record.target.id), class: 'kit-mono', text: record.target.id });
  return ui.el('span', { text: record.target.id });
}

export async function renderAudit(cx, root, params) {
  const { t, ui } = cx;
  const { content } = cx.page(root, { crumbs: [{ label: t('nav.audit') }], title: t('nav.audit'), owner: t('audit.owner'), actions: [ui.el('a', { class: 'button button-quiet', href: '#account-audit', text: t('audit.manage_accounts') })] });
  const form = ui.el('form', { class: 'zt-filters', attrs: { role: 'search', 'aria-label': t('audit.filters') } },
    ui.field(t, { label: 'audit.filter.source', name: 'source', value: params.get('source') || '', options: [{ value: '', label: 'access.any' }, ...SOURCES.map(value => ({ value, label: `audit.source.${value}` }))] }),
    ui.field(t, { label: 'audit.filter.outcome', name: 'outcome', value: params.get('outcome') || '', options: [{ value: '', label: 'access.any' }, ...OUTCOMES.map(value => ({ value, label: `ui.status.${value}` }))] }),
    ui.field(t, { label: 'audit.filter.actor', name: 'actor', value: params.get('actor') || '', maxLength: 128 }),
    ui.field(t, { label: 'audit.filter.action', name: 'action', value: params.get('action') || '', maxLength: 128 }),
    ui.el('div', { class: 'button-row zt-filter-actions' }, ui.el('button', { type: 'submit', class: 'button button-primary', text: t('access.apply') }), ui.el('button', { type: 'button', class: 'button button-quiet', text: t('access.reset'), on: { click: () => cx.navigate('#audit') } })));
  form.addEventListener('submit', event => {
    event.preventDefault();
    const next = new URLSearchParams();
    for (const name of ['source', 'outcome', 'actor', 'action']) { const value = form.elements[name].value.trim(); if (value) next.set(name, value); }
    cx.navigate(cx.hashFor('audit', [], next));
  });
  const sources = ui.el('ul', { class: 'zt-sources', attrs: { 'aria-label': t('audit.sources') } });
  const partial = ui.el('div', { class: 'zt-banner', hidden: true, attrs: { role: 'alert' } });
  let loaded = null;
  const table = ui.dataTable(t, {
    id: 'unified-audit', caption: 'audit.caption', owner: 'ui.owner.host', rowKey: record => record.id,
    empty: { title: 'audit.empty.title', body: params.toString() ? 'access.empty.filtered' : 'audit.empty.body' },
    expand: record => detail(cx, record),
    columns: [
      { key: 'time', label: 'audit.col.time', render: record => ui.timeCell(t, record.time), title: record => ui.formatFullTime(record.time) },
      { key: 'source', label: 'audit.col.source', render: record => t(`audit.source.${record.source}`) },
      { key: 'actor', label: 'audit.col.actor', render: record => ui.el('span', { class: 'kit-mono', text: record.actor || '—' }) },
      { key: 'action', label: 'audit.col.action', render: record => ui.el('code', { text: record.action }) },
      { key: 'target', label: 'audit.col.target', render: record => target(cx, record) },
      { key: 'outcome', label: 'audit.col.outcome', render: record => ui.statusBadge(t, record.outcome) },
      { key: 'summary', label: 'audit.col.detail', render: record => ui.el('span', { class: 'zt-inline' }, ui.el('span', { text: record.summary }), record.digest ? ui.hashChip(t, record.digest) : null), title: record => record.summary },
    ],
    order: 'desc',
    fetchPage: async ({ cursor, order }) => {
      loaded ??= await loadAuditRecords(cx);
      const { failures, disconnected } = loaded;
      sources.replaceChildren(...SOURCES.map(source => ui.el('li', {}, ui.el('span', { text: t(`audit.source.${source}`) }), ' ',
        failures.includes(source) ? ui.statusBadge(t, 'unavailable') : disconnected.includes(source) ? ui.statusBadge(t, 'disabled', 'audit.source.not_connected') : ui.statusBadge(t, 'healthy'))));
      partial.hidden = !failures.length;
      partial.textContent = failures.length ? t('audit.partial', { sources: failures.map(source => t(`audit.source.${source}`)).join(', ') }) : '';
      const actor = (params.get('actor') || '').toLowerCase(), action = (params.get('action') || '').toLowerCase();
      let rows = loaded.records.filter(record => (!params.get('source') || record.source === params.get('source')) && (!params.get('outcome') || record.outcome === params.get('outcome')) && (!actor || String(record.actor).toLowerCase().includes(actor)) && (!action || record.action.toLowerCase().includes(action)));
      if (order === 'asc') rows = [...rows].reverse();
      const start = Number(cursor || 0);
      return { items: rows.slice(start, start + 50), nextCursor: start + 50 < rows.length ? String(start + 50) : null };
    },
  });
  content.append(form, sources, partial, table.element);
  cx.signal.addEventListener('abort', () => table.destroy(), { once: true });
  await table.reload();
}
