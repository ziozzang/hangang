// Unified administrative audit: one timeline federated from the authorities'
// own journals. Each source keeps its ownership; a failed source is labelled
// and never shown as "no activity".
const SOURCES = Object.freeze(['accounts', 'plugins', 'pumgye', 'hopae', 'sumunjang']);
const CONNECTED = Object.freeze(['accounts', 'plugins', 'pumgye']);
const OUTCOMES = Object.freeze(['committed', 'refused', 'uncertain']);

function outcomeFromStatus(status) {
  if (!Number.isFinite(status)) return 'uncertain';
  if (status >= 200 && status < 300) return 'committed';
  if (status >= 400 && status < 500) return 'refused';
  return 'uncertain';
}

/** Loads one page per connected source and merges newest first. */
export async function loadAuditRecords(cx) {
  const failures = [];
  const records = [];
  const [accounts, users, plugins, pumgye] = await Promise.allSettled([
    cx.api('/v1/audit/users?limit=100'), cx.api('/v1/users'), cx.api('/v1/plugins/audit'), cx.api('/v1/pumgye/audit'),
  ]);
  for (const result of [accounts, users, plugins, pumgye]) if (result.status === 'rejected' && result.reason?.status === 401) throw result.reason;
  const names = new Map();
  if (users.status === 'fulfilled') for (const user of (Array.isArray(users.value.data) ? users.value.data : users.value.data?.users) || []) if (user && Number.isFinite(user.id)) names.set(user.id, user.username);
  if (accounts.status === 'fulfilled') {
    for (const record of accounts.value.data?.records || []) {
      const actor = record.actor_user_id ? (names.get(record.actor_user_id) ?? `#${record.actor_user_id}`) : cx.t(`audit.actor.${record.actor_kind || 'unknown'}`);
      records.push({ id: `accounts:${record.id}`, source: 'accounts', time: new Date(record.time_unix_ms), actor, action: `account.${record.action}`, target: record.target_user_id ? { type: 'account', id: names.get(record.target_user_id) ?? `#${record.target_user_id}` } : null, outcome: 'committed', before: record.before, after: record.after, operation: String(record.id) });
    }
  } else failures.push('accounts');
  if (plugins.status === 'fulfilled') {
    for (const operation of plugins.value.data?.operations || []) {
      records.push({ id: `plugins:${operation.id}`, source: 'plugins', time: new Date((operation.completed_at ?? operation.started_at) * 1000), actor: operation.actor_name, action: `${operation.method} ${operation.path}`, target: { type: 'plugin', id: operation.plugin }, outcome: operation.completed_at === null ? 'uncertain' : outcomeFromStatus(operation.status), digest: operation.body_sha256, operation: String(operation.id) });
    }
  } else failures.push('plugins');
  if (pumgye.status === 'fulfilled') {
    const data = pumgye.value.data;
    const list = Array.isArray(data) ? data : data?.records || data?.audit || data?.receipts || [];
    for (const receipt of list) {
      records.push({ id: `pumgye:${receipt.revision}`, source: 'pumgye', time: new Date((receipt.at_unix ?? 0) * 1000), actor: receipt.actor, action: 'publish', target: { type: 'revision', id: String(receipt.revision) }, outcome: 'committed', digest: receipt.sha256, operation: String(receipt.revision) });
    }
  } else failures.push('pumgye');
  records.sort((a, b) => b.time - a.time);
  return { records, failures };
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
    caption: 'audit.caption', owner: 'ui.owner.host', rowKey: record => record.id,
    empty: { title: 'audit.empty.title', body: params.toString() ? 'access.empty.filtered' : 'audit.empty.body' },
    columns: [
      { key: 'time', label: 'audit.col.time', render: record => ui.el('time', { dateTime: record.time.toISOString(), text: new Intl.DateTimeFormat(document.documentElement.lang || undefined, { dateStyle: 'medium', timeStyle: 'medium' }).format(record.time) }) },
      { key: 'source', label: 'audit.col.source', render: record => t(`audit.source.${record.source}`) },
      { key: 'actor', label: 'audit.col.actor', render: record => ui.el('span', { class: 'kit-mono', text: record.actor || '—' }) },
      { key: 'action', label: 'audit.col.action', render: record => ui.el('code', { text: record.action }) },
      { key: 'target', label: 'audit.col.target', render: record => record.target ? (record.target.type === 'plugin' ? ui.el('a', { href: `#plugin-${record.target.id}`, text: record.target.id }) : record.target.type === 'revision' ? ui.el('a', { href: '#pumgye', text: t('ui.revision', { revision: record.target.id }) }) : ui.el('span', { text: record.target.id })) : '—' },
      { key: 'outcome', label: 'audit.col.outcome', render: record => ui.statusBadge(t, record.outcome) },
      { key: 'detail', label: 'audit.col.detail', render: record => {
        if (record.before || record.after) { const details = ui.el('details', {}, ui.el('summary', { text: t('audit.diff') }), ui.structuredDiff(t, record.before, record.after)); return details; }
        return record.digest ? ui.el('span', { class: 'kit-entity-id', text: record.digest.slice(0, 16), attrs: { title: record.digest } }) : '—';
      } },
    ],
    order: 'desc',
    fetchPage: async ({ cursor, order }) => {
      loaded ??= await loadAuditRecords(cx);
      const failures = loaded.failures;
      sources.replaceChildren(...SOURCES.map(source => ui.el('li', {}, ui.el('span', { text: t(`audit.source.${source}`) }), ' ',
        CONNECTED.includes(source) ? ui.statusBadge(t, failures.includes(source) ? 'unavailable' : 'healthy') : ui.statusBadge(t, 'disabled', 'audit.source.not_connected'))));
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
