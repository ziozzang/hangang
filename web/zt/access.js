// Access section: decision log (server-side filtered, cursor-paginated) and
// the request detail stage timeline (ADR 0020 §2, data from ADR 0019).
const RANGES = Object.freeze({ '1h': 3_600_000, '24h': 86_400_000, '7d': 7 * 86_400_000, '30d': 30 * 86_400_000 });
const OUTCOMES = Object.freeze(['allow', 'deny', 'challenge', 'error', 'unavailable']);
const STAGES = Object.freeze(['network', 'identity', 'authorization', 'enforcement']);
const PRINCIPALS = Object.freeze(['human', 'service', 'workload']);
const FILTERS = Object.freeze(['range', 'outcome', 'stage', 'reason', 'route', 'service', 'class', 'principal', 'country', 'subject', 'ip']);
const TAIL_LIMIT_MS = 10 * 60_000;
const IDENT = /^[A-Za-z0-9_.:-]{1,128}$/;
const REQUEST_ID = /^hg-[0-9a-f]{16}$/;

function looksLikeIp(value) { return /^[0-9.]{7,15}$/.test(value) || (value.includes(':') && /^[0-9A-Fa-f:.]{2,45}$/.test(value)); }

export function stage(event, name) { return (event.stages || []).find(entry => entry.stage === name); }

function formatTime(value, withSeconds = true) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value || '—';
  return new Intl.DateTimeFormat(document.documentElement.lang || undefined, { dateStyle: 'medium', timeStyle: withSeconds ? 'medium' : 'short' }).format(date);
}
export { formatTime };

/** Time of day for today, short date plus time otherwise; full value in the title. */
function compactTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value || '—';
  const locale = document.documentElement.lang || undefined;
  const today = new Date().toDateString() === date.toDateString();
  return new Intl.DateTimeFormat(locale, today ? { timeStyle: 'medium' } : { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(date);
}

/** Decision query for the exporter broker from the URL filter state. */
export function decisionQuery(params, { cursor, order, limit = 50, now = Date.now() } = {}) {
  const query = new URLSearchParams();
  const range = RANGES[params.get('range')] ?? RANGES['24h'];
  query.set('from', String(now - range));
  query.set('to', String(now));
  for (const name of ['outcome', 'stage', 'reason', 'route', 'service', 'class', 'principal', 'country', 'subject', 'ip']) {
    const value = params.get(name);
    if (value) query.set(name, value);
  }
  query.set('limit', String(limit));
  if (order) query.set('order', order);
  if (cursor) query.set('cursor', cursor);
  return query;
}

export function outcomeBadge(cx, event) {
  const { t, ui } = cx;
  const result = event.outcome?.result || 'unknown';
  const badge = ui.statusBadge(t, OUTCOMES.includes(result) ? result : 'unknown', `decision.result.${OUTCOMES.includes(result) ? result : 'unknown'}`);
  if (event.kind === 'simulation') badge.append(ui.el('span', { class: 'kit-tag', text: t('decision.kind.simulation') }));
  if (event.sampling && event.sampling.rate < 1) badge.append(ui.el('span', { class: 'kit-tag', text: t('decision.sampled', { percent: Math.round(event.sampling.rate * 10000) / 100 }), attrs: { title: t('decision.sampled.help') } }));
  return badge;
}

export function subjectCell(cx, event) {
  const { t, ui } = cx;
  const identity = stage(event, 'identity');
  if (!identity) return ui.el('span', { class: 'kit-muted', text: t('decision.subject.none') });
  const wrapper = ui.el('span', { class: 'zt-subject' });
  if (identity.subject_ref) wrapper.append(ui.el('span', { class: 'kit-tag', text: t('decision.subject.pseudonymous') }), ui.el('code', { class: 'kit-entity-id', text: identity.subject_ref }), ui.copyButton(t, identity.subject_ref));
  else wrapper.append(ui.el('span', { class: 'kit-muted', text: t(`decision.verdict.${identity.verdict || 'unspecified'}`) }));
  if (identity.principal && identity.principal !== 'unspecified') wrapper.append(ui.el('small', { class: 'kit-muted', text: t(`decision.principal.${identity.principal}`) }));
  return wrapper;
}

function routeCell(cx, event) {
  const { t, ui } = cx;
  const route = event.route || {};
  const cell = ui.el('span', { class: 'zt-route' });
  if (route.service) cell.append(ui.entityLink(t, { type: 'service', id: route.service }));
  cell.append(ui.el('span', {}, ui.el('strong', { text: route.route_id || t('decision.route.none') })),
    ui.el('small', { class: 'kit-muted' }, [route.method, route.path_template].filter(Boolean).join(' ')));
  return cell;
}

function stageCell(cx, event) {
  const { t, ui } = cx;
  const name = event.outcome?.deciding_stage;
  if (!STAGES.includes(name)) return ui.el('span', { class: 'kit-muted', text: '—' });
  const decided = stage(event, name);
  return ui.el('span', { class: 'zt-stack' }, ui.el('strong', { text: t(`decision.stage.${name}`) }), decided && Number.isFinite(decided.revision) ? ui.el('small', { class: 'kit-muted', text: t('ui.revision', { revision: decided.revision }) }) : null);
}

function sourceCell(cx, event) {
  const { t, ui } = cx;
  const client = stage(event, 'network')?.client || {};
  const parts = [client.country, Number.isFinite(client.asn) ? t('decision.asn', { asn: client.asn }) : null].filter(Boolean);
  return ui.el('span', { class: 'zt-stack' }, ui.el('span', {}, parts.length ? parts.join(' · ') : '—'), client.prefix_ref ? ui.el('small', { class: 'kit-entity-id', text: client.prefix_ref }) : null);
}

function reasonCell(cx, event) {
  const { t, ui } = cx;
  const reason = event.outcome?.reason;
  const cell = ui.el('span', { class: 'zt-reason' }, reason ? ui.reasonText(t, reason) : '—');
  if (event.suppressed) cell.append(ui.el('span', { class: 'kit-tag', text: t('decision.suppressed', { count: event.suppressed.count }) }));
  return cell;
}

function filterForm(cx, params, apply) {
  const { t, ui } = cx;
  const option = (prefix, values, allKey) => [{ value: '', label: allKey }, ...values.map(value => ({ value, label: `${prefix}.${value}` }))];
  const form = ui.el('form', { class: 'zt-filters', attrs: { role: 'search', 'aria-label': t('access.filters') } });
  const active = FILTERS.filter(name => params.get(name)).length;
  const sheet = ui.el('details', { class: 'zt-filter-sheet', open: active > 0 || window.matchMedia('(min-width: 721px)').matches },
    ui.el('summary', { text: t('access.filters.summary', { count: active }) }), form);
  form.append(
    ui.field(t, { label: 'access.filter.range', name: 'range', value: params.get('range') || '24h', options: Object.keys(RANGES).map(value => ({ value, label: `access.range.${value}` })) }),
    ui.field(t, { label: 'access.filter.outcome', name: 'outcome', value: params.get('outcome') || '', options: option('decision.result', OUTCOMES, 'access.any') }),
    ui.field(t, { label: 'access.filter.stage', name: 'stage', value: params.get('stage') || '', options: option('decision.stage', STAGES, 'access.any') }),
    ui.field(t, { label: 'access.filter.principal', name: 'principal', value: params.get('principal') || '', options: option('decision.principal', PRINCIPALS, 'access.any') }),
    ui.field(t, { label: 'access.filter.reason', name: 'reason', value: params.get('reason') || '', pattern: '(sumunjang|hopae|pumgye|hangang)\\.[a-z0-9_]{1,64}', placeholder: 'access.filter.reason.placeholder' }),
    ui.field(t, { label: 'access.filter.route', name: 'route', value: params.get('route') || '', pattern: IDENT.source.slice(1, -1) }),
    ui.field(t, { label: 'access.filter.service', name: 'service', value: params.get('service') || '', pattern: IDENT.source.slice(1, -1) }),
    ui.field(t, { label: 'access.filter.class', name: 'class', value: params.get('class') || '', pattern: IDENT.source.slice(1, -1) }),
    ui.subjectPicker(t, cx.api, { label: 'access.filter.subject', name: 'subject', value: params.get('subject') || '', help: 'access.filter.subject.help' }),
    ui.field(t, { label: 'access.filter.ip', name: 'ip', value: params.get('ip') || '', maxLength: 45 }),
    ui.field(t, { label: 'access.filter.country', name: 'country', value: params.get('country') || '', pattern: '[A-Z]{2}', maxLength: 2 }),
    ui.el('div', { class: 'button-row zt-filter-actions' },
      ui.el('button', { type: 'submit', class: 'button button-primary', text: t('access.apply') }),
      ui.el('button', { type: 'button', class: 'button button-quiet', text: t('access.reset'), on: { click: () => apply(new URLSearchParams()) } })));
  form.addEventListener('submit', event => {
    event.preventDefault();
    if (!form.reportValidity()) return;
    const next = new URLSearchParams();
    for (const name of FILTERS) { const value = form.elements[name]?.value.trim(); if (value && !(name === 'range' && value === '24h')) next.set(name, value); }
    apply(next);
  });
  return sheet;
}

function searchBox(cx) {
  const { t, ui } = cx;
  const input = ui.el('input', { type: 'search', name: 'q', maxLength: 1024, autocomplete: 'off', spellcheck: false });
  input.placeholder = t('access.search.placeholder');
  input.setAttribute('aria-label', t('access.search'));
  const form = ui.el('form', { class: 'zt-search', attrs: { role: 'search' } }, input, ui.el('button', { type: 'submit', class: 'button', text: t('access.search.go') }));
  form.addEventListener('submit', event => {
    event.preventDefault();
    const value = input.value.trim();
    if (!value) return;
    if (REQUEST_ID.test(value)) return cx.navigate(cx.hashFor('access', ['requests', value]));
    const params = new URLSearchParams();
    params.set(looksLikeIp(value) ? 'ip' : 'subject', value);
    cx.navigate(cx.hashFor('access', ['decisions'], params));
  });
  return form;
}

export function decisionColumns(cx) {
  const { t, ui } = cx;
  return [
    { key: 'time', label: 'access.col.time', render: event => ui.el('a', { href: cx.hashFor('access', ['requests', event.request_id]), class: 'zt-time-link' }, ui.el('time', { dateTime: event.time, text: compactTime(event.time) })) },
    { key: 'result', label: 'access.col.result', render: event => outcomeBadge(cx, event) },
    { key: 'user', label: 'access.col.user', render: event => subjectCell(cx, event) },
    { key: 'route', label: 'access.col.route', render: event => routeCell(cx, event) },
    { key: 'stage', label: 'access.col.stage', render: event => stageCell(cx, event) },
    { key: 'reason', label: 'access.col.reason', render: event => reasonCell(cx, event) },
    { key: 'source', label: 'access.col.source', render: event => sourceCell(cx, event) },
    { key: 'revision', label: 'access.col.revision', render: event => {
      const entries = Object.entries(event.revisions || {});
      if (!entries.length) return '—';
      return ui.el('ul', { class: 'zt-revision-list' }, entries.map(([name, value]) => ui.el('li', {}, ui.el('span', { class: 'kit-muted', text: t(`decision.authority.${name}`) }), ' ', ui.el('span', { class: 'kit-mono', text: String(value) }))));
    } },
  ];
}

/** Shared state for disabled/strict profiles in any decision table. */
export function decisionReplacement(cx, data) {
  const { t, ui } = cx;
  if (data?.state === 'disabled') return ui.emptyState(t, { title: 'access.disabled.title', body: 'access.disabled.body', action: ui.el('a', { class: 'button', href: '#system', text: t('access.disabled.action') }) });
  return null;
}

export function decisionFetcher(cx, params, { limit = 50, onProfile } = {}) {
  return async ({ cursor, order, signal }) => {
    const { data } = await cx.api(`/v1/observability/decisions?${decisionQuery(params, { cursor, order, limit })}`, { signal });
    const replace = decisionReplacement(cx, data);
    if (replace) return { replace, items: [] };
    onProfile?.(data?.profile);
    return { items: Array.isArray(data?.items) ? data.items : [], nextCursor: data?.next_cursor };
  };
}

export async function renderDecisionLog(cx, root, params) {
  const { t, ui } = cx;
  const { content } = cx.page(root, { crumbs: [{ label: t('nav.access'), href: '#access' }, { label: t('access.log.title') }], title: t('access.log.title'), owner: t('access.log.owner') });
  const apply = next => cx.navigate(cx.hashFor('access', ['decisions'], next));
  const banner = ui.el('div', { class: 'zt-banner', hidden: true, attrs: { role: 'note' } });
  const live = ui.el('input', { type: 'checkbox', name: 'live' });
  const liveLabel = ui.el('label', { class: 'zt-live' }, live, ui.el('span', { text: t('access.live') }));
  const table = ui.dataTable(t, {
    caption: 'access.log.caption', owner: 'ui.owner.exporter', columns: decisionColumns(cx),
    rowKey: event => event.event_id,
    empty: { title: 'access.empty.title', body: params.toString() ? 'access.empty.filtered' : 'access.empty.body' },
    fetchPage: decisionFetcher(cx, params, { onProfile: profile => {
      banner.hidden = profile !== 'strict';
      banner.textContent = profile === 'strict' ? t('access.strict') : '';
    } }),
  });
  content.append(ui.el('div', { class: 'zt-toolbar' }, searchBox(cx), liveLabel), filterForm(cx, params, apply), banner, table.element);
  let timer = null, started = 0;
  const stop = () => { clearInterval(timer); timer = null; live.checked = false; };
  live.addEventListener('change', () => {
    if (!live.checked) return stop();
    started = Date.now();
    timer = setInterval(() => {
      if (cx.signal.aborted || Date.now() - started > TAIL_LIMIT_MS) return stop();
      if (!document.hidden) table.reload();
    }, 5000);
  });
  cx.signal.addEventListener('abort', () => { stop(); table.destroy(); }, { once: true });
  await table.reload();
}

function detailList(cx, entries) {
  const list = cx.ui.el('dl', { class: 'zt-dl' });
  for (const [key, value] of entries) {
    if (value === null || value === undefined || value === '' || (Array.isArray(value) && !value.length)) continue;
    list.append(cx.ui.el('dt', { text: cx.t(key) }), cx.ui.el('dd', {}, value instanceof Node ? value : Array.isArray(value) ? value.join(', ') : String(value)));
  }
  return list.childElementCount ? list : null;
}

function stageDetail(cx, entry) {
  const { t, ui } = cx;
  if (entry.stage === 'network') {
    const client = entry.client || {};
    return detailList(cx, [
      ['decision.field.mode', entry.mode && entry.mode !== 'unspecified' ? t(`decision.mode.${entry.mode}`) : null],
      ['decision.field.rules', entry.rules], ['decision.field.ip', client.ip_ref ? ui.el('code', { text: client.ip_ref }) : null],
      ['decision.field.prefix', client.prefix_ref ? ui.el('code', { text: client.prefix_ref }) : null], ['decision.field.country', client.country],
      ['decision.field.asn', client.asn], ['decision.field.transport', entry.transport !== 'unspecified' ? entry.transport : null],
    ]);
  }
  if (entry.stage === 'identity') {
    return detailList(cx, [
      ['decision.field.subject', entry.subject_ref ? ui.el('code', { text: entry.subject_ref }) : null],
      ['decision.field.principal', entry.principal && entry.principal !== 'unspecified' ? t(`decision.principal.${entry.principal}`) : null],
      ['decision.field.provider', entry.provider], ['decision.field.aal', entry.aal],
      ['decision.field.factors', (entry.factors || []).map(factor => t(`decision.factor.${factor}`))],
      ['decision.field.sealed', entry.subject_sealed ? t('decision.sealed.yes') : null],
      ['decision.field.transport', entry.transport !== 'unspecified' ? entry.transport : null],
    ]);
  }
  if (entry.stage === 'authorization') {
    return detailList(cx, [
      ['decision.field.roles', entry.roles], ['decision.field.class', entry.information_class],
      ['decision.field.required_aal', entry.required_aal], ['decision.field.permit', entry.permit],
      ['decision.field.transport', entry.transport !== 'unspecified' ? entry.transport : null],
    ]);
  }
  return detailList(cx, [
    ['decision.field.obligations', entry.obligations], ['decision.field.fence', entry.fence !== 'unspecified' ? t(`decision.fence.${entry.fence}`) : null],
    ['decision.field.upstream', entry.upstream_status_class ? t('decision.upstream', { class: entry.upstream_status_class }) : null],
  ]);
}

async function currentRevisions(cx) {
  const current = {};
  const [status, pumgye] = await Promise.allSettled([cx.api('/v1/status'), cx.api('/v1/pumgye/status')]);
  if (status.status === 'fulfilled' && Number.isFinite(status.value.data?.revision)) current.hangang = status.value.data.revision;
  const pumgyeRevision = pumgye.status === 'fulfilled' ? (pumgye.value.data?.revision ?? pumgye.value.data?.policy_revision) : undefined;
  if (Number.isFinite(pumgyeRevision)) current.pumgye = pumgyeRevision;
  return current;
}

function revisionVector(cx, event, current) {
  const { t, ui } = cx;
  const list = ui.el('ul', { class: 'zt-revisions', attrs: { 'aria-label': t('decision.revisions') } });
  for (const [name, value] of Object.entries(event.revisions || {})) {
    const now = current[name];
    list.append(ui.el('li', { dataset: { authority: name } }, ui.el('strong', { text: t(`decision.authority.${name}`) }), ' ', ui.el('span', { class: 'kit-mono', text: String(value) }),
      Number.isFinite(now) && now !== value ? ui.el('span', { class: 'kit-tag kit-tag-warn', text: t('decision.revision.changed', { revision: now }) }) : null));
  }
  if (!list.childElementCount) list.append(ui.el('li', { class: 'kit-muted', text: t('decision.revisions.none') }));
  return list;
}

function unavailableAction(cx, label, why) {
  const { t, ui } = cx;
  const id = `zt-why-${Math.random().toString(36).slice(2, 8)}`;
  return ui.el('span', { class: 'zt-action-off' }, ui.el('button', { type: 'button', class: 'button button-quiet', disabled: true, text: t(label), attrs: { 'aria-describedby': id } }), ui.el('small', { id, class: 'kit-muted', text: t(why) }));
}

export async function renderRequest(cx, root, requestId) {
  const { t, ui } = cx;
  const crumbs = [{ label: t('nav.access'), href: '#access' }, { label: t('access.log.title'), href: '#access/decisions' }, { label: requestId }];
  if (!/^[A-Za-z0-9_.:-]{1,64}$/.test(requestId)) {
    const { content } = cx.page(root, { crumbs, title: t('request.title') });
    content.append(ui.emptyState(t, { title: 'request.invalid.title', body: 'request.invalid.body' }));
    return;
  }
  const [{ data }, current] = await Promise.all([cx.api(`/v1/observability/requests/${encodeURIComponent(requestId)}`), currentRevisions(cx)]);
  if (cx.signal.aborted) return;
  const events = Array.isArray(data?.events) ? data.events : [];
  const primary = events.find(event => event.kind === 'enforced') || events[0];
  const actions = [];
  if (primary) {
    const identity = stage(primary, 'identity');
    const network = stage(primary, 'network');
    actions.push(unavailableAction(cx, 'request.action.simulate', 'request.action.simulate.why'));
    actions.push(identity?.subject_ref ? unavailableAction(cx, 'request.action.user', 'request.action.pseudonymous') : null);
    actions.push(network?.client?.ip_ref ? unavailableAction(cx, 'request.action.ip', 'request.action.pseudonymous') : null);
  }
  const { content } = cx.page(root, { crumbs, title: t('request.title'), owner: t('request.owner'), actions: actions.filter(Boolean) });
  const replacement = decisionReplacement(cx, data);
  if (replacement) { content.append(replacement); return; }
  if (!primary) { content.append(ui.emptyState(t, { title: 'request.empty.title', body: 'request.empty.body' })); return; }
  for (const event of events) {
    const route = event.route || {};
    const card = ui.el('section', { class: `panel zt-request${event.kind === 'simulation' ? ' is-simulation' : ''}`, attrs: { 'aria-label': t('request.event', { kind: t(`decision.kind.${event.kind}`) }) } });
    card.append(
      ui.el('div', { class: 'zt-request-head' }, outcomeBadge(cx, event), ui.el('strong', { text: t('request.status', { status: event.outcome?.status || '—' }) }), ui.el('span', { text: formatTime(event.time) }),
        ui.el('span', { class: 'zt-ref' }, ui.el('span', { class: 'kit-muted', text: t('request.reference') }), ' ', ui.el('code', { text: event.request_id }), ui.copyButton(t, event.request_id))),
      ui.el('p', { class: 'zt-request-route' }, [route.method, route.host, route.path_template].filter(Boolean).join(' ') || t('decision.route.none')),
      detailList(cx, [['decision.field.route', route.route_id], ['decision.field.service', route.service ? ui.entityLink(t, { type: 'service', id: route.service }) : null], ['decision.field.resource', route.resource], ['decision.field.action', route.action]]) || '',
      ui.stageTimeline(t, event, { renderDetail: entry => stageDetail(cx, entry) }),
      ui.el('h2', { class: 'zt-subhead', text: t('decision.revisions') }), revisionVector(cx, event, current));
    if (event.suppressed) card.append(ui.el('p', { class: 'zt-banner', text: t('decision.suppressed.detail', { count: event.suppressed.count, first: formatTime(event.suppressed.first), last: formatTime(event.suppressed.last) }) }));
    content.append(card);
  }
}
