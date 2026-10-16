// @hangang/console-ui kit v1 (ADR 0020): vanilla ES components shared by host
// sections and console packages. Every untrusted string is rendered as a text
// node; labels come from message keys through the caller's `t`.
export const KIT_VERSION = '1';

/** Element factory. `text` sets textContent; children may be nodes or strings (text nodes). */
export function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (name === 'class') node.className = value;
    else if (name === 'text') node.textContent = value;
    else if (name === 'dataset') Object.assign(node.dataset, value);
    else if (name === 'on') for (const [event, handler] of Object.entries(value)) node.addEventListener(event, handler);
    else if (name === 'attrs') for (const [attr, attrValue] of Object.entries(value)) { if (attrValue !== undefined && attrValue !== null && attrValue !== false) node.setAttribute(attr, attrValue === true ? '' : String(attrValue)); }
    else node[name] = value;
  }
  append(node, children);
  return node;
}

function append(node, children) {
  for (const child of children.flat(Infinity)) {
    if (child === undefined || child === null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

export function clear(node, ...children) { node.replaceChildren(); append(node, children); return node; }

const STATUS_GLYPHS = Object.freeze({ allow: '✓', healthy: '●', deny: '✕', challenge: '?', error: '!', unavailable: '◌', stale: '▲', disabled: '○', unknown: '·', simulation: '◇', pending: '…', committed: '✓', refused: '✕', uncertain: '?' });

/** Text plus glyph, never colour alone. `kind` selects the token colour. */
export function statusBadge(t, kind, labelKey = `ui.status.${kind}`) {
  const safe = Object.hasOwn(STATUS_GLYPHS, kind) ? kind : 'unknown';
  return el('span', { class: `kit-badge kit-badge-${safe}`, dataset: { status: safe } },
    el('span', { class: 'kit-badge-glyph', text: STATUS_GLYPHS[safe], attrs: { 'aria-hidden': 'true' } }),
    el('span', { text: t(labelKey) }));
}

export function relativeAge(t, ageMs) {
  const seconds = Math.max(0, Math.round(ageMs / 1000));
  if (seconds < 120) return t('ui.age.seconds', { count: seconds });
  const minutes = Math.round(seconds / 60);
  if (minutes < 120) return t('ui.age.minutes', { count: minutes });
  return t('ui.age.hours', { count: Math.round(minutes / 60) });
}

/** Fresh/stale/unknown with age; unknown is never rendered as healthy. */
export function freshnessBadge(t, observedMs, staleAfterMs = 60_000, now = Date.now()) {
  if (!Number.isFinite(observedMs) || observedMs <= 0) return statusBadge(t, 'unknown', 'ui.freshness.unknown');
  const age = now - observedMs;
  const kind = age > staleAfterMs ? 'stale' : 'healthy';
  return el('span', { class: `kit-badge kit-badge-${kind}`, dataset: { status: kind } },
    el('span', { class: 'kit-badge-glyph', text: STATUS_GLYPHS[kind], attrs: { 'aria-hidden': 'true' } }),
    el('span', { text: t(age > staleAfterMs ? 'ui.freshness.stale' : 'ui.freshness.fresh', { age: relativeAge(t, age) }) }));
}

export function copyButton(t, value) {
  const button = el('button', { type: 'button', class: 'kit-copy', text: '⧉', attrs: { 'aria-label': t('ui.copy', { value }), title: t('ui.copy', { value }) } });
  button.addEventListener('click', async event => {
    event.preventDefault(); event.stopPropagation();
    try { await navigator.clipboard.writeText(value); button.dataset.copied = 'true'; button.setAttribute('aria-label', t('ui.copied')); }
    catch { button.dataset.copied = 'false'; }
  });
  return button;
}

const ENTITY_ROUTES = Object.freeze({
  request: id => `#access/requests/${encodeURIComponent(id)}`,
  user: id => `#identities/users/${encodeURIComponent(id)}`,
  ip: id => `#network/ip/${encodeURIComponent(id)}`,
  service: id => `#policies/services/${encodeURIComponent(id)}`,
});
const ENTITY_OWNERS = Object.freeze({ request: 'ui.owner.exporter', user: 'ui.owner.hopae', ip: 'ui.owner.sumunjang', service: 'ui.owner.pumgye' });

export function entityHref(type, id) { return Object.hasOwn(ENTITY_ROUTES, type) ? ENTITY_ROUTES[type](id) : null; }

/**
 * Entity link: human label first, opaque ID secondary (monospace, copyable),
 * and a hover/focus card naming the owner. Without a label the ID is primary.
 */
export function entityLink(t, { type, id, label, status }) {
  const href = entityHref(type, id);
  const wrapper = el('span', { class: 'kit-entity', dataset: { entity: type } });
  const anchor = el(href ? 'a' : 'span', { class: 'kit-entity-link', href: href || undefined });
  if (label) anchor.append(el('span', { class: 'kit-entity-label', text: label }), el('span', { class: 'kit-entity-id', text: id }));
  else anchor.append(el('span', { class: 'kit-entity-id kit-entity-id-only', text: id }));
  const card = el('span', { class: 'kit-hovercard', attrs: { role: 'tooltip' } },
    el('strong', { text: t(`ui.entity.${type}`) }),
    el('span', { text: t('ui.entity.owner', { owner: t(ENTITY_OWNERS[type] || 'ui.owner.host') }) }),
    status ? el('span', { text: status }) : null);
  const cardId = `kit-card-${Math.random().toString(36).slice(2, 10)}`;
  card.id = cardId; anchor.setAttribute('aria-describedby', cardId);
  wrapper.append(anchor, copyButton(t, id), card);
  return wrapper;
}

export function emptyState(t, { title, body, action }) {
  return el('div', { class: 'kit-state kit-empty', attrs: { role: 'status' } },
    el('strong', { text: t(title) }), body ? el('p', { text: t(body) }) : null, action || null);
}

export function errorState(t, { owner, message, retry }) {
  const box = el('div', { class: 'kit-state kit-error', attrs: { role: 'alert' } },
    el('strong', { text: t('ui.error.title', { owner: t(owner || 'ui.owner.host') }) }),
    message ? el('p', { class: 'kit-error-detail', text: message }) : null);
  if (retry) box.append(el('button', { type: 'button', class: 'button button-quiet', text: t('ui.retry'), on: { click: retry } }));
  return box;
}

export function loadingState(t) {
  return el('div', { class: 'kit-state kit-loading', attrs: { role: 'status', 'aria-live': 'polite' } }, el('span', { class: 'kit-spinner', attrs: { 'aria-hidden': 'true' } }), el('span', { text: t('ui.loading') }));
}

/** Labelled form control; `options` makes a select. */
export function field(t, { label, name, value = '', options, type = 'text', help, pattern, maxLength = 256, placeholder }) {
  const id = `kit-field-${name}-${Math.random().toString(36).slice(2, 8)}`;
  let control;
  if (options) {
    control = el('select', { id, name });
    for (const option of options) control.append(el('option', { value: option.value, text: t(option.label), selected: option.value === value }));
  } else {
    control = el('input', { id, name, type, value, maxLength, autocomplete: 'off', spellcheck: false });
    if (pattern) control.pattern = pattern;
    if (placeholder) control.placeholder = t(placeholder);
  }
  const helpNode = help ? el('small', { class: 'kit-help', id: `${id}-help`, text: t(help) }) : null;
  if (helpNode) control.setAttribute('aria-describedby', helpNode.id);
  return el('label', { class: 'kit-field', htmlFor: id }, el('span', { class: 'kit-field-label', text: t(label) }), control, helpNode);
}

/**
 * Server-driven data table: the caller's `fetchPage({cursor, order, signal})`
 * performs search/filter/sort/pagination; the table keeps a cursor stack for
 * Back, renders loading/empty/error states and becomes cards at narrow widths.
 */
export function dataTable(t, { caption, columns, fetchPage, rowKey, empty, order = 'desc', sortable = 'time', owner, onPage }) {
  const root = el('div', { class: 'kit-table-wrap' });
  const status = el('div', { class: 'kit-table-status', attrs: { 'aria-live': 'polite' } });
  const table = el('table', { class: 'kit-table' });
  const body = el('tbody');
  const pager = el('nav', { class: 'kit-pager', attrs: { 'aria-label': t('ui.table.pagination') } });
  const prev = el('button', { type: 'button', class: 'button button-quiet', text: t('ui.table.previous') });
  const next = el('button', { type: 'button', class: 'button button-quiet', text: t('ui.table.next') });
  const position = el('span', { class: 'kit-pager-position' });
  pager.append(prev, position, next);
  let cursors = [null], page = 0, nextCursor = null, controller = null, rows = 0, destroyed = false;
  const head = el('tr');
  for (const column of columns) {
    const th = el('th', { scope: 'col' });
    if (column.key === sortable) {
      const button = el('button', { type: 'button', class: 'kit-sort', text: t(column.label) });
      const sync = () => { th.setAttribute('aria-sort', order === 'asc' ? 'ascending' : 'descending'); button.dataset.order = order; };
      button.addEventListener('click', () => { order = order === 'asc' ? 'desc' : 'asc'; sync(); reset(); });
      sync(); th.append(button);
    } else th.textContent = t(column.label);
    head.append(th);
  }
  table.append(el('caption', { class: 'kit-visually-hidden', text: t(caption) }), el('thead', {}, head), body);
  root.append(status, table, pager);
  async function load() {
    controller?.abort();
    controller = new AbortController();
    const signal = controller.signal;
    table.setAttribute('aria-busy', 'true');
    clear(status, loadingState(t));
    prev.disabled = true; next.disabled = true;
    try {
      const result = await fetchPage({ cursor: cursors[page], order, signal });
      if (signal.aborted || destroyed) return;
      body.replaceChildren();
      if (result.replace) { clear(status, result.replace); table.hidden = true; pager.hidden = true; return; }
      table.hidden = false; pager.hidden = false; status.replaceChildren();
      rows = result.items.length;
      for (const item of result.items) {
        const tr = el('tr', { dataset: { key: rowKey(item) } });
        for (const column of columns) {
          const cell = column.render(item);
          tr.append(el('td', { dataset: { label: t(column.label) } }, cell));
        }
        body.append(tr);
      }
      nextCursor = result.nextCursor || null;
      if (!rows) clear(status, emptyState(t, empty));
      prev.disabled = page === 0; next.disabled = !nextCursor;
      position.textContent = rows ? t('ui.table.page', { page: page + 1, count: rows }) : '';
      onPage?.(result);
    } catch (error) {
      if (signal.aborted || destroyed) return;
      body.replaceChildren(); table.hidden = true; pager.hidden = true;
      clear(status, errorState(t, { owner, message: error.message, retry: () => load() }));
    } finally {
      if (!signal.aborted) table.removeAttribute('aria-busy');
    }
  }
  function reset() { cursors = [null]; page = 0; return load(); }
  prev.addEventListener('click', () => { if (page > 0) { page -= 1; load(); } });
  next.addEventListener('click', () => { if (nextCursor) { cursors[page + 1] = nextCursor; page += 1; load(); } });
  return { element: root, reload: reset, refresh: load, destroy() { destroyed = true; controller?.abort(); } };
}

const STAGES = Object.freeze(['network', 'identity', 'authorization', 'enforcement']);
const STAGE_VERDICT = Object.freeze({ allow: 'allow', observe: 'allow', authenticated: 'allow', forwarded: 'allow', redirected: 'allow', Allow: 'allow', deny: 'deny', denied: 'deny', refused: 'deny', challenge: 'challenge', challenged: 'challenge', anonymous: 'challenge', unavailable: 'unavailable', Unavailable: 'unavailable', GuardUnavailable: 'unavailable' });

function stageVerdict(stage) {
  const value = stage.verdict ?? stage.decision ?? stage.action ?? 'unspecified';
  return { value, kind: Object.hasOwn(STAGE_VERDICT, value) ? STAGE_VERDICT[value] : (/Denied|Guest|Unknown|NotMapped/.test(value) ? 'deny' : 'unknown') };
}

/**
 * Network → identity → authorization → enforcement timeline. Stages not
 * reached are listed as not evaluated; the deciding stage is highlighted with
 * its localized reason and remediation hint.
 */
export function stageTimeline(t, event, { renderDetail } = {}) {
  const list = el('ol', { class: 'kit-timeline' });
  const deciding = event.outcome?.deciding_stage;
  const byName = new Map((event.stages || []).map(stage => [stage.stage, stage]));
  for (const name of STAGES) {
    const stage = byName.get(name);
    const decidingStage = deciding === name;
    const item = el('li', { class: `kit-stage${decidingStage ? ' is-deciding' : ''}${stage ? '' : ' is-skipped'}`, dataset: { stage: name } });
    const heading = el('div', { class: 'kit-stage-head' }, el('strong', { text: t(`decision.stage.${name}`) }));
    if (stage) {
      const verdict = stageVerdict(stage);
      heading.append(statusBadge(t, verdict.kind, `decision.verdict.${verdict.value}`));
      if (stage.authority) heading.append(el('span', { class: 'kit-muted', text: t(`decision.authority.${stage.authority}`) }));
      if (Number.isFinite(stage.revision)) heading.append(el('span', { class: 'kit-muted', text: t('ui.revision', { revision: stage.revision }) }));
      if (Number.isFinite(stage.latency_us) && stage.latency_us > 0) heading.append(el('span', { class: 'kit-muted', text: t('ui.latency', { latency: stage.latency_us }) }));
    } else {
      heading.append(statusBadge(t, 'disabled', 'decision.stage.not_evaluated'));
    }
    item.append(heading);
    if (stage && renderDetail) { const detail = renderDetail(stage); if (detail) item.append(detail); }
    if (decidingStage && event.outcome?.reason) {
      item.append(el('p', { class: 'kit-why' }, el('strong', { text: t('decision.why') }), ' ', reasonText(t, event.outcome.reason)),
        el('p', { class: 'kit-fix' }, el('strong', { text: t('decision.fix') }), ' ', fixText(t, event.outcome.reason)));
    }
    if (!stage && decidingStage) item.append(el('p', { class: 'kit-muted', text: t('decision.stage.decided_before') }));
    list.append(item);
  }
  return list;
}

export function reasonText(t, code) {
  const key = `decision.reason.${code}`;
  const text = t(key);
  return text === key ? t('decision.reason.unknown', { code }) : text;
}

export function fixText(t, code) {
  const key = `decision.fix.${code}`;
  const text = t(key);
  return text === key ? t('decision.fix.unknown') : text;
}

function flatten(value, prefix = '', out = new Map()) {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    for (const [key, inner] of Object.entries(value)) flatten(inner, prefix ? `${prefix}.${key}` : key, out);
  } else out.set(prefix, value);
  return out;
}

/** Entity-grouped added/removed/changed entries between two plain objects. */
export function structuredDiff(t, before, after) {
  const left = flatten(before ?? {}), right = flatten(after ?? {});
  const list = el('ul', { class: 'kit-diff' });
  const keys = [...new Set([...left.keys(), ...right.keys()])].sort();
  let changes = 0;
  for (const key of keys) {
    const a = left.get(key), b = right.get(key);
    const show = value => value === undefined ? '—' : JSON.stringify(value);
    if (!left.has(key)) list.append(el('li', { class: 'kit-diff-add' }, el('span', { class: 'kit-diff-mark', text: '+', attrs: { 'aria-label': t('ui.diff.added') } }), el('code', { text: key }), ' ', show(b)));
    else if (!right.has(key)) list.append(el('li', { class: 'kit-diff-remove' }, el('span', { class: 'kit-diff-mark', text: '−', attrs: { 'aria-label': t('ui.diff.removed') } }), el('code', { text: key }), ' ', show(a)));
    else if (JSON.stringify(a) !== JSON.stringify(b)) list.append(el('li', { class: 'kit-diff-change' }, el('span', { class: 'kit-diff-mark', text: '~', attrs: { 'aria-label': t('ui.diff.changed') } }), el('code', { text: key }), ' ', show(a), ' → ', show(b)));
    else continue;
    changes += 1;
  }
  if (!changes) return el('p', { class: 'kit-muted', text: t('ui.diff.none') });
  return list;
}

/**
 * Confirmation naming the target and effect. The operator must type the target
 * name exactly and give a reason; resolves `{reason}` or `null` on cancel.
 */
export function confirmDialog(t, { title, effect, target, confirmLabel = 'ui.confirm.action' }) {
  return new Promise(resolve => {
    const reason = el('textarea', { required: true, maxLength: 512, rows: 3 });
    const typed = el('input', { type: 'text', autocomplete: 'off', spellcheck: false, maxLength: 256 });
    const confirm = el('button', { type: 'submit', class: 'button button-danger', text: t(confirmLabel), disabled: true });
    const cancel = el('button', { type: 'button', class: 'button button-quiet', text: t('ui.cancel') });
    const reasonId = `kit-reason-${Math.random().toString(36).slice(2, 8)}`, typedId = `${reasonId}-target`;
    reason.id = reasonId; typed.id = typedId;
    const form = el('form', { method: 'dialog', class: 'kit-confirm' },
      el('h2', { text: t(title) }),
      el('p', { text: t(effect, { target }) }),
      el('label', { htmlFor: typedId }, el('span', { text: t('ui.confirm.type_target', { target }) }), typed),
      el('label', { htmlFor: reasonId }, el('span', { text: t('ui.confirm.reason') }), reason),
      el('div', { class: 'button-row' }, cancel, confirm));
    const dialog = el('dialog', { class: 'kit-dialog' }, form);
    dialog.setAttribute('aria-label', t(title));
    const sync = () => { confirm.disabled = typed.value !== target || !reason.value.trim(); };
    typed.addEventListener('input', sync); reason.addEventListener('input', sync);
    const finish = value => { dialog.close(); dialog.remove(); resolve(value); };
    cancel.addEventListener('click', () => finish(null));
    dialog.addEventListener('cancel', event => { event.preventDefault(); finish(null); });
    form.addEventListener('submit', event => { event.preventDefault(); if (!confirm.disabled) finish({ reason: reason.value.trim() }); });
    document.body.append(dialog);
    dialog.showModal();
    typed.focus();
  });
}

/**
 * Batches subject IDs per view into Hopae `subjects/resolve` (≤100 IDs, read
 * only). Unavailable resolution degrades to the opaque ID; an ID Hopae does
 * not know is reported as unknown.
 */
export function subjectResolver(api, path = '/v1/plugins/hopae/subjects/resolve') {
  const cache = new Map();
  let pending = new Map(), timer = null, available = true;
  async function flush() {
    timer = null;
    const batch = pending; pending = new Map();
    const ids = [...batch.keys()];
    for (let start = 0; start < ids.length; start += 100) {
      const slice = ids.slice(start, start + 100);
      let resolved = new Map();
      if (available) {
        try {
          const { data } = await api(path, { method: 'POST', json: { ids: slice } });
          const records = Array.isArray(data) ? data : Array.isArray(data?.subjects) ? data.subjects : Array.isArray(data?.items) ? data.items : Object.entries(data?.subjects || {}).map(([id, value]) => ({ id, ...value }));
          for (const record of records) if (record && typeof record.id === 'string') resolved.set(record.id, record);
        } catch (error) {
          if (error?.status === 404 || error?.status === 403 || error?.status === 501) available = false;
          resolved = null;
        }
      }
      for (const id of slice) {
        const record = resolved?.get(id);
        const value = resolved === null || !available ? { state: 'unavailable' } : record ? { state: 'resolved', display: typeof record.display_name === 'string' ? record.display_name : null, principal: record.principal_kind || record.kind || null, status: record.status || null, provider: record.provider || (Array.isArray(record.providers) ? record.providers[0] : null) } : { state: 'unknown' };
        cache.set(id, Promise.resolve(value));
        batch.get(id)(value);
      }
    }
  }
  return {
    resolve(id) {
      if (cache.has(id)) return cache.get(id);
      const promise = new Promise(resolve => pending.set(id, resolve));
      cache.set(id, promise);
      if (!timer) timer = setTimeout(flush, 0);
      return promise;
    },
    get available() { return available; },
  };
}

export const ui = Object.freeze({ version: KIT_VERSION, el, clear, statusBadge, freshnessBadge, relativeAge, copyButton, entityLink, entityHref, emptyState, errorState, loadingState, field, dataTable, stageTimeline, reasonText, fixText, structuredDiff, confirmDialog, subjectResolver });
