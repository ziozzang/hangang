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
  const hours = Math.round(minutes / 60);
  if (hours < 48) return t('ui.age.hours', { count: hours });
  return t('ui.age.days', { count: Math.round(hours / 24) });
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
    for (const option of options) control.append(el('option', { value: option.value, text: option.text ?? t(option.label), selected: option.value === value }));
  } else {
    control = el('input', { id, name, type, value, maxLength, autocomplete: 'off', spellcheck: false });
    if (pattern) control.pattern = pattern;
    if (placeholder) control.placeholder = t(placeholder);
  }
  const helpNode = help ? el('small', { class: 'kit-help', id: `${id}-help`, text: t(help) }) : null;
  if (helpNode) control.setAttribute('aria-describedby', helpNode.id);
  return el('label', { class: 'kit-field', htmlFor: id }, el('span', { class: 'kit-field-label', text: t(label) }), control, helpNode);
}

function locale() { return document.documentElement.lang || undefined; }

/** Full localized date and time. */
export function formatFullTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value ?? '—');
  return new Intl.DateTimeFormat(locale(), { dateStyle: 'medium', timeStyle: 'medium' }).format(date);
}

/** Compact 24-hour time: time only today, month-day and time otherwise. */
export function formatCompactTime(value, now = Date.now()) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value ?? '—');
  const sameDay = date.toDateString() === new Date(now).toDateString();
  const sameYear = date.getFullYear() === new Date(now).getFullYear();
  const options = { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' };
  if (!sameDay) Object.assign(options, { month: '2-digit', day: '2-digit' });
  if (!sameYear) options.year = 'numeric';
  return new Intl.DateTimeFormat(locale(), options).format(date);
}

/** `<time>` with the compact form; full date and relative age in the tooltip. */
export function timeCell(t, value, now = Date.now()) {
  const date = new Date(value);
  const valid = !Number.isNaN(date.getTime());
  return el('time', { class: 'kit-time', dateTime: valid ? date.toISOString() : undefined, text: formatCompactTime(value, now), title: valid ? `${formatFullTime(value)} · ${relativeAge(t, now - date.getTime())}` : undefined });
}

/** Short copyable digest chip (first 12 hex characters). */
export function hashChip(t, value, { full = false } = {}) {
  return el('span', { class: `kit-chip${full ? ' kit-chip-full' : ''}`, title: value }, el('span', { class: 'kit-mono', text: full ? String(value) : String(value).slice(0, 12) }), copyButton(t, value));
}

/**
 * Disabled action rendered as a real button with an info tooltip that names
 * the reason; the wrapper stays focusable so keyboard users can read it.
 */
export function disabledAction(t, label, reason) {
  const id = `kit-tip-${Math.random().toString(36).slice(2, 8)}`;
  const button = el('button', { type: 'button', class: 'button button-quiet', disabled: true, text: t(label), attrs: { 'aria-describedby': id } });
  return el('span', { class: 'kit-action-off', tabIndex: 0, attrs: { 'aria-label': `${t(label)}: ${t(reason)}` } }, button,
    el('span', { class: 'kit-info', text: 'ⓘ', attrs: { 'aria-hidden': 'true' } }),
    el('span', { class: 'kit-tip', id, text: t(reason), attrs: { role: 'tooltip' } }));
}

function readHidden(id, columns) {
  const defaults = new Set(columns.filter(column => column.hidden).map(column => column.key));
  if (!id) return defaults;
  try {
    const stored = JSON.parse(localStorage.getItem(`kit-columns:${id}`) || 'null');
    return Array.isArray(stored) ? new Set(stored.filter(key => columns.some(column => column.key === key))) : defaults;
  } catch { return defaults; }
}

function writeHidden(id, hidden) {
  if (!id) return;
  try { localStorage.setItem(`kit-columns:${id}`, JSON.stringify([...hidden])); } catch { /* Preferences are optional. */ }
}

/**
 * Server-driven data table: the caller's `fetchPage({cursor, order, signal})`
 * performs search/filter/sort/pagination; the table keeps a cursor stack for
 * Back, renders loading/empty/error states, single-line dense rows with
 * truncation tooltips, a sticky header, a column chooser, row activation or
 * expansion, and becomes cards at narrow widths.
 */
export function dataTable(t, { id, caption, columns, fetchPage, rowKey, empty, order = 'desc', sortable = 'time', owner, onPage, onRowOpen, expand }) {
  const root = el('div', { class: 'kit-table-wrap' });
  const status = el('div', { class: 'kit-table-status', attrs: { 'aria-live': 'polite' } });
  const table = el('table', { class: 'kit-table kit-dense' });
  const body = el('tbody');
  const pager = el('nav', { class: 'kit-pager', attrs: { 'aria-label': t('ui.table.pagination') } });
  const prev = el('button', { type: 'button', class: 'button button-quiet', text: t('ui.table.previous') });
  const next = el('button', { type: 'button', class: 'button button-quiet', text: t('ui.table.next') });
  const position = el('span', { class: 'kit-pager-position' });
  pager.append(prev, position, next);
  const hidden = readHidden(id, columns);
  const chooser = el('details', { class: 'kit-columns' }, el('summary', { text: t('ui.table.columns') }));
  const chooserList = el('div', { class: 'kit-columns-list', attrs: { role: 'group', 'aria-label': t('ui.table.columns') } });
  chooser.append(chooserList);
  for (const column of columns) {
    if (column.key === sortable) continue;
    const box = el('input', { type: 'checkbox', checked: !hidden.has(column.key) });
    box.addEventListener('change', () => { if (box.checked) hidden.delete(column.key); else hidden.add(column.key); writeHidden(id, hidden); renderHead(); renderRows(); });
    chooserList.append(el('label', {}, box, el('span', { text: t(column.label) })));
  }
  let cursors = [null], page = 0, nextCursor = null, controller = null, rows = [], destroyed = false;
  const visible = () => columns.filter(column => !hidden.has(column.key));
  const thead = el('thead');
  function renderHead() {
    const head = el('tr');
    for (const column of visible()) {
      const th = el('th', { scope: 'col', class: `kit-col-${column.key}` });
      if (column.key === sortable) {
        const button = el('button', { type: 'button', class: 'kit-sort', text: t(column.label), dataset: { order } });
        th.setAttribute('aria-sort', order === 'asc' ? 'ascending' : 'descending');
        button.addEventListener('click', () => { order = order === 'asc' ? 'desc' : 'asc'; reset(); });
        th.append(button);
      } else th.textContent = t(column.label);
      head.append(th);
    }
    thead.replaceChildren(head);
  }
  function renderRows() {
    body.replaceChildren();
    const shown = visible();
    for (const item of rows) {
      const tr = el('tr', { dataset: { key: rowKey(item) } });
      for (const column of shown) {
        const content = column.render(item);
        const cell = el('div', { class: 'kit-cell' }, content);
        const tip = column.title ? column.title(item) : cell.textContent;
        if (tip) cell.title = tip;
        tr.append(el('td', { class: `kit-col-${column.key}`, dataset: { label: t(column.label) } }, cell));
      }
      if (onRowOpen || expand) {
        tr.classList.add('is-interactive');
        tr.tabIndex = 0;
        if (expand) tr.setAttribute('aria-expanded', 'false');
        const activate = () => {
          if (onRowOpen) return onRowOpen(item);
          const open = tr.getAttribute('aria-expanded') === 'true';
          tr.setAttribute('aria-expanded', String(!open));
          if (open) tr.nextElementSibling?.classList.contains('kit-expansion') && tr.nextElementSibling.remove();
          else tr.after(el('tr', { class: 'kit-expansion' }, el('td', { colSpan: shown.length }, expand(item))));
        };
        tr.addEventListener('click', event => { if (!event.target.closest('a, button, input, select, textarea, summary')) activate(); });
        tr.addEventListener('keydown', event => { if ((event.key === 'Enter' || event.key === ' ') && event.target === tr) { event.preventDefault(); activate(); } });
      }
      body.append(tr);
    }
  }
  renderHead();
  table.append(el('caption', { class: 'kit-visually-hidden', text: t(caption) }), thead, body);
  root.append(el('div', { class: 'kit-table-tools' }, chooser), status, table, pager);
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
      if (result.replace) { body.replaceChildren(); clear(status, result.replace); table.hidden = true; pager.hidden = true; return; }
      table.hidden = false; pager.hidden = false; status.replaceChildren();
      rows = result.items;
      renderRows();
      nextCursor = result.nextCursor || null;
      if (!rows.length) clear(status, emptyState(t, empty));
      prev.disabled = page === 0; next.disabled = !nextCursor;
      position.textContent = rows.length ? t('ui.table.page', { page: page + 1, count: rows.length }) : '';
      onPage?.(result);
    } catch (error) {
      if (signal.aborted || destroyed) return;
      body.replaceChildren(); table.hidden = true; pager.hidden = true;
      clear(status, errorState(t, { owner, message: error.message, retry: () => load() }));
    } finally {
      if (!signal.aborted) table.removeAttribute('aria-busy');
    }
  }
  function reset() { cursors = [null]; page = 0; renderHead(); return load(); }
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

/**
 * Generic ordered trace (owner explain APIs): each entry has a label, a
 * result (`pass`, `deny`, `warn`, `not_evaluated`) and an explanation; the
 * deciding entry is highlighted.
 */
export function traceTimeline(t, entries) {
  const list = el('ol', { class: 'kit-timeline kit-trace' });
  const kinds = { pass: 'allow', deny: 'deny', warn: 'challenge', not_evaluated: 'disabled' };
  for (const entry of entries) {
    const kind = kinds[entry.result] || 'unknown';
    const item = el('li', { class: `kit-stage${entry.deciding ? ' is-deciding' : ''}${entry.result === 'not_evaluated' ? ' is-skipped' : ''}`, dataset: { stage: entry.stage || '', result: entry.result || '' } },
      el('div', { class: 'kit-stage-head' }, el('strong', { text: entry.label }), statusBadge(t, kind, `ui.trace.${Object.hasOwn(kinds, entry.result) ? entry.result : 'unknown'}`)),
      entry.text ? el('p', { class: 'kit-trace-text', text: entry.text }) : null,
      entry.extra || null);
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
export function confirmDialog(t, { title, effect, target, confirmLabel = 'ui.confirm.action', reason: initialReason = '' }) {
  return new Promise(resolve => {
    const reason = el('textarea', { required: true, maxLength: 512, rows: 3 });
    // Optional prefill so a reason already entered on the page is not asked twice.
    reason.value = String(initialReason || '');
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

const SUBJECT_STATUSES = Object.freeze(['active', 'disabled', 'deleted', 'unknown']);
const SUBJECT_KINDS = Object.freeze(['human', 'service', 'workload']);
const SUBJECT_REASONS = Object.freeze(['credential_expired', 'not_found', 'unrecognized', 'human_subjects_not_configured', 'index_incomplete', 'not_enumerable']);
const textOrNull = value => (typeof value === 'string' && value ? value : null);
const numberOrNull = value => (Number.isFinite(value) ? value : null);

/**
 * One item of Hopae `subjects/resolve` or `subjects/search` (Hopae
 * docs/SUBJECT_DIRECTORY.md). Returns null for anything outside the contract.
 */
export function parseSubject(item) {
  if (!item || typeof item !== 'object' || typeof item.id !== 'string' || !SUBJECT_STATUSES.includes(item.status)) return null;
  if (item.reason !== null && !SUBJECT_REASONS.includes(item.reason)) return null;
  return Object.freeze({
    id: item.id, status: item.status, reason: item.reason,
    kind: SUBJECT_KINDS.includes(item.kind) ? item.kind : null,
    userId: textOrNull(item.user_id), humanSubject: textOrNull(item.human_subject),
    displayName: textOrNull(item.display_name), email: textOrNull(item.email),
    providers: Array.isArray(item.providers) ? item.providers.filter(value => typeof value === 'string') : [],
    createdAt: numberOrNull(item.created_at), lastLoginAt: numberOrNull(item.last_login_at), lastSeenAt: numberOrNull(item.last_seen_at),
    serviceId: textOrNull(item.service_id), realm: textOrNull(item.realm), expiresAt: numberOrNull(item.expires_at),
  });
}

/**
 * Batches subject references per view into Hopae `subjects/resolve`
 * (≤100 IDs per request, read only, audited by Hopae). Resolves each ID to
 * `{state: 'resolved', subject}` (subject.status is active, disabled, deleted
 * or unknown with its reason), or `{state: 'unavailable', retry}` when the
 * directory cannot answer, in which case callers show the opaque ID.
 */
export function subjectResolver(api, { path = '/v1/plugins/hopae/subjects/resolve', privacyProfile = 'standard' } = {}) {
  const cache = new Map();
  let pending = new Map(), timer = null, installed = true;
  async function flush() {
    timer = null;
    const batch = pending; pending = new Map();
    const ids = [...batch.keys()];
    for (let start = 0; start < ids.length; start += 100) {
      const slice = ids.slice(start, start + 100);
      let answer = null, retry = false;
      if (installed) {
        try {
          const { data } = await api(path, { method: 'POST', json: { ids: slice, privacy_profile: privacyProfile } });
          if (data && Array.isArray(data.items)) {
            answer = new Map();
            for (const item of data.items) { const subject = parseSubject(item); if (subject) answer.set(subject.id, subject); }
          }
        } catch (error) {
          if (error?.status === 404) installed = false;
          retry = error?.status === 429 || error?.status === 503;
        }
      }
      for (const id of slice) {
        const subject = answer?.get(id);
        const value = subject ? { state: 'resolved', subject } : { state: 'unavailable', retry };
        // Unavailable answers are not cached: the next view asks again.
        if (subject) cache.set(id, Promise.resolve(value)); else cache.delete(id);
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
    get installed() { return installed; },
  };
}

/** Human label of a resolved subject: display name, else masked e-mail, else null. */
export function subjectLabel(subject) { return subject?.displayName || subject?.email || null; }

/**
 * Accessible subject picker (combobox) backed by Hopae `subjects/search`.
 * Without the directory it remains a plain ID input.
 */
export function subjectPicker(t, api, { label, name, value = '', kind = 'human', help = 'ui.picker.help', path = '/v1/plugins/hopae/subjects/search', privacyProfile = 'standard' }) {
  const wrapper = field(t, { label, name, value, maxLength: 1024, help });
  const input = wrapper.querySelector('input');
  const list = el('ul', { class: 'kit-picker', hidden: true, attrs: { role: 'listbox' } });
  list.id = `${input.id}-list`;
  input.setAttribute('role', 'combobox');
  input.setAttribute('aria-autocomplete', 'list');
  input.setAttribute('aria-expanded', 'false');
  input.setAttribute('aria-controls', list.id);
  wrapper.append(list);
  let timer = null, sequence = 0, active = -1, items = [], available = true;
  const close = () => { list.hidden = true; input.setAttribute('aria-expanded', 'false'); input.removeAttribute('aria-activedescendant'); active = -1; };
  const choose = subject => { input.value = subject.id; close(); input.dispatchEvent(new Event('change', { bubbles: true })); };
  const highlight = index => {
    active = index;
    [...list.children].forEach((option, position) => option.setAttribute('aria-selected', String(position === index)));
    if (index >= 0) input.setAttribute('aria-activedescendant', list.children[index].id); else input.removeAttribute('aria-activedescendant');
  };
  async function search(query) {
    const current = ++sequence;
    try {
      const { data } = await api(path, { method: 'POST', json: { q: query, kind, limit: 10, cursor: null, privacy_profile: privacyProfile } });
      if (current !== sequence) return;
      items = (Array.isArray(data?.items) ? data.items : []).map(parseSubject).filter(subject => subject && subject.status !== 'unknown');
      list.replaceChildren(...items.map((subject, index) => {
        const option = el('li', { id: `${list.id}-${index}`, class: `kit-picker-option kit-subject-${subject.status}`, attrs: { role: 'option', 'aria-selected': 'false' } },
          el('span', { class: 'kit-entity-label', text: subjectLabel(subject) || subject.id }),
          el('span', { class: 'kit-entity-id', text: subject.id }),
          subject.status !== 'active' ? el('span', { class: 'kit-tag', text: t(`ui.subject.status.${subject.status}`) }) : null);
        option.addEventListener('mousedown', event => { event.preventDefault(); choose(subject); });
        return option;
      }));
      if (!items.length) list.append(el('li', { class: 'kit-picker-empty', text: t('ui.picker.none'), attrs: { role: 'option', 'aria-disabled': 'true' } }));
      list.hidden = false; input.setAttribute('aria-expanded', 'true'); highlight(-1);
    } catch (error) {
      if (error?.status === 404) available = false;
      close();
    }
  }
  input.addEventListener('input', () => {
    clearTimeout(timer);
    const query = input.value.trim();
    if (!available || query.length < 2 || query.length > 128) return close();
    timer = setTimeout(() => search(query), 250);
  });
  input.addEventListener('keydown', event => {
    if (list.hidden || !items.length) return;
    if (event.key === 'ArrowDown') { event.preventDefault(); highlight(Math.min(items.length - 1, active + 1)); }
    else if (event.key === 'ArrowUp') { event.preventDefault(); highlight(Math.max(0, active - 1)); }
    else if (event.key === 'Enter' && active >= 0) { event.preventDefault(); choose(items[active]); }
    else if (event.key === 'Escape') { event.preventDefault(); close(); }
  });
  input.addEventListener('blur', () => setTimeout(close, 100));
  return wrapper;
}

export const ui = Object.freeze({ version: KIT_VERSION, el, clear, statusBadge, freshnessBadge, relativeAge, copyButton, entityLink, entityHref, emptyState, errorState, loadingState, field, dataTable, stageTimeline, reasonText, fixText, structuredDiff, traceTimeline, confirmDialog, formatFullTime, formatCompactTime, timeCell, hashChip, disabledAction, subjectResolver, subjectPicker, subjectLabel, parseSubject });
