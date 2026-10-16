// Policies section (ADR 0020 §4, Pumgye policy v1): service catalog, service
// detail, matrix, advanced JSON and the review-and-publish flow.
import { loadCatalogs } from '../../kit/i18n.js';
import { policyState, loadPolicy, working, edit, discardDraft, replaceDraft, resetPolicyState } from './store.js';
import { serviceSummary, countChanges, CONTEXTS, IDENT, assignments, effectiveRights, highestClass, clone } from './model.js';
import { renderService } from './service.js';
import { renderPublish } from './publish.js';

let catalogs = null;
export { resetPolicyState as resetPolicies };

async function ensureCatalogs() {
  catalogs ??= Promise.all([loadCatalogs('/ui/zt/messages', ['en', 'ko'], 'policies.'), loadCatalogs('/ui/zt/messages', ['en', 'ko'], 'pumgye.')]).catch(error => { catalogs = null; throw error; });
  return catalogs;
}

/** Source strip and draft bar shared by every Policies page. */
export function policyHeader(cx) {
  const { t, ui } = cx;
  const state = policyState();
  const strip = ui.el('div', { class: 'zt-authority', attrs: { role: 'group', 'aria-label': t('policies.authority') } },
    ui.el('span', { class: 'kit-muted', text: t('ui.entity.owner', { owner: t('ui.owner.pumgye') }) }),
    ui.el('span', { class: 'kit-mono', text: t('policies.revision', { revision: state.revision }) }),
    ui.statusBadge(t, state.managed ? 'disabled' : 'healthy', state.managed ? `policies.source.${state.owner === 'kubernetes' ? 'kubernetes' : 'unknown'}` : state.independent ? 'policies.source.independent' : 'policies.source.embedded'));
  const parts = [strip];
  if (state.managed) parts.push(ui.el('p', { class: 'zt-banner', attrs: { role: 'note' }, text: t(state.owner === 'kubernetes' ? 'policies.managed.kubernetes' : 'policies.managed.unknown') }));
  if (state.outcomeUnknown) parts.push(ui.el('p', { class: 'zt-banner zt-banner-warn', attrs: { role: 'alert' }, text: t('policies.publish.unknown') }));
  if (state.draft) {
    const count = countChanges(state.base, state.draft);
    parts.push(ui.el('div', { class: 'zt-draftbar', attrs: { role: 'status' } },
      ui.el('strong', { text: t('policies.draft.count', { count }) }),
      ui.el('span', { class: 'kit-muted', text: t('policies.draft.base', { revision: state.revision }) }),
      ui.el('span', { class: 'zt-draftbar-actions' },
        ui.el('a', { class: 'button button-primary', href: '#policies/publish', text: t('policies.draft.review') }),
        ui.el('button', { type: 'button', class: 'button button-quiet', text: t('policies.draft.discard'), on: { click: async () => {
          const ok = await ui.confirmDialog(t, { title: 'policies.draft.discard', effect: 'policies.draft.discard.effect', target: t('policies.draft.discard.word'), confirmLabel: 'policies.draft.discard' });
          if (ok) { discardDraft(); cx.reload(); }
        } } }))));
  }
  return ui.el('div', { class: 'zt-policy-head' }, parts);
}

function catalogTable(cx, policy, query) {
  const { t, ui } = cx;
  const ids = Object.keys(policy.services || {}).sort().filter(id => !query || id.toLowerCase().includes(query.toLowerCase()));
  const table = ui.dataTable(t, {
    id: 'policy-services', caption: 'policies.catalog.caption', owner: 'ui.owner.pumgye', sortable: 'service', order: 'asc',
    rowKey: row => row.id, onRowOpen: row => cx.navigate(cx.hashFor('policies', ['services', row.id])),
    empty: { title: query ? 'policies.catalog.empty.filtered' : 'policies.catalog.empty', body: 'policies.catalog.empty.body' },
    columns: [
      { key: 'service', label: 'policies.col.service', render: row => ui.el('a', { href: cx.hashFor('policies', ['services', row.id]), class: 'kit-mono', text: row.id }) },
      { key: 'context', label: 'policies.col.context', render: row => ui.el('span', { class: 'kit-tag', text: t(`policies.context.${row.context}`) }) },
      { key: 'guard', label: 'policies.col.guard', render: row => ui.statusBadge(t, row.requireGuard ? 'healthy' : 'disabled', row.requireGuard ? 'policies.guard.required' : 'policies.guard.optional') },
      { key: 'roles', label: 'policies.col.roles', render: row => String(row.roles) },
      { key: 'assignments', label: 'policies.col.assignments', render: row => String(row.assignments) },
      { key: 'networks', label: 'policies.col.networks', render: row => String(row.networks) },
      { key: 'resources', label: 'policies.col.resources', render: row => String(row.resources) },
      { key: 'class', label: 'policies.col.class', render: row => row.highestClass ? ui.el('span', { class: `zt-class zt-class-${row.highestClass === (policy.information_classes || []).at(-1) ? 'top' : 'normal'}`, text: row.highestClass }) : '—' },
    ],
    fetchPage: async ({ cursor, order }) => {
      const sorted = order === 'desc' ? [...ids].reverse() : ids;
      const start = Number(cursor || 0);
      return { items: sorted.slice(start, start + 50).map(id => serviceSummary(policy, id)), nextCursor: start + 50 < sorted.length ? String(start + 50) : null };
    },
  });
  cx.signal.addEventListener('abort', () => table.destroy(), { once: true });
  return table;
}

function newServiceForm(cx, policy) {
  const { t, ui } = cx;
  const form = ui.el('form', { class: 'zt-filters zt-inline-form', attrs: { 'aria-label': t('policies.service.new') } },
    ui.field(t, { label: 'policies.service.id', name: 'id', pattern: IDENT.source.slice(1, -1), maxLength: 128 }),
    ui.field(t, { label: 'policies.col.context', name: 'context', options: CONTEXTS.map(value => ({ value, label: `policies.context.${value}` })) }),
    ui.el('div', { class: 'button-row zt-filter-actions' }, ui.el('button', { type: 'submit', class: 'button', text: t('policies.service.create') })),
    ui.el('p', { class: 'kit-field-error', attrs: { role: 'alert' } }));
  form.addEventListener('submit', event => {
    event.preventDefault();
    const id = form.elements.id.value.trim(), context = form.elements.context.value;
    const error = form.querySelector('.kit-field-error');
    if (!IDENT.test(id) || Object.hasOwn(policy.services || {}, id)) { error.textContent = t('policies.service.invalid'); form.elements.id.setAttribute('aria-invalid', 'true'); return; }
    const api = context === 'kubernetes_api';
    edit(document => {
      const information = document.information_classes?.[0] || 'public';
      document.services[id] = { permissions: ['read', 'write'], roles: { reader: { permissions: ['read'], information_classes: [information], inherits: [], minimum_aal: api ? 0 : 1 }, writer: { permissions: ['write'], information_classes: [information], inherits: ['reader'], minimum_aal: api ? 0 : 2 } }, users: {}, networks: [], require_guard: !api };
      if (api) document.services[id].authorization_context = 'kubernetes_api';
    });
    cx.navigate(cx.hashFor('policies', ['services', id]));
  });
  return form;
}

async function renderCatalog(cx, root, params) {
  const { t, ui } = cx;
  const state = policyState();
  const policy = working();
  const query = params.get('q') || '';
  const actions = [ui.el('a', { class: 'button button-quiet', href: '#policies/matrix', text: t('policies.matrix.title') }), ui.el('a', { class: 'button button-quiet', href: '#policies/advanced', text: t('policies.advanced.title') })];
  const { content } = cx.page(root, { crumbs: [{ label: t('nav.policies') }], title: t('policies.catalog.title'), owner: t('policies.catalog.owner'), actions });
  const search = ui.el('form', { class: 'zt-search', attrs: { role: 'search' } });
  const input = ui.el('input', { type: 'search', name: 'q', value: query, maxLength: 128, autocomplete: 'off' });
  input.setAttribute('aria-label', t('policies.catalog.search'));
  input.placeholder = t('policies.catalog.search');
  search.append(input, ui.el('button', { type: 'submit', class: 'button', text: t('access.search.go') }));
  search.addEventListener('submit', event => { event.preventDefault(); const next = new URLSearchParams(); if (input.value.trim()) next.set('q', input.value.trim()); cx.navigate(cx.hashFor('policies', [], next)); });
  const classes = ui.el('p', { class: 'kit-muted' }, ui.el('span', { text: t('policies.classes') }), ' ', (policy.information_classes || []).map((name, index, all) => ui.el('span', { class: `zt-class zt-class-${index === all.length - 1 ? 'top' : 'normal'}`, text: name })));
  const table = catalogTable(cx, policy, query);
  content.append(policyHeader(cx), ui.el('div', { class: 'zt-toolbar' }, search), classes, table.element);
  if (!state.managed) content.append(ui.el('details', { class: 'panel zt-panel' }, ui.el('summary', { text: t('policies.service.new') }), newServiceForm(cx, policy)));
  await table.reload();
}

async function renderMatrix(cx, root, params) {
  const { t, ui } = cx;
  const policy = working();
  const { content } = cx.page(root, { crumbs: [{ label: t('nav.policies'), href: '#policies' }, { label: t('policies.matrix.title') }], title: t('policies.matrix.title'), owner: t('policies.matrix.owner') });
  const services = Object.keys(policy.services || {}).sort();
  const subjects = new Map();
  for (const id of services) for (const row of assignments(policy.services[id])) {
    const key = `${row.kind}:${row.subject}`;
    if (!subjects.has(key)) subjects.set(key, { kind: row.kind, subject: row.subject, services: {} });
    subjects.get(key).services[id] = row.roles;
  }
  const filter = (params.get('q') || '').toLowerCase();
  const rows = [...subjects.values()].filter(row => !filter || row.subject.toLowerCase().includes(filter)).sort((a, b) => a.subject.localeCompare(b.subject));
  const columns = [
    { key: 'subject', label: 'policies.col.subject', render: row => subjectCell(cx, row.subject, row.kind) },
    ...services.map(id => ({ key: `svc-${id}`, label: id, render: row => {
      const roles = row.services[id];
      if (!roles) return ui.el('span', { class: 'kit-muted', text: '—' });
      const rights = effectiveRights(policy.services[id], roles);
      const top = highestClass(policy, rights.classes);
      return ui.el('span', { class: 'zt-matrix-cell' }, ui.el('strong', { text: roles.join(', ') }), ui.el('small', { class: 'kit-muted', text: t('policies.matrix.cell', { permissions: rights.permissions.length, cls: top || '—', aal: rights.minimumAal }) }));
    }, title: row => {
      const roles = row.services[id];
      if (!roles) return '';
      const rights = effectiveRights(policy.services[id], roles);
      return `${id}: ${rights.permissions.join(', ')} · ${rights.classes.join(', ')} · AAL${rights.minimumAal}`;
    } })),
  ];
  const t2 = (key, params) => (key.startsWith('policies.') || key.startsWith('ui.') ? t(key, params) : key);
  const table = ui.dataTable(t2, { id: 'policy-matrix', caption: 'policies.matrix.caption', owner: 'ui.owner.pumgye', sortable: 'subject', order: 'asc', rowKey: row => `${row.kind}:${row.subject}`, empty: { title: 'policies.matrix.empty' }, columns,
    fetchPage: async ({ cursor, order }) => { const sorted = order === 'desc' ? [...rows].reverse() : rows; const start = Number(cursor || 0); return { items: sorted.slice(start, start + 100), nextCursor: start + 100 < sorted.length ? String(start + 100) : null }; } });
  const search = ui.el('form', { class: 'zt-search', attrs: { role: 'search' } });
  const input = ui.el('input', { type: 'search', name: 'q', value: params.get('q') || '', maxLength: 256 });
  input.setAttribute('aria-label', t('policies.matrix.search'));
  input.placeholder = t('policies.matrix.search');
  search.append(input, ui.el('button', { type: 'submit', class: 'button', text: t('access.search.go') }));
  search.addEventListener('submit', event => { event.preventDefault(); const next = new URLSearchParams(); if (input.value.trim()) next.set('q', input.value.trim()); cx.navigate(cx.hashFor('policies', ['matrix'], next)); });
  content.append(policyHeader(cx), search, ui.el('div', { class: 'zt-scroll-x' }, table.element));
  cx.signal.addEventListener('abort', () => table.destroy(), { once: true });
  await table.reload();
}

/** Subject with its resolved Hopae label when available. */
export function subjectCell(cx, subject, kind) {
  const { t, ui } = cx;
  const cell = ui.el('span', { class: 'zt-inline' }, ui.el('code', { class: 'kit-entity-id', text: subject }), ui.el('small', { class: 'kit-tag', text: t(`policies.kind.${kind}`) }));
  if (kind === 'user' || kind === 'human') {
    cx.resolver.resolve(subject).then(value => {
      const label = value.state === 'resolved' ? cx.ui.subjectLabel(value.subject) : null;
      if (value.state === 'resolved' && value.subject.status !== 'active') cell.append(ui.el('small', { class: 'kit-tag kit-tag-warn', text: t(`ui.subject.status.${value.subject.status}`) }));
      if (label && cell.isConnected !== false) cell.prepend(ui.el('a', { href: ui.entityHref('user', subject), class: 'zt-subject-name', text: label }));
    });
  }
  return cell;
}

async function renderAdvanced(cx, root) {
  const { t, ui } = cx;
  const state = policyState();
  const { content } = cx.page(root, { crumbs: [{ label: t('nav.policies'), href: '#policies' }, { label: t('policies.advanced.title') }], title: t('policies.advanced.title'), owner: t('policies.advanced.owner') });
  const pre = ui.el('pre', { class: 'kit-mono zt-json', text: JSON.stringify(working(), null, 2), tabIndex: 0 });
  pre.setAttribute('aria-label', t('policies.advanced.document'));
  const editor = ui.el('textarea', { class: 'kit-mono zt-json', rows: 24, spellcheck: false, hidden: true });
  editor.setAttribute('aria-label', t('policies.advanced.document'));
  const error = ui.el('p', { class: 'kit-field-error', attrs: { role: 'alert' } });
  const apply = ui.el('button', { type: 'button', class: 'button button-primary', text: t('policies.advanced.apply'), hidden: true });
  const toggle = state.managed ? ui.disabledAction(t, 'policies.advanced.edit', 'policies.managed.short') : ui.el('button', { type: 'button', class: 'button', text: t('policies.advanced.edit') });
  if (!state.managed) toggle.addEventListener('click', () => { editor.value = JSON.stringify(working(), null, 2); editor.hidden = false; pre.hidden = true; apply.hidden = false; toggle.hidden = true; editor.focus(); });
  apply.addEventListener('click', () => {
    let document;
    try { document = JSON.parse(editor.value); } catch { error.textContent = t('policies.advanced.invalid_json'); editor.setAttribute('aria-invalid', 'true'); return; }
    if (!document || typeof document !== 'object' || document.version !== 1 || !Array.isArray(document.information_classes) || typeof document.services !== 'object') { error.textContent = t('policies.advanced.invalid_shape'); editor.setAttribute('aria-invalid', 'true'); return; }
    replaceDraft(document);
    cx.navigate('#policies/publish');
  });
  content.append(policyHeader(cx), ui.el('p', { class: 'zt-banner', attrs: { role: 'note' }, text: t('policies.advanced.note') }), ui.el('div', { class: 'button-row' }, toggle, apply), error, pre, editor);
}

/** Subject kind implied by an identifier format (Hopae user ids, human1:, s_ workload ids). */
function kindForSubject(subject) {
  if (subject.startsWith('human1:')) return 'human';
  if (/^s_[A-Za-z0-9]+$/.test(subject)) return 'workload';
  return 'user';
}

/**
 * `#policies/simulate?subject=…[&service=…]` — cross-section entry (Identities
 * links here). The simulator is per service: with a known service (or only one)
 * redirect into its simulator tab; otherwise let the operator pick the service,
 * listing the ones the subject is assigned in first. All parameters are kept.
 */
function renderSimulateEntry(cx, root, params) {
  const { t, ui } = cx;
  const policy = working();
  const services = Object.keys(policy.services || {}).sort();
  const subject = (params.get('subject') || '').trim().slice(0, 256);
  const target = id => {
    const next = new URLSearchParams(params);
    next.delete('service');
    next.set('tab', 'simulate');
    if (subject && !next.get('kind')) next.set('kind', kindForSubject(subject));
    return cx.hashFor('policies', ['services', id], next);
  };
  const requested = params.get('service');
  if (requested && Object.hasOwn(policy.services || {}, requested)) { location.replace(target(requested)); return; }
  if (services.length === 1) { location.replace(target(services[0])); return; }
  const { content } = cx.page(root, { crumbs: [{ label: t('nav.policies'), href: '#policies' }, { label: t('policies.simulate.title') }], title: t('policies.simulate.title'), owner: subject ? t('policies.simulate.for', { subject }) : t('policies.simulate.subtitle') });
  content.append(policyHeader(cx));
  if (!services.length) { content.append(ui.emptyState ? ui.emptyState(t, { title: 'policies.catalog.empty' }) : ui.el('p', { class: 'kit-muted', text: t('policies.catalog.empty') })); return; }
  const assigned = new Set(subject ? services.filter(id => assignments(policy.services[id]).some(row => row.subject === subject)) : []);
  const ordered = [...services.filter(id => assigned.has(id)), ...services.filter(id => !assigned.has(id))];
  content.append(ui.el('section', { class: 'panel zt-panel', attrs: { 'aria-label': t('policies.simulate.pick') } },
    ui.el('h2', { text: t('policies.simulate.pick') }),
    ui.el('ul', { class: 'zt-network-list zt-simulate-pick' }, ordered.map(id => ui.el('li', {},
      ui.el('a', { href: target(id), class: 'kit-mono', text: id }),
      assigned.has(id) ? ui.el('span', { class: 'kit-tag', text: t('policies.simulate.assigned') }) : null)))));
}

export async function renderPolicies(cx, root, route) {
  const { t, ui } = cx;
  await ensureCatalogs();
  try { await loadPolicy(cx, { force: route.params.get('refresh') === '1' }); }
  catch (error) {
    if (error?.status === 401) throw error;
    const { content } = cx.page(root, { crumbs: [{ label: t('nav.policies') }], title: t('policies.catalog.title') });
    content.append(ui.errorState(t, { owner: 'ui.owner.pumgye', message: error.message, retry: () => cx.reload() }));
    return;
  }
  const [page, id] = route.parts;
  if (page === 'services' && id) return renderService(cx, root, id, route.params, { header: policyHeader, subjectCell });
  if (page === 'matrix') return renderMatrix(cx, root, route.params);
  if (page === 'simulate') return renderSimulateEntry(cx, root, route.params);
  if (page === 'advanced') return renderAdvanced(cx, root);
  if (page === 'publish') return renderPublish(cx, root, { header: policyHeader });
  return renderCatalog(cx, root, route.params);
}

export { clone };
