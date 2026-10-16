// Service detail: overview, resources & actions, roles, assignments,
// access simulator and change history.
import { policyState, working, edit } from './store.js';
import { contextOf, kindsFor, fieldFor, subjectProblem, assignments, effectiveRights, roleHolders, wouldCycle, highestClass, IDENT, serviceSummary } from './model.js';
import { renderSimulator } from './simulator.js';

const TABS = Object.freeze(['overview', 'resources', 'roles', 'assignments', 'simulate', 'history']);

function tabs(cx, id, current) {
  const { t, ui } = cx;
  const nav = ui.el('nav', { class: 'zt-tabs', attrs: { 'aria-label': t('policies.tabs') } });
  for (const tab of TABS) {
    const params = new URLSearchParams(); if (tab !== 'overview') params.set('tab', tab);
    nav.append(ui.el('a', { href: cx.hashFor('policies', ['services', id], params), class: `zt-tab${tab === current ? ' is-active' : ''}`, text: t(`policies.tab.${tab}`), attrs: { 'aria-current': tab === current ? 'page' : null } }));
  }
  return nav;
}

/** Read-only notice for managed sources; returns true when edits are allowed. */
function editable(cx) { return !policyState().managed; }

function chips(cx, values, kind = '') {
  return cx.ui.el('span', { class: 'zt-chips' }, values.length ? values.map(value => cx.ui.el('span', { class: `kit-tag ${kind}`, text: value })) : cx.ui.el('span', { class: 'kit-muted', text: '—' }));
}

function overview(cx, id, service, policy) {
  const { t, ui } = cx;
  const summary = serviceSummary(policy, id);
  const cards = ui.el('div', { class: 'zt-kpis' },
    [['policies.col.roles', summary.roles], ['policies.col.assignments', summary.assignments], ['policies.col.networks', summary.networks], ['policies.col.resources', summary.resources]]
      .map(([label, value]) => ui.el('div', { class: 'zt-kpi' }, ui.el('span', { class: 'zt-kpi-label', text: t(label) }), ui.el('strong', { class: 'zt-kpi-value', text: String(value) }))));
  const vocabulary = ui.el('section', { class: 'panel zt-panel' }, ui.el('h2', { text: t('policies.permissions') }), chips(cx, service.permissions || []));
  if (editable(cx)) {
    const form = ui.el('form', { class: 'zt-inline-form' }, ui.field(t, { label: 'policies.permission.new', name: 'permission', pattern: IDENT.source.slice(1, -1), maxLength: 128 }), ui.el('button', { type: 'submit', class: 'button', text: t('policies.add') }));
    form.addEventListener('submit', event => {
      event.preventDefault();
      const value = form.elements.permission.value.trim();
      if (!IDENT.test(value) || (service.permissions || []).includes(value)) { form.elements.permission.setAttribute('aria-invalid', 'true'); return; }
      edit(document => { document.services[id].permissions = [...(document.services[id].permissions || []), value]; });
      cx.reload();
    });
    vocabulary.append(form);
  }
  const guard = ui.el('label', { class: 'zt-switch' }, ui.el('input', { type: 'checkbox', checked: service.require_guard !== false, disabled: !editable(cx) || contextOf(service) === 'kubernetes_api' }), ui.el('span', { text: t('policies.guard.toggle') }));
  guard.querySelector('input').addEventListener('change', event => { edit(document => { document.services[id].require_guard = event.target.checked; }); cx.reload(); });
  const settings = ui.el('section', { class: 'panel zt-panel' }, ui.el('h2', { text: t('policies.settings') }),
    ui.el('dl', { class: 'zt-dl' }, ui.el('dt', { text: t('policies.col.context') }), ui.el('dd', { text: t(`policies.context.${contextOf(service)}`) }),
      ui.el('dt', { text: t('policies.col.class') }), ui.el('dd', { text: summary.highestClass || '—' })), guard,
    ui.el('p', { class: 'kit-muted', text: t(contextOf(service) === 'kubernetes_api' ? 'policies.guard.kubernetes' : 'policies.guard.help') }),
    ui.el('a', { class: 'button button-quiet', href: cx.hashFor('access', ['decisions'], new URLSearchParams({ service: id })), text: t('policies.decisions') }));
  return [cards, ui.el('div', { class: 'zt-grid' }, vocabulary, settings)];
}

function resources(cx, id, service, policy) {
  const { t, ui } = cx;
  const entries = Object.entries(policy.resources || {}).filter(([, resource]) => resource.service === id);
  const wrap = ui.el('div', { class: 'zt-stack-list' });
  if (!entries.length) wrap.append(ui.emptyState(t, { title: 'policies.resources.empty', body: 'policies.resources.empty.body' }));
  for (const [name, resource] of entries) {
    const panel = ui.el('section', { class: 'panel zt-panel', dataset: { resource: name } },
      ui.el('div', { class: 'zt-panel-head' }, ui.el('h2', { class: 'kit-mono', text: name }), ui.el('span', { class: 'zt-chips' }, ui.el('span', { class: 'zt-class zt-class-normal', text: resource.information_class }), ui.el('span', { class: 'kit-tag', text: t('policies.aal', { aal: resource.minimum_aal || 0 }) }))));
    const table = ui.el('table', { class: 'kit-table zt-simple-table' }, ui.el('thead', {}, ui.el('tr', {}, ui.el('th', { text: t('policies.col.action') }), ui.el('th', { text: t('policies.col.permission') }), ui.el('th', { text: '' }))));
    const body = ui.el('tbody');
    for (const [action, permission] of Object.entries(resource.actions || {})) {
      const select = ui.el('select', { disabled: !editable(cx) }, (service.permissions || []).map(value => ui.el('option', { value, text: value, selected: value === permission })));
      select.setAttribute('aria-label', t('policies.action.permission', { action }));
      select.addEventListener('change', () => { edit(document => { document.resources[name].actions[action] = select.value; }); cx.reload(); });
      const remove = ui.el('button', { type: 'button', class: 'button button-quiet', text: t('policies.remove'), disabled: !editable(cx) });
      remove.addEventListener('click', () => { edit(document => { delete document.resources[name].actions[action]; }); cx.reload(); });
      body.append(ui.el('tr', {}, ui.el('td', { class: 'kit-mono', text: action }), ui.el('td', {}, select), ui.el('td', {}, remove)));
    }
    table.append(body);
    panel.append(table);
    if (editable(cx)) {
      const form = ui.el('form', { class: 'zt-inline-form' }, ui.field(t, { label: 'policies.action.new', name: 'action', pattern: IDENT.source.slice(1, -1), maxLength: 128 }), ui.field(t, { label: 'policies.col.permission', name: 'permission', options: (service.permissions || []).map(value => ({ value, text: value })) }), ui.el('button', { type: 'submit', class: 'button', text: t('policies.add') }));
      form.addEventListener('submit', event => {
        event.preventDefault();
        const action = form.elements.action.value.trim();
        if (!IDENT.test(action) || Object.hasOwn(resource.actions || {}, action)) { form.elements.action.setAttribute('aria-invalid', 'true'); return; }
        edit(document => { document.resources[name].actions = { ...(document.resources[name].actions || {}), [action]: form.elements.permission.value }; });
        cx.reload();
      });
      panel.append(form);
    }
    wrap.append(panel);
  }
  if (editable(cx)) {
    const form = ui.el('form', { class: 'panel zt-panel zt-inline-form', attrs: { 'aria-label': t('policies.resource.new') } },
      ui.el('h2', { text: t('policies.resource.new') }),
      ui.field(t, { label: 'policies.resource.id', name: 'resource', pattern: IDENT.source.slice(1, -1), maxLength: 128 }),
      ui.field(t, { label: 'policies.col.class', name: 'class', options: (policy.information_classes || []).map(value => ({ value, text: value })) }),
      ui.field(t, { label: 'policies.role.aal', name: 'aal', options: [0, 1, 2, 3].map(value => ({ value: String(value), label: `policies.aal.option.${value}` })) }),
      ui.el('button', { type: 'submit', class: 'button', text: t('policies.add') }));
    form.addEventListener('submit', event => {
      event.preventDefault();
      const name = form.elements.resource.value.trim();
      if (!IDENT.test(name) || Object.hasOwn(policy.resources || {}, name)) { form.elements.resource.setAttribute('aria-invalid', 'true'); return; }
      edit(document => { document.resources = { ...(document.resources || {}), [name]: { service: id, information_class: form.elements.class.value, actions: {}, minimum_aal: Number(form.elements.aal.value) } }; });
      cx.reload();
    });
    wrap.append(form);
  }
  return [wrap];
}

function roleEditor(cx, id, service, policy, name) {
  const { t, ui } = cx;
  const role = service.roles[name] || { permissions: [], information_classes: [], inherits: [], minimum_aal: 0 };
  const isNew = !service.roles[name];
  const form = ui.el('form', { class: 'panel zt-panel zt-role-editor', attrs: { 'aria-label': t('policies.role.edit', { role: name || '' }) } });
  const disabled = !editable(cx);
  if (isNew) form.append(ui.field(t, { label: 'policies.role.name', name: 'name', pattern: IDENT.source.slice(1, -1), maxLength: 128 }));
  else form.append(ui.el('h2', {}, ui.el('span', { class: 'kit-mono', text: name }), ' ', ui.el('small', { class: 'kit-muted', text: t('policies.role.used', { count: roleHolders(service, name) }) })));
  const fieldset = (legend, children) => ui.el('fieldset', { class: 'zt-fieldset', disabled }, ui.el('legend', { text: t(legend) }), children);
  form.append(fieldset('policies.permissions', (service.permissions || []).map(permission => ui.el('label', { class: 'zt-check' }, ui.el('input', { type: 'checkbox', name: 'permission', value: permission, checked: role.permissions.includes(permission) }), ui.el('span', { class: 'kit-mono', text: permission })))));
  const classes = policy.information_classes || [];
  // Pumgye v1 grants exactly the listed classes (a membership set, not a
  // hierarchy): granting the top class does not imply the lower ones.
  const classSet = ui.el('div', { class: 'zt-check-row' }, classes.map(information => ui.el('label', { class: 'zt-check' }, ui.el('input', { type: 'checkbox', name: 'class', value: information, checked: role.information_classes.includes(information) }), ui.el('span', { class: `zt-class zt-class-${information === classes.at(-1) ? 'top' : 'normal'}`, text: information }))));
  form.append(fieldset('policies.role.classes', [classSet, ui.el('small', { class: 'kit-help zt-fieldset-help', text: t('policies.role.classes.help') })]));
  form.append(ui.el('fieldset', { class: 'zt-fieldset', disabled }, [ui.field(t, { label: 'policies.role.aal', name: 'aal', value: String(role.minimum_aal || 0), options: [0, 1, 2, 3].map(value => ({ value: String(value), label: `policies.aal.option.${value}` })) })]));
  const parents = Object.keys(service.roles).filter(other => other !== name);
  form.append(fieldset('policies.role.inherits', parents.length ? parents.map(parent => ui.el('label', { class: 'zt-check' }, ui.el('input', { type: 'checkbox', name: 'inherits', value: parent, checked: (role.inherits || []).includes(parent) }), ui.el('span', { class: 'kit-mono', text: parent }))) : ui.el('span', { class: 'kit-muted', text: t('policies.role.inherits.none') })));
  const effective = effectiveRights(service, [name]);
  if (!isNew) form.append(ui.el('p', { class: 'kit-muted', text: t('policies.role.effective', { permissions: effective.permissions.join(', ') || '—', classes: effective.classes.join(', ') || '—', aal: effective.minimumAal }) }));
  const error = ui.el('p', { class: 'kit-field-error', attrs: { role: 'alert' } });
  const actions = ui.el('div', { class: 'button-row' });
  if (disabled) actions.append(ui.disabledAction(t, 'policies.role.save', 'policies.managed.short'));
  else {
    actions.append(ui.el('button', { type: 'submit', class: 'button button-primary', text: t(isNew ? 'policies.role.create' : 'policies.role.save') }));
    if (!isNew) {
      const used = roleHolders(service, name) + Object.values(service.roles).filter(other => (other.inherits || []).includes(name)).length;
      if (used) actions.append(ui.disabledAction(t, 'policies.role.delete', 'policies.role.delete.blocked'));
      else actions.append(ui.el('button', { type: 'button', class: 'button button-quiet', text: t('policies.role.delete'), on: { click: () => { edit(document => { delete document.services[id].roles[name]; }); cx.navigate(cx.hashFor('policies', ['services', id], new URLSearchParams({ tab: 'roles' }))); } } }));
    }
  }
  form.append(error, actions);
  form.addEventListener('submit', event => {
    event.preventDefault();
    const target = isNew ? form.elements.name.value.trim() : name;
    if (!IDENT.test(target) || target === 'guest' || (isNew && Object.hasOwn(service.roles, target))) { error.textContent = t('policies.role.invalid_name'); return; }
    const selected = selector => [...form.querySelectorAll(selector)].filter(box => box.checked).map(box => box.value);
    const inherits = selected('input[name="inherits"]');
    if (wouldCycle(service, target, inherits)) { error.textContent = t('policies.role.cycle'); return; }
    const next = { permissions: selected('input[name="permission"]'), information_classes: selected('input[name="class"]'), inherits, minimum_aal: Number(form.elements.aal.value) };
    edit(document => { document.services[id].roles[target] = next; });
    cx.navigate(cx.hashFor('policies', ['services', id], new URLSearchParams({ tab: 'roles', role: target })));
  });
  return form;
}

function roles(cx, id, service, policy, params) {
  const { t, ui } = cx;
  const names = Object.keys(service.roles || {}).sort();
  const selected = params.get('role');
  const list = ui.el('ul', { class: 'zt-role-list', attrs: { 'aria-label': t('policies.tab.roles') } });
  for (const name of names) {
    const role = service.roles[name];
    const top = highestClass(policy, role.information_classes || []);
    const linkParams = new URLSearchParams({ tab: 'roles', role: name });
    list.append(ui.el('li', { class: name === selected ? 'is-selected' : '' }, ui.el('a', { href: cx.hashFor('policies', ['services', id], linkParams), attrs: { 'aria-current': name === selected ? 'true' : null } },
      ui.el('span', { class: 'zt-role-name kit-mono', text: name }),
      ui.el('span', { class: 'zt-chips' }, (role.permissions || []).map(permission => ui.el('span', { class: 'kit-tag', text: permission }))),
      ui.el('span', { class: 'zt-role-meta' }, top ? ui.el('span', { class: `zt-class zt-class-${top === (policy.information_classes || []).at(-1) ? 'top' : 'normal'}`, text: top }) : null, ui.el('span', { class: 'kit-tag', text: t('policies.aal', { aal: role.minimum_aal || 0 }) }), ui.el('small', { class: 'kit-muted', text: t('policies.role.used', { count: roleHolders(service, name) }) })))));
  }
  const graph = ui.el('section', { class: 'panel zt-panel' }, ui.el('h2', { text: t('policies.role.graph') }));
  const edges = names.flatMap(name => (service.roles[name].inherits || []).map(parent => [name, parent]));
  graph.append(edges.length ? ui.el('ul', { class: 'zt-graph' }, edges.map(([child, parent]) => ui.el('li', {}, ui.el('span', { class: 'kit-mono', text: child }), ui.el('span', { class: 'zt-graph-arrow', text: '→', attrs: { 'aria-label': t('policies.role.inherits_from') } }), ui.el('span', { class: 'kit-mono', text: parent })))) : ui.el('p', { class: 'kit-muted', text: t('policies.role.graph.none') }));
  const side = ui.el('div', { class: 'zt-role-side' }, list, graph);
  if (editable(cx)) side.prepend(ui.el('a', { class: 'button', href: cx.hashFor('policies', ['services', id], new URLSearchParams({ tab: 'roles', role: '' })), text: t('policies.role.new') }));
  const editor = selected !== null ? roleEditor(cx, id, service, policy, selected) : ui.emptyState(t, { title: 'policies.role.pick', body: 'policies.role.pick.body' });
  return [ui.el('div', { class: 'zt-split' }, side, editor)];
}

function assignmentsTab(cx, id, service, params) {
  const { t, ui } = cx;
  const kinds = kindsFor(service);
  const roleNames = Object.keys(service.roles || {}).sort();
  const filterKind = params.get('kind') || '', filterRole = params.get('role') || '', filterText = (params.get('q') || '').toLowerCase();
  const rows = assignments(service).filter(row => (!filterKind || row.kind === filterKind) && (!filterRole || row.roles.includes(filterRole)) && (!filterText || row.subject.toLowerCase().includes(filterText)));
  const selected = new Set();
  const bulk = ui.el('div', { class: 'zt-bulk', hidden: true, attrs: { role: 'region', 'aria-label': t('policies.bulk') } });
  const bulkCount = ui.el('strong');
  const revoke = ui.el('button', { type: 'button', class: 'button button-danger', text: t('policies.bulk.revoke') });
  bulk.append(bulkCount, revoke);
  const syncBulk = () => { bulk.hidden = !selected.size; bulkCount.textContent = t('policies.bulk.selected', { count: selected.size }); };
  revoke.addEventListener('click', async () => {
    const accepted = await ui.confirmDialog(t, { title: 'policies.bulk.revoke', effect: 'policies.bulk.revoke.effect', target: id, confirmLabel: 'policies.bulk.revoke' });
    if (!accepted) return;
    edit(document => { for (const key of selected) { const [field, subject] = key.split('\u0000'); delete document.services[id][field][subject]; } });
    cx.reload();
  });
  const columns = [
    { key: 'select', label: 'policies.col.select', render: row => {
      const box = ui.el('input', { type: 'checkbox', disabled: !editable(cx) });
      box.setAttribute('aria-label', t('policies.select', { subject: row.subject }));
      box.addEventListener('change', () => { const key = `${row.field}\u0000${row.subject}`; if (box.checked) selected.add(key); else selected.delete(key); syncBulk(); });
      return box;
    } },
    { key: 'subject', label: 'policies.col.subject', render: row => cx.subjectCell(cx, row.subject, row.kind), title: row => row.subject },
    { key: 'roles', label: 'policies.col.roles', render: row => chips(cx, row.roles) },
    { key: 'rights', label: 'policies.col.rights', render: row => { const rights = effectiveRights(service, row.roles); return t('policies.rights', { permissions: rights.permissions.join(', ') || '—', aal: rights.minimumAal }); } },
    { key: 'actions', label: 'policies.col.actions', render: row => editable(cx) ? ui.el('button', { type: 'button', class: 'button button-quiet', text: t('policies.revoke'), on: { click: () => { edit(document => { delete document.services[id][row.field][row.subject]; }); cx.reload(); } } }) : '—' },
  ];
  const table = ui.dataTable(t, { id: 'policy-assignments', caption: 'policies.assignments.caption', owner: 'ui.owner.pumgye', sortable: 'subject', order: 'asc', columns, rowKey: row => `${row.field}:${row.subject}`, empty: { title: 'policies.assignments.empty', body: 'policies.assignments.empty.body' },
    fetchPage: async ({ cursor, order }) => { const sorted = [...rows].sort((a, b) => a.subject.localeCompare(b.subject)); if (order === 'desc') sorted.reverse(); const start = Number(cursor || 0); return { items: sorted.slice(start, start + 50), nextCursor: start + 50 < sorted.length ? String(start + 50) : null }; } });
  cx.signal.addEventListener('abort', () => table.destroy(), { once: true });
  const filters = ui.el('form', { class: 'zt-filters', attrs: { role: 'search', 'aria-label': t('policies.assignments.filters') } },
    ui.field(t, { label: 'policies.col.kind', name: 'kind', value: filterKind, options: [{ value: '', label: 'access.any' }, ...kinds.map(value => ({ value, label: `policies.kind.${value}` }))] }),
    ui.field(t, { label: 'policies.col.role', name: 'role', value: filterRole, options: [{ value: '', label: 'access.any' }, ...roleNames.map(value => ({ value, text: value }))] }),
    ui.field(t, { label: 'policies.col.subject', name: 'q', value: params.get('q') || '', maxLength: 128 }),
    ui.el('div', { class: 'button-row zt-filter-actions' }, ui.el('button', { type: 'submit', class: 'button', text: t('access.apply') })));
  filters.addEventListener('submit', event => {
    event.preventDefault();
    const next = new URLSearchParams({ tab: 'assignments' });
    for (const name of ['kind', 'role', 'q']) { const value = filters.elements[name].value.trim(); if (value) next.set(name, value); }
    cx.navigate(cx.hashFor('policies', ['services', id], next));
  });
  const parts = [filters, bulk, table.element];
  if (editable(cx)) parts.unshift(assignmentForm(cx, id, service, kinds, roleNames));
  parts.push(networks(cx, id, service, roleNames));
  table.reload();
  return parts;
}

function assignmentForm(cx, id, service, kinds, roleNames) {
  const { t, ui } = cx;
  const form = ui.el('form', { class: 'panel zt-panel zt-assign', attrs: { 'aria-label': t('policies.assign') } }, ui.el('h2', { text: t('policies.assign') }));
  const kind = ui.field(t, { label: 'policies.col.kind', name: 'kind', options: kinds.map(value => ({ value, label: `policies.kind.${value}` })) });
  const picker = ui.subjectPicker(t, cx.api, { label: 'policies.col.subject', name: 'subject', help: 'policies.assign.subject.help' });
  const roleBoxes = ui.el('fieldset', { class: 'zt-fieldset' }, ui.el('legend', { text: t('policies.col.roles') }), [...roleNames, 'guest'].map(role => ui.el('label', { class: 'zt-check' }, ui.el('input', { type: 'checkbox', name: 'role', value: role }), ui.el('span', { class: 'kit-mono', text: role }))));
  const error = ui.el('p', { class: 'kit-field-error', attrs: { role: 'alert' } });
  form.append(ui.el('div', { class: 'zt-assign-row' }, kind, picker), roleBoxes, error, ui.el('div', { class: 'button-row' }, ui.el('button', { type: 'submit', class: 'button button-primary', text: t('policies.assign.add') })));
  form.addEventListener('submit', event => {
    event.preventDefault();
    const selectedKind = form.elements.kind.value;
    const subject = form.elements.subject.value.trim();
    const chosen = [...form.querySelectorAll('input[name="role"]')].filter(box => box.checked).map(box => box.value);
    const subjectInput = form.elements.subject;
    subjectInput.removeAttribute('aria-invalid');
    if (!kinds.includes(selectedKind)) { error.textContent = t('policies.assign.kind'); return; }
    const problem = subjectProblem(selectedKind, subject);
    if (problem) { error.textContent = t(problem); subjectInput.setAttribute('aria-invalid', 'true'); subjectInput.focus(); return; }
    if (!chosen.length || (chosen.includes('guest') && chosen.length > 1)) { error.textContent = t('policies.assign.roles'); return; }
    const field = selectedKind === 'kubernetes_api' ? 'users' : fieldFor(selectedKind);
    edit(document => { const target = document.services[id]; target[field] = { ...(target[field] || {}), [subject]: chosen }; });
    cx.reload();
  });
  return form;
}

function networks(cx, id, service, roleNames) {
  const { t, ui } = cx;
  const panel = ui.el('section', { class: 'panel zt-panel' }, ui.el('h2', { text: t('policies.networks') }), ui.el('p', { class: 'kit-muted', text: t('policies.networks.help') }));
  if (contextOf(service) === 'kubernetes_api') { panel.append(ui.el('p', { class: 'kit-muted', text: t('policies.networks.kubernetes') })); return panel; }
  const list = ui.el('ul', { class: 'zt-network-list' });
  for (const [index, network] of (service.networks || []).entries()) {
    list.append(ui.el('li', {}, ui.el('code', { class: 'kit-mono', text: network.cidr }), chips(cx, network.roles || []),
      editable(cx) ? ui.el('button', { type: 'button', class: 'button button-quiet', text: t('policies.remove'), on: { click: () => { edit(document => { document.services[id].networks.splice(index, 1); }); cx.reload(); } } }) : null));
  }
  if (!(service.networks || []).length) list.append(ui.el('li', { class: 'kit-muted', text: t('policies.networks.none') }));
  panel.append(list);
  if (editable(cx)) {
    const form = ui.el('form', { class: 'zt-inline-form' }, ui.field(t, { label: 'policies.network.cidr', name: 'cidr', maxLength: 64 }),
      ui.el('fieldset', { class: 'zt-fieldset' }, ui.el('legend', { text: t('policies.col.roles') }), [...roleNames, 'guest'].map(role => ui.el('label', { class: 'zt-check' }, ui.el('input', { type: 'checkbox', name: 'nrole', value: role }), ui.el('span', { class: 'kit-mono', text: role })))),
      ui.el('button', { type: 'submit', class: 'button', text: t('policies.add') }));
    form.addEventListener('submit', event => {
      event.preventDefault();
      const cidr = form.elements.cidr.value.trim();
      const chosen = [...form.querySelectorAll('input[name="nrole"]')].filter(box => box.checked).map(box => box.value);
      if (!/^[0-9a-fA-F:.]+\/\d{1,3}$/.test(cidr) || !chosen.length) { form.elements.cidr.setAttribute('aria-invalid', 'true'); return; }
      edit(document => { const target = document.services[id]; target.networks = [...(target.networks || []).filter(network => network.cidr !== cidr), { cidr, roles: chosen }]; });
      cx.reload();
    });
    panel.append(form);
  }
  return panel;
}

function history(cx, id) {
  const { t, ui } = cx;
  const state = policyState();
  if (!state.independent) return [ui.emptyState(t, { title: 'policies.history.embedded', body: 'policies.history.embedded.body', action: ui.el('a', { class: 'button', href: '#config-operations', text: t('policies.history.config') }) })];
  if (state.auditError) return [ui.errorState(t, { owner: 'ui.owner.pumgye', message: state.auditError.message })];
  const rows = [...state.publications].sort((a, b) => (b.revision ?? 0) - (a.revision ?? 0));
  const table = ui.dataTable(t, { id: 'policy-history', caption: 'policies.history.caption', owner: 'ui.owner.pumgye', columns: [
    { key: 'time', label: 'audit.col.time', render: row => ui.timeCell(t, (row.at_unix ?? 0) * 1000) },
    { key: 'revision', label: 'policies.col.revision', render: row => t('ui.revision', { revision: row.revision }) },
    { key: 'actor', label: 'audit.col.actor', render: row => ui.el('span', { class: 'kit-mono', text: row.actor || '—' }) },
    { key: 'digest', label: 'audit.digest', render: row => row.sha256 ? ui.hashChip(t, row.sha256) : '—' },
  ], rowKey: row => String(row.revision), empty: { title: 'policies.history.empty' },
  fetchPage: async ({ cursor }) => { const start = Number(cursor || 0); return { items: rows.slice(start, start + 50), nextCursor: start + 50 < rows.length ? String(start + 50) : null }; } });
  cx.signal.addEventListener('abort', () => table.destroy(), { once: true });
  table.reload();
  const simulations = ui.el('section', { class: 'panel zt-panel' }, ui.el('h2', { text: t('policies.history.simulations') }), ui.loadingState(t));
  cx.api('/v1/pumgye/audit/simulations').then(({ data }) => {
    const list = (Array.isArray(data) ? data : []).slice(-20).reverse();
    simulations.lastChild.replaceWith(list.length ? ui.el('ul', { class: 'zt-changes' }, list.map(row => ui.el('li', {}, ui.el('span', { class: 'zt-change-main' },
      ui.el('strong', { text: row.on_behalf_of || row.actor || '—' }), ' · ', ui.el('span', { text: t('policies.history.simulation', { operation: row.operation, cases: row.cases ?? 0, denied: row.denied ?? 0, changed: row.changed ?? 0, revision: row.revision ?? '—' }) })),
      ui.timeCell(t, (row.at_unix ?? 0) * 1000)))) : ui.el('p', { class: 'kit-muted', text: t('policies.history.simulations.none') }));
  }).catch(error => { if (error?.status !== 401) simulations.lastChild.replaceWith(ui.errorState(t, { owner: 'ui.owner.pumgye', message: error.message })); });
  return [ui.el('p', { class: 'kit-muted', text: t('policies.history.note', { service: id }) }), table.element, ui.el('a', { class: 'button button-quiet', href: '#audit?source=pumgye', text: t('policies.history.audit') }), simulations];
}

export async function renderService(cx, root, id, params, { header, subjectCell }) {
  const { t, ui } = cx;
  const policy = working();
  const service = policy.services?.[id];
  const tab = TABS.includes(params.get('tab')) ? params.get('tab') : 'overview';
  const crumbs = [{ label: t('nav.policies'), href: '#policies' }, { label: t('policies.catalog.title'), href: '#policies' }, { label: id }];
  if (!service) {
    const { content } = cx.page(root, { crumbs, title: id });
    content.append(header(cx), ui.emptyState(t, { title: 'policies.service.missing', body: 'policies.service.missing.body', action: ui.el('a', { class: 'button', href: '#policies', text: t('policies.catalog.title') }) }));
    return;
  }
  const badges = ui.el('span', { class: 'zt-chips' }, ui.el('span', { class: 'kit-tag', text: t(`policies.context.${contextOf(service)}`) }), ui.statusBadge(t, service.require_guard !== false ? 'healthy' : 'disabled', service.require_guard !== false ? 'policies.guard.required' : 'policies.guard.optional'));
  const { content } = cx.page(root, { crumbs, title: id, owner: t('policies.service.owner'), actions: [badges] });
  const scoped = { ...cx, subjectCell };
  const body = tab === 'resources' ? resources(scoped, id, service, policy)
    : tab === 'roles' ? roles(scoped, id, service, policy, params)
    : tab === 'assignments' ? assignmentsTab(scoped, id, service, params)
    : tab === 'simulate' ? [await renderSimulator(scoped, id, service, policy, params)]
    : tab === 'history' ? history(scoped, id)
    : overview(scoped, id, service, policy);
  content.append(header(cx), tabs(cx, id, tab), ui.el('div', { class: 'zt-tabpanel', attrs: { role: 'region', 'aria-label': t(`policies.tab.${tab}`) } }, body));
}
