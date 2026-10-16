// Review and publish: structured diff, what-if impact (Pumgye explain/diff and
// explain/batch against the draft as a candidate), mandatory reason, typed
// confirmation for high impact and a three-way view on revision conflicts.
import { policyState, publish, replaceDraft, discardDraft } from './store.js';
import { countChanges, impactCases, touched, rebase, clone, describeChanges } from './model.js';

/** Subject as its resolved Hopae name with the opaque id secondary. */
export function subjectName(cx, subject, kind) {
  const { ui } = cx;
  const id = ui.el('code', { class: 'kit-mono zt-subject-id', text: subject });
  const node = ui.el('span', { class: 'zt-subject' }, id);
  if ((kind === 'user' || kind === 'human') && cx.resolver) {
    cx.resolver.resolve(subject).then(value => {
      if (value.state !== 'resolved') return;
      const label = ui.subjectLabel(value.subject);
      if (!label || label === subject) return;
      node.prepend(ui.el('span', { class: 'zt-subject-name', text: label }));
      id.classList.add('is-secondary');
    }).catch(() => {});
  }
  return node;
}

function changeItem(cx, change) {
  const { t, ui } = cx;
  const sentence = ui.el('span', { class: 'zt-change-text' });
  if (change.subject) sentence.append(subjectName(cx, change.subject, change.kind), ': ');
  sentence.append(t(change.key, change.params));
  return ui.el('li', { class: 'zt-change', dataset: { key: change.key } }, sentence, ui.el('code', { class: 'kit-mono zt-change-path', text: change.path }));
}

function diffSections(cx, base, draft) {
  const { t, ui } = cx;
  const changes = describeChanges(base, draft);
  const groups = new Map();
  for (const change of changes) {
    const group = change.service ?? '';
    if (!groups.has(group)) groups.set(group, []);
    groups.get(group).push(change);
  }
  const sections = [];
  for (const [id, list] of [...groups.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const before = id ? base.services?.[id] : null, after = id ? draft.services?.[id] : null;
    const label = !id ? null : !before ? 'policies.diff.added' : !after ? 'policies.diff.removed' : 'policies.diff.changed';
    const heading = id ? ui.el('h3', {}, ui.el('span', { class: 'kit-mono', text: id }), ' ', ui.el('span', { class: 'kit-tag', text: t(label) })) : ui.el('h3', { text: t('policies.classes') });
    const json = id ? ui.el('details', { class: 'zt-diff-json' }, ui.el('summary', { text: t('policies.change.json') }), ui.structuredDiff(t, before || {}, after || {})) : null;
    sections.push(ui.el('section', { class: 'zt-diff-group', dataset: id ? { service: id } : {} }, heading, ui.el('ul', { class: 'zt-change-list' }, list.map(change => changeItem(cx, change))), json));
  }
  return sections;
}

const MAP_KIND = Object.freeze({ users: 'user', human_users: 'human', workload_users: 'workload' });

function errorDetails(cx, error) {
  const { t, ui } = cx;
  const body = error?.payload?.error;
  if (!body) return ui.errorState(t, { owner: 'ui.owner.pumgye', message: error?.message });
  return ui.el('div', { class: 'kit-state kit-error', attrs: { role: 'alert' } }, ui.el('strong', { text: t(body.message_key || body.code) }),
    ui.el('ul', { class: 'zt-error-list' }, (body.details || []).map(detail => ui.el('li', {}, ui.el('code', { class: 'kit-mono', text: detail.path.replace(/^snapshot\.policy\./, '').replace(/^policy\./, '') }), ' ', t(detail.message_key || detail.code)))));
}

async function impact(cx, state) {
  const { t, ui } = cx;
  const panel = ui.el('section', { class: 'panel zt-panel zt-impact', attrs: { 'aria-live': 'polite' } }, ui.el('h2', { text: t('policies.impact.title') }));
  const result = { allowToDeny: 0, denyToAllow: 0, blocked: false };
  if (!state.independent) { panel.append(ui.el('p', { class: 'kit-muted', text: t('policies.impact.embedded') })); return { panel, result }; }
  let diff;
  try {
    diff = (await cx.api('/v1/pumgye/explain/diff', { method: 'POST', json: { base_revision: state.revision, policy: state.draft, limit: 100 } })).data;
  } catch (error) {
    if (error?.status === 401) throw error;
    result.blocked = error?.status === 422 || error?.status === 400;
    panel.append(errorDetails(cx, error));
    if (error?.status === 409) panel.append(ui.el('p', { class: 'zt-banner zt-banner-warn', text: t('policies.publish.stale') }));
    return { panel, result };
  }
  const changes = diff.changes || [];
  const rows = ui.el('tbody');
  for (const change of changes) {
    const delta = change.delta || {};
    const parts = [];
    if (delta.added_permissions?.length) parts.push(t('policies.impact.added_permissions', { list: delta.added_permissions.join(', ') }));
    if (delta.removed_permissions?.length) parts.push(t('policies.impact.removed_permissions', { list: delta.removed_permissions.join(', ') }));
    if (delta.added_information_classes?.length) parts.push(t('policies.impact.added_classes', { list: delta.added_information_classes.join(', ') }));
    if (delta.removed_information_classes?.length) parts.push(t('policies.impact.removed_classes', { list: delta.removed_information_classes.join(', ') }));
    if (Array.isArray(delta.minimum_aal) && delta.minimum_aal[0] !== delta.minimum_aal[1]) parts.push(t('policies.impact.aal', { before: delta.minimum_aal[0], after: delta.minimum_aal[1] }));
    rows.append(ui.el('tr', {}, ui.el('td', { text: t(`policies.impact.entity.${change.entity}`) }), ui.el('td', { class: 'kit-mono', text: change.service || '—' }),
      ui.el('td', {}, change.subject ? subjectName(cx, change.subject, MAP_KIND[change.map] || 'user') : ui.el('code', { class: 'kit-mono', text: change.cidr || change.resource || '—' })), ui.el('td', {}, ui.statusBadge(t, change.change === 'removed' ? 'deny' : change.change === 'added' ? 'allow' : 'stale', `policies.impact.change.${change.change}`)),
      ui.el('td', { text: parts.join(' · ') || '—' })));
  }
  panel.append(ui.el('p', { class: 'kit-muted', text: t('policies.impact.rights', { count: diff.total ?? changes.length }) }));
  if (changes.length) panel.append(ui.el('table', { class: 'kit-table zt-simple-table' }, ui.el('thead', {}, ui.el('tr', {}, ['policies.impact.col.entity', 'policies.col.service', 'policies.col.subject', 'policies.impact.col.change', 'policies.impact.col.delta'].map(key => ui.el('th', { text: t(key) })))), rows));
  const cases = impactCases(state.base, state.draft, changes);
  if (cases.length) {
    try {
      const batch = (await cx.api('/v1/pumgye/explain/batch', { method: 'POST', json: { snapshot: { source: 'candidate', base_revision: state.revision, policy: state.draft }, cases, trace: false } })).data;
      const summary = batch.summary || {};
      result.allowToDeny = summary.allow_to_deny || 0;
      result.denyToAllow = summary.deny_to_allow || 0;
      const examples = (batch.results || []).filter(entry => entry.comparison?.changed).slice(0, 5);
      panel.append(ui.el('div', { class: 'zt-kpis zt-impact-kpis' },
        ui.el('div', { class: `zt-kpi${result.allowToDeny ? ' is-warn' : ''}` }, ui.el('span', { class: 'zt-kpi-label', text: t('policies.impact.allow_to_deny') }), ui.el('strong', { class: 'zt-kpi-value', text: String(result.allowToDeny) })),
        ui.el('div', { class: 'zt-kpi' }, ui.el('span', { class: 'zt-kpi-label', text: t('policies.impact.deny_to_allow') }), ui.el('strong', { class: 'zt-kpi-value', text: String(result.denyToAllow) })),
        ui.el('div', { class: 'zt-kpi' }, ui.el('span', { class: 'zt-kpi-label', text: t('policies.impact.cases') }), ui.el('strong', { class: 'zt-kpi-value', text: String(summary.cases ?? cases.length) }))));
      if (examples.length) panel.append(ui.el('h3', { text: t('policies.impact.examples') }), ui.el('ul', { class: 'zt-examples' }, examples.map(entry => {
        const testCase = cases.find(item => item.label === entry.label) || {};
        return ui.el('li', {}, testCase.subject ? subjectName(cx, testCase.subject.id, testCase.subject.kind) : null, ' · ', ui.el('code', { class: 'kit-mono', text: `${testCase.service} · ${testCase.permission}/${testCase.information_class}` }), ' ',
          ui.el('span', { text: t('policies.sim.changed', { before: entry.comparison.published?.decision ?? '—', after: entry.outcome?.decision ?? '—' }) }));
      })));
      panel.append(ui.el('p', { class: 'kit-muted', text: t('policies.impact.note') }));
    } catch (error) {
      if (error?.status === 401) throw error;
      panel.append(errorDetails(cx, error));
    }
  } else panel.append(ui.el('p', { class: 'kit-muted', text: t('policies.impact.no_cases') }));
  return { panel, result };
}

async function conflictView(cx, root, header) {
  const { t, ui } = cx;
  const state = policyState();
  const latest = await cx.api('/v1/pumgye/policy');
  const theirs = latest.data.policy;
  const preview = rebase(state.base, state.draft, theirs, true);
  const { content } = cx.page(root, { crumbs: [{ label: t('nav.policies'), href: '#policies' }, { label: t('policies.conflict.title') }], title: t('policies.conflict.title'), owner: t('policies.conflict.owner', { mine: state.revision, theirs: latest.data.revision }) });
  const apply = preferMine => {
    const { result } = rebase(state.base, state.draft, theirs, preferMine);
    state.base = theirs; state.revision = latest.data.revision; state.etag = latest.etag || `"${latest.data.revision}"`;
    state.authorityRevision = latest.response?.headers?.get('x-hangang-config-revision') || state.authorityRevision;
    state.key = `pumgye:${state.revision}`;
    replaceDraft(result);
    cx.navigate('#policies/publish');
    cx.reload();
  };
  content.append(header(cx),
    ui.el('p', { class: 'zt-banner zt-banner-warn', attrs: { role: 'alert' }, text: t('policies.conflict.body') }),
    ui.el('div', { class: 'zt-grid' },
      ui.el('section', { class: 'panel zt-panel' }, ui.el('h2', { text: t('policies.conflict.theirs', { revision: latest.data.revision }) }), ui.structuredDiff(t, state.base, theirs)),
      ui.el('section', { class: 'panel zt-panel' }, ui.el('h2', { text: t('policies.conflict.mine') }), ui.structuredDiff(t, state.base, state.draft))),
    ui.el('section', { class: 'panel zt-panel' }, ui.el('h2', { text: t('policies.conflict.overlap', { count: preview.conflicts.length }) }),
      preview.conflicts.length ? ui.el('ul', {}, preview.conflicts.map(path => ui.el('li', {}, ui.el('code', { class: 'kit-mono', text: path })))) : ui.el('p', { class: 'kit-muted', text: t('policies.conflict.none') })),
    ui.el('div', { class: 'button-row' },
      ui.el('button', { type: 'button', class: 'button button-primary', text: t('policies.conflict.keep_mine'), on: { click: () => apply(true) } }),
      ui.el('button', { type: 'button', class: 'button', text: t('policies.conflict.keep_theirs'), on: { click: () => apply(false) } }),
      ui.el('button', { type: 'button', class: 'button button-quiet', text: t('policies.draft.discard'), on: { click: () => { discardDraft(); cx.navigate('#policies?refresh=1'); } } })));
}

export async function renderPublish(cx, root, { header }) {
  const { t, ui } = cx;
  const state = policyState();
  const crumbs = [{ label: t('nav.policies'), href: '#policies' }, { label: t('policies.publish.title') }];
  if (!state.draft) {
    const { content } = cx.page(root, { crumbs, title: t('policies.publish.title') });
    content.append(header(cx), ui.emptyState(t, { title: 'policies.publish.nothing', body: 'policies.publish.nothing.body', action: ui.el('a', { class: 'button', href: '#policies', text: t('policies.catalog.title') }) }));
    return;
  }
  const scope = touched(state.base, state.draft);
  const { content } = cx.page(root, { crumbs, title: t('policies.publish.title'), owner: t('policies.publish.owner', { revision: state.revision, next: state.revision + 1 }) });
  const diff = ui.el('section', { class: 'panel zt-panel' }, ui.el('h2', { text: t('policies.publish.changes', { count: describeChanges(state.base, state.draft).length || countChanges(state.base, state.draft) }) }), diffSections(cx, state.base, state.draft));
  content.append(header(cx), diff);
  const loading = ui.loadingState(t);
  content.append(loading);
  const { panel, result } = await impact(cx, state);
  loading.replaceWith(panel);
  const highImpact = result.allowToDeny > 0 || scope.restricted;
  const form = ui.el('form', { class: 'panel zt-panel zt-publish-form', attrs: { 'aria-label': t('policies.publish.title') } });
  const reason = ui.el('textarea', { name: 'reason', rows: 3, maxLength: 512, attrs: { 'aria-required': 'true' } });
  const reasonId = 'policies-publish-reason';
  reason.id = reasonId;
  const error = ui.el('p', { class: 'kit-field-error', attrs: { role: 'alert' } });
  form.append(ui.el('label', { htmlFor: reasonId, class: 'kit-field' }, ui.el('span', { class: 'kit-field-label', text: t('policies.publish.reason') }), reason, ui.el('small', { class: 'kit-help', text: t('policies.publish.reason.help') })));
  if (highImpact) form.append(ui.el('p', { class: 'zt-banner zt-banner-warn', text: t(scope.restricted ? 'policies.publish.restricted' : 'policies.publish.high_impact', { count: result.allowToDeny }) }));
  const blocked = state.managed ? 'policies.managed.short' : state.outcomeUnknown ? 'policies.publish.unknown' : result.blocked ? 'policies.publish.invalid' : null;
  const actions = ui.el('div', { class: 'button-row' });
  if (blocked) actions.append(ui.disabledAction(t, 'policies.publish.action', blocked));
  else actions.append(ui.el('button', { type: 'submit', class: 'button button-primary', text: t('policies.publish.action_revision', { revision: state.revision + 1 }) }));
  actions.append(ui.el('a', { class: 'button button-quiet', href: '#policies', text: t('policies.publish.keep_editing') }));
  form.append(error, actions);
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (blocked) return;
    let text = reason.value.trim();
    if (!text) { error.textContent = t('policies.publish.reason.required'); reason.setAttribute('aria-invalid', 'true'); reason.focus(); return; }
    if (highImpact) {
      const target = scope.services.length === 1 ? scope.services[0] : t('policies.publish.confirm_word');
      const accepted = await ui.confirmDialog(t, { title: 'policies.publish.confirm', effect: 'policies.publish.confirm.effect', target, confirmLabel: 'policies.publish.action', reason: text });
      if (!accepted) return;
      if (accepted.reason) { text = accepted.reason; reason.value = text; }
    }
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    try {
      const outcome = await publish(cx, text);
      if (outcome.conflict) { await conflictView(cx, root, header); return; }
      cx.navigate('#policies?refresh=1');
    } catch (failure) {
      if (failure?.status === 401) throw failure;
      button.disabled = false;
      error.textContent = state.outcomeUnknown ? t('policies.publish.unknown') : failure?.payload?.error ? t(failure.payload.error.message_key || failure.payload.error.code) : failure.message;
      if (state.outcomeUnknown) cx.reload();
    }
  });
  content.append(form);
}

export { clone };
