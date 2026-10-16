// Review and publish: structured diff, what-if impact (Pumgye explain/diff and
// explain/batch against the draft as a candidate), mandatory reason, typed
// confirmation for high impact and a three-way view on revision conflicts.
import { policyState, publish, replaceDraft, discardDraft } from './store.js';
import { countChanges, impactCases, touched, rebase, clone } from './model.js';

function diffSections(cx, base, draft) {
  const { t, ui } = cx;
  const sections = [];
  const services = new Set([...Object.keys(base.services || {}), ...Object.keys(draft.services || {})]);
  for (const id of [...services].sort()) {
    const before = base.services?.[id], after = draft.services?.[id];
    if (JSON.stringify(before) === JSON.stringify(after)) continue;
    const label = !before ? 'policies.diff.added' : !after ? 'policies.diff.removed' : 'policies.diff.changed';
    sections.push(ui.el('section', { class: 'zt-diff-group', dataset: { service: id } }, ui.el('h3', {}, ui.el('span', { class: 'kit-mono', text: id }), ' ', ui.el('span', { class: 'kit-tag', text: t(label) })), ui.structuredDiff(t, before || {}, after || {})));
  }
  if (JSON.stringify(base.resources || {}) !== JSON.stringify(draft.resources || {})) sections.push(ui.el('section', { class: 'zt-diff-group' }, ui.el('h3', { text: t('policies.col.resources') }), ui.structuredDiff(t, base.resources || {}, draft.resources || {})));
  if (JSON.stringify(base.information_classes) !== JSON.stringify(draft.information_classes)) sections.push(ui.el('section', { class: 'zt-diff-group' }, ui.el('h3', { text: t('policies.classes') }), ui.structuredDiff(t, { classes: base.information_classes }, { classes: draft.information_classes })));
  return sections;
}

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
      ui.el('td', { class: 'kit-mono', text: change.subject || change.cidr || change.resource || '—' }), ui.el('td', {}, ui.statusBadge(t, change.change === 'removed' ? 'deny' : change.change === 'added' ? 'allow' : 'challenge', `policies.impact.change.${change.change}`)),
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
        return ui.el('li', {}, ui.el('code', { class: 'kit-mono', text: `${testCase.subject?.id} · ${testCase.service} · ${testCase.permission}/${testCase.information_class}` }), ' ',
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
  const diff = ui.el('section', { class: 'panel zt-panel' }, ui.el('h2', { text: t('policies.publish.changes', { count: countChanges(state.base, state.draft) }) }), diffSections(cx, state.base, state.draft));
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
    const text = reason.value.trim();
    if (!text) { error.textContent = t('policies.publish.reason.required'); reason.setAttribute('aria-invalid', 'true'); reason.focus(); return; }
    if (highImpact) {
      const target = scope.services.length === 1 ? scope.services[0] : t('policies.publish.confirm_word');
      const accepted = await ui.confirmDialog(t, { title: 'policies.publish.confirm', effect: 'policies.publish.confirm.effect', target, confirmLabel: 'policies.publish.action' });
      if (!accepted) return;
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
