// Common policy editor pieces for Hopae documents (ADR 0020 §4): entity-
// grouped change list with localized field labels, draft persistence across
// navigation (ADM-01) and CAS publish with a required reason.
import { hopae, errorText, isConflict, isUncertain, outcomeBanner, formDialog } from './common.js';

/**
 * Change list between two `{entity: {fieldKey: displayString}}` maps. Field
 * keys are message keys, so no snake_case reaches the operator.
 */
export function changeList(cx, before, after) {
  const { t, ui } = cx;
  const list = ui.el('ul', { class: 'zt-changes-list' });
  let count = 0;
  for (const entity of [...new Set([...Object.keys(before), ...Object.keys(after)])]) {
    const a = before[entity], b = after[entity];
    const kind = !a ? 'add' : !b ? 'remove' : 'change';
    const lines = [];
    for (const field of [...new Set([...Object.keys(a || {}), ...Object.keys(b || {})])]) {
      const left = a?.[field], right = b?.[field];
      if (left === right) continue;
      const mark = left === undefined ? '+' : right === undefined ? '−' : '~';
      lines.push(ui.el('li', { class: `kit-diff-${left === undefined ? 'add' : right === undefined ? 'remove' : 'change'}` },
        ui.el('span', { class: 'kit-diff-mark', text: mark, attrs: { 'aria-label': t(left === undefined ? 'ui.diff.added' : right === undefined ? 'ui.diff.removed' : 'ui.diff.changed') } }),
        ui.el('span', { class: 'zt-diff-field', text: t(field) }), ' ',
        left === undefined ? ui.el('span', { text: right }) : right === undefined ? ui.el('del', { text: left }) : [ui.el('del', { text: left }), ' → ', ui.el('ins', { text: right })]));
    }
    if (!lines.length) continue;
    count += lines.length;
    list.append(ui.el('li', { class: `zt-change zt-change-${kind}` },
      ui.el('div', { class: 'zt-change-head' }, ui.el('span', { class: 'kit-tag', text: t(`identities.diff.${kind}`) }), ui.el('strong', { text: entity })),
      ui.el('ul', { class: 'kit-diff' }, lines)));
  }
  return { element: count ? list : ui.el('p', { class: 'kit-muted', text: t('ui.diff.none') }), count };
}

const STORE = 'hangang:identities:draft:';
export function loadDraft(name) {
  try { const value = JSON.parse(sessionStorage.getItem(STORE + name) || 'null'); return value && typeof value === 'object' ? value : null; } catch { return null; }
}
export function saveDraft(name, base, draft) {
  try { sessionStorage.setItem(STORE + name, JSON.stringify({ base, draft, saved: Date.now() })); } catch { /* Drafts are a convenience. */ }
}
export function dropDraft(name) { try { sessionStorage.removeItem(STORE + name); } catch { /* ignore */ } }

/**
 * Review dialog → publish. Resolves the publish answer or null. A stale base
 * revision keeps the draft and reports the conflict inside the dialog.
 */
export async function publish(cx, { route, revision, configuration, diff, target, status }) {
  const { t, ui } = cx;
  const review = ui.el('div', { class: 'zt-review' }, ui.el('p', { text: t('identities.publish.base', { revision, next: revision + 1 }) }), diff.element);
  try {
    return await formDialog(cx, {
      title: 'identities.publish.title', confirm: target, confirmLabel: 'identities.publish.confirm', danger: true,
      fields: [{ node: review }],
      submit: async values => hopae(cx, route, { json: { revision, configuration }, reason: values.reason }),
    });
  } catch (error) {
    if (error?.status === 401) throw error;
    ui.clear(status, outcomeBanner(cx, isUncertain(error) ? 'uncertain' : 'refused', isConflict(error) ? 'identities.publish.conflict' : 'identities.literal', { value: errorText(t, error) }));
    return null;
  }
}
