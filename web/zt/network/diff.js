// Entity-grouped change list with localized field labels, draft persistence
// across navigation (ADM-01) and the what-if impact summary for candidates.
import { guard, number, ipLink } from './common.js';
import { verdictBadge } from './trace.js';

/** Change list between `{entity: {fieldKey: displayString}}` maps; field keys are message keys. */
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
      const which = left === undefined ? 'add' : right === undefined ? 'remove' : 'change';
      lines.push(ui.el('li', { class: `kit-diff-${which}` },
        ui.el('span', { class: 'kit-diff-mark', text: which === 'add' ? '+' : which === 'remove' ? '−' : '~', attrs: { 'aria-label': t(`ui.diff.${which === 'add' ? 'added' : which === 'remove' ? 'removed' : 'changed'}`) } }),
        ui.el('span', { class: 'zt-diff-field', text: t(field) }), ' ',
        which === 'add' ? ui.el('span', { text: right }) : which === 'remove' ? ui.el('del', { text: left }) : [ui.el('del', { text: left }), ' → ', ui.el('ins', { text: right })]));
    }
    if (!lines.length) continue;
    count += lines.length;
    list.append(ui.el('li', { class: `zt-change zt-change-${kind}` }, ui.el('div', { class: 'zt-change-head' }, ui.el('span', { class: 'kit-tag', text: t(`network.diff.${kind}`) }), ui.el('strong', { text: entity })), ui.el('ul', { class: 'kit-diff' }, lines)));
  }
  return { element: count ? list : ui.el('p', { class: 'kit-muted', text: t('ui.diff.none') }), count };
}

const STORE = 'hangang:network:draft:';
export function loadDraft(name) { try { const value = JSON.parse(sessionStorage.getItem(STORE + name) || 'null'); return value && typeof value === 'object' ? value : null; } catch { return null; } }
export function saveDraft(name, base, draft) { try { sessionStorage.setItem(STORE + name, JSON.stringify({ base, draft, saved: Date.now() })); } catch { /* optional */ } }
export function dropDraft(name) { try { sessionStorage.removeItem(STORE + name); } catch { /* optional */ } }

/** Addresses to replay: every tracked candidate plus exact-address blocks (≤1024). */
export async function trafficSample(cx) {
  const [candidates, blocks] = await Promise.all([
    guard(cx, 'candidates').then(answer => (Array.isArray(answer.data) ? answer.data : [])).catch(error => { if (error?.status === 401) throw error; return []; }),
    guard(cx, 'blocks').then(answer => (Array.isArray(answer.data) ? answer.data : [])).catch(error => { if (error?.status === 401) throw error; return []; }),
  ]);
  const ips = new Set(candidates.sort((a, b) => (b.score ?? 0) - (a.score ?? 0)).map(candidate => candidate.ip));
  for (const block of blocks) { const match = /^(.+)\/(32|128)$/.exec(block.network); if (match) ips.add(match[1]); }
  return [...ips].slice(0, 1024);
}

/**
 * What-if: replays the sample through the published view and the candidate
 * (`explain/batch`), never storing anything. Renders the summary and the
 * addresses whose outcome changes.
 */
export async function whatIf(cx, candidate, sample) {
  const { t, ui } = cx;
  if (!sample.length) return ui.emptyState(t, { title: 'network.whatif.no_sample', body: 'network.whatif.no_sample.body' });
  const { data } = await guard(cx, 'explain/batch', { json: { ips: sample, candidate } });
  const summary = data?.summary || { total: sample.length, changed: 0, allow_to_deny: 0, deny_to_allow: 0, reason_changed: 0 };
  const changed = (data?.results || []).filter(entry => entry.changed);
  const tiles = ui.el('div', { class: 'zt-whatif-tiles' }, [
    ['network.whatif.total', summary.total, ''], ['network.whatif.allow_to_deny', summary.allow_to_deny, 'is-deny'], ['network.whatif.deny_to_allow', summary.deny_to_allow, 'is-allow'], ['network.whatif.reason_changed', summary.reason_changed, ''],
  ].map(([label, value, tone]) => ui.el('div', { class: `zt-whatif-tile ${tone}` }, ui.el('span', { class: 'zt-kpi-value', text: number(value) }), ui.el('span', { class: 'kit-muted', text: t(label) }))));
  const rows = changed.slice(0, 50).map(entry => ui.el('li', {}, ipLink(cx, entry.ip), ' ', verdictBadge(cx, entry.published?.verdict), ' → ', verdictBadge(cx, entry.candidate?.verdict),
    entry.candidate?.rules?.length ? ui.el('span', { class: 'kit-muted', text: t('network.whatif.by_rules', { rules: entry.candidate.rules.join(', ') }) }) : null));
  return ui.el('div', { class: 'zt-whatif' }, tiles,
    changed.length ? ui.el('ul', { class: 'zt-whatif-list' }, rows) : ui.el('p', { class: 'kit-muted', text: t('network.whatif.none_changed') }),
    ui.el('small', { class: 'kit-muted', text: t('network.whatif.note', { count: sample.length, revision: data?.evaluated?.published_revision ?? '—' }) }));
}
