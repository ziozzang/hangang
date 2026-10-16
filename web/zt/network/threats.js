// Network ▸ Threat queue: Sumunjang candidates (bounded per-IP evidence
// aggregates) with score, stage, ASN and age; filters in the URL; bulk
// approval of eligible candidates with typed confirmation and a reason.
import { can, guard, sectionPage, capabilities, notConnected, modeBanner, suspicionBadge, SUSPICIONS, ipLink, asnText, number, outcomeBanner, errorText, signalChips } from './common.js';
import { approveCandidates } from './actions.js';

const PAGE = 50;

function scoreBar(cx, score, threshold) {
  const { t, ui } = cx;
  const ratio = threshold ? Math.min(1, score / (threshold * 3)) : 0;
  const bar = ui.el('span', { class: 'zt-score', title: t('network.threats.score.title', { score, threshold }) }, ui.el('span', { class: 'zt-score-value', text: number(score) }), ui.el('span', { class: 'zt-score-track', attrs: { 'aria-hidden': 'true' } }, ui.el('span', { class: 'zt-score-fill' })));
  bar.querySelector('.zt-score-fill').style.inlineSize = `${Math.round(ratio * 100)}%`;
  return bar;
}

export async function renderThreats(cx, root, params) {
  const { t, ui } = cx;
  const caps = await capabilities(cx);
  if (cx.signal.aborted) return;
  const { content } = sectionPage(cx, root, { active: 'threats', title: t('network.page.threats'), owner: t('network.threats.owner') });
  if (!caps.installed || !can(caps, 'candidates')) { content.append(notConnected(cx, caps, 'candidates')); return; }
  const q = params.get('q') || '', stage = SUSPICIONS.includes(params.get('stage')) ? params.get('stage') : '', eligibleOnly = params.get('eligible') === '1', asn = params.get('asn') || '', country = /^[A-Z]{2}$/.test(params.get('country') || '') ? params.get('country') : '';
  let policy = null, all = [];
  const banner = ui.el('div');
  const load = async () => {
    const [candidates, document] = await Promise.all([guard(cx, 'candidates'), guard(cx, 'policy/document').catch(error => { if (error?.status === 401) throw error; return { data: null }; })]);
    policy = document.data?.policy || null;
    all = (Array.isArray(candidates.data) ? candidates.data : []).sort((a, b) => (b.score ?? 0) - (a.score ?? 0) || (b.last_seen ?? 0) - (a.last_seen ?? 0));
    ui.clear(banner, policy ? modeBanner(cx, policy) : null);
  };
  const filtered = () => all.filter(entry => (!q || entry.ip.includes(q)) && (!stage || entry.suspicion === stage) && (!eligibleOnly || entry.eligible) && (!asn || String(entry.asn) === asn) && (!country || entry.country === country));
  // Filters.
  const form = ui.el('form', { class: 'zt-filters', attrs: { role: 'search', 'aria-label': t('network.threats.filters') } });
  const search = ui.field(t, { label: 'network.threats.search', name: 'q', value: q, maxLength: 45, placeholder: 'network.threats.search.placeholder' });
  search.querySelector('input').type = 'search';
  const eligibleId = `zt-eligible-${Math.random().toString(36).slice(2, 6)}`;
  form.append(search,
    ui.field(t, { label: 'network.threats.filter.stage', name: 'stage', value: stage, options: [{ value: '', label: 'network.filter.any' }, ...SUSPICIONS.map(value => ({ value, label: `network.suspicion.${value}` }))] }),
    ui.field(t, { label: 'network.threats.filter.asn', name: 'asn', value: asn, pattern: '\\d{1,10}', maxLength: 10 }),
    ui.el('label', { class: 'zt-check', htmlFor: eligibleId }, ui.el('input', { type: 'checkbox', id: eligibleId, name: 'eligible', checked: eligibleOnly }), ui.el('span', { text: t('network.threats.filter.eligible') })),
    ui.field(t, { label: 'network.threats.filter.country', name: 'country', value: country, pattern: '[A-Za-z]{2}', maxLength: 2, placeholder: 'network.threats.filter.country.placeholder' }),
    ui.el('div', { class: 'button-row zt-filter-actions' }, ui.el('button', { type: 'submit', class: 'button button-primary', text: t('network.filter.apply') }), ui.el('a', { class: 'button button-quiet', href: '#network/threats', text: t('network.filter.reset') })));
  form.addEventListener('submit', event => {
    event.preventDefault();
    if (!form.reportValidity()) return;
    const next = new URLSearchParams();
    for (const name of ['q', 'stage', 'asn', 'country']) { const value = form.elements[name].value.trim(); if (value) next.set(name, name === 'country' ? value.toUpperCase() : value); }
    if (form.elements.eligible.checked) next.set('eligible', '1');
    cx.navigate(cx.hashFor('network', ['threats'], next));
  });
  // Selection and bulk approval.
  const selected = new Set();
  const count = ui.el('span', { class: 'zt-bulk-count', attrs: { 'aria-live': 'polite' } });
  const approve = ui.el('button', { type: 'button', class: 'button button-danger', text: t('network.threats.bulk.approve'), disabled: true });
  const clearButton = ui.el('button', { type: 'button', class: 'button button-quiet', text: t('network.threats.bulk.clear'), disabled: true });
  const results = ui.el('div', { class: 'zt-bulk-results' });
  const sync = () => { count.textContent = selected.size ? t('network.threats.bulk.count', { count: selected.size }) : t('network.threats.bulk.none'); approve.disabled = !selected.size; clearButton.disabled = !selected.size; };
  sync();
  const bulk = ui.el('div', { class: 'zt-bulk', attrs: { role: 'region', 'aria-label': t('network.threats.bulk.region') } }, count, can(caps, 'candidates/approve') ? approve : ui.disabledAction(t, 'network.threats.bulk.approve', 'network.gap.not_declared'), clearButton);
  const checkbox = entry => {
    const box = ui.el('input', { type: 'checkbox', checked: selected.has(entry.ip), disabled: !entry.eligible, attrs: { 'aria-label': t('network.threats.select', { ip: entry.ip }) } });
    if (!entry.eligible) box.title = t('network.threats.not_eligible');
    box.addEventListener('change', () => { if (box.checked) selected.add(entry.ip); else selected.delete(entry.ip); sync(); });
    return box;
  };
  const columns = [
    { key: 'select', label: 'network.threats.col.select', render: checkbox, title: () => '' },
    { key: 'ip', label: 'network.threats.col.ip', render: entry => ipLink(cx, entry.ip) },
    { key: 'score', label: 'network.threats.col.score', render: entry => scoreBar(cx, entry.score ?? 0, policy?.threshold ?? 0), title: () => '' },
    { key: 'stage', label: 'network.threats.col.stage', render: entry => suspicionBadge(cx, entry.suspicion) },
    { key: 'signals', label: 'network.threats.col.signals', render: entry => ui.el('span', { class: 'zt-stack' }, entry.signals ? signalChips(cx, entry.signals) : null, ui.el('span', { class: 'kit-muted', text: t('network.threats.events', { count: entry.events ?? 0 }) })), title: () => '' },
    { key: 'country', label: 'network.threats.col.country', render: entry => entry.country ? ui.el('a', { href: `#network/threats?country=${entry.country}`, text: entry.country }) : ui.el('span', { class: 'kit-muted', text: t('network.none') }) },
    { key: 'asn', label: 'network.threats.col.asn', render: entry => Number.isFinite(entry.asn) ? ui.el('a', { href: `#network/threats?asn=${entry.asn}`, text: asnText(cx, entry.asn) }) : ui.el('span', { class: 'kit-muted', text: asnText(cx, null) }) },
    { key: 'eligible', label: 'network.threats.col.eligible', render: entry => entry.eligible ? ui.statusBadge(t, 'challenge', 'network.threats.eligible') : ui.el('span', { class: 'kit-muted', text: t('network.threats.below_threshold') }) },
    { key: 'last_seen', label: 'network.threats.col.last_seen', render: entry => ui.timeCell(t, (entry.last_seen || 0) * 1000) },
    { key: 'first_seen', label: 'network.threats.col.first_seen', render: entry => ui.timeCell(t, (entry.first_seen || 0) * 1000), hidden: true },
  ];
  const table = ui.dataTable(t, {
    id: 'network-threats', caption: 'network.threats.caption', owner: 'ui.owner.sumunjang', columns, sortable: 'none', rowKey: entry => entry.ip,
    empty: { title: q || stage || eligibleOnly || asn || country ? 'network.threats.empty.filtered' : 'network.threats.empty', body: 'network.threats.empty.body' },
    onRowOpen: entry => cx.navigate(`#network/ip/${encodeURIComponent(entry.ip)}`),
    fetchPage: async ({ cursor }) => {
      if (!cursor) await load();
      const offset = Number(cursor || 0), rows = filtered();
      return { items: rows.slice(offset, offset + PAGE), nextCursor: offset + PAGE < rows.length ? String(offset + PAGE) : null };
    },
  });
  cx.signal.addEventListener('abort', () => table.destroy(), { once: true });
  clearButton.addEventListener('click', () => { selected.clear(); table.element.querySelectorAll('tbody input[type=checkbox]').forEach(box => { box.checked = false; }); sync(); });
  approve.addEventListener('click', async () => {
    const list = ui.el('ul', { class: 'zt-result-list' });
    const outcome = await approveCandidates(cx, [...selected], { onEach: result => list.append(ui.el('li', {}, ipLink(cx, result.ip), ' ', outcomeBanner(cx, result.kind, result.kind === 'committed' ? 'network.threats.approved_one' : 'network.literal', { operation: result.operation || '—', value: result.error ? errorText(t, result.error) : '' }))) });
    if (!outcome) return;
    const tally = kind => outcome.filter(result => result.kind === kind).length;
    ui.clear(results, outcomeBanner(cx, tally('uncertain') ? 'uncertain' : tally('refused') ? 'refused' : 'committed', 'network.threats.bulk.summary', { committed: tally('committed'), refused: tally('refused'), uncertain: tally('uncertain') }), list);
    for (const result of outcome) if (result.kind === 'committed') selected.delete(result.ip);
    sync(); table.reload();
  });
  content.append(banner, form, bulk, results, table.element);
  await table.reload();
}
