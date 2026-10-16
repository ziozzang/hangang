// Network ▸ ASN pools (read-only): the offline ASN prefix catalog Sumunjang
// uses for rule context (`asn/catalog/query`, paginated, filter by ASN), the
// ASNs seen in its evidence and the rules that name them. ASN-wide decisions
// stay explicit, reviewed rules (Sumunjang docs/DESIGN.md); proposals are a
// later workflow.
import { can, guard, sectionPage, capabilities, notConnected, panel, asnText, number, suspicionBadge, SUSPICIONS, failure } from './common.js';

const PREFIX_PREVIEW = 6;

function evidencePools(candidates, rules) {
  const pools = new Map();
  const pool = asn => { if (!pools.has(asn)) pools.set(asn, { asn, ips: 0, events: 0, score: 0, worst: 'normal', eligible: 0, rules: [] }); return pools.get(asn); };
  for (const entry of candidates) {
    if (!Number.isFinite(entry.asn)) continue;
    const item = pool(entry.asn);
    item.ips += 1; item.events += entry.events ?? 0; item.score += entry.score ?? 0; if (entry.eligible) item.eligible += 1;
    if (SUSPICIONS.indexOf(entry.suspicion) > SUSPICIONS.indexOf(item.worst)) item.worst = entry.suspicion;
  }
  for (const rule of rules) for (const asn of rule.asns || []) pool(asn).rules.push(rule);
  return pools;
}

function ruleChips(cx, rules) {
  const { t, ui } = cx;
  if (!rules.length) return ui.el('span', { class: 'kit-muted', text: t('network.asn.no_rule') });
  return ui.el('span', { class: 'zt-chips' }, rules.map(rule => ui.el('a', { class: 'kit-tag', href: `#network/rules?rule=${encodeURIComponent(rule.id)}`, text: `${rule.id} · ${t(`network.rule.action.${['allow', 'deny', 'observe'].includes(rule.action) ? rule.action : 'observe'}`)}` })));
}

function evidenceCell(cx, item) {
  const { t, ui } = cx;
  if (!item?.ips) return ui.el('span', { class: 'kit-muted', text: t('network.asn.no_evidence') });
  return ui.el('span', { class: 'zt-inline' }, suspicionBadge(cx, item.worst), ui.el('a', { href: `#network/threats?asn=${item.asn}`, text: t('network.asn.evidence', { ips: number(item.ips), score: number(item.score) }) }));
}

export async function renderAsn(cx, root, params) {
  const { t, ui } = cx;
  const caps = await capabilities(cx);
  if (cx.signal.aborted) return;
  const { content } = sectionPage(cx, root, { active: 'asn', title: t('network.page.asn'), owner: t('network.asn.owner'), actions: [ui.disabledAction(t, 'network.asn.propose', 'network.gap.asn_proposals')] });
  if (!caps.installed || !can(caps, 'candidates')) { content.append(notConnected(cx, caps, 'candidates')); return; }
  const holder = ui.el('div', { class: 'zt-content' }, ui.loadingState(t));
  content.append(holder);
  let candidates, rules;
  try { [candidates, rules] = await Promise.all([guard(cx, 'candidates').then(answer => (Array.isArray(answer.data) ? answer.data : [])), guard(cx, 'rules').then(answer => answer.data?.rules || [])]); }
  catch (error) { ui.clear(holder, failure(cx, error, () => cx.navigate(`#network/asn?retry=${Date.now()}`))); return; }
  if (cx.signal.aborted) return;
  const pools = evidencePools(candidates, rules);
  const blocks = [ui.el('p', { class: 'zt-banner', attrs: { role: 'note' }, text: t('network.asn.note') })];
  const tables = [];
  const filterAsn = /^\d{1,10}$/.test(params?.get('asn') || '') ? Number(params.get('asn')) : null;
  if (can(caps, 'asn/catalog/query')) {
    // Offline catalog, grouped per ASN, paginated by prefix rows.
    const summary = ui.el('p', { class: 'kit-muted', attrs: { 'aria-live': 'polite' } });
    const form = ui.el('form', { class: 'zt-search', attrs: { role: 'search', 'aria-label': t('network.asn.filter') } });
    const field = ui.field(t, { label: 'network.asn.filter', name: 'asn', value: filterAsn === null ? '' : String(filterAsn), pattern: '\\d{1,10}', maxLength: 10, placeholder: 'network.asn.filter.placeholder' });
    form.append(field, ui.el('button', { type: 'submit', class: 'button', text: t('network.filter.apply') }), filterAsn === null ? null : ui.el('a', { class: 'button button-quiet', href: '#network/asn', text: t('network.filter.reset') }));
    form.addEventListener('submit', event => { event.preventDefault(); if (!form.reportValidity()) return; const value = form.elements.asn.value.trim(); cx.navigate(value ? `#network/asn?asn=${value}` : '#network/asn'); });
    const catalog = ui.dataTable(t, {
      id: 'network-asn-catalog', caption: 'network.asn.catalog.caption', owner: 'ui.owner.sumunjang', sortable: 'none', rowKey: row => String(row.asn),
      columns: [
        { key: 'asn', label: 'network.asn.col.asn', render: row => ui.el('strong', { text: asnText(cx, row.asn) }) },
        { key: 'prefixes', label: 'network.asn.col.prefixes', render: row => { const list = Array.isArray(row.prefixes) ? row.prefixes : []; return ui.el('span', { class: 'zt-asn-prefixes' }, list.slice(0, PREFIX_PREVIEW).map(prefix => ui.el('code', { class: 'kit-tag kit-mono', text: prefix })), list.length > PREFIX_PREVIEW ? ui.el('span', { class: 'kit-muted', text: t('network.asn.more_prefixes', { count: list.length - PREFIX_PREVIEW }) }) : null); }, title: row => (row.prefixes || []).join(', ') },
        { key: 'count', label: 'network.asn.col.prefix_count', render: row => ui.el('span', { class: 'zt-num', text: number((row.prefixes || []).length) }) },
        { key: 'evidence', label: 'network.asn.col.evidence', render: row => evidenceCell(cx, pools.get(row.asn)) },
        { key: 'rules', label: 'network.asn.col.rules', render: row => ruleChips(cx, pools.get(row.asn)?.rules || []) },
      ],
      empty: { title: filterAsn === null ? 'network.asn.catalog.empty' : 'network.asn.catalog.empty.filtered', body: 'network.asn.catalog.empty.body' },
      expand: row => ui.el('div', { class: 'zt-asn-prefixes' }, (row.prefixes || []).map(prefix => ui.el('code', { class: 'kit-tag kit-mono', text: prefix }))),
      fetchPage: async ({ cursor }) => {
        const { data } = await guard(cx, 'asn/catalog/query', { json: { limit: 200, ...(filterAsn === null ? {} : { asn: filterAsn }), ...(cursor ? { cursor } : {}) } });
        summary.textContent = t('network.asn.catalog.summary', { asns: number(data?.total_asns ?? 0), prefixes: number(data?.total_prefixes ?? 0) });
        return { items: Array.isArray(data?.entries) ? data.entries : [], nextCursor: data?.next_cursor || null };
      },
    });
    tables.push(catalog);
    blocks.push(panel(cx, 'network.asn.catalog', ui.el('div', { class: 'zt-content' }, form, summary, catalog.element, ui.el('p', { class: 'kit-help', text: t('network.asn.catalog.help') }))));
  }
  // ASNs from evidence and rules (also those the catalog does not list).
  const rows = [...pools.values()].sort((a, b) => b.score - a.score || a.asn - b.asn).filter(row => filterAsn === null || row.asn === filterAsn);
  const evidence = ui.dataTable(t, {
    id: 'network-asn', caption: 'network.asn.caption', owner: 'ui.owner.sumunjang', sortable: 'none', rowKey: row => String(row.asn),
    columns: [
      { key: 'asn', label: 'network.asn.col.asn', render: row => ui.el('a', { href: `#network/threats?asn=${row.asn}`, text: asnText(cx, row.asn) }) },
      { key: 'ips', label: 'network.asn.col.ips', render: row => ui.el('span', { class: 'zt-num', text: number(row.ips) }) },
      { key: 'events', label: 'network.asn.col.events', render: row => ui.el('span', { class: 'zt-num', text: number(row.events) }) },
      { key: 'score', label: 'network.asn.col.score', render: row => ui.el('span', { class: 'zt-num', text: number(row.score) }) },
      { key: 'stage', label: 'network.asn.col.stage', render: row => row.ips ? suspicionBadge(cx, row.worst) : ui.el('span', { class: 'kit-muted', text: t('network.none') }) },
      { key: 'rules', label: 'network.asn.col.rules', render: row => ruleChips(cx, row.rules) },
    ],
    empty: { title: 'network.asn.empty', body: 'network.asn.empty.body' },
    onRowOpen: row => cx.navigate(`#network/threats?asn=${row.asn}`),
    fetchPage: async ({ cursor }) => { const offset = Number(cursor || 0); return { items: rows.slice(offset, offset + 50), nextCursor: offset + 50 < rows.length ? String(offset + 50) : null }; },
  });
  tables.push(evidence);
  blocks.push(panel(cx, 'network.asn.evidence_title', evidence.element));
  if (!can(caps, 'asn/catalog/query')) blocks.push(ui.el('p', { class: 'zt-gap', attrs: { role: 'note' } }, ui.el('span', { class: 'kit-info', text: 'ⓘ', attrs: { 'aria-hidden': 'true' } }), ' ', ui.el('span', { text: t('network.gap.asn_catalog') })));
  blocks.push(panel(cx, 'network.asn.proposals', ui.emptyState(t, { title: 'network.asn.proposals.planned', body: 'network.asn.proposals.body' })));
  for (const table of tables) cx.signal.addEventListener('abort', () => table.destroy(), { once: true });
  ui.clear(holder, ...blocks);
  await Promise.all(tables.map(table => table.reload()));
}
