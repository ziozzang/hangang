// Network ▸ ASN pools (read-only for now): ASNs seen in Sumunjang evidence,
// rules that name ASNs, and the proposal workflow placeholder. ASN-wide
// decisions stay explicit operator choices (Sumunjang docs/DESIGN.md).
import { can, guard, sectionPage, capabilities, notConnected, panel, asnText, number, suspicionBadge, SUSPICIONS, failure } from './common.js';

export async function renderAsn(cx, root) {
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
  const pools = new Map();
  for (const entry of candidates) {
    if (!Number.isFinite(entry.asn)) continue;
    const pool = pools.get(entry.asn) || { asn: entry.asn, ips: 0, events: 0, score: 0, worst: 'normal', eligible: 0, rules: [] };
    pool.ips += 1; pool.events += entry.events ?? 0; pool.score += entry.score ?? 0; if (entry.eligible) pool.eligible += 1;
    if (SUSPICIONS.indexOf(entry.suspicion) > SUSPICIONS.indexOf(pool.worst)) pool.worst = entry.suspicion;
    pools.set(entry.asn, pool);
  }
  for (const rule of rules) for (const asn of rule.asns || []) { const pool = pools.get(asn) || { asn, ips: 0, events: 0, score: 0, worst: 'normal', eligible: 0, rules: [] }; pool.rules.push(rule); pools.set(asn, pool); }
  const rows = [...pools.values()].sort((a, b) => b.score - a.score || a.asn - b.asn);
  const table = ui.dataTable(t, {
    id: 'network-asn', caption: 'network.asn.caption', owner: 'ui.owner.sumunjang', sortable: 'none', rowKey: row => String(row.asn),
    columns: [
      { key: 'asn', label: 'network.asn.col.asn', render: row => ui.el('a', { href: `#network/threats?asn=${row.asn}`, text: asnText(cx, row.asn) }) },
      { key: 'ips', label: 'network.asn.col.ips', render: row => ui.el('span', { class: 'zt-num', text: number(row.ips) }) },
      { key: 'events', label: 'network.asn.col.events', render: row => ui.el('span', { class: 'zt-num', text: number(row.events) }) },
      { key: 'score', label: 'network.asn.col.score', render: row => ui.el('span', { class: 'zt-num', text: number(row.score) }) },
      { key: 'stage', label: 'network.asn.col.stage', render: row => row.ips ? suspicionBadge(cx, row.worst) : ui.el('span', { class: 'kit-muted', text: t('network.none') }) },
      { key: 'rules', label: 'network.asn.col.rules', render: row => row.rules.length ? ui.el('span', { class: 'zt-chips' }, row.rules.map(rule => ui.el('a', { class: 'kit-tag', href: `#network/rules?rule=${encodeURIComponent(rule.id)}`, text: `${rule.id} · ${t(`network.rule.action.${['allow', 'deny', 'observe'].includes(rule.action) ? rule.action : 'observe'}`)}` }))) : ui.el('span', { class: 'kit-muted', text: t('network.asn.no_rule') }) },
    ],
    empty: { title: 'network.asn.empty', body: 'network.asn.empty.body' },
    onRowOpen: row => cx.navigate(`#network/threats?asn=${row.asn}`),
    fetchPage: async ({ cursor }) => { const offset = Number(cursor || 0); return { items: rows.slice(offset, offset + 50), nextCursor: offset + 50 < rows.length ? String(offset + 50) : null }; },
  });
  cx.signal.addEventListener('abort', () => table.destroy(), { once: true });
  ui.clear(holder,
    ui.el('p', { class: 'zt-banner', attrs: { role: 'note' }, text: t('network.asn.note') }),
    table.element,
    panel(cx, 'network.asn.proposals', ui.el('div', { class: 'zt-content' }, ui.emptyState(t, { title: 'network.asn.proposals.planned', body: 'network.asn.proposals.body' }),
      ui.el('p', { class: 'zt-gap', attrs: { role: 'note' } }, ui.el('span', { class: 'kit-info', text: 'ⓘ', attrs: { 'aria-hidden': 'true' } }), ' ', ui.el('span', { text: t('network.gap.asn_catalog') })))));
  await table.reload();
}
