// Network ▸ Blocks & allowlist: active blocks (manual, approved candidate,
// automatic) with expiry countdown and removal; allowlist entries from the
// policy document. Additions validate the CIDR and preview the impact.
import { can, guard, sectionPage, capabilities, notConnected, modeBanner, networkLink, expiry, blockKind, outcomeBanner, button, failure } from './common.js';
import { blockDialog, unblockDialog, allowDialog } from './actions.js';

const KINDS = Object.freeze(['manual', 'approved', 'automatic']);

function tabs(cx, active, counts) {
  const { t, ui } = cx;
  return ui.el('nav', { class: 'zt-tabs', attrs: { 'aria-label': t('network.blocks.tabs') } },
    ['blocks', 'allowlist'].map(name => ui.el('a', { href: name === 'blocks' ? '#network/blocks' : '#network/blocks/allowlist', attrs: { 'aria-current': name === active ? 'page' : false } }, ui.el('span', { text: t(`network.blocks.tab.${name}`) }), counts[name] === null ? null : ui.el('span', { class: 'kit-tag', text: String(counts[name]) }))));
}

export async function renderBlocks(cx, root, parts, params) {
  const { t, ui } = cx;
  const caps = await capabilities(cx);
  if (cx.signal.aborted) return;
  const active = parts[0] === 'allowlist' ? 'allowlist' : 'blocks';
  const view = sectionPage(cx, root, { active: 'blocks', title: t('network.page.blocks'), owner: t('network.blocks.owner') });
  const { content } = view;
  if (!caps.installed || !can(caps, 'blocks')) { content.append(notConnected(cx, caps, 'blocks')); return; }
  const status = ui.el('div', { class: 'zt-notes' });
  const holder = ui.el('div', { class: 'zt-content' }, ui.loadingState(t));
  content.append(status, holder);
  let blocks, document;
  try { [blocks, document] = await Promise.all([guard(cx, 'blocks').then(answer => (Array.isArray(answer.data) ? answer.data : [])), guard(cx, 'policy/document').then(answer => answer.data)]); }
  catch (error) { ui.clear(holder, failure(cx, error, () => cx.navigate(`${location.hash.split('?')[0]}?retry=${Date.now()}`))); return; }
  if (cx.signal.aborted) return;
  const reload = (key, result) => { ui.clear(status, outcomeBanner(cx, 'committed', key, { operation: result?.operation || '—' })); setTimeout(() => cx.navigate(`${location.hash.split('?')[0]}?updated=${Date.now()}`), 900); };
  const allow = document?.policy?.allow || [];
  const actionsRow = root.querySelector('.zt-actions');
  if (actionsRow) actionsRow.append(
    can(caps, 'blocks', 'POST') ? button(cx, 'network.blocks.add', async () => { const r = await blockDialog(cx, { mode: document?.policy?.mode }); if (r) reload('network.block.done', r); }, { kind: 'danger' }) : ui.disabledAction(t, 'network.blocks.add', 'network.gap.not_declared'),
    can(caps, 'policy/document', 'PUT') ? button(cx, 'network.allow.add', async () => { const r = await allowDialog(cx, {}); if (r) reload('network.allow.done', r); }) : ui.disabledAction(t, 'network.allow.add', 'network.gap.not_declared'));
  const kind = KINDS.includes(params.get('kind')) ? params.get('kind') : '';
  let table;
  if (active === 'blocks') {
    const filter = ui.el('nav', { class: 'zt-chips zt-filter-chips', attrs: { 'aria-label': t('network.blocks.filter') } },
      ['', ...KINDS].map(value => ui.el('a', { class: 'kit-tag', href: value ? `#network/blocks?kind=${value}` : '#network/blocks', text: t(value ? `network.block.kind.${value}` : 'network.filter.any'), attrs: { 'aria-current': value === kind ? 'true' : false } })));
    const rows = blocks.filter(block => !kind || blockKind(block) === kind).sort((a, b) => (a.expires_at ?? 0) - (b.expires_at ?? 0));
    table = ui.dataTable(t, {
      id: 'network-blocks', caption: 'network.blocks.caption', owner: 'ui.owner.sumunjang', sortable: 'none', rowKey: block => block.network,
      columns: [
        { key: 'network', label: 'network.blocks.col.network', render: block => networkLink(cx, block.network) },
        { key: 'kind', label: 'network.blocks.col.kind', render: block => ui.statusBadge(t, blockKind(block) === 'automatic' ? 'stale' : 'deny', `network.block.kind.${blockKind(block)}`) },
        { key: 'reason', label: 'network.blocks.col.reason', render: block => ui.el('span', { text: blockKind(block) === 'manual' ? block.reason : t(`network.block.reason.${blockKind(block)}`) }) },
        { key: 'expires', label: 'network.blocks.col.expires', render: block => expiry(cx, block.expires_at) },
        { key: 'actions', label: 'network.col.actions', title: () => '', render: block => can(caps, 'blocks', 'DELETE') ? ui.el('button', { type: 'button', class: 'button button-quiet zt-row-action', text: t('network.unblock'), on: { click: async event => { event.stopPropagation(); const r = await unblockDialog(cx, block); if (r) reload('network.unblock.done', r); } } }) : ui.disabledAction(t, 'network.unblock', 'network.gap.not_declared') },
      ],
      empty: { title: kind ? 'network.blocks.empty.filtered' : 'network.blocks.empty', body: 'network.blocks.empty.body' },
      onRowOpen: block => { const host = /^(.+)\/(32|128)$/.exec(block.network); if (host) cx.navigate(`#network/ip/${encodeURIComponent(host[1])}`); },
      fetchPage: async ({ cursor }) => { const offset = Number(cursor || 0); return { items: rows.slice(offset, offset + 50), nextCursor: offset + 50 < rows.length ? String(offset + 50) : null }; },
    });
    ui.clear(holder, modeBanner(cx, document?.policy), tabs(cx, active, { blocks: blocks.length, allowlist: allow.length }), filter, table.element,
      ui.el('p', { class: 'zt-gap', attrs: { role: 'note' } }, ui.el('span', { class: 'kit-info', text: 'ⓘ', attrs: { 'aria-hidden': 'true' } }), ' ', ui.el('span', { text: t('network.gap.block_metadata') })));
  } else {
    const rows = allow.map(network => ({ network }));
    table = ui.dataTable(t, {
      id: 'network-allowlist', caption: 'network.allow.caption', owner: 'ui.owner.sumunjang', sortable: 'none', rowKey: row => row.network,
      columns: [
        { key: 'network', label: 'network.blocks.col.network', render: row => networkLink(cx, row.network) },
        { key: 'expires', label: 'network.blocks.col.expires', render: () => ui.el('span', { class: 'kit-muted', text: t('network.expiry.never') }) },
        { key: 'actions', label: 'network.col.actions', title: () => '', render: row => can(caps, 'policy/document', 'PUT') ? ui.el('button', { type: 'button', class: 'button button-quiet zt-row-action', text: t('network.unallow'), on: { click: async event => { event.stopPropagation(); const r = await allowDialog(cx, { network: row.network, remove: true }); if (r) reload('network.unallow.done', r); } } }) : ui.disabledAction(t, 'network.unallow', 'network.gap.not_declared') },
      ],
      empty: { title: 'network.allow.empty', body: 'network.allow.empty.body' },
      fetchPage: async ({ cursor }) => { const offset = Number(cursor || 0); return { items: rows.slice(offset, offset + 50), nextCursor: offset + 50 < rows.length ? String(offset + 50) : null }; },
    });
    ui.clear(holder, ui.el('p', { class: 'zt-banner', attrs: { role: 'note' }, text: t('network.allow.note') }), tabs(cx, active, { blocks: blocks.length, allowlist: allow.length }), table.element);
  }
  cx.signal.addEventListener('abort', () => table.destroy(), { once: true });
  await table.reload();
}
