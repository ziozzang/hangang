// Network ▸ Zones (Sumunjang docs/NETWORK_ZONES.md): named prefix sets that
// label addresses in evidence and explain and feed Pumgye zone conditions.
// They never change a Sumunjang admission decision. Writes are a
// compare-and-set on the zone revision with a reason; validation errors come
// back as JSON Pointer paths (`/zone/id`, `/zone/prefixes/N`).
import { can, guard, sectionPage, capabilities, notConnected, panel, facts, button, formDialog, outcomeBanner, failure, timeOrDash, number, ipLink, isCidr, isIp, hostNetwork } from './common.js';
import { contains } from './actions.js';
import { trafficSample } from './diff.js';

const ID = /^[A-Za-z0-9_.:-]{1,128}$/;
/** JSON Pointer Sumunjang uses for a prefix (`/zone/prefixes/N`). */
const prefixPointer = index => ['', 'zone', 'prefixes', index].join('/');

/** `updated_by`: the delegated console actor, or the shared admin credential. */
function actorLabel(cx, value) { return value === 'admin-credential' ? cx.t('network.zone.actor.credential') : value; }

function zoneLink(cx, zone) {
  const { ui } = cx;
  return ui.el('a', { class: 'zt-stack', href: `#network/zones/${encodeURIComponent(zone.id)}` }, ui.el('strong', { text: zone.display_name || zone.id }), zone.display_name ? ui.el('span', { class: 'kit-entity-id', text: zone.id }) : null);
}

/** Zone badge used by the IP page and the threat queue. */
export function zoneBadges(cx, ids) {
  const { t, ui } = cx;
  if (!Array.isArray(ids) || !ids.length) return ui.el('span', { class: 'kit-muted', text: t('network.zone.none') });
  return ui.el('span', { class: 'zt-chips' }, ids.map(id => ui.el('a', { class: 'kit-tag zt-zone', href: `#network/zones/${encodeURIComponent(id)}`, text: id })));
}

function parsePrefixes(text) {
  return text.split(/[\n,]/).map(line => line.trim()).filter(Boolean).map(value => (isIp(value) ? hostNetwork(value) : value));
}

/**
 * Membership change on tracked traffic: Sumunjang's current zones of each
 * tracked address (`explain/batch`) against the draft prefixes. Zones only
 * label; decisions do not change.
 */
async function zoneImpact(cx, zoneId, before, after) {
  const { t, ui } = cx;
  const sample = await trafficSample(cx);
  if (!sample.length) return ui.el('p', { class: 'kit-muted', text: t('network.zone.impact.no_sample') });
  const { data } = await guard(cx, 'explain/batch', { json: { ips: sample } });
  const current = new Map((data?.results || []).map(entry => [entry.ip, Array.isArray(entry.zones) ? entry.zones : []]));
  const inside = prefixes => ip => prefixes.some(prefix => contains(prefix, ip));
  const wasIn = sample.filter(ip => (current.get(ip) || []).includes(zoneId) || inside(before)(ip));
  const willBe = sample.filter(inside(after));
  const joining = willBe.filter(ip => !wasIn.includes(ip)), leaving = wasIn.filter(ip => !willBe.includes(ip));
  return ui.el('div', { class: 'zt-impact' }, ui.el('strong', { text: t('network.zone.impact.title') }),
    ui.el('ul', {}, ui.el('li', { text: t('network.zone.impact.members', { count: willBe.length, total: sample.length }) }), ui.el('li', { text: t('network.zone.impact.joining', { count: joining.length }) }), ui.el('li', { text: t('network.zone.impact.leaving', { count: leaving.length }) })),
    joining.length || leaving.length ? ui.el('p', { class: 'zt-chips' }, [...joining.slice(0, 6).map(ip => ui.el('span', { class: 'kit-tag kit-tag-add' }, '+ ', ipLink(cx, ip))), ...leaving.slice(0, 6).map(ip => ui.el('span', { class: 'kit-tag kit-tag-warn' }, '− ', ipLink(cx, ip)))]) : null,
    ui.el('small', { class: 'kit-muted', text: t('network.zone.impact.note') }));
}

/** Create or replace a zone. `zone` is null for a new zone. */
export async function zoneDialog(cx, document, zone) {
  const { t, ui } = cx;
  const fields = [
    { label: 'network.zone.field.id', name: 'id', value: zone?.id || '', maxLength: 128, pattern: ID.source.slice(1, -1), help: 'network.zone.help.id' },
    { label: 'network.zone.field.display_name', name: 'display_name', value: zone?.display_name || '', maxLength: 128 },
    { label: 'network.zone.field.owner', name: 'owner', value: zone?.owner || '', maxLength: 128, help: 'network.zone.help.owner' },
    { label: 'network.zone.field.description', name: 'description', value: zone?.description || '', maxLength: 512 },
  ].map(spec => ({ ...spec, node: ui.field(t, spec) }));
  const idInput = fields[0].node.querySelector('input');
  idInput.required = true; idInput.readOnly = Boolean(zone);
  const areaId = `zt-prefixes-${Math.random().toString(36).slice(2, 6)}`;
  const area = ui.el('textarea', { id: areaId, name: 'prefixes', rows: 6, required: true, spellcheck: false, class: 'kit-mono', value: (zone?.prefixes || []).join('\n') });
  const areaHelp = ui.el('small', { class: 'kit-help', id: `${areaId}-help`, text: t('network.zone.help.prefixes') });
  area.setAttribute('aria-describedby', areaHelp.id);
  const lineErrors = ui.el('ul', { class: 'zt-field-errors', attrs: { 'aria-live': 'polite' } });
  const preview = ui.el('div');
  const check = () => {
    const list = parsePrefixes(area.value);
    const bad = list.map((prefix, index) => [prefix, index]).filter(([prefix]) => !isCidr(prefix));
    ui.clear(lineErrors, bad.slice(0, 8).map(([prefix, index]) => ui.el('li', {}, ui.el('code', { class: 'kit-mono', text: prefixPointer(index) }), ' ', ui.el('span', { text: t('network.zone.error.prefix', { prefix }) }))));
    area.setCustomValidity(list.length && !bad.length ? '' : t(list.length ? 'network.zone.error.prefixes' : 'network.zone.error.empty'));
    if (list.length && !bad.length && can(document.caps, 'explain/batch')) zoneImpact(cx, idInput.value.trim() || zone?.id || '', zone?.prefixes || [], list).then(node => ui.clear(preview, node)).catch(error => { if (error?.status === 401) throw error; ui.clear(preview); });
  };
  area.addEventListener('change', check);
  if (zone) check();
  const prefixesField = ui.el('label', { class: 'kit-field zt-field-wide', htmlFor: areaId }, ui.el('span', { class: 'kit-field-label', text: t('network.zone.field.prefixes') }), area, areaHelp, lineErrors);
  return formDialog(cx, {
    title: zone ? 'network.zone.edit.title' : 'network.zone.create.title', intro: t('network.zone.effect'), body: preview,
    fields: [...fields, { node: prefixesField, name: 'prefixes' }], confirmLabel: zone ? 'network.zone.edit.save' : 'network.zone.create',
    submit: async values => {
      const body = { id: zone?.id || values.id, prefixes: parsePrefixes(values.prefixes) };
      for (const name of ['display_name', 'owner', 'description']) if (values[name]) body[name] = values[name];
      try {
        return await guard(cx, 'zones', { json: { expected_revision: document.revision, zone: body, reason: values.reason }, reason: values.reason });
      } catch (error) {
        // Mark the fields Sumunjang names (JSON Pointer paths) before the dialog shows the list.
        for (const entry of Array.isArray(error?.payload?.errors) ? error.payload.errors : []) {
          if (entry.path === '/zone/id') idInput.setAttribute('aria-invalid', 'true');
          if (String(entry.path || '').startsWith('/zone/prefixes')) area.setAttribute('aria-invalid', 'true');
        }
        throw error;
      }
    },
  });
}

async function loadZones(cx) {
  const { data } = await guard(cx, 'zones');
  return { revision: data?.revision ?? 0, limits: data?.limits || {}, zones: Array.isArray(data?.zones) ? data.zones : [] };
}

export async function renderZones(cx, root, parts) {
  const { t, ui } = cx;
  const caps = await capabilities(cx);
  if (cx.signal.aborted) return;
  const id = parts[0] || null;
  const { content, heading } = sectionPage(cx, root, { active: 'zones', crumbs: id ? [{ label: t('network.page.zones'), href: '#network/zones' }, { label: id }] : [], title: id || t('network.page.zones'), owner: t(id ? 'network.zone.owner' : 'network.zones.owner') });
  if (!caps.installed || !can(caps, 'zones', 'GET')) { content.append(notConnected(cx, caps, 'zones')); return; }
  const status = ui.el('div', { class: 'zt-notes' });
  const holder = ui.el('div', { class: 'zt-content' }, ui.loadingState(t));
  content.append(status, holder);
  let document;
  try { document = { ...(await loadZones(cx)), caps }; }
  catch (error) { ui.clear(holder, failure(cx, error, () => cx.navigate(`${location.hash.split('?')[0]}?retry=${Date.now()}`))); return; }
  if (cx.signal.aborted) return;
  const canWrite = can(caps, 'zones', 'POST');
  const done = (key, result, next) => { ui.clear(status, outcomeBanner(cx, 'committed', key, { operation: result?.operation || '—' })); setTimeout(() => cx.navigate(`${next || location.hash.split('?')[0]}?updated=${Date.now()}`), 900); };
  const actionsRow = root.querySelector('.zt-actions');
  const strip = ui.el('div', { class: 'zt-authority' },
    ui.el('span', { class: 'zt-authority-item' }, ui.el('span', { class: 'kit-muted', text: t('network.zone.owner_label') }), ' ', ui.el('strong', { text: t('ui.owner.sumunjang') })),
    ui.el('span', { class: 'zt-authority-item', text: t('ui.revision', { revision: document.revision }) }),
    ui.el('span', { class: 'zt-authority-item', text: t('network.zones.usage', { zones: number(document.zones.length), max_zones: number(document.limits.zones ?? 64), prefixes: number(document.zones.reduce((sum, zone) => sum + (zone.prefixes || []).length, 0)), max_prefixes: number(document.limits.prefixes ?? 65536) }) }));
  if (!id) {
    if (actionsRow) actionsRow.append(canWrite ? button(cx, 'network.zone.create', async () => { const result = await zoneDialog(cx, document, null); if (result) done('network.zone.created', result, `#network/zones/${encodeURIComponent(result.data?.zone?.id || '')}`); }, { kind: 'primary' }) : ui.disabledAction(t, 'network.zone.create', 'network.gap.not_declared'));
    const table = ui.dataTable(t, {
      id: 'network-zones', caption: 'network.zones.caption', owner: 'ui.owner.sumunjang', sortable: 'none', rowKey: zone => zone.id,
      columns: [
        { key: 'zone', label: 'network.zone.col.zone', render: zone => zoneLink(cx, zone) },
        { key: 'prefixes', label: 'network.zone.col.prefixes', render: zone => ui.el('span', { class: 'zt-asn-prefixes' }, (zone.prefixes || []).slice(0, 4).map(prefix => ui.el('code', { class: 'kit-tag kit-mono', text: prefix })), (zone.prefixes || []).length > 4 ? ui.el('span', { class: 'kit-muted', text: t('network.zone.more', { count: zone.prefixes.length - 4 }) }) : null), title: zone => (zone.prefixes || []).join(', ') },
        { key: 'count', label: 'network.zone.col.count', render: zone => ui.el('span', { class: 'zt-num', text: number((zone.prefixes || []).length) }) },
        { key: 'owner', label: 'network.zone.col.owner', render: zone => ui.el('span', { text: zone.owner || t('network.none') }) },
        { key: 'updated', label: 'network.zone.col.updated', render: zone => ui.el('span', { class: 'zt-stack' }, timeOrDash(cx, zone.updated_at), zone.updated_by ? ui.el('span', { class: 'kit-muted', text: actorLabel(cx, zone.updated_by) }) : null) },
      ],
      empty: { title: 'network.zones.empty', body: 'network.zones.empty.body' },
      onRowOpen: zone => cx.navigate(`#network/zones/${encodeURIComponent(zone.id)}`),
      fetchPage: async () => ({ items: [...document.zones].sort((a, b) => a.id.localeCompare(b.id)), nextCursor: null }),
    });
    table.element.classList.add('zt-static');
    cx.signal.addEventListener('abort', () => table.destroy(), { once: true });
    ui.clear(holder, strip, ui.el('p', { class: 'zt-banner', attrs: { role: 'note' }, text: t('network.zones.note') }), table.element);
    await table.reload();
    return;
  }
  const zone = document.zones.find(entry => entry.id === id);
  if (!zone) { ui.clear(holder, ui.emptyState(t, { title: 'network.zone.missing', body: 'network.zone.missing.body', action: ui.el('a', { class: 'button button-quiet', href: '#network/zones', text: t('network.page.zones') }) })); return; }
  if (zone.display_name) heading.textContent = zone.display_name;
  if (actionsRow) actionsRow.append(
    canWrite ? button(cx, 'network.zone.edit', async () => { const result = await zoneDialog(cx, document, zone); if (result) done('network.zone.updated', result); }) : ui.disabledAction(t, 'network.zone.edit', 'network.gap.not_declared'),
    canWrite ? button(cx, 'network.zone.delete', async () => {
      const result = await formDialog(cx, { title: 'network.zone.delete.title', intro: t('network.zone.delete.effect', { zone: zone.id }), confirm: zone.id, confirmLabel: 'network.zone.delete', danger: true,
        submit: values => guard(cx, 'zones', { json: { expected_revision: document.revision, remove: zone.id, reason: values.reason }, reason: values.reason }) });
      if (result) done('network.zone.deleted', result, '#network/zones');
    }, { kind: 'danger' }) : ui.disabledAction(t, 'network.zone.delete', 'network.gap.not_declared'));
  const prefixes = ui.dataTable(t, {
    id: 'network-zone-prefixes', caption: 'network.zone.prefixes.caption', owner: 'ui.owner.sumunjang', sortable: 'none', rowKey: row => row.prefix,
    columns: [
      { key: 'index', label: 'network.zone.col.index', render: row => ui.el('span', { class: 'kit-muted zt-num', text: String(row.index) }) },
      { key: 'prefix', label: 'network.zone.col.prefix', render: row => ui.el('code', { class: 'kit-mono', text: row.prefix }) },
      { key: 'family', label: 'network.zone.col.family', render: row => ui.el('span', { text: t(row.prefix.includes(':') ? 'network.zone.family.v6' : 'network.zone.family.v4') }) },
    ],
    empty: { title: 'network.zone.prefixes.empty' },
    fetchPage: async ({ cursor }) => { const rows = (zone.prefixes || []).map((prefix, index) => ({ prefix, index })); const offset = Number(cursor || 0); return { items: rows.slice(offset, offset + 100), nextCursor: offset + 100 < rows.length ? String(offset + 100) : null }; },
  });
  cx.signal.addEventListener('abort', () => prefixes.destroy(), { once: true });
  const members = ui.el('div', {}, ui.loadingState(t));
  ui.clear(holder, strip, panel(cx, 'network.zone.details', facts(cx, [
    ['network.zone.field.id', ui.el('span', { class: 'zt-id' }, ui.el('code', { class: 'kit-mono', text: zone.id }), ui.copyButton(t, zone.id))],
    ['network.zone.field.display_name', zone.display_name || null],
    ['network.zone.field.owner', zone.owner || null],
    ['network.zone.field.description', zone.description || null],
    ['network.zone.col.updated', zone.updated_at ? ui.el('span', {}, timeOrDash(cx, zone.updated_at), zone.updated_by ? ui.el('span', { class: 'kit-muted' }, ' · ', actorLabel(cx, zone.updated_by)) : null) : null],
  ])), panel(cx, 'network.zone.prefixes.title', prefixes.element, { params: { count: (zone.prefixes || []).length } }), panel(cx, 'network.zone.members', members));
  await prefixes.reload();
  // Tracked addresses currently labelled with this zone.
  try {
    const sample = await trafficSample(cx);
    const inZone = sample.filter(ip => (zone.prefixes || []).some(prefix => contains(prefix, ip)));
    ui.clear(members, inZone.length ? ui.el('p', { class: 'zt-chips' }, inZone.slice(0, 30).map(ip => ipLink(cx, ip))) : ui.el('p', { class: 'kit-muted', text: t('network.zone.members.none') }), ui.el('p', { class: 'kit-help', text: t('network.zone.members.note') }));
  } catch (error) { if (error?.status === 401) throw error; ui.clear(members, ui.el('p', { class: 'kit-muted', text: t('network.zone.impact.unavailable') })); }
}
