// System › Network authority (Sumunjang): health and capacity, GeoIP
// databases with reload, signed update status and check, and Kubernetes
// source diagnostics. Raw diagnostics only inside a collapsed disclosure.
import { can, guard, capabilities, panel, facts, button, formDialog, outcomeBanner, errorText, number, timeOrDash } from './common.js';

async function settle(promise) { try { return { ok: true, value: (await promise).data }; } catch (error) { if (error?.status === 401) throw error; return { ok: false, error }; } }

function database(cx, entry) {
  const { t, ui } = cx;
  if (!entry) return ui.el('span', { class: 'kit-muted', text: t('network.system.geoip.none') });
  return ui.el('span', { class: 'zt-stack' }, ui.el('span', { text: entry.database_type || '—' }), ui.el('span', { class: 'kit-muted' }, ui.el('span', { text: t('network.system.geoip.built') }), ' ', timeOrDash(cx, entry.build_epoch), ' · ', ui.el('span', { text: t('network.system.geoip.size', { size: number(Math.round((entry.bytes || 0) / 1048576)) }) })));
}

/** Panels appended to the System section; empty when Sumunjang is absent. */
export async function networkSystemPanels(cx) {
  const { t, ui } = cx;
  const caps = await capabilities(cx);
  if (!caps.installed) return [];
  const [status, update, source, authority] = await Promise.all([
    can(caps, 'status') ? settle(guard(cx, 'status')) : { ok: false },
    can(caps, 'update/status') ? settle(guard(cx, 'update/status')) : { ok: false },
    can(caps, 'kubernetes/status') ? settle(guard(cx, 'kubernetes/status')) : { ok: false },
    can(caps, 'kubernetes/authority') ? settle(guard(cx, 'kubernetes/authority')) : { ok: false },
  ]);
  const result = ui.el('div', { class: 'zt-notes' });
  const confirm = (title, effect, route, okKey) => async () => {
    const answer = await formDialog(cx, { title, intro: t(effect), confirmLabel: 'network.system.run', danger: true, submit: values => guard(cx, route, { json: {}, reason: values.reason }) });
    if (answer) ui.clear(result, outcomeBanner(cx, 'committed', okKey, { operation: answer.operation || '—' }));
  };
  const health = status.ok ? status.value : null;
  const geoip = health?.geoip || {};
  const panels = [];
  panels.push(panel(cx, 'network.system.title', ui.el('div', { class: 'zt-content' }, result,
    health ? facts(cx, [
      ['network.system.health', ui.statusBadge(t, health.health === 'ok' ? 'healthy' : 'unavailable', health.health === 'ok' ? 'network.system.health.ok' : 'ui.status.unavailable')],
      ['network.system.capacity', t('network.system.capacity_value', { candidates: number(health.capacity?.candidates), max_candidates: number(health.capacity?.max_candidates), blocks: number(health.capacity?.blocks), max_blocks: number(health.capacity?.max_blocks) })],
      ['network.system.events', t('network.system.events_value', { accepted: number(health.stats?.accepted), dropped: number(health.stats?.dropped_capacity), rejected: number(health.stats?.block_capacity_rejections) })],
      ['network.system.rules', t('network.system.rules_value', { count: health.rules?.count ?? 0 })],
    ]) : ui.errorState(t, { owner: 'ui.owner.sumunjang', message: status.error ? errorText(t, status.error) : t('network.gap.not_declared') })), { className: 'zt-network-system' }));
  panels.push(panel(cx, 'network.system.geoip', ui.el('div', { class: 'zt-content' }, facts(cx, [['network.system.geoip.country', database(cx, geoip.country)], ['network.system.geoip.asn', database(cx, geoip.asn)]]), ui.el('p', { class: 'kit-help', text: t('network.system.geoip.help') })),
    { actions: [can(caps, 'geoip/reload') ? button(cx, 'network.system.geoip.reload', confirm('network.system.geoip.reload', 'network.system.geoip.reload.effect', 'geoip/reload', 'network.system.geoip.reloaded')) : ui.disabledAction(t, 'network.system.geoip.reload', 'network.gap.not_declared')] }));
  const up = update.ok ? update.value : null;
  panels.push(panel(cx, 'network.system.update', up ? facts(cx, [
    ['network.system.update.phase', t(`network.system.update.phase.${['disabled', 'idle', 'checking', 'available', 'downloading', 'staged', 'applied', 'failed', 'current'].includes(up.phase) ? up.phase : 'other'}`)],
    ['network.system.update.current', up.current_version],
    ['network.system.update.available', up.available_version || up.latest_version || null],
    ['network.system.update.checked', up.checked_at ? timeOrDash(cx, up.checked_at) : null],
  ]) : ui.el('p', { class: 'kit-muted', text: update.error ? errorText(t, update.error) : t('network.gap.not_declared') }),
    { actions: [up?.enabled !== false && can(caps, 'update/check') ? button(cx, 'network.system.update.check', confirm('network.system.update.check', 'network.system.update.check.effect', 'update/check', 'network.system.update.checked_done')) : ui.disabledAction(t, 'network.system.update.check', up?.enabled === false ? 'network.system.update.disabled' : 'network.gap.not_declared')] }));
  const sourceState = source.ok ? (source.value?.fresh ? 'fresh' : 'stale') : source.error?.payload?.state || (authority.ok && authority.value?.enabled === false ? 'disabled' : 'unavailable');
  const raw = ui.el('details', { class: 'zt-raw' }, ui.el('summary', { text: t('system.raw') }), ui.el('pre', { class: 'kit-mono', text: JSON.stringify({ source: source.ok ? source.value : source.error?.payload ?? null, authority: authority.ok ? authority.value : null }, null, 2) }));
  panels.push(panel(cx, 'network.system.kubernetes', ui.el('div', { class: 'zt-content' }, facts(cx, [
    ['network.system.kubernetes.source', ui.statusBadge(t, sourceState === 'fresh' ? 'healthy' : sourceState === 'disabled' ? 'disabled' : sourceState === 'collecting' ? 'pending' : 'unavailable', `network.system.kubernetes.state.${['fresh', 'stale', 'disabled', 'collecting', 'failed', 'stopped', 'unavailable'].includes(sourceState) ? sourceState : 'unavailable'}`)],
    ['network.system.kubernetes.authority', t(authority.ok && authority.value?.enabled ? 'network.system.kubernetes.authority.on' : 'network.system.kubernetes.authority.off')],
  ]), raw)));
  return panels;
}
