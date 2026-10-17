// Network write actions shared by the IP page, threat queue and blocks page:
// block, unblock, allowlist add/remove and candidate approval. Each asks for
// a reason and previews the impact through Sumunjang's own evaluation.
import { guard, formDialog, isCidr, isIp, hostNetwork, number, IPV4, capabilities, can } from './common.js';

const DURATIONS = Object.freeze({ '15m': 900, '1h': 3600, '24h': 86400, '7d': 604800, '30d': 2592000 });

function bits(ip) {
  if (IPV4.test(ip)) return { v: 4, n: ip.split('.').reduce((acc, part) => (acc << 8n) + BigInt(Number(part)), 0n) };
  let text = ip.toLowerCase();
  if (text.includes('.')) {
    const tail = text.slice(text.lastIndexOf(':') + 1);
    if (!IPV4.test(tail)) return null;
    const four = tail.split('.').map(Number);
    text = `${text.slice(0, text.lastIndexOf(':') + 1)}${((four[0] << 8) | four[1]).toString(16)}:${((four[2] << 8) | four[3]).toString(16)}`;
  }
  const [head, tail = null] = text.split('::');
  const left = head ? head.split(':') : [], right = tail ? tail.split(':') : [];
  const groups = tail === null ? left : [...left, ...Array(8 - left.length - right.length).fill('0'), ...right];
  if (groups.length !== 8 || groups.some(group => !/^[0-9a-f]{1,4}$/.test(group))) return null;
  return { v: 6, n: groups.reduce((acc, group) => (acc << 16n) + BigInt(parseInt(group, 16)), 0n) };
}

/** True when `ip` lies inside `cidr` (same family). */
export function contains(cidr, ip) {
  const [base, prefix] = String(cidr).split('/');
  const a = bits(base), b = bits(ip);
  if (!a || !b || a.v !== b.v) return false;
  const width = a.v === 4 ? 32n : 128n, length = BigInt(Number(prefix ?? width));
  const shift = width - length;
  return (a.n >> shift) === (b.n >> shift);
}

/**
 * Impact of putting `network` on the block or allow list for the addresses
 * Sumunjang currently tracks: network aggregate (`networks/inspect`) plus the
 * published decision of each tracked address in range (`explain/batch`), and
 * for an allowlist change the candidate evaluation.
 */
export async function impactPreview(cx, network, { allow = false, candidates = null, policyDocument = null } = {}) {
  const { t, ui } = cx;
  const box = ui.el('div', { class: 'zt-impact', attrs: { 'aria-live': 'polite' } }, ui.loadingState(t));
  (async () => {
    try {
      const [inspect, list] = await Promise.all([
        guard(cx, 'networks/inspect', { json: { network } }).then(answer => answer.data).catch(error => { if (error?.status === 401) throw error; return null; }),
        candidates ? Promise.resolve(candidates) : guard(cx, 'candidates').then(answer => (Array.isArray(answer.data) ? answer.data : [])),
      ]);
      const inRange = list.filter(candidate => contains(network, candidate.ip)).slice(0, 1024);
      let batch = null;
      if (inRange.length) {
        const json = { ips: inRange.map(candidate => candidate.ip) };
        if (allow && policyDocument) json.candidate = { policy: { ...policyDocument.policy, allow: [...new Set([...(policyDocument.policy.allow || []), network])] } };
        batch = (await guard(cx, 'explain/batch', { json })).data;
      }
      if (cx.signal.aborted) return;
      const allowed = batch ? batch.results.filter(entry => entry.published?.action !== 'deny').length : 0;
      const lines = [
        inspect ? t('network.impact.inspect', { ips: number(inspect.unique_ips ?? 0), events: number(inspect.events ?? 0), max: number(inspect.max_ip_score ?? 0) }) : t('network.impact.inspect_unavailable'),
        inRange.length ? t('network.impact.tracked', { count: inRange.length, allowed, denied: inRange.length - allowed }) : t('network.impact.none_tracked'),
      ];
      if (batch?.summary) lines.push(t('network.impact.allow_change', { changed: batch.summary.deny_to_allow ?? 0 }));
      ui.clear(box, ui.el('strong', { text: t('network.impact.title') }), ui.el('ul', {}, lines.map(line => ui.el('li', { text: line }))), ui.el('small', { class: 'kit-muted', text: t('network.impact.note') }));
    } catch (error) {
      if (error?.status === 401) throw error;
      ui.clear(box, ui.el('p', { class: 'kit-muted', text: t('network.impact.unavailable') }));
    }
  })();
  return box;
}

/** Manual block of an address or CIDR with an expiry; the operator reason is the block reason. */
export async function blockDialog(cx, { network = '', mode, fixed = false } = {}) {
  const { t, ui } = cx;
  const target = network ? hostNetwork(network) : '';
  const preview = ui.el('div');
  const fields = [
    { label: 'network.block.network', name: 'network', value: target, maxLength: 64, help: 'network.block.network.help', placeholder: 'network.block.network.placeholder' },
    { label: 'network.block.duration', name: 'duration', value: '24h', options: Object.keys(DURATIONS).map(value => ({ value, label: `network.duration.${value}` })) },
  ];
  const nodes = fields.map(spec => ({ ...spec, node: ui.field(t, spec) }));
  const input = nodes[0].node.querySelector('input');
  input.required = true;
  input.readOnly = fixed;
  const refresh = () => { const value = input.value.trim(); const cidr = isIp(value) ? hostNetwork(value) : value; input.setCustomValidity(isCidr(cidr) ? '' : t('network.block.network.invalid')); if (isCidr(cidr)) impactPreview(cx, cidr).then(node => ui.clear(preview, node)); else ui.clear(preview); };
  input.addEventListener('change', refresh);
  if (target) refresh();
  return formDialog(cx, {
    title: 'network.block.title', intro: t(mode === 'observe' ? 'network.block.effect.observe' : 'network.block.effect'), body: preview,
    fields: nodes, confirm: fixed ? target : null, confirmLabel: 'network.block.confirm', danger: true,
    submit: async values => {
      const cidr = isIp(values.network) ? hostNetwork(values.network) : values.network;
      let reason = values.reason;
      // Sumunjang keeps at most 128 bytes of block reason; the journal keeps the full text.
      while (new TextEncoder().encode(reason).length > 128) reason = reason.slice(0, -1);
      return guard(cx, 'blocks', { json: { network: cidr, expires_at: Math.floor(Date.now() / 1000) + DURATIONS[values.duration], reason }, reason: values.reason });
    },
  });
}

export async function unblockDialog(cx, block) {
  const { t } = cx;
  return formDialog(cx, {
    title: 'network.unblock.title', intro: t('network.unblock.effect', { network: block.network }), confirm: block.network, confirmLabel: 'network.unblock.confirm', danger: true,
    submit: values => guard(cx, 'blocks', { method: 'DELETE', json: { network: block.network, reason: values.reason }, reason: values.reason }),
  });
}

/** Allowlist duration choices; entries without expiry stay until removed. */
const ALLOW_DURATIONS = Object.freeze({ never: 0, '24h': 86400, '7d': 604800, '30d': 2592000, '90d': 7776000 });

/**
 * Allowlist add/remove with a reason. Uses Sumunjang's dedicated allowlist
 * routes (expiry and reason per entry, CAS on the policy revision) and falls
 * back to the policy document for older packages.
 */
export async function allowDialog(cx, { network = '', remove = false, fixed = false } = {}) {
  const { t, ui } = cx;
  const caps = await capabilities(cx);
  const dedicated = can(caps, 'allowlist', 'GET') && can(caps, 'allowlist', remove ? 'DELETE' : 'POST');
  const { data: document } = await guard(cx, 'policy/document');
  const revision = dedicated ? (await guard(cx, 'allowlist')).data?.revision ?? document.revision : document.revision;
  const target = network ? hostNetwork(network) : '';
  const preview = ui.el('div');
  const spec = { label: 'network.allow.network', name: 'network', value: target, maxLength: 64, help: 'network.allow.network.help', placeholder: 'network.block.network.placeholder' };
  const node = ui.field(t, spec);
  const input = node.querySelector('input');
  input.required = true; input.readOnly = fixed || remove;
  const refresh = () => { const value = input.value.trim(); const cidr = isIp(value) ? hostNetwork(value) : value; input.setCustomValidity(isCidr(cidr) ? '' : t('network.block.network.invalid')); if (isCidr(cidr) && !remove) impactPreview(cx, cidr, { allow: true, policyDocument: document }).then(box => ui.clear(preview, box)); };
  input.addEventListener('change', refresh);
  if (target) refresh();
  const fields = [{ ...spec, node }];
  if (dedicated && !remove) fields.push({ label: 'network.allow.duration', name: 'duration', value: 'never', options: Object.keys(ALLOW_DURATIONS).map(value => ({ value, label: `network.allow.duration.${value}` })), help: 'network.allow.duration.help' });
  return formDialog(cx, {
    title: remove ? 'network.unallow.title' : 'network.allow.title', intro: t(remove ? 'network.unallow.effect' : 'network.allow.effect', { network: target || '—' }), body: preview,
    fields, confirm: remove || fixed ? target : null, confirmLabel: remove ? 'network.unallow.confirm' : 'network.allow.confirm', danger: !remove,
    submit: values => {
      const cidr = isIp(values.network) ? hostNetwork(values.network) : values.network;
      if (dedicated) {
        if (remove) return guard(cx, 'allowlist', { method: 'DELETE', json: { expected_revision: revision, network: cidr, reason: values.reason }, reason: values.reason });
        let reason = values.reason;
        // Sumunjang keeps at most 128 bytes of entry reason; the journal keeps the full text.
        while (new TextEncoder().encode(reason).length > 128) reason = reason.slice(0, -1);
        const seconds = ALLOW_DURATIONS[values.duration] || 0;
        return guard(cx, 'allowlist', { method: 'POST', json: { expected_revision: revision, network: cidr, ...(seconds ? { expires_at: Math.floor(Date.now() / 1000) + seconds } : {}), reason }, reason: values.reason });
      }
      const allow = remove ? (document.policy.allow || []).filter(entry => entry !== cidr) : [...new Set([...(document.policy.allow || []), cidr])];
      return guard(cx, 'policy/document', { method: 'PUT', json: { expected_revision: document.revision, policy: { ...document.policy, allow }, reason: values.reason }, reason: values.reason });
    },
  });
}

/** Approve candidate blocks one by one (Sumunjang approves exact addresses). */
export async function approveCandidates(cx, ips, { onEach } = {}) {
  const { t } = cx;
  const target = ips.length === 1 ? ips[0] : t('network.threats.bulk.target', { count: ips.length });
  const confirmed = await formDialog(cx, { title: 'network.threats.approve.title', intro: t('network.threats.approve.effect', { target }), confirm: target, confirmLabel: 'network.threats.approve.confirm', danger: true });
  if (!confirmed) return null;
  const results = [];
  for (const ip of ips) {
    try { const { operation } = await guard(cx, 'candidates/approve', { json: { ip, reason: confirmed.reason }, reason: confirmed.reason }); results.push({ ip, kind: 'committed', operation }); }
    catch (error) { if (error?.status === 401) throw error; results.push({ ip, kind: !error?.status || error.status >= 500 ? 'uncertain' : 'refused', error }); }
    onEach?.(results.at(-1));
  }
  return results;
}
