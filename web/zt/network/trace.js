// Sumunjang explain trace (docs/AUDIT_EXPLAIN.md) rendered with the kit's
// stage timeline styling: mode → allowlist → geo → rules → blocklist →
// outcome, then the informational score and automatic-block stages.
import { codeText, expiry, networkLink, asnText } from './common.js';

export const TRACE_STAGES = Object.freeze(['mode', 'allowlist', 'geo', 'rules', 'blocklist', 'outcome', 'score', 'auto_block']);
const DECIDING = Object.freeze({ observe: 'mode', allowlist: 'allowlist', rule: 'rules', block: 'blocklist', default: 'outcome' });
export // Sumunjang's fixed English reasons for approved and automatic blocks; the origin is shown elsewhere.
const FIXED_REASONS = new Set(['automatic threshold', 'manual candidate approval']);
export const VERDICTS = Object.freeze(['allow', 'deny', 'observe']);
const VERDICT_KIND = Object.freeze({ allow: 'allow', deny: 'deny', observe: 'simulation' });

export function verdictBadge(cx, verdict) {
  const safe = VERDICTS.includes(verdict) ? verdict : 'observe';
  return cx.ui.statusBadge(cx.t, VERDICT_KIND[safe], `network.verdict.${safe}`);
}

function stageBadge(cx, stage) {
  const { t, ui } = cx;
  if (stage.stage === 'mode') return ui.statusBadge(t, stage.mode === 'enforce' ? 'healthy' : 'simulation', `network.mode.${stage.mode === 'enforce' ? 'enforce' : 'observe'}`);
  if (stage.stage === 'allowlist') return ui.statusBadge(t, stage.matched ? 'allow' : 'disabled', stage.matched ? 'network.trace.matched' : 'network.trace.no_match');
  if (stage.stage === 'rules') return ui.statusBadge(t, stage.winner ? (stage.matched?.find(rule => rule.winner)?.action === 'deny' ? 'deny' : 'allow') : 'disabled', stage.winner ? 'network.trace.winner' : 'network.trace.no_match');
  if (stage.stage === 'blocklist') return ui.statusBadge(t, stage.block ? 'deny' : 'disabled', stage.block ? 'network.trace.blocked' : 'network.trace.no_match');
  if (stage.stage === 'outcome') return ui.statusBadge(t, stage.action === 'deny' ? 'deny' : 'allow', stage.action === 'deny' ? 'network.verdict.deny' : 'network.verdict.allow');
  if (stage.stage === 'auto_block') return ui.statusBadge(t, stage.would_trigger ? 'challenge' : 'disabled', stage.would_trigger ? 'network.trace.would_trigger' : 'network.trace.not_triggered');
  return null;
}

function stageDetail(cx, stage) {
  const { t, ui } = cx;
  if (stage.stage === 'rules') {
    const rows = [...(stage.matched || []).map(rule => ({ ...rule, expired: false })), ...(stage.expired || []).map(rule => ({ ...rule, expired: true }))];
    if (!rows.length) return null;
    return ui.el('ul', { class: 'zt-trace-rules' }, rows.map(rule => ui.el('li', { class: rule.winner ? 'is-winner' : rule.expired ? 'is-expired' : '' },
      ui.el('a', { class: 'kit-mono', href: `#network/rules?rule=${encodeURIComponent(rule.id)}`, text: rule.id }),
      ui.el('span', { class: 'kit-tag', text: t(`network.rule.action.${['allow', 'deny', 'observe'].includes(rule.action) ? rule.action : 'observe'}`) }),
      ui.el('span', { class: 'kit-muted', text: t('network.rule.priority_value', { priority: rule.priority ?? 0 }) }),
      Number.isFinite(rule.score) ? ui.el('span', { class: 'kit-muted', text: t('network.rule.score_value', { score: rule.score }) }) : null,
      rule.winner ? ui.el('strong', { text: t('network.trace.winner') }) : null,
      rule.expired ? ui.el('span', { class: 'kit-tag kit-tag-warn', text: t('network.expiry.expired') }) : null)));
  }
  if (stage.stage === 'blocklist') {
    const items = [];
    if (stage.block) items.push(ui.el('li', {}, networkLink(cx, stage.block.network), ' ', FIXED_REASONS.has(stage.block.reason) ? null : ui.el('span', { class: 'kit-muted', text: stage.block.reason || '' }), ' ', expiry(cx, stage.block.expires_at)));
    for (const block of stage.expired || []) items.push(ui.el('li', { class: 'is-expired' }, networkLink(cx, block.network), ' ', ui.el('span', { class: 'kit-tag kit-tag-warn', text: t('network.expiry.expired') })));
    return items.length ? ui.el('ul', { class: 'zt-trace-rules' }, items) : null;
  }
  if (stage.stage === 'geo') return ui.el('p', { class: 'kit-muted', text: t('network.trace.geo', { country: stage.country || '—', asn: asnText(cx, stage.asn), source: t(`network.asn_source.${['geoip', 'catalog', 'none'].includes(stage.asn_source) ? stage.asn_source : 'none'}`) }) });
  if (stage.stage === 'score') return ui.el('p', { class: 'kit-muted', text: t('network.trace.score', { signal: stage.signal_score ?? 0, rules: stage.static_rule_score ?? 0, total: stage.total ?? 0, threshold: stage.threshold ?? 0 }) });
  return null;
}

/** One explain answer as a timeline; `title` labels published vs enforce preview. */
export function explainTimeline(cx, result) {
  const { t, ui } = cx;
  const stages = Array.isArray(result?.stages) ? result.stages : [];
  const outcome = stages.find(stage => stage.stage === 'outcome');
  const deciding = DECIDING[outcome?.deciding_stage] || null;
  const list = ui.el('ol', { class: 'kit-timeline zt-guard-trace' });
  for (const name of TRACE_STAGES) {
    const stage = stages.find(entry => entry.stage === name);
    if (!stage && (name === 'score' || name === 'auto_block')) continue;
    const isDeciding = deciding === name;
    const item = ui.el('li', { class: `kit-stage${isDeciding ? ' is-deciding' : ''}${stage ? '' : ' is-skipped'}${stage?.informational ? ' is-informational' : ''}`, dataset: { stage: name } });
    const head = ui.el('div', { class: 'kit-stage-head' }, ui.el('strong', { text: t(`network.trace.stage.${name}`) }));
    if (stage) {
      const badge = stageBadge(cx, stage);
      if (badge) head.append(badge);
      if (stage.informational) head.append(ui.el('span', { class: 'kit-tag', text: t('network.trace.informational') }));
      if (isDeciding) head.append(ui.el('span', { class: 'kit-tag zt-deciding', text: t('network.trace.deciding') }));
    } else head.append(ui.statusBadge(t, 'disabled', 'network.trace.not_reached'));
    item.append(head);
    if (stage?.code) item.append(ui.el('p', { class: 'zt-trace-text', text: codeText(t, stage.code, stage.params) }));
    if (stage) { const detail = stageDetail(cx, stage); if (detail) item.append(detail); }
    if (isDeciding) item.append(ui.el('p', { class: 'kit-why' }, ui.el('strong', { text: t('decision.why') }), ' ', codeText(t, result.reason_code, result.params)));
    list.append(item);
  }
  return list;
}
