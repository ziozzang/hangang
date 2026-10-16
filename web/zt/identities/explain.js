// "Test access as a user": Hopae `explain/authentication` (docs/
// AUTHENTICATION_EXPLAIN.md). Read-only; Hopae records only an audit read.
import { hopae, errorText, aalBadge, factorList, panel, facts } from './common.js';

const OUTCOME_KIND = Object.freeze({ allow: 'allow', login: 'challenge', step_up: 'challenge', reauth: 'challenge', deny: 'deny', unavailable: 'unavailable', indeterminate: 'unknown', not_applicable: 'disabled' });
const RESULT_KIND = Object.freeze({ pass: 'allow', fail: 'deny', skip: 'disabled', info: 'unknown' });
export const EXPLAIN_REASONS = Object.freeze(['allowed', 'unknown_app', 'app_disabled', 'port_not_allowed', 'insecure_transport', 'contract_violation', 'path_not_canonical', 'reserved_path', 'entry_point', 'login_required', 'handle_absent', 'unknown_handle', 'session_terminated', 'idle', 'absolute', 'clock_skew', 'binding_ip', 'binding_ua', 'binding_not_evaluated', 'user_disabled', 'authz_change', 'step_up_required', 'step_up_unavailable', 'reauth_required', 'subject_unknown', 'subject_deleted', 'service_credential_required', 'service_profile_absent', 'service_principal_unknown', 'credential_expired', 'network_denied', 'network_not_evaluated', 'eligibility_denied', 'eligibility_unavailable', 'remote_verifier', 'machine_step_up', 'authority_unavailable']);
export const EXPLAIN_CHECKS = Object.freeze(['path', 'transport', 'application', 'reserved', 'service_profile', 'service_credential', 'network', 'eligibility', 'session', 'handle', 'lifetimes', 'binding', 'user', 'subject', 'step_up', 'freshness']);

function reasonSentence(t, reason) {
  const code = typeof reason?.code === 'string' ? reason.code.replace(/^hopae\./, '') : null;
  if (code && EXPLAIN_REASONS.includes(code)) return t(`identities.explain.reason.${code}`);
  return t('identities.explain.reason.other');
}

function outcomeBadge(cx, outcome) {
  const safe = Object.hasOwn(OUTCOME_KIND, outcome) ? outcome : 'indeterminate';
  return cx.ui.statusBadge(cx.t, OUTCOME_KIND[safe], `identities.explain.outcome.${safe}`);
}

function traceList(cx, trace) {
  const { t, ui } = cx;
  const list = ui.el('ol', { class: 'zt-trace' });
  for (const step of Array.isArray(trace) ? trace : []) {
    const check = EXPLAIN_CHECKS.includes(step.check) ? t(`identities.explain.check.${step.check}`) : t('identities.explain.check.other');
    const result = Object.hasOwn(RESULT_KIND, step.result) ? step.result : 'info';
    list.append(ui.el('li', { class: `zt-trace-step zt-trace-${result}` },
      ui.statusBadge(t, RESULT_KIND[result], `identities.explain.result.${result}`),
      ui.el('strong', { text: check }),
      step.reason ? ui.el('span', { class: 'kit-muted', text: reasonSentence(t, step.reason) }) : null));
  }
  return list;
}

/** Renders one explain answer: outcome, why, assurance, step-up, freshness and trace. */
export function explainResult(cx, answer) {
  const { t, ui } = cx;
  const box = ui.el('div', { class: 'zt-explain-result', attrs: { 'aria-label': t('identities.explain.result') } });
  const head = ui.el('div', { class: 'zt-explain-head' }, outcomeBadge(cx, answer.outcome),
    Number.isFinite(answer.status_code) ? ui.el('span', { class: 'kit-tag', text: t('identities.explain.status', { status: answer.status_code }) }) : null,
    ui.el('span', { class: 'kit-tag', text: t('identities.explain.simulated') }));
  box.append(head, ui.el('p', { class: 'kit-why' }, ui.el('strong', { text: t('decision.why') }), ' ', reasonSentence(t, answer.reason)));
  const fix = { step_up: 'identities.explain.fix.step_up', login: 'identities.explain.fix.login', reauth: 'identities.explain.fix.reauth', deny: 'identities.explain.fix.deny', unavailable: 'identities.explain.fix.unavailable' }[answer.outcome];
  if (fix) box.append(ui.el('p', { class: 'kit-fix' }, ui.el('strong', { text: t('decision.fix') }), ' ', t(fix)));
  const assurance = answer.assurance || {};
  const stepUp = answer.step_up || {};
  const freshness = answer.freshness || {};
  const app = answer.application;
  const profile = answer.service_profile;
  const subject = answer.subject?.item;
  const second = assurance.second_factors || {};
  const secondFactors = [second.totp_enrolled ? 'totp' : null, Array.isArray(second.external) && second.external.length ? 'external' : null].filter(Boolean);
  const verdict = stepUp.verdict === 'not_required' ? 'not_required' : stepUp.verdict && typeof stepUp.verdict === 'object' && stepUp.verdict.required ? 'required' : null;
  box.append(ui.el('div', { class: 'zt-grid' },
    panel(cx, 'identities.explain.assurance', facts(cx, [
      ['identities.explain.current_aal', aalBadge(cx, assurance.current_aal)],
      ['identities.explain.required_aal', aalBadge(cx, assurance.required_aal ?? stepUp.required_aal)],
      // Hopae 0.1.10: AAL 3 rules are met only by a live high-assurance passkey elevation.
      ['identities.explain.presented_aal', Number.isFinite(stepUp.presented_aal) ? aalBadge(cx, stepUp.presented_aal) : null],
      ['identities.explain.aal3_evidence', typeof stepUp.aal3_evidence === 'boolean' ? t(stepUp.aal3_evidence ? 'identities.explain.aal3_evidence.yes' : 'identities.explain.aal3_evidence.no') : null],
      ['identities.explain.achievable_aal', aalBadge(cx, assurance.achievable_aal)],
      ['identities.explain.totp', second.totp_configured === undefined ? null : t(second.totp_enrolled ? 'identities.explain.totp.enrolled' : !second.totp_configured ? 'identities.explain.totp.not_configured' : second.totp_enrolled === false ? 'identities.explain.totp.not_enrolled' : 'identities.explain.totp.unknown')],
      ['identities.explain.second_factors', secondFactors.length ? factorList(cx, secondFactors) : null],
    ])),
    panel(cx, 'identities.explain.policy', facts(cx, [
      ['identities.explain.application', app ? (app.display_name || app.app_id) : null],
      ['identities.explain.service_profile', profile ? `${profile.service_id} · ${profile.realm}` : null],
      ['identities.explain.step_up', verdict === 'required' ? t('identities.explain.step_up.required', { aal: stepUp.verdict.required.aal ?? '—' }) : verdict ? t('identities.explain.step_up.not_required') : null],
      ['identities.explain.rules', Array.isArray(stepUp.matched_rules) ? t('identities.explain.rules.count', { count: stepUp.matched_rules.length }) : null],
      ['identities.explain.freshness', freshness.max_auth_age_seconds ? t(freshness.fresh ? 'identities.explain.fresh' : 'identities.explain.stale', { max: Math.round(freshness.max_auth_age_seconds / 60) }) : null],
      ['identities.explain.user', subject ? (subject.display_name || subject.email || subject.id) : t(`identities.explain.input.${['session', 'subject', 'anonymous'].includes(answer.subject?.input) ? answer.subject.input : 'anonymous'}`)],
    ]))));
  if (answer.after_login) {
    const after = answer.after_login;
    box.append(ui.el('div', { class: 'zt-after' }, ui.el('h3', { class: 'zt-subhead', text: t(after.basis === 'handoff' ? 'identities.explain.after.handoff' : 'identities.explain.after.sign_in') }),
      ui.el('div', { class: 'zt-explain-head' }, outcomeBadge(cx, after.outcome), ui.el('span', { text: reasonSentence(t, after.reason) }))));
  }
  const trace = ui.el('details', { class: 'zt-trace-box' }, ui.el('summary', { text: t('identities.explain.trace', { count: Array.isArray(answer.trace) ? answer.trace.length : 0 }) }), traceList(cx, answer.trace));
  box.append(trace, facts(cx, [['identities.explain.generation', answer.config_generation], ['identities.explain.profile_revision', answer.service_profile_revision]]));
  return box;
}

/** The test form. `subject` pre-fills the user; the URL state is kept in `params`. */
export function explainPanel(cx, { subject = '', url = '', onRun, embedded = false } = {}) {
  const { t, ui } = cx;
  const form = ui.el('form', { class: 'zt-filters zt-explain-form', attrs: { 'aria-label': t('identities.explain.form') } });
  const urlField = ui.field(t, { label: 'identities.explain.url', name: 'url', value: url, type: 'url', maxLength: 2048, placeholder: 'identities.explain.url.placeholder', help: 'identities.explain.url.help' });
  urlField.querySelector('input').required = true;
  urlField.classList.add('zt-field-wide');
  const subjectField = ui.subjectPicker(t, cx.api, { label: 'identities.explain.subject', name: 'subject', value: subject, help: 'identities.explain.subject.help' });
  const factorsBox = ui.el('fieldset', { class: 'zt-checks' }, ui.el('legend', { text: t('identities.explain.factors') }),
    ...['webauthn', 'totp'].map(factor => ui.el('label', {}, ui.el('input', { type: 'checkbox', name: `factor_${factor}` }), ui.el('span', { text: t(`identities.factor.${factor}`) }))));
  form.append(urlField, subjectField,
    ui.field(t, { label: 'identities.explain.navigation', name: 'navigation', value: 'document', options: [{ value: 'document', label: 'identities.explain.navigation.document' }, { value: 'other', label: 'identities.explain.navigation.other' }] }),
    ui.field(t, { label: 'identities.explain.client_ip', name: 'client_ip', maxLength: 45, help: 'identities.explain.client_ip.help' }),
    ui.field(t, { label: 'identities.explain.aal', name: 'aal', value: '', options: [{ value: '', label: 'identities.explain.aal.default' }, { value: '1', label: 'identities.explain.aal.1' }, { value: '2', label: 'identities.explain.aal.2' }, { value: '3', label: 'identities.explain.aal.3' }] }),
    factorsBox,
    ui.el('div', { class: 'button-row zt-filter-actions' }, ui.el('button', { type: 'submit', class: 'button button-primary', text: t('identities.explain.run') })));
  const output = ui.el('div', { class: 'zt-explain-output', attrs: { 'aria-live': 'polite' } }, ui.el('p', { class: 'kit-muted', text: t('identities.explain.idle') }));
  async function run() {
    const values = form.elements;
    const body = { url: values.url.value.trim(), navigation: values.navigation.value };
    const who = values.subject.value.trim();
    if (who) body.subject = who;
    const ip = values.client_ip.value.trim();
    if (ip) body.client_ip = ip;
    const factors = ['webauthn', 'totp'].filter(factor => values[`factor_${factor}`].checked);
    if (values.aal.value || factors.length) body.hypothetical = { aal: Number(values.aal.value || (factors.length ? 2 : 1)), factors };
    ui.clear(output, ui.loadingState(t));
    try {
      const { data } = await hopae(cx, 'explain/authentication', { json: body });
      if (cx.signal.aborted) return;
      ui.clear(output, explainResult(cx, data || {}));
      onRun?.(body);
    } catch (error) {
      if (error?.status === 401) throw error;
      ui.clear(output, ui.errorState(t, { owner: 'ui.owner.hopae', message: errorText(t, error), retry: run }));
    }
  }
  form.addEventListener('submit', event => { event.preventDefault(); if (form.reportValidity()) run(); });
  const body = ui.el('div', { class: 'zt-explain' }, ui.el('p', { class: 'kit-muted', text: t('identities.explain.intro') }), form, output);
  return { element: embedded ? body : panel(cx, 'identities.explain.title', body), run, form };
}
