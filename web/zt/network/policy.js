// Network ▸ Policy: mode, automatic blocking, window, threshold, block
// lifetime and signal weights as a form; structured diff, what-if on the
// tracked sample and CAS publish (`expected_revision`) with a reason.
// Switching to enforce requires typing the new mode.
import { can, guard, sectionPage, capabilities, notConnected, modeBanner, panel, button, formDialog, outcomeBanner, errorText, failure, number } from './common.js';
import { changeList, loadDraft, saveDraft, dropDraft, trafficSample, whatIf } from './diff.js';

const SIGNALS = Object.freeze(['honeypot', 'scanner', 'auth_failure', 'invalid_request']);
const NUMBERS = Object.freeze([['window_secs', 1, 86400], ['threshold', 1, 1000000], ['block_ttl_secs', 1, 2592000]]);

export function policyEntities(cx, policy) {
  const { t } = cx;
  if (!policy) return {};
  return {
    [t('network.policy.entity.decision')]: {
      'network.policy.field.mode': t(`network.mode.${policy.mode === 'enforce' ? 'enforce' : 'observe'}`),
      'network.policy.field.auto_block': t(policy.auto_block ? 'network.yes' : 'network.no'),
      'network.policy.field.window_secs': t('network.seconds', { count: policy.window_secs }),
      'network.policy.field.threshold': number(policy.threshold),
      'network.policy.field.block_ttl_secs': t('network.seconds', { count: policy.block_ttl_secs }),
    },
    [t('network.policy.entity.weights')]: Object.fromEntries(SIGNALS.map(signal => [`network.signal.${signal}`, number(policy.weights?.[signal] ?? 0)])),
    [t('network.policy.entity.allowlist')]: { 'network.policy.field.allow': t('network.policy.allow_count', { count: (policy.allow || []).length }) },
  };
}

export async function renderPolicy(cx, root) {
  const { t, ui } = cx;
  const caps = await capabilities(cx);
  if (cx.signal.aborted) return;
  const { content } = sectionPage(cx, root, { active: 'policy', title: t('network.page.policy'), owner: t('network.policy.owner') });
  if (!caps.installed || !can(caps, 'policy/document')) { content.append(notConnected(cx, caps, 'policy/document')); return; }
  const status = ui.el('div', { class: 'zt-notes' });
  const holder = ui.el('div', { class: 'zt-content' }, ui.loadingState(t));
  content.append(status, holder);
  let document;
  try { document = (await guard(cx, 'policy/document')).data; }
  catch (error) { ui.clear(holder, failure(cx, error, () => cx.navigate(`#network/policy?retry=${Date.now()}`))); return; }
  if (cx.signal.aborted) return;
  const published = document.policy;
  const stored = loadDraft('policy');
  let draft = structuredClone(published);
  if (stored?.base === document.revision && stored.draft) { draft = stored.draft; status.append(ui.el('p', { class: 'zt-banner', attrs: { role: 'status' } }, ui.el('span', { text: t('network.draft.restored') }), ' ', button(cx, 'network.draft.discard', () => { dropDraft('policy'); cx.navigate(`#network/policy?fresh=${Date.now()}`); }))); }
  else if (stored && stored.base !== document.revision) status.append(ui.el('p', { class: 'zt-banner zt-banner-warn', attrs: { role: 'alert' } }, ui.el('span', { text: t('network.draft.stale') }), ' ', button(cx, 'network.draft.keep', () => { saveDraft('policy', document.revision, { ...stored.draft, allow: published.allow }); cx.navigate(`#network/policy?rebased=${Date.now()}`); }), ' ', button(cx, 'network.draft.discard', () => { dropDraft('policy'); cx.navigate(`#network/policy?fresh=${Date.now()}`); })));
  const canPublish = can(caps, 'policy/document', 'PUT');
  const form = ui.el('form', { class: 'zt-editor zt-policy-form', attrs: { 'aria-label': t('network.policy.editor') } });
  form.addEventListener('submit', event => event.preventDefault());
  // Mode as a radio group with the consequence of each choice.
  const modes = ui.el('fieldset', { class: 'zt-mode-choice' }, ui.el('legend', { text: t('network.policy.field.mode') }),
    ['observe', 'enforce'].map(mode => ui.el('label', { class: 'zt-choice' }, ui.el('input', { type: 'radio', name: 'mode', value: mode, checked: draft.mode === mode, disabled: !canPublish }), ui.el('span', { class: 'zt-stack' }, ui.el('strong', { text: t(`network.mode.${mode}`) }), ui.el('span', { class: 'kit-muted', text: t(`network.mode.${mode}.body`) })))));
  const autoId = `zt-auto-${Math.random().toString(36).slice(2, 6)}`;
  const auto = ui.el('label', { class: 'zt-check', htmlFor: autoId }, ui.el('input', { type: 'checkbox', id: autoId, name: 'auto_block', checked: Boolean(draft.auto_block), disabled: !canPublish }), ui.el('span', { class: 'zt-stack' }, ui.el('strong', { text: t('network.policy.field.auto_block') }), ui.el('small', { class: 'kit-help', text: t('network.policy.help.auto_block') })));
  const numbers = ui.el('div', { class: 'zt-form-grid' }, NUMBERS.map(([name, min, max]) => { const node = ui.field(t, { label: `network.policy.field.${name}`, name, value: String(draft[name] ?? ''), type: 'number', help: `network.policy.help.${name}` }); const input = node.querySelector('input'); input.min = min; input.max = max; input.step = 1; input.required = true; input.disabled = !canPublish; return node; }));
  const weights = ui.el('fieldset', { class: 'zt-form-grid zt-weights' }, ui.el('legend', { text: t('network.policy.entity.weights') }), SIGNALS.map(signal => { const node = ui.field(t, { label: `network.signal.${signal}`, name: `weight_${signal}`, value: String(draft.weights?.[signal] ?? 0), type: 'number', help: `network.signal.${signal}.help` }); const input = node.querySelector('input'); input.min = 0; input.max = 1000000; input.step = 1; input.required = true; input.disabled = !canPublish; return node; }));
  form.append(modes, auto, numbers, weights, ui.el('p', { class: 'kit-help' }, ui.el('span', { text: t('network.policy.allow_note', { count: (draft.allow || []).length }) }), ' ', ui.el('a', { href: '#network/blocks/allowlist', text: t('network.blocks.tab.allowlist') })));
  const counter = ui.el('span', { class: 'zt-change-count', attrs: { 'aria-live': 'polite' } });
  const diffBox = ui.el('div');
  const impactBox = ui.el('div', {}, ui.el('p', { class: 'kit-muted', text: t('network.whatif.idle') }));
  const publishButton = ui.el('button', { type: 'button', class: 'button button-primary', text: t('network.publish.review'), disabled: true });
  const read = () => {
    const value = name => form.elements[name];
    draft = { ...draft, mode: form.querySelector('input[name=mode]:checked')?.value || draft.mode, auto_block: value('auto_block').checked,
      ...Object.fromEntries(NUMBERS.map(([name]) => [name, Number(value(name).value)])),
      weights: Object.fromEntries(SIGNALS.map(signal => [signal, Number(value(`weight_${signal}`).value)])) };
  };
  const changed = () => {
    read();
    const diff = changeList(cx, policyEntities(cx, published), policyEntities(cx, draft));
    counter.textContent = t('network.publish.changes', { count: diff.count });
    publishButton.disabled = !canPublish || !diff.count;
    ui.clear(diffBox, diff.element);
    if (diff.count) saveDraft('policy', document.revision, draft); else dropDraft('policy');
    return diff;
  };
  form.addEventListener('input', changed); form.addEventListener('change', changed);
  const impact = async () => {
    ui.clear(impactBox, ui.loadingState(t));
    try { ui.clear(impactBox, await whatIf(cx, { policy: draft }, await trafficSample(cx))); }
    catch (error) { if (error?.status === 401) throw error; ui.clear(impactBox, outcomeBanner(cx, 'refused', 'network.literal', { value: errorText(t, error) })); }
  };
  publishButton.addEventListener('click', async () => {
    if (!form.reportValidity()) return;
    const diff = changed();
    const toEnforce = published.mode !== 'enforce' && draft.mode === 'enforce';
    const sampleBox = ui.el('div', {}, ui.loadingState(t));
    trafficSample(cx).then(sample => whatIf(cx, { policy: draft }, sample)).then(node => ui.clear(sampleBox, node)).catch(error => { if (error?.status === 401) throw error; ui.clear(sampleBox, ui.el('p', { class: 'kit-muted', text: errorText(t, error) })); });
    const result = await formDialog(cx, {
      title: 'network.publish.title', intro: t(toEnforce ? 'network.policy.publish.enforce' : 'network.policy.publish.body', { revision: document.revision }),
      body: ui.el('div', { class: 'zt-review' }, ui.el('h3', { class: 'zt-subhead', text: t('network.publish.changes', { count: diff.count }) }), changeList(cx, policyEntities(cx, published), policyEntities(cx, draft)).element, ui.el('h3', { class: 'zt-subhead', text: t('network.whatif.title') }), sampleBox),
      confirm: toEnforce ? t('network.mode.enforce') : t('network.policy.confirm_target'), confirmLabel: 'network.publish.confirm', danger: true,
      submit: values => guard(cx, 'policy/document', { method: 'PUT', json: { expected_revision: document.revision, policy: draft, reason: values.reason }, reason: values.reason }),
    });
    if (!result) return;
    dropDraft('policy');
    ui.clear(status, outcomeBanner(cx, 'committed', 'network.policy.published', { operation: result.operation || '—' }));
    setTimeout(() => cx.navigate(`#network/policy?published=${Date.now()}`), 1200);
  });
  const toolbar = ui.el('div', { class: 'zt-editor-bar' }, counter, ui.el('div', { class: 'button-row' },
    can(caps, 'explain/batch') ? button(cx, 'network.whatif.run', () => { if (form.reportValidity()) impact(); }) : ui.disabledAction(t, 'network.whatif.run', 'network.gap.not_declared'),
    canPublish ? publishButton : ui.disabledAction(t, 'network.publish.review', 'network.gap.not_declared')));
  ui.clear(holder, modeBanner(cx, published), ui.el('p', { class: 'kit-muted', text: t('ui.revision', { revision: document.revision }) }), toolbar, form, ui.el('div', { class: 'zt-grid' }, panel(cx, 'network.publish.preview', diffBox), panel(cx, 'network.whatif.title', impactBox)));
  changed();
}
