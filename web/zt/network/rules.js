// Network ▸ Rules: Sumunjang JSON rules as a structured form or Lua in the
// host CodeMirror editor; validate with Sumunjang, structured diff against
// the published rules, what-if on the tracked traffic sample, publish with a
// reason. Sumunjang's rule replacement has no revision precondition, so the
// console re-reads the published rules right before publishing and refuses
// when they changed (the draft is kept).
import { can, guard, sectionPage, capabilities, notConnected, modeBanner, panel, button, formDialog, outcomeBanner, errorText, fieldErrors, failure, isCidr } from './common.js';
import { changeList, loadDraft, saveDraft, dropDraft, trafficSample, whatIf } from './diff.js';
import { createLuaEditor } from '../../lua-editor.js';

const ACTIONS = Object.freeze(['deny', 'allow', 'observe']);
const LUA_TEMPLATE = 'local rules = {}\nreturn { version = 1, rules = rules }\n';

function localDateTime(seconds) {
  if (!Number.isFinite(seconds)) return '';
  const date = new Date(seconds * 1000), pad = value => String(value).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

/** Display projection of a rule set for the change list. */
export function ruleEntities(cx, set) {
  const { t } = cx;
  const out = {};
  for (const rule of set?.rules || []) {
    out[rule.id] = {
      'network.rule.field.action': t(`network.rule.action.${ACTIONS.includes(rule.action) ? rule.action : 'observe'}`),
      'network.rule.field.priority': String(rule.priority ?? 0),
      'network.rule.field.network': rule.network || t('network.rule.any'),
      'network.rule.field.countries': (rule.countries || []).join(', ') || t('network.rule.any'),
      'network.rule.field.asns': (rule.asns || []).join(', ') || t('network.rule.any'),
      'network.rule.field.score': String(rule.score ?? 0),
      'network.rule.field.expires': rule.expires_at ? new Date(rule.expires_at * 1000).toISOString().slice(0, 16).replace('T', ' ') : t('network.expiry.never'),
      'network.rule.field.description': rule.description || '—',
    };
  }
  return out;
}

function normalize(rule) {
  const out = { id: rule.id, priority: Number(rule.priority) || 0, action: rule.action, score: Number(rule.score) || 0 };
  if (rule.network) out.network = rule.network;
  if (rule.countries?.length) out.countries = rule.countries;
  if (rule.asns?.length) out.asns = rule.asns;
  if (rule.expires_at) out.expires_at = rule.expires_at;
  if (rule.description) out.description = rule.description;
  return out;
}

function ruleRow(cx, rule, index, { readOnly, highlight, onChange, onRemove }) {
  const { t, ui } = cx;
  const row = ui.el('tr', { class: `zt-rule${highlight ? ' is-highlighted' : ''}`, dataset: { rule: rule.id || '' } });
  const input = (name, value, label, extra = {}) => { const node = ui.el('input', { name, value: value ?? '', disabled: readOnly, spellcheck: false, autocomplete: 'off', ...extra }); node.setAttribute('aria-label', t(label)); return ui.el('td', { dataset: { label: t(label) } }, node); };
  const action = ui.el('select', { name: 'action', disabled: readOnly }, ACTIONS.map(value => ui.el('option', { value, text: t(`network.rule.action.${value}`), selected: rule.action === value })));
  action.setAttribute('aria-label', t('network.rule.field.action'));
  row.append(
    input('id', rule.id, 'network.rule.field.id', { required: true, maxLength: 64, pattern: '[\\x21-\\x7e]{1,64}' }),
    input('priority', rule.priority ?? 0, 'network.rule.field.priority', { type: 'number', min: -2147483648, max: 2147483647, step: 1 }),
    ui.el('td', { dataset: { label: t('network.rule.field.action') } }, action),
    input('network', rule.network, 'network.rule.field.network', { maxLength: 64, placeholder: t('network.rule.any') }),
    input('countries', (rule.countries || []).join(', '), 'network.rule.field.countries', { maxLength: 1024, pattern: '\\s*([A-Za-z]{2}\\s*(,\\s*[A-Za-z]{2}\\s*)*)?', placeholder: t('network.rule.any') }),
    input('asns', (rule.asns || []).join(', '), 'network.rule.field.asns', { maxLength: 2048, pattern: '\\s*(\\d{1,10}\\s*(,\\s*\\d{1,10}\\s*)*)?', placeholder: t('network.rule.any') }),
    input('score', rule.score ?? 0, 'network.rule.field.score', { type: 'number', min: 0, max: 1000000, step: 1 }),
    input('expires', localDateTime(rule.expires_at), 'network.rule.field.expires', { type: 'datetime-local' }),
    input('description', rule.description, 'network.rule.field.description', { maxLength: 256 }),
    ui.el('td', { dataset: { label: t('network.col.actions') } }, readOnly ? null : ui.el('button', { type: 'button', class: 'button button-quiet', text: t('network.rule.remove'), on: { click: onRemove } })));
  const networkInput = row.querySelector('[name=network]');
  const emit = () => {
    const value = name => row.querySelector(`[name=${name}]`).value.trim();
    networkInput.setCustomValidity(!value('network') || isCidr(value('network')) || /^[0-9a-f:.]+$/i.test(value('network')) ? '' : t('network.block.network.invalid'));
    const expires = value('expires');
    onChange(normalize({ id: value('id'), priority: value('priority'), action: action.value, network: value('network'), countries: value('countries').split(',').map(part => part.trim().toUpperCase()).filter(Boolean), asns: value('asns').split(',').map(part => Number(part.trim())).filter(Number.isFinite).filter(n => n > 0), score: value('score'), expires_at: expires ? Math.floor(new Date(expires).getTime() / 1000) : null, description: value('description') }));
  };
  row.addEventListener('input', emit); row.addEventListener('change', emit);
  return row;
}

export async function renderRules(cx, root, parts, params) {
  const { t, ui } = cx;
  const caps = await capabilities(cx);
  if (cx.signal.aborted) return;
  const lua = parts[0] === 'lua';
  const { content } = sectionPage(cx, root, { active: 'rules', crumbs: lua ? [{ label: t('network.page.rules'), href: '#network/rules' }, { label: t('network.rules.tab.lua') }] : [], title: t('network.page.rules'), owner: t('network.rules.owner') });
  if (!caps.installed || !can(caps, 'rules')) { content.append(notConnected(cx, caps, 'rules')); return; }
  const status = ui.el('div', { class: 'zt-notes' });
  const holder = ui.el('div', { class: 'zt-content' }, ui.loadingState(t));
  content.append(ui.el('nav', { class: 'zt-tabs', attrs: { 'aria-label': t('network.rules.tabs') } }, ['json', 'lua'].map(name => ui.el('a', { href: name === 'json' ? '#network/rules' : '#network/rules/lua', text: t(`network.rules.tab.${name}`), attrs: { 'aria-current': (name === 'lua') === lua ? 'page' : false } }))), status, holder);
  let published, policy = null;
  try {
    [published, policy] = await Promise.all([guard(cx, 'rules').then(answer => answer.data || { version: 1, rules: [] }), guard(cx, 'policy/document').then(answer => answer.data?.policy).catch(error => { if (error?.status === 401) throw error; return null; })]);
  } catch (error) { ui.clear(holder, failure(cx, error, () => cx.navigate(`#network/rules?retry=${Date.now()}`))); return; }
  if (cx.signal.aborted) return;
  const base = JSON.stringify(published);
  const draftName = lua ? 'rules-lua' : 'rules';
  const stored = loadDraft(draftName);
  let draft = lua ? { script: LUA_TEMPLATE } : structuredClone({ version: published.version || 1, rules: (published.rules || []).map(normalize) });
  if (stored?.base === base && stored.draft) { draft = stored.draft; status.append(ui.el('p', { class: 'zt-banner', attrs: { role: 'status' } }, ui.el('span', { text: t('network.draft.restored') }), ' ', button(cx, 'network.draft.discard', () => { dropDraft(draftName); cx.navigate(`${location.hash.split('?')[0]}?fresh=${Date.now()}`); }))); }
  else if (stored && stored.base !== base) status.append(ui.el('p', { class: 'zt-banner zt-banner-warn', attrs: { role: 'alert' } }, ui.el('span', { text: t('network.draft.stale') }), ' ', button(cx, 'network.draft.keep', () => { saveDraft(draftName, base, stored.draft); cx.navigate(`${location.hash.split('?')[0]}?rebased=${Date.now()}`); }), ' ', button(cx, 'network.draft.discard', () => { dropDraft(draftName); cx.navigate(`${location.hash.split('?')[0]}?fresh=${Date.now()}`); })));
  const canPublish = can(caps, lua ? 'rules/lua' : 'rules', 'PUT');
  const canValidate = can(caps, 'rules/validate');
  const counter = ui.el('span', { class: 'zt-change-count', attrs: { 'aria-live': 'polite' } });
  const validation = ui.el('div', { class: 'zt-validation', attrs: { 'aria-live': 'polite' } });
  const diffBox = ui.el('div');
  const impactBox = ui.el('div', {}, ui.el('p', { class: 'kit-muted', text: t('network.whatif.idle') }));
  let compiled = lua ? null : draft;
  const publishButton = ui.el('button', { type: 'button', class: 'button button-primary', text: t('network.publish.review'), disabled: true });
  const changed = () => {
    if (!lua) compiled = draft;
    const diff = compiled ? changeList(cx, ruleEntities(cx, published), ruleEntities(cx, compiled)) : { element: ui.el('p', { class: 'kit-muted', text: t('network.rules.lua.validate_first') }), count: lua ? (draft.script.trim() ? 1 : 0) : 0 };
    counter.textContent = t('network.publish.changes', { count: diff.count });
    publishButton.disabled = !canPublish || !diff.count;
    ui.clear(diffBox, diff.element);
    if (lua ? draft.script !== LUA_TEMPLATE : diff.count) saveDraft(draftName, base, draft); else dropDraft(draftName);
    return diff;
  };
  const candidate = () => (lua ? { script: draft.script } : { rules: draft });
  async function validate() {
    ui.clear(validation, ui.loadingState(t));
    try {
      const { data } = await guard(cx, 'rules/validate', { json: lua ? { script: draft.script } : { rules: draft } });
      compiled = data?.rules || compiled;
      ui.clear(validation, outcomeBanner(cx, 'committed', 'network.rules.valid', { count: data?.rules?.rules?.length ?? 0 }));
      changed();
      return true;
    } catch (error) {
      if (error?.status === 401) throw error;
      ui.clear(validation, outcomeBanner(cx, 'refused', 'network.literal', { value: error?.payload?.error && !error.payload.errors ? String(error.payload.error) : errorText(t, error) }), fieldErrors(cx, error));
      return false;
    }
  }
  async function impact() {
    ui.clear(impactBox, ui.loadingState(t));
    try { const sample = await trafficSample(cx); ui.clear(impactBox, await whatIf(cx, candidate(), sample)); }
    catch (error) { if (error?.status === 401) throw error; ui.clear(impactBox, outcomeBanner(cx, 'refused', 'network.literal', { value: errorText(t, error) }), fieldErrors(cx, error)); }
  }
  // Editor body.
  let editorNode, luaEditor = null;
  const form = ui.el('form', { class: 'zt-editor', attrs: { 'aria-label': t('network.rules.editor') } });
  form.addEventListener('submit', event => event.preventDefault());
  if (lua) {
    const id = `zt-lua-${Math.random().toString(36).slice(2, 6)}`;
    const area = ui.el('textarea', { id, name: 'script', rows: 16, value: draft.script, spellcheck: false, disabled: !canPublish && !canValidate, class: 'kit-mono zt-lua' });
    area.addEventListener('input', () => { draft.script = area.value; compiled = null; ui.clear(validation); changed(); });
    editorNode = ui.el('label', { class: 'kit-field zt-field-wide', htmlFor: id }, ui.el('span', { class: 'kit-field-label', text: t('network.rules.lua.label') }), area, ui.el('small', { class: 'kit-help', text: t('network.rules.lua.help') }));
    form.append(ui.el('p', { class: 'zt-banner', attrs: { role: 'note' }, text: t('network.gap.lua_source') }), editorNode);
    queueMicrotask(() => { try { luaEditor = createLuaEditor(area, { context: 'body', label: t('network.rules.lua.label') }); } catch { luaEditor = null; } });
    cx.signal.addEventListener('abort', () => luaEditor?.destroy(), { once: true });
  } else {
    const tbody = ui.el('tbody');
    const highlight = params.get('rule');
    const renderRows = () => {
      ui.clear(tbody, draft.rules.map((rule, index) => ruleRow(cx, rule, index, { readOnly: !canPublish, highlight: highlight && rule.id === highlight, onChange: next => { draft.rules[index] = next; changed(); }, onRemove: () => { draft.rules.splice(index, 1); renderRows(); changed(); } })));
      if (!draft.rules.length) tbody.append(ui.el('tr', {}, ui.el('td', { colSpan: 10 }, ui.emptyState(t, { title: 'network.rules.empty', body: 'network.rules.empty.body' }))));
    };
    renderRows();
    const table = ui.el('table', { class: 'zt-keys zt-rules-table' }, ui.el('caption', { class: 'kit-visually-hidden', text: t('network.rules.editor') }),
      ui.el('thead', {}, ui.el('tr', {}, ['id', 'priority', 'action', 'network', 'countries', 'asns', 'score', 'expires', 'description'].map(key => ui.el('th', { scope: 'col', text: t(`network.rule.field.${key}`) })), ui.el('th', { scope: 'col', text: t('network.col.actions') }))), tbody);
    form.append(ui.el('div', { class: 'zt-table-scroll' }, table), canPublish ? button(cx, 'network.rule.add', () => { draft.rules.push({ id: '', priority: 0, action: 'deny', score: 0 }); renderRows(); changed(); tbody.lastElementChild?.querySelector('input')?.focus(); }) : null,
      ui.el('p', { class: 'kit-help', text: t('network.rules.precedence') }));
    if (highlight) queueMicrotask(() => tbody.querySelector('.is-highlighted')?.scrollIntoView({ block: 'center' }));
  }
  publishButton.addEventListener('click', async () => {
    if (!form.reportValidity()) return;
    if (!(await validate())) return;
    const diff = changed();
    const sampleBox = ui.el('div', {}, ui.loadingState(t));
    trafficSample(cx).then(sample => whatIf(cx, candidate(), sample)).then(node => ui.clear(sampleBox, node)).catch(error => { if (error?.status === 401) throw error; ui.clear(sampleBox, ui.el('p', { class: 'kit-muted', text: errorText(t, error) })); });
    const result = await formDialog(cx, {
      title: 'network.publish.title', intro: t(policy?.mode === 'observe' ? 'network.rules.publish.observe' : 'network.rules.publish.enforce'),
      body: ui.el('div', { class: 'zt-review' }, ui.el('h3', { class: 'zt-subhead', text: t('network.publish.changes', { count: diff.count }) }), changeList(cx, ruleEntities(cx, published), ruleEntities(cx, compiled)).element, ui.el('h3', { class: 'zt-subhead', text: t('network.whatif.title') }), sampleBox),
      confirm: t('network.rules.confirm_target'), confirmLabel: 'network.publish.confirm', danger: true,
      submit: async values => {
        // Revision guard: Sumunjang's PUT has no precondition, so compare with a fresh read.
        const current = (await guard(cx, 'rules')).data;
        if (JSON.stringify(current) !== base) throw Object.assign(new Error('conflict'), { status: 409, payload: { error: 'rules changed since loaded' } });
        return lua ? guard(cx, 'rules/lua', { method: 'PUT', json: { script: draft.script }, reason: values.reason }) : guard(cx, 'rules', { method: 'PUT', json: draft, reason: values.reason });
      },
    });
    if (!result) return;
    dropDraft(draftName);
    ui.clear(status, outcomeBanner(cx, 'committed', 'network.rules.published', { count: result.data?.rules?.length ?? 0, operation: result.operation || '—' }));
    setTimeout(() => cx.navigate(`${location.hash.split('?')[0]}?published=${Date.now()}`), 1200);
  });
  const toolbar = ui.el('div', { class: 'zt-editor-bar' }, counter, ui.el('div', { class: 'button-row' },
    canValidate ? button(cx, 'network.rules.validate', () => { if (form.reportValidity()) validate(); }) : ui.disabledAction(t, 'network.rules.validate', 'network.gap.not_declared'),
    can(caps, 'explain/batch') ? button(cx, 'network.whatif.run', () => { if (form.reportValidity()) impact(); }) : ui.disabledAction(t, 'network.whatif.run', 'network.gap.not_declared'),
    canPublish ? publishButton : ui.disabledAction(t, 'network.publish.review', 'network.gap.not_declared')));
  ui.clear(holder, policy ? modeBanner(cx, policy) : null, toolbar, validation, form, ui.el('div', { class: 'zt-grid' }, panel(cx, 'network.publish.preview', diffBox), panel(cx, 'network.whatif.title', impactBox)));
  changed();
}
