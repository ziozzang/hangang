// Identities ▸ Authentication: service authentication profiles as a form
// (Hopae `authentication/profiles`, CAS publish with a reason) and the
// "test access as a user" panel (`explain/authentication`).
import { can, hopae, failure, sectionPage, notConnected, capabilities, panel, outcomeBanner, button, errorText } from './common.js';
import { changeList, loadDraft, saveDraft, dropDraft, publish } from './editor.js';
import { explainPanel } from './explain.js';

const DRAFT = 'profiles';
const IDENT = '[A-Za-z0-9_.\\-]{1,128}';

function tabs(cx, active) {
  const { t, ui } = cx;
  return ui.el('nav', { class: 'zt-tabs', attrs: { 'aria-label': t('identities.auth.tabs') } },
    ['profiles', 'test'].map(name => ui.el('a', { href: name === 'profiles' ? '#identities/authentication' : '#identities/authentication/test', text: t(`identities.auth.tab.${name}`), attrs: { 'aria-current': name === active ? 'page' : false } })));
}

function fnv(text) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < text.length; index += 1) { hash ^= text.charCodeAt(index); hash = Math.imul(hash, 0x01000193) >>> 0; }
  return hash.toString(16).padStart(8, '0');
}

/** Display projection of a profile document for the change list. */
export function profileEntities(cx, config) {
  const { t } = cx;
  const out = {};
  if (!config) return out;
  out[t('identities.profile.authority')] = { 'identities.profile.field.authority_id': config.authority_id || '' };
  for (const profile of config.profiles || []) {
    const name = `${profile.service_id} · ${profile.host}`;
    const fields = {
      'identities.profile.field.ports': (profile.ports || []).join(', '),
      'identities.profile.field.realm': profile.realm || '',
      'identities.profile.field.networks': (profile.networks || []).join(', ') || t('identities.profile.networks.any'),
      'identities.profile.field.session_fallback': t(profile.session_fallback ? 'identities.yes' : 'identities.no'),
    };
    if (profile.relay_token_prefix) fields['identities.profile.field.relay_token_prefix'] = profile.relay_token_prefix;
    if (profile.eligibility_lua) fields['identities.profile.field.eligibility_lua'] = t('identities.profile.lua.summary', { count: profile.eligibility_lua.split('\n').length, digest: fnv(profile.eligibility_lua) });
    for (const [key, label] of [['api_relay', 'identities.profile.connector.api_relay'], ['kubernetes_tokenreview', 'identities.profile.connector.kubernetes'], ['composition', 'identities.profile.connector.composition']]) {
      if (profile[key]) fields[label] = t('identities.profile.connector.digest', { digest: fnv(JSON.stringify(profile[key])) });
    }
    out[name] = fields;
    for (const key of profile.api_keys || []) {
      out[`${name} › ${key.subject}`] = { 'identities.profile.field.token_env': key.token_env, 'identities.profile.field.expires': key.expires_at ? new Date(key.expires_at).toISOString().slice(0, 16).replace('T', ' ') : t('identities.profile.expires.never') };
    }
  }
  return out;
}

function blankProfile() { return { service_id: '', host: '', ports: [443], realm: '', api_keys: [], networks: [], session_fallback: false }; }

function localDateTime(ms) {
  if (!Number.isFinite(ms)) return '';
  const date = new Date(ms);
  const pad = value => String(value).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

/** Form for one profile; `onChange` receives the updated object. Connectors are preserved as is. */
function profileForm(cx, profile, index, { onChange, onRemove, readOnly }) {
  const { t, ui } = cx;
  const box = ui.el('details', { class: 'zt-profile', open: true, dataset: { index: String(index) } });
  const title = ui.el('span', { text: profile.service_id ? `${profile.service_id} · ${profile.host}` : t('identities.profile.new') });
  box.append(ui.el('summary', {}, title, profile.api_keys?.length ? ui.el('span', { class: 'kit-tag', text: t('identities.profile.keys', { count: profile.api_keys.length }) }) : null));
  const form = ui.el('div', { class: 'zt-form-grid' });
  const text = (label, name, value, extra = {}) => { const node = ui.field(t, { label, name, value: value ?? '', ...extra }); node.querySelector('input,select').disabled = readOnly; return node; };
  form.append(
    text('identities.profile.field.service_id', 'service_id', profile.service_id, { pattern: IDENT, help: 'identities.profile.help.service_id' }),
    text('identities.profile.field.host', 'host', profile.host, { pattern: '[A-Za-z0-9.\\-]{1,253}', help: 'identities.profile.help.host' }),
    text('identities.profile.field.ports', 'ports', (profile.ports || []).join(', '), { pattern: '\\s*\\d{1,5}(\\s*,\\s*\\d{1,5})*\\s*', help: 'identities.profile.help.ports' }),
    text('identities.profile.field.realm', 'realm', profile.realm, { pattern: IDENT, help: 'identities.profile.help.realm' }),
    text('identities.profile.field.relay_token_prefix', 'relay_token_prefix', profile.relay_token_prefix, { help: 'identities.profile.help.relay_token_prefix' }));
  const fallbackId = `zt-fallback-${index}-${Math.random().toString(36).slice(2, 6)}`;
  const fallback = ui.el('input', { type: 'checkbox', id: fallbackId, name: 'session_fallback', checked: Boolean(profile.session_fallback), disabled: readOnly });
  form.append(ui.el('label', { class: 'zt-check', htmlFor: fallbackId }, fallback, ui.el('span', { class: 'zt-stack' }, ui.el('strong', { text: t('identities.profile.field.session_fallback') }), ui.el('small', { class: 'kit-help', text: t('identities.profile.help.session_fallback') }))));
  const networksId = `zt-networks-${index}-${Math.random().toString(36).slice(2, 6)}`;
  const networks = ui.el('textarea', { id: networksId, name: 'networks', rows: 2, value: (profile.networks || []).join('\n'), disabled: readOnly, spellcheck: false });
  networks.setAttribute('aria-describedby', `${networksId}-help`);
  form.append(ui.el('label', { class: 'kit-field zt-field-wide', htmlFor: networksId }, ui.el('span', { class: 'kit-field-label', text: t('identities.profile.field.networks') }), networks, ui.el('small', { class: 'kit-help', id: `${networksId}-help`, text: t('identities.profile.help.networks') })));
  const luaId = `zt-lua-${index}-${Math.random().toString(36).slice(2, 6)}`;
  const lua = ui.el('textarea', { id: luaId, name: 'eligibility_lua', rows: 4, value: profile.eligibility_lua || '', disabled: readOnly, spellcheck: false, class: 'kit-mono' });
  form.append(ui.el('label', { class: 'kit-field zt-field-wide', htmlFor: luaId }, ui.el('span', { class: 'kit-field-label', text: t('identities.profile.field.eligibility_lua') }), lua, ui.el('small', { class: 'kit-help', text: t('identities.profile.help.eligibility_lua') })));
  // API keys: subject, environment reference and expiry.
  const keys = ui.el('table', { class: 'zt-keys' }, ui.el('caption', { class: 'kit-visually-hidden', text: t('identities.profile.keys.caption') }),
    ui.el('thead', {}, ui.el('tr', {}, ['identities.profile.field.subject', 'identities.profile.field.token_env', 'identities.profile.field.expires', 'identities.session.col.actions'].map(key => ui.el('th', { scope: 'col', text: t(key) })))));
  const keyBody = ui.el('tbody');
  const keyRow = key => {
    const row = ui.el('tr', { class: 'zt-key' });
    const cell = (name, value, extra) => { const input = ui.el('input', { name, value: value ?? '', disabled: readOnly, spellcheck: false, autocomplete: 'off', ...extra }); input.setAttribute('aria-label', t(`identities.profile.field.${name === 'key_subject' ? 'subject' : name === 'key_env' ? 'token_env' : 'expires'}`)); return ui.el('td', {}, input); };
    row.append(cell('key_subject', key.subject, { maxLength: 128 }), cell('key_env', key.token_env, { maxLength: 128, pattern: '[A-Z_][A-Z0-9_]{0,127}' }), cell('key_expires', localDateTime(key.expires_at), { type: 'datetime-local' }),
      ui.el('td', {}, readOnly ? null : ui.el('button', { type: 'button', class: 'button button-quiet', text: t('identities.profile.key.remove'), on: { click: () => { row.remove(); emit(); } } })));
    keyBody.append(row);
  };
  (profile.api_keys || []).forEach(keyRow);
  keys.append(keyBody);
  const keysBox = ui.el('div', { class: 'zt-field-wide zt-keys-box' }, ui.el('h3', { class: 'zt-subhead', text: t('identities.profile.keys.title') }), ui.el('p', { class: 'kit-help', text: t('identities.profile.help.keys') }), keys,
    readOnly ? null : ui.el('button', { type: 'button', class: 'button button-quiet', text: t('identities.profile.key.add'), on: { click: () => { keyRow({ subject: '', token_env: '' }); } } }));
  form.append(keysBox);
  const connectors = [['api_relay', 'identities.profile.connector.api_relay'], ['kubernetes_tokenreview', 'identities.profile.connector.kubernetes'], ['composition', 'identities.profile.connector.composition']].filter(([key]) => profile[key]);
  if (connectors.length) form.append(ui.el('div', { class: 'zt-field-wide zt-connectors' }, ui.el('h3', { class: 'zt-subhead', text: t('identities.profile.connectors') }), ui.el('ul', {}, connectors.map(([, label]) => ui.el('li', {}, ui.el('strong', { text: t(label) }), ' ', ui.el('span', { class: 'kit-muted', text: t('identities.profile.connector.preserved') }))))));
  if (!readOnly) form.append(ui.el('div', { class: 'button-row zt-field-wide' }, ui.el('button', { type: 'button', class: 'button button-quiet button-danger-quiet', text: t('identities.profile.remove'), on: { click: onRemove } })));
  box.append(form);
  function emit() {
    const value = name => box.querySelector(`[name="${name}"]`)?.value.trim() ?? '';
    const next = { ...profile };
    next.service_id = value('service_id'); next.host = value('host'); next.realm = value('realm');
    next.ports = value('ports').split(',').map(part => Number(part.trim())).filter(port => Number.isInteger(port) && port > 0 && port < 65536);
    next.networks = networks.value.split(/[\n,]/).map(part => part.trim()).filter(Boolean);
    next.session_fallback = fallback.checked;
    const prefix = value('relay_token_prefix');
    if (prefix) next.relay_token_prefix = prefix; else delete next.relay_token_prefix;
    if (lua.value.trim()) next.eligibility_lua = lua.value; else delete next.eligibility_lua;
    next.api_keys = [...keyBody.querySelectorAll('tr')].map(row => {
      const subject = row.querySelector('[name=key_subject]').value.trim(), env = row.querySelector('[name=key_env]').value.trim(), expires = row.querySelector('[name=key_expires]').value;
      const key = { token_env: env, subject };
      key.expires_at = expires ? new Date(expires).getTime() : null;
      return key;
    }).filter(key => key.subject || key.token_env);
    title.textContent = next.service_id ? `${next.service_id} · ${next.host}` : t('identities.profile.new');
    onChange(next);
  }
  box.addEventListener('input', emit);
  box.addEventListener('change', emit);
  return box;
}

const VALIDATION_CODES = Object.freeze(['invalid_document', 'undeclared_reference', 'invalid_profile', 'configuration_rule', 'invalid_configuration', 'compile_failed']);
const FIELD_NAMES = Object.freeze({ token_env: 'key_env', subject: 'key_subject', expires_at: 'key_expires' });

/**
 * Inline findings from `authentication/profiles/validate`: paths such as
 * `profiles[0].ports[1]` or `profiles[1].api_keys[0].token_env` mark the
 * field in the form; every finding is also listed with its path.
 */
function showFindings(cx, editor, box, errors) {
  const { t, ui } = cx;
  editor.querySelectorAll('[aria-invalid="true"]').forEach(node => { node.removeAttribute('aria-invalid'); node.closest('.kit-field, td')?.querySelector('.zt-field-error')?.remove(); });
  const items = errors.map(error => {
    const code = VALIDATION_CODES.includes(error.code) ? error.code : 'other';
    const path = String(error.path ?? '');
    const match = /^profiles\[(\d+)\](?:\.([a-z_]+))?(?:\[(\d+)\])?(?:\.([a-z_]+))?/.exec(path);
    let target = null;
    if (path === 'authority_id') target = editor.querySelector('[name="authority_id"]');
    else if (match) {
      const profile = editor.querySelector(`.zt-profile[data-index="${match[1]}"]`);
      if (profile) {
        profile.open = true;
        if (match[2] === 'api_keys' && match[3] !== undefined) target = profile.querySelectorAll('tr.zt-key')[Number(match[3])]?.querySelector(`[name="${FIELD_NAMES[match[4]] || 'key_env'}"]`) || null;
        else if (match[2]) target = profile.querySelector(`[name="${match[2]}"]`);
        target ??= profile.querySelector('summary');
      }
    }
    const message = t(`identities.validate.code.${code}`);
    if (target && target.tagName !== 'SUMMARY') {
      target.setAttribute('aria-invalid', 'true');
      (target.closest('.kit-field') || target.parentElement).append(ui.el('small', { class: 'zt-field-error', text: message }));
    }
    return ui.el('li', {}, ui.el('code', { class: 'kit-mono', text: path || t('identities.validate.document') }), ' ', ui.el('span', { text: message }), error.message ? ui.el('span', { class: 'kit-muted', title: String(error.message), text: ' ⓘ' }) : null);
  });
  ui.clear(box, ui.el('div', { class: 'zt-outcome zt-outcome-refused', attrs: { role: 'alert' } }, ui.statusBadge(t, 'refused', 'identities.outcome.refused'), ui.el('span', { text: t('identities.validate.invalid', { count: errors.length }) })), ui.el('ul', { class: 'zt-field-errors' }, items));
  (editor.querySelector('[aria-invalid="true"]') || box).scrollIntoView?.({ block: 'center' });
}

async function renderProfiles(cx, content, caps) {
  const { t, ui } = cx;
  if (!can(caps, 'authentication/profiles')) { content.append(notConnected(cx, caps, 'authentication/profiles')); return; }
  const strip = ui.el('div', { class: 'zt-authority' }, ui.loadingState(t));
  const status = ui.el('div', { class: 'zt-notes' });
  const editor = ui.el('div', { class: 'zt-profiles' });
  content.append(strip, status, editor);
  let document, runtime = null;
  try {
    const [profiles, hopaeStatus] = await Promise.allSettled([hopae(cx, 'authentication/profiles'), can(caps, 'status') ? hopae(cx, 'status') : Promise.reject(Object.assign(new Error('status'), { status: 404 }))]);
    if (profiles.status === 'rejected') throw profiles.reason;
    document = profiles.value.data || { revision: 0, configuration: null };
    if (hopaeStatus.status === 'fulfilled') runtime = hopaeStatus.value.data?.authentication_gateway || null;
  } catch (error) { ui.clear(strip, failure(cx, error, () => cx.navigate('#identities/authentication'))); return; }
  if (cx.signal.aborted) return;
  const revision = Number(document.revision) || 0;
  const canPublish = can(caps, 'authentication/profiles/publish');
  ui.clear(strip,
    ui.el('span', { class: 'zt-authority-item' }, ui.el('span', { class: 'kit-muted', text: t('identities.authority.owner') }), ' ', ui.el('strong', { text: t('ui.owner.hopae') })),
    ui.el('span', { class: 'zt-authority-item', text: t('ui.revision', { revision }) }),
    document.digest ? ui.el('span', { class: 'zt-authority-item' }, ui.el('span', { class: 'kit-muted', text: t('identities.authority.digest') }), ' ', ui.hashChip(t, document.digest)) : null,
    runtime ? ui.statusBadge(t, runtime.available ? 'healthy' : 'unavailable', runtime.available ? 'identities.authority.runtime.ready' : 'identities.authority.runtime.unavailable') : ui.statusBadge(t, 'unknown', 'identities.authority.runtime.unknown'),
    canPublish ? null : ui.el('span', { class: 'kit-tag', text: t('identities.authority.read_only') }));
  const base = document.configuration ? structuredClone(document.configuration) : null;
  const stored = loadDraft(DRAFT);
  let draft = structuredClone(base || { authority_id: '', profiles: [] });
  if (stored && stored.base === revision && stored.draft) {
    draft = stored.draft;
    status.append(ui.el('p', { class: 'zt-banner', attrs: { role: 'status' } }, ui.el('span', { text: t('identities.draft.restored') }), ' ', button(cx, 'identities.draft.discard', () => { dropDraft(DRAFT); cx.navigate('#identities/authentication?fresh=' + Date.now()); })));
  } else if (stored && stored.base !== revision) {
    status.append(ui.el('p', { class: 'zt-banner zt-banner-warn', attrs: { role: 'alert' } }, ui.el('span', { text: t('identities.draft.stale', { base: stored.base, revision }) }), ' ',
      button(cx, 'identities.draft.keep', () => { saveDraft(DRAFT, revision, stored.draft); cx.navigate('#identities/authentication?rebased=' + Date.now()); }), ' ',
      button(cx, 'identities.draft.discard', () => { dropDraft(DRAFT); cx.navigate('#identities/authentication?fresh=' + Date.now()); })));
  }
  const counter = ui.el('span', { class: 'zt-change-count', attrs: { 'aria-live': 'polite' } });
  const publishButton = ui.el('button', { type: 'button', class: 'button button-primary', text: t('identities.publish.review'), disabled: true });
  const authority = ui.field(t, { label: 'identities.profile.field.authority_id', name: 'authority_id', value: draft.authority_id || '', pattern: IDENT, help: 'identities.profile.help.authority_id' });
  authority.querySelector('input').disabled = !canPublish;
  const list = ui.el('div', { class: 'zt-profile-list' });
  const preview = ui.el('div', { class: 'zt-preview' });
  function changed() {
    const diff = changeList(cx, profileEntities(cx, base), profileEntities(cx, draft));
    counter.textContent = t('identities.publish.changes', { count: diff.count });
    publishButton.disabled = !diff.count || !canPublish;
    ui.clear(preview, diff.element);
    if (diff.count) saveDraft(DRAFT, revision, draft); else dropDraft(DRAFT);
    return diff;
  }
  function renderList() {
    ui.clear(list);
    if (!draft.profiles.length) list.append(ui.emptyState(t, { title: 'identities.profile.empty', body: 'identities.profile.empty.body' }));
    draft.profiles.forEach((profile, index) => list.append(profileForm(cx, profile, index, {
      readOnly: !canPublish,
      onChange: next => { draft.profiles[index] = next; changed(); },
      onRemove: () => { draft.profiles.splice(index, 1); renderList(); changed(); },
    })));
  }
  authority.querySelector('input').addEventListener('input', event => { draft.authority_id = event.target.value.trim(); changed(); });
  const findings = ui.el('div', { class: 'zt-validation', attrs: { 'aria-live': 'polite' } });
  publishButton.addEventListener('click', async () => {
    const form = editor.querySelector('form');
    if (form && !form.reportValidity()) return;
    changed();
    // Hopae 0.1.10 dry-run: the publication's own checks, shown inline before review.
    if (can(caps, 'authentication/profiles/validate')) {
      ui.clear(findings, ui.loadingState(t));
      let report;
      try { report = (await hopae(cx, 'authentication/profiles/validate', { json: { configuration: draft } })).data; }
      catch (error) { if (error?.status === 401) throw error; ui.clear(findings, outcomeBanner(cx, 'refused', 'identities.literal', { value: errorText(t, error) })); return; }
      if (cx.signal.aborted) return;
      if (!report?.valid) { showFindings(cx, editor, findings, Array.isArray(report?.errors) ? report.errors : []); return; }
      ui.clear(findings, outcomeBanner(cx, 'committed', 'identities.validate.valid'));
    }
    const result = await publish(cx, { route: 'authentication/profiles/publish', revision, configuration: draft, diff: changeList(cx, profileEntities(cx, base), profileEntities(cx, draft)), target: draft.authority_id || t('identities.profile.authority'), status });
    if (!result) return;
    dropDraft(DRAFT);
    ui.clear(status, outcomeBanner(cx, 'committed', 'identities.publish.done', { revision: result.data?.revision ?? revision + 1, operation: result.operation || '—' }));
    setTimeout(() => cx.navigate('#identities/authentication?published=' + Date.now()), 1200);
  });
  const toolbar = ui.el('div', { class: 'zt-editor-bar' }, counter, canPublish
    ? ui.el('div', { class: 'button-row' }, button(cx, 'identities.profile.add', () => { draft.profiles.push(blankProfile()); renderList(); changed(); }), publishButton)
    : ui.disabledAction(t, 'identities.publish.review', 'identities.gap.not_declared'));
  const form = ui.el('form', { class: 'zt-editor', attrs: { 'aria-label': t('identities.profile.editor') } }, authority, list);
  form.addEventListener('submit', event => event.preventDefault());
  ui.clear(editor, toolbar, findings, form, panel(cx, 'identities.publish.preview', preview));
  renderList();
  changed();
  if (document.configuration === null) status.append(ui.el('p', { class: 'zt-banner', attrs: { role: 'note' }, text: t('identities.profile.none_published') }));
}

export async function renderAuthentication(cx, root, parts, params) {
  const { t, ui } = cx;
  const caps = await capabilities(cx);
  if (cx.signal.aborted) return;
  const active = parts[0] === 'test' ? 'test' : 'profiles';
  const { content } = sectionPage(cx, root, { active: 'authentication', crumbs: [{ label: t('identities.page.authentication'), href: '#identities/authentication' }, ...(active === 'test' ? [{ label: t('identities.auth.tab.test') }] : [])], title: t(active === 'test' ? 'identities.explain.title' : 'identities.page.authentication'), owner: t(active === 'test' ? 'identities.explain.owner' : 'identities.auth.owner') });
  content.append(tabs(cx, active));
  if (!caps.installed) { content.append(notConnected(cx, caps, 'authentication/profiles')); return; }
  if (active === 'test') {
    if (!can(caps, 'explain/authentication')) { content.append(notConnected(cx, caps, 'explain/authentication')); return; }
    const test = explainPanel(cx, { subject: params.get('subject') || '', url: params.get('url') || '', embedded: true, onRun: body => {
      const next = new URLSearchParams();
      if (body.subject) next.set('subject', body.subject);
      next.set('url', body.url);
      history.replaceState(null, '', cx.hashFor('identities', ['authentication', 'test'], next));
    } });
    content.append(ui.el('section', { class: 'panel zt-panel' }, test.element));
    if (params.get('url')) await test.run();
    return;
  }
  await renderProfiles(cx, content, caps);
}
