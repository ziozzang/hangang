import { recordStatus, resetConsole, startLive, stopLive, isLive, renderSecurity } from './console.js';
import { t, getLocale, initLocale } from './i18n.js';
import { loadOperations, refreshOperationsCopy, resetOperations } from './operations.js';
import { loadDockerPanel, refreshDockerCopy, resetDockerPanel } from './docker.js';
import { createLuaEditor } from './lua-editor.js';
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const luaFields = [
  ['lua', 'policy', 'Lua policy'],
  ['request_transform_lua', 'body', 'Request transform Lua'],
  ['response_transform_lua', 'body', 'Response transform Lua'],
];
const luaEditors = new Map();

function destroyLuaEditors() {
  for (const { editor } of luaEditors.values()) editor.destroy();
  luaEditors.clear();
}

function mountLuaEditors() {
  destroyLuaEditors();
  if (state.editing?.type !== 'http') return;
  for (const [name, context, label] of luaFields) {
    const textarea = $('#route-form').elements[name];
    if (!textarea) continue;
    const editor = createLuaEditor(textarea, { context, label: t(label), translateInfo: t });
    luaEditors.set(textarea, { editor, label });
    editor.setDisabled(textarea.disabled);
  }
}

const state = {
  token: '',
  authGeneration: 0,
  user: null,
  authMode: 'token',
  accountAuthAvailable: false,
  view: 'status',
  statusTimer: null,
  workloadMaterialTimer: null,
  workloadMaterialAbort: null,
  workloadMaterials: null,
  workloadMaterialsRevision: null,
  tcpRoutesRevision: null,
  revision: null,
  config: null,
  configEtag: null,
  configDirty: false,
  cachePolicyDirty: false,
  cacheLoadSequence: 0,
  cacheRuntime: null,
  /** `state.configuration_source` from the last status: shared-store members purge fleet-wide. */
  configurationSource: null,
  /** Last shared-store epoch shown, for the copy button. */
  storeEpoch: null,
  /** Why the fleet-settings controls could not be mirrored into the document; blocks validate/apply. */
  settingsError: null,
  certificateDirty: false,
  certificateInventory: null,
  certificateInventoryOffset: 0,
  certificateInventoryLoadSequence: 0,
  certificateTimer: null,
  certificateLoadSequence: 0,
  routes: { http: [], tcp: [] },
  routeEtags: { http: null, tcp: null },
  routeInventory: { http: { query: '', policy: 'all', sort: 'priority-desc', page: 1, pageSize: 25 }, tcp: { query: '', policy: 'all', sort: 'priority-desc', page: 1, pageSize: 25 } },
  editing: null,
  openapi: null,
  lastStatus: null,
  lastUpdateStatus: null,
};

/** Tag generated copy so a locale change can update it without rebuilding editable controls. */
function copy(el, source, params = {}) {
  el.dataset.appI18n = source;
  el.appI18nParams = params;
  el.textContent = t(source, params.role ? { ...params, role: t(params.role) } : params);
  return el;
}

function refreshAppCopy() {
  setLoginMode(state.authMode);
  updateAccess();
  refreshTokenToggle();
  for (const el of $$('[data-app-i18n]')) {
    if (el.disabled && el.dataset.label) continue;
    const params = el.appI18nParams || {};
    el.textContent = t(el.dataset.appI18n, params.role ? { ...params, role: t(params.role) } : params);
  }
  for (const el of $$('[data-app-i18n-placeholder]')) el.placeholder = t(el.dataset.appI18nPlaceholder);
  for (const { editor, label } of luaEditors.values()) { editor.setLabel(t(label)); editor.setTranslateInfo?.(t); }
  if (state.lastStatus) renderStatus(state.lastStatus, false);
  refreshWorkloadMaterialBadges();
  if (state.lastUpdateStatus) renderUpdateStatus(state.lastUpdateStatus);
  if (state.cacheRuntime) renderCache(state.cacheRuntime);
  refreshCacheToggle(state.config?.cache ?? null);
  if (state.certificateInventory) renderCertificateInventory(state.certificateInventory);
  if (state.config && $('#certificate-list').children.length) renderCertificates(state.config.certificates || []);
  if (state.config) updateConfigPreview();
  for (const type of ['http', 'tcp']) if ($(`#${type}-routes`).querySelector('.route-inventory, .empty-state')) renderRoutes(type);
  if (state.openapi) renderDocs(state.openapi);
  refreshOperationsCopy();
  refreshDockerCopy();
  if ($('#route-dialog').open && $('#route-form').dataset.invalidNative) {
    try { routeFromForm(); delete $('#route-form').dataset.invalidNative; message($('#route-message')); }
    catch (error) { $('#route-form').dataset.invalidNative = error.message; message($('#route-message'), error.message, 'error'); }
  }
}

function refreshTokenToggle() {
  const visible = $('#token-input').type === 'text';
  $('#toggle-token').textContent = t(visible ? 'Hide' : 'Show');
  $('#toggle-token').setAttribute('aria-label', t(visible ? 'Hide token' : 'Show token'));
}

const DEFAULT_TRANSFORM = { mode: 'buffered', operations: [], lua: null, max_buffer_bytes: 65536, max_output_bytes: 65536, timeout_ms: 5000, set_headers: {}, remove_headers: [] };
const DEFAULT_UPSTREAM = { connect_address: null, unix_socket: null, dns_servers: [], socks5: null, tls: null };
const HEADER_NAME = /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/;
const MAX_GENERATION = 4294967295;
/** Identity names an authorization service may return under the otherwise reserved x-forwarded- prefix. */
const AUTH_IDENTITY_HEADERS = ['x-forwarded-user', 'x-forwarded-email', 'x-forwarded-groups', 'x-forwarded-preferred-username', 'x-forwarded-access-token'];
/** Names the proxy generates or owns; neither authorization list may carry them (x-forwarded-* and forwarded are matched separately). */
const AUTH_RESERVED_HEADERS = ['host', 'connection', 'content-length', 'transfer-encoding', 'upgrade', 'te', 'trailer', 'keep-alive', 'proxy-authorization', 'proxy-connection', 'proxy-authenticate', 'x-real-ip', 'x-original-method', 'x-original-uri', 'x-original-url', 'x-original-client-ip', 'forwarded'];
/**
 * Problem titles from the shared configuration store whose meaning is not obvious from the
 * detail alone; they are shown as "Title: detail" wherever the error surfaces.
 */
const STORE_PROBLEM_TITLES = new Set(['Store Unavailable', 'Indeterminate Outcome', 'Authority Changed']);
/** Human explanation of each shared-store failure class reported by GET /v1/status. */
const STORE_REASONS = {
  unavailable: ['transport', 'The shared store could not be reached.'],
  invalid: ['transport', 'The stored document could not be read or decoded.'],
  indeterminate: ['transport', 'The store did not acknowledge the last operation; its outcome is unknown.'],
  missing: ['transport', 'The store holds no configuration document.'],
  stalled: ['transport', 'A reconciliation poll did not complete within its deadline.'],
  rollback: ['authority', 'The store revision is older than the revision this instance activated.'],
  divergence: ['authority', 'The store document differs from the local one at the same revision.'],
  authority_changed: ['authority', 'The store was re-seeded under a different epoch; restart this instance to follow it.'],
  unpreparable: ['authority', 'The authoritative revision could not be activated on this instance.'],
};

class ApiError extends Error {
  constructor(message, status, response, payload, title = null) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.response = response;
    this.payload = payload;
    /** RFC 9457 problem title when the server answered application/problem+json. */
    this.title = title;
  }
}

class StaleSessionError extends Error {}

const ACCOUNT_SESSION_KEY = 'hangang.account.session.v1';

function storedAccountToken() {
  try { return sessionStorage.getItem(ACCOUNT_SESSION_KEY) || ''; }
  catch { return ''; }
}

function rememberAccountToken(token) {
  try { sessionStorage.setItem(ACCOUNT_SESSION_KEY, token); }
  catch { /* Private browsing or storage policy may deny persistence. */ }
}

function forgetAccountToken() {
  try { sessionStorage.removeItem(ACCOUNT_SESSION_KEY); }
  catch { /* The in-memory session is still cleared below. */ }
}

/** A 409 that means "retry against the latest revision" rather than a store authority or controller problem. */
function isRevisionConflict(error) { return error.status === 409 && (!error.title || error.title === 'Revision Conflict' || error.title === 'Route Conflict'); }
/** The shared store did not acknowledge a write: it may have been applied, so the caller must reload before retrying. */
function isIndeterminate(error) { return error.status === 500 && error.title === 'Indeterminate Outcome'; }

async function api(path, options = {}) {
  const generation = state.authGeneration;
  const token = state.token;
  const headers = new Headers(options.headers || {});
  if (token) headers.set('Authorization', `Bearer ${token}`);
  if (options.json !== undefined) {
    headers.set('Content-Type', 'application/json');
    options.body = JSON.stringify(options.json);
  }
  let response;
  try {
    response = await fetch(path, { ...options, headers, cache: 'no-store' });
  } catch (error) {
    throw new ApiError(t('The proxy could not be reached.'), 0, null, error);
  }
  if (generation !== state.authGeneration || token !== state.token) throw new StaleSessionError();
  const type = response.headers.get('content-type') || '';
  let payload = null;
  if (response.status !== 204) {
    payload = type.includes('json') ? await response.json().catch(() => null) : await response.text().catch(() => '');
  }
  if (generation !== state.authGeneration || token !== state.token) throw new StaleSessionError();
  if (!response.ok) {
    const title = isObject(payload) && typeof payload.title === 'string' && payload.title ? payload.title : null;
    const detail = payload?.detail || payload?.title || payload?.error || (typeof payload === 'string' && payload.trim()) || `${response.status} ${response.statusText}`;
    // Server-side and store failures carry a title that explains the class of failure; keep it verbatim next to the detail.
    const message = title && detail !== title && (response.status >= 500 || STORE_PROBLEM_TITLES.has(title)) ? `${title}: ${detail}` : detail;
    throw new ApiError(message, response.status, response, payload, title);
  }
  return { data: payload, response, etag: response.headers.get('etag') };
}

function isObject(value) { return Boolean(value) && typeof value === 'object' && !Array.isArray(value); }

function setConnection(online, label = online ? t('Connected') : t('Disconnected')) {
  const el = $('#connection-state');
  el.classList.toggle('is-online', online);
  el.classList.toggle('is-offline', !online);
  el.lastChild.textContent = label;
}

function setRevision(revision) {
  if (revision === undefined || revision === null) return;
  state.revision = revision;
  $('#revision-badge').textContent = `REV ${revision}`;
}

/** Inline status text; `action` ({ label, run }) appends a button, for example a reload after an indeterminate write. */
function message(el, text = '', kind = '', action = null) {
  el.textContent = text;
  el.className = `inline-message${kind ? ` is-${kind}` : ''}`;
  if (action) {
    const button = document.createElement('button');
    button.type = 'button'; button.className = 'button button-quiet'; button.textContent = action.label;
    button.addEventListener('click', () => { setBusy(button, true, t('Reloading…')); Promise.resolve().then(action.run).finally(() => setBusy(button, false)); });
    el.append(' ', button);
  }
}

function toast(text, kind = '') {
  const el = document.createElement('div');
  el.className = `toast${kind ? ` is-${kind}` : ''}`;
  el.textContent = text;
  $('#toast-region').append(el);
  setTimeout(() => el.remove(), 4500);
}

function setBusy(button, busy, busyText = t('Working…')) {
  if (!button) return;
  if (busy) {
    button.dataset.label = button.textContent;
    button.textContent = busyText;
    button.disabled = true;
  } else {
    button.textContent = button.dataset.appI18n ? t(button.dataset.appI18n, button.appI18nParams || {}) : button.dataset.label || button.textContent;
    button.disabled = false;
  }
}

function formatNumber(value) {
  return new Intl.NumberFormat(getLocale(), { notation: Number(value) >= 1_000_000 ? 'compact' : 'standard', maximumFractionDigits: 1 }).format(Number(value) || 0);
}

function duration(seconds) {
  seconds = Math.max(0, Number(seconds) || 0);
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${minutes}m`;
  return `${minutes}m ${Math.floor(seconds % 60)}s`;
}

/** Modal confirmation through the in-page dialog; resolves true only for an explicit accept. */
function confirmDialog({ title, body, accept = t('Confirm'), danger = true }) {
  const dialog = $('#confirm-dialog');
  $('#confirm-title').textContent = title;
  $('#confirm-message').textContent = body;
  const button = $('#confirm-accept');
  button.textContent = accept;
  button.className = `button ${danger ? 'button-danger' : 'button-primary'}`;
  dialog.returnValue = '';
  dialog.showModal();
  return new Promise((resolve) => dialog.addEventListener('close', () => resolve(dialog.returnValue === 'confirm'), { once: true }));
}

function showLogin(error = '') {
  stopStatusPolling();
  message($('#login-error'), error, error ? 'error' : '');
  const dialog = $('#login-dialog');
  if (!dialog.open) dialog.showModal();
  const first = { token: '#token-input', account: '#login-username', setup: '#setup-token' }[state.authMode];
  setTimeout(() => $(first).focus(), 0);
}

function setLoginMode(mode) {
  if (state.authMode !== mode) {
    for (const id of ['token-input', 'login-password', 'setup-token', 'setup-password', 'setup-confirm']) $(`#${id}`).value = '';
  }
  state.authMode = mode;
  for (const name of ['token', 'account', 'setup']) {
    const fields = $(`#${name}-login-fields`);
    fields.hidden = name !== mode;
    $$('input', fields).forEach((input) => { input.required = name === mode; });
  }
  const details = {
    token: [t('Connect to this proxy'), t('Enter the administrator bearer token. It stays in memory for this tab.')],
    account: [t('Sign in'), t('Use an account on this proxy instance. Your session survives reloads in this tab.')],
    setup: [t('Create the first administrator'), t('Enter the existing administrator token to authorize setup, then choose a username and password.')],
  }[mode];
  $('#login-title').textContent = details[0];
  $('#login-description').textContent = details[1];
  $('#login-submit').textContent = mode === 'setup' ? t('Create administrator') : mode === 'account' ? t('Sign in') : t('Connect');
  $('#switch-to-token').hidden = !state.accountAuthAvailable || mode === 'token';
  $('#switch-to-account').hidden = !state.accountAuthAvailable || mode === 'account';
  message($('#login-error'));
}

async function discoverAuth() {
  let problem = '';
  try {
    const { data } = await api('/v1/auth/setup');
    state.accountAuthAvailable = true;
    setLoginMode(data?.bootstrap_required ? 'setup' : 'account');
  } catch (error) {
    // Older gateways only support the administrator bearer token.
    setLoginMode('token');
    if (error.status !== 404) problem = error.message;
  }
  showLogin(problem);
}

async function restoreAccountSession() {
  const token = storedAccountToken();
  if (!token) return discoverAuth();
  try {
    // A saved bearer has no authority in this page until the server confirms
    // both its validity and current role. No privileged view loads before this.
    const { data } = await api('/v1/auth/me', { headers: { Authorization: `Bearer ${token}` } });
    if (!data?.user || !['admin', 'viewer'].includes(data.user.role)) throw new Error(t('Invalid account identity.'));
    state.accountAuthAvailable = true;
    setLoginMode('account');
    await activateSession(token, data.user, 'account');
  } catch {
    forgetAccountToken();
    if (state.token) logout('Your session could not be restored. Sign in again.');
    else await discoverAuth();
  }
}

function isAdmin() { return state.user?.role === 'admin'; }

function updateAccess() {
  const admin = isAdmin();
  $$('[data-admin-only]').forEach((element) => { element.hidden = !admin; });
  const label = $('#signed-in-user');
  label.hidden = !state.user;
  label.textContent = state.user ? `${state.user.username} · ${t(state.user.role)}` : '';
  $('#restart-server').hidden = !admin || $('#restart-server').hidden;
  $('#check-update').hidden = !admin || $('#check-update').hidden;
  $('#verify-session').hidden = !state.accountAuthAvailable || !state.token;
}

/** Remove every rendered piece of server data so a signed-out tab exposes nothing. */
function scrubRenderedData() {
  resetConsole();
  resetOperations();
  resetDockerPanel();
  destroyLuaEditors();
  for (const id of ['route-dialog', 'docker-dialog', 'confirm-dialog']) { const dialog = $(`#${id}`); if (dialog.open) dialog.close(); }
  state.editing = null;
  for (const id of ['metric-grid', 'secondary-metric-grid', 'cache-metric-grid', 'http-routes', 'tcp-routes', 'certificate-list', 'certificate-acme-state', 'certificate-inventory', 'certificate-inventory-pages', 'route-form-fields', 'user-list']) $(`#${id}`).replaceChildren();
  $('#certificate-inventory-count').textContent = '—';
  for (const id of ['runtime-state', 'configuration-source', 'uptime', 'last-sync', 'acme-state', 'server-version', 'process-id', 'instance-id', 'instance-digest', 'store-state', 'store-reason', 'store-confirmed', 'store-epoch', 'store-revision', 'cache-state', 'cache-memory-policy', 'cache-disk-policy', 'cache-active-fills', 'cache-generation', 'cache-purge-scope']) $(`#${id}`).textContent = '—';
  for (const id of ['acme-detail', 'update-detail', 'metrics-output', 'health-result', 'session-result', 'utility-hash-message', 'store-state-detail', 'store-reason-help', 'store-grace', 'store-detail']) $(`#${id}`).textContent = '';
  $('#utility-credential').value = '';
  $('#utility-copy-credential').disabled = true;
  $('#utility-hash-form').reset();
  $('#update-state').textContent = t('Loading status');
  for (const id of ['config-editor', 'cache-policy-editor', 'certificate-editor', 'route-json']) { const editor = $(`#${id}`); editor.value = ''; editor.setAttribute('aria-invalid', 'false'); }
  if ($('#workload-http-panel')) { $('#workload-http-list').replaceChildren(); $('#workload-http-form').reset(); $('#workload-http-form').hidden = true; message($('#workload-http-message')); }
  $('#cache-generation-input').value = '';
  $('#cache-generation-input').setAttribute('aria-invalid', 'false');
  showSettings(undefined);
  for (const key of SETTINGS_FIELDS) $(`#setting-active-${key}`).textContent = '—';
  $('#config-diff').textContent = t('Load the active configuration to compare changes.');
  $('#preview-count').textContent = t('No changes');
  for (const id of ['config-message', 'cache-message', 'certificate-message', 'route-message', 'docker-message', 'users-message']) message($(`#${id}`));
  for (const id of ['config-dirty', 'cache-policy-dirty', 'certificate-dirty', 'status-content', 'cache-content', 'metrics-output', 'store-panel']) $(`#${id}`).hidden = true;
  $('#status-loading').hidden = false;
  $('#cache-loading').hidden = false;
  $('#global-alert').hidden = true;
  $('#global-alert').textContent = '';
}

function logout(reason = '') {
  stopCertificatePolling();
  stopWorkloadMaterialPolling();
  const token = state.token;
  const revoke = state.accountAuthAvailable && token && state.authMode !== 'token';
  forgetAccountToken();
  state.token = '';
  state.authGeneration += 1;
  state.user = null;
  state.config = null;
  state.configEtag = null;
  state.configDirty = false;
  state.routes = { http: [], tcp: [] };
  state.routeEtags = { http: null, tcp: null };
  state.routeInventory = { http: { query: '', policy: 'all', sort: 'priority-desc', page: 1, pageSize: 25 }, tcp: { query: '', policy: 'all', sort: 'priority-desc', page: 1, pageSize: 25 } };
  state.cachePolicyDirty = false;
  state.cacheRuntime = null;
  state.configurationSource = null;
  state.storeEpoch = null;
  state.settingsError = null;
  state.certificateDirty = false;
  state.certificateInventory = null;
  state.certificateInventoryOffset = 0;
  state.certificateInventoryLoadSequence++;
  state.certificateLoadSequence++;
  state.lastStatus = null;
  state.lastUpdateStatus = null;
  state.workloadMaterials = null;
  state.workloadMaterialsRevision = null;
  state.tcpRoutesRevision = null;
  scrubRenderedData();
  $('#token-input').value = '';
  for (const id of ['login-username', 'login-password', 'setup-token', 'setup-username', 'setup-password', 'setup-confirm']) $(`#${id}`).value = '';
  $('#logout-button').hidden = true;
  $('#revision-badge').textContent = 'REV —';
  $('#uptime-small').textContent = t('Awaiting sign in');
  setConnection(false);
  updateAccess();
  if (state.authMode === 'setup') setLoginMode('account');
  showLogin(reason);
  if (revoke) {
    // Revoke the server-side session after immediately removing it from the UI.
    fetch('/v1/auth/logout', { method: 'POST', headers: { Authorization: `Bearer ${token}` }, cache: 'no-store', keepalive: true }).catch(() => {});
  }
}

async function activateSession(token, user, mode) {
  if (mode === 'account' && (!user || !['admin', 'viewer'].includes(user.role))) throw new Error(t('Invalid account identity.'));
  state.authGeneration += 1;
  state.token = token;
  state.authMode = mode;
  state.user = user;
  const { data } = await api('/v1/status');
  // Persist only after authorization succeeds, before the UI exposes the
  // signed-in state. A user can refresh as soon as the dialog closes.
  if (mode === 'account') rememberAccountToken(token);
  $('#login-dialog').close();
  for (const id of ['token-input', 'login-password', 'setup-token', 'setup-password', 'setup-confirm']) $(`#${id}`).value = '';
  $('#logout-button').hidden = false;
  setConnection(true);
  updateAccess();
  if (!isAdmin() && state.view !== 'status') {
    state.view = 'status';
    history.replaceState(null, '', '#status');
    $$('.view').forEach((view) => { view.hidden = view.id !== 'view-status'; });
    $$('.nav-link').forEach((link) => link.classList.toggle('is-active', link.dataset.view === 'status'));
  }
  renderStatus(data);
  startStatusPolling();
  await loadView(state.view, true);
}

async function login(event) {
  event.preventDefault();
  const button = $('#login-form [type="submit"]');
  message($('#login-error'));
  setBusy(button, true, t('Connecting…'));
  try {
    if (state.authMode === 'setup') {
      const username = $('#setup-username').value.trim();
      const password = $('#setup-password').value;
      if (password !== $('#setup-confirm').value) throw new ApiError(t('Passwords do not match.'), 0);
      const token = $('#setup-token').value;
      await api('/v1/auth/bootstrap', { method: 'POST', headers: { Authorization: `Bearer ${token}` }, json: { username, password } });
      setLoginMode('account');
      $('#login-username').value = username;
      $('#login-password').value = password;
    }
    if (state.authMode === 'account') {
      const { data } = await api('/v1/auth/login', { method: 'POST', json: { username: $('#login-username').value.trim(), password: $('#login-password').value } });
      await activateSession(data.token, data.user, 'account');
    } else {
      const candidate = $('#token-input').value;
      let user = { username: 'system', role: 'admin' };
      if (state.accountAuthAvailable) {
        state.token = candidate;
        try { ({ user } = (await api('/v1/auth/me')).data); }
        finally { state.token = ''; }
      }
      await activateSession(candidate, user, 'token');
    }
  } catch (error) {
    state.token = '';
    state.user = null;
    if (state.authMode === 'setup' && error.status === 409) {
      await discoverAuth();
      message($('#login-error'), t('An administrator was already created. Sign in with that account.'), 'error');
    } else {
      const failure = error.status === 401
        ? state.authMode === 'token' ? t('That administrator token was rejected.') : state.authMode === 'setup' ? t('The bootstrap token was rejected.') : t('Incorrect username or password.')
        : error.message;
      message($('#login-error'), failure, 'error');
    }
  } finally {
    for (const id of ['login-password', 'setup-password', 'setup-confirm']) $(`#${id}`).value = '';
    setBusy(button, false);
    // Setup switches this same form to sign-in while the submit is busy.
    button.textContent = state.authMode === 'setup' ? t('Create administrator') : state.authMode === 'account' ? t('Sign in') : t('Connect');
    delete button.dataset.label;
  }
}

function normalizeView(hash) {
  const name = (hash || '').replace(/^#/, '').split('/')[0];
  return ['status', 'http', 'tcp', 'docker', 'cache', 'certificates', 'security', 'config', 'users', 'operations', 'utilities', 'docs'].includes(name) ? name : 'status';
}

async function switchView() {
  let name = normalizeView(location.hash);
  if (state.user && !isAdmin() && name !== 'status') {
    name = 'status';
    if (location.hash !== '#status') history.replaceState(null, '', '#status');
  }
  state.view = name;
  $$('.view').forEach((view) => {
    const active = view.id === `view-${name}`;
    view.hidden = !active;
    view.classList.toggle('is-active', active);
  });
  $$('.nav-link').forEach((link) => link.classList.toggle('is-active', link.dataset.view === name));
  if (name === 'status' && state.token) startStatusPolling(); else stopStatusPolling();
  if (name !== 'config' && name !== 'tcp') stopWorkloadMaterialPolling();
  if (name === 'certificates' && state.token && !document.hidden) startCertificatePolling(); else stopCertificatePolling();
  if (state.token) await loadView(name);
  $('#main').focus({ preventScroll: true });
}

async function loadView(name, quiet = false) {
  try {
    if (name === 'status') await loadStatus();
    if (name === 'http' || name === 'tcp') await loadRoutes(name);
    if (name === 'cache') await loadCache(false);
    if (name === 'certificates') await loadCertificates(false);
    if (name === 'config') await loadConfig(false);
    if (name === 'config' || name === 'tcp') {
      await refreshWorkloadMaterialStatus();
      startWorkloadMaterialPolling();
    }
    if (name === 'users' && isAdmin()) await loadUsers();
    if (name === 'operations' && isAdmin()) await loadOperations(api, () => logout(t('Your session is no longer authorized.')));
    if (name === 'docker' && isAdmin()) await loadDockerPanel(api, () => logout(t('Your session is no longer authorized.')));
    if (name === 'security' && isAdmin()) { const latest = await api('/v1/config'); renderSecurity(latest.data); }
    if (name === 'docs') await loadDocs();
    $('#global-alert').hidden = true;
  } catch (error) {
    if (error instanceof StaleSessionError) return;
    if (error.status === 401) return logout('Your session is no longer authorized.');
    if (!quiet) showGlobalError(error.message);
  }
}

function showGlobalError(text) {
  const alert = $('#global-alert');
  alert.textContent = text;
  alert.hidden = false;
}

async function loadStatus() {
  if (!state.token) return;
  const { data } = await api('/v1/status');
  if (!isLive()) renderStatus(data);
  try {
    const { data: update } = await api('/v1/update/status');
    state.lastUpdateStatus = update;
    renderUpdateStatus(update);
  } catch (error) {
    if (error instanceof StaleSessionError) return;
    if (error.status === 401) return logout('Your session is no longer authorized.');
    state.lastUpdateStatus = { unavailable: true, detail: error.message };
    renderUpdateStatus(state.lastUpdateStatus);
  }
}

function renderUpdateStatus(update) {
  $('#update-state').textContent = update.unavailable ? t('Update status unavailable') : update.enabled ? `${update.current_version} · ${t(update.phase)}` : t('Automatic updates are not configured');
  $('#update-detail').textContent = update.detail || '';
  $('#check-update').hidden = !isAdmin() || !update.enabled;
  $('#check-update').disabled = update.phase === 'checking';
}

function renderStatus(data, record = true) {
  state.lastStatus = data;
  // Locale-only rerenders may carry an older status snapshot than a recent
  // Configuration/TCP material poll; keep the newer local slot observation.
  if (record) acceptWorkloadMaterials(data);
  if (record) recordStatus(data);
  setRevision(data.revision);
  setConnection(true);
  $('#status-loading').hidden = true;
  $('#status-content').hidden = false;
  const metrics = data.metrics || {};
  const definitions = [
    [t('Requests'), metrics.requests_total, t('Total processed'), ''],
    [t('Active'), metrics.active_connections, t('Open connections'), 'is-good'],
    [t('Errors'), metrics.errors_total, t('Request failures'), Number(metrics.errors_total) ? 'is-error' : ''],
    [t('Rejected'), metrics.rejected_connections_total, t('Policy or capacity'), Number(metrics.rejected_connections_total) ? 'is-error' : ''],
    [t('Rejected requests'), metrics.rejected_requests_total, t('Admission or limit'), Number(metrics.rejected_requests_total) ? 'is-error' : ''],
    [t('HTTP routes'), data.http_routes, t('Active match rules'), ''],
    [t('TCP routes'), data.tcp_routes, t('Configured routes'), ''],
    [t('Cache hits'), metrics.cache_hits_total, t('{misses} misses · {bypasses} bypasses', { misses: formatNumber(metrics.cache_misses_total), bypasses: formatNumber(metrics.cache_bypasses_total) }), ''],
    [t('Body transform errors'), metrics.body_transform_errors_total, t('Buffer or stream failures'), Number(metrics.body_transform_errors_total) ? 'is-error' : ''],
    [t('Policy errors'), metrics.policy_errors_total, t('Lua policy failures, including capacity rejections'), Number(metrics.policy_errors_total) ? 'is-error' : ''],
    [t('Lua capacity rejections'), Number.isFinite(metrics.policy_capacity_rejections_total) ? metrics.policy_capacity_rejections_total : null, t('Worker busy or restarting; counted in policy errors'), Number(metrics.policy_capacity_rejections_total) ? 'is-error' : ''],
    [t('Config updates'), metrics.config_updates_total, t('Published revisions'), ''],
  ];
  const grid = $('#metric-grid');
  const cards = definitions.map(([label, value, note, style], index) => {
    const card = document.createElement('article');
    card.className = `metric ${style}${index >= 4 ? ' is-secondary' : ''}`.trim();
    const head = document.createElement('span'); head.className = 'metric-label'; head.textContent = label;
    const number = document.createElement('strong'); number.className = 'metric-value'; number.textContent = value === null ? '—' : formatNumber(value);
    const detail = document.createElement('span'); detail.className = 'metric-note'; detail.textContent = note;
    card.append(head, number, detail); return card;
  });
  grid.replaceChildren(...cards.slice(0, 4));
  $('#secondary-metric-grid').replaceChildren(...cards.slice(4));
  const draining = Boolean(data.state?.draining);
  $('#restart-server').hidden = !isAdmin() || !data.state?.supervised;
  $('#restart-server').disabled = draining;
  $('#runtime-state').textContent = draining ? t('Draining') : data.state?.ready === false ? t('Waiting for configuration') : t('Accepting traffic');
  state.configurationSource = data.state?.configuration_source || 'file';
  $('#configuration-source').textContent = state.configurationSource;
  $('#cache-purge-scope').textContent = state.configurationSource === 'shared' ? t('Fleet') : t('This instance');
  $('#server-version').textContent = data.version ? `${data.version}${data.state?.supervised ? t(' · supervised') : ''}` : '—';
  $('#process-id').textContent = data.process_id !== undefined ? String(data.process_id) : '—';
  $('#instance-id').textContent = data.instance?.id || '—';
  $('#instance-digest').textContent = data.instance?.config_digest || '—';
  renderStore(data.store);
  renderSettings(data.settings);
  $('#acme-state').textContent = data.acme?.enabled ? t(data.acme.phase) : t('External or not configured');
  $('#acme-detail').textContent = data.acme?.enabled ? `${(data.acme.domains || []).join(', ')}${data.acme.expires_unix ? t(' · Expires {date}', { date: new Date(data.acme.expires_unix * 1000).toLocaleString(getLocale()) }) : ''}` : t('A standalone issuer may manage the certificate files. Its renewal state is not reported by this process.');
  $('#runtime-state').style.color = draining ? 'var(--amber)' : 'var(--green)';
  const uptime = duration(data.uptime_seconds);
  $('#uptime').textContent = uptime;
  $('#uptime-small').textContent = t('Uptime {uptime}', { uptime });
  $('#last-sync').textContent = new Date().toLocaleTimeString(getLocale());
}

/**
 * Shared configuration store diagnostics (`store` in GET /v1/status). Null in file and controller
 * modes hides the panel. Transport-class failures are tolerated for `grace_seconds` since the last
 * confirmation (degraded); authority disagreements withdraw readiness immediately.
 */
function renderStore(store) {
  const panel = $('#store-panel');
  if (!isObject(store)) { panel.hidden = true; state.storeEpoch = null; return; }
  panel.hidden = false;
  const reason = typeof store.reason === 'string' ? store.reason : null;
  const [klass, explanation] = STORE_REASONS[reason] || (reason ? ['authority', 'Unrecognized failure class; consult the server log.'] : [null, '']);
  const withdrawn = store.ready === false;
  const degraded = !withdrawn && (Boolean(store.degraded) || Boolean(reason));
  const badge = $('#store-state');
  badge.textContent = withdrawn ? t('Withdrawn') : degraded ? t('Degraded') : t('Ready');
  badge.style.color = withdrawn ? 'var(--red)' : degraded ? 'var(--amber)' : 'var(--green)';
  $('#store-state-detail').textContent = withdrawn
    ? t('Readiness is withdrawn: this instance no longer agrees with the authority and answers 503 on /healthz.')
    : degraded ? t('A transport failure is being tolerated inside the grace window; the local snapshot keeps serving.') : t('The last poll confirmed agreement with the shared authority.');
  $('#store-reason').textContent = reason || t('none');
  $('#store-reason').style.color = reason ? (klass === 'authority' ? 'var(--red)' : 'var(--amber)') : '';
  const graceSeconds = Number(store.grace_seconds) || 0;
  $('#store-reason-help').textContent = !reason ? ''
    : klass === 'transport' ? t('{explanation} Transport class: tolerated for {seconds} s after the last confirmation, then readiness is withdrawn.', { explanation: t(explanation), seconds: graceSeconds })
    : t('{explanation} Authority disagreement: readiness is withdrawn immediately.', { explanation: t(explanation) });
  const ago = store.last_confirmed_seconds_ago;
  $('#store-confirmed').textContent = ago === null || ago === undefined ? t('Never') : t('confirmed {seconds} s ago', { seconds: Number(ago) });
  $('#store-grace').textContent = t('Grace window {seconds} s (--store-grace-seconds).', { seconds: graceSeconds });
  state.storeEpoch = typeof store.epoch === 'string' ? store.epoch : null;
  $('#store-epoch').textContent = state.storeEpoch || t('Not yet polled');
  $('#copy-epoch').disabled = !state.storeEpoch;
  $('#store-revision').textContent = store.revision !== undefined && store.revision !== null ? String(store.revision) : '—';
  $('#store-detail').textContent = store.detail || (reason ? '' : t('No failure recorded.'));
}

async function copyEpoch() {
  if (!state.storeEpoch) return;
  try {
    await navigator.clipboard.writeText(state.storeEpoch);
    toast(t('Authority epoch copied.'));
  } catch (_) {
    // Clipboard access can be denied (insecure context, permissions); select the text so a manual copy works.
    const range = document.createRange(); range.selectNodeContents($('#store-epoch'));
    const selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range);
    toast(t('Clipboard unavailable; the epoch is selected for manual copying.'), 'error');
  }
}

async function checkHealth() {
  const button = $('#check-health'); setBusy(button, true, t('Checking…'));
  const result = $('#health-result');
  try {
    const { data } = await api('/healthz');
    result.textContent = t('Healthy · {result} · {time}', { result: String(data).trim() || 'ok', time: new Date().toLocaleTimeString(getLocale()) });
    result.className = 'inline-message is-success';
  } catch (error) {
    if (error.status === 401) return logout('Your session is no longer authorized.');
    result.textContent = error.status === 503 ? t('Not ready · {detail}', { detail: error.message }) : error.message;
    result.className = 'inline-message is-error';
  } finally { setBusy(button, false); }
}

async function verifySession() {
  const button = $('#verify-session');
  const result = $('#session-result');
  setBusy(button, true, t('Verifying…'));
  try {
    const { data } = await api('/v1/auth/me');
    if (!isObject(data?.user) || !['admin', 'viewer'].includes(data.user.role)) throw new Error(t('Invalid account identity.'));
    if (isAdmin() && data.user.role !== 'admin') return logout(t('Your session is no longer authorized.'));
    state.user = data.user;
    updateAccess();
    if (!isAdmin() && state.view !== 'status') location.hash = '#status';
    message(result, t('Session valid: {username} · {role}', { username: data.user.username, role: t(data.user.role) }), 'success');
  } catch (error) {
    if (error instanceof StaleSessionError) return;
    if (error.status === 401 || error.status === 403) return logout(t('Your session is no longer authorized.'));
    message(result, error.message, 'error');
  } finally { setBusy(button, false); }
}

async function loadMetrics() {
  const button = $('#load-metrics'); setBusy(button, true, t('Loading…'));
  const output = $('#metrics-output');
  try {
    const { data } = await api('/metrics');
    output.textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
    output.hidden = false;
  } catch (error) {
    if (error.status === 401) return logout('Your session is no longer authorized.');
    output.textContent = error.message; output.hidden = false;
  } finally { setBusy(button, false); }
}

function formatBytes(value) {
  const bytes = Math.max(0, Number(value) || 0);
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let amount = bytes / 1024;
  let unit = units[0];
  for (let index = 1; amount >= 1024 && index < units.length; index++) {
    amount /= 1024;
    unit = units[index];
  }
  return `${amount.toFixed(amount >= 10 ? 0 : 1)} ${unit}`;
}

async function loadCache(force) {
  const sequence = ++state.cacheLoadSequence;
  if (state.cachePolicyDirty && !force) {
    const { data } = await api('/v1/cache');
    if (sequence !== state.cacheLoadSequence) return;
    state.cacheRuntime = data;
    renderCache(data);
    return;
  }
  const [{ data: runtime }, latest] = await Promise.all([api('/v1/cache'), api('/v1/config')]);
  // A newer edit, load, or write supersedes this response. Never replace an active draft.
  if (sequence !== state.cacheLoadSequence) return;
  state.cacheRuntime = runtime;
  if (!state.configDirty) {
    state.config = latest.data;
    state.configEtag = latest.etag || `"${latest.data.revision}"`;
    showConfigDocument(latest.data);
    setRevision(latest.data.revision);
  }
  showCachePolicy(latest.data.cache ?? null);
  message($('#cache-message'));
  renderCache(runtime);
}

/** Put an active policy into the editor and its generation field; the draft is clean afterwards. */
function showCachePolicy(policy) {
  const editor = $('#cache-policy-editor');
  editor.value = JSON.stringify(policy, null, 2);
  editor.setAttribute('aria-invalid', 'false');
  const generation = $('#cache-generation-input');
  generation.value = isObject(policy) && policy.generation !== undefined && policy.generation !== null ? String(policy.generation) : '';
  generation.setAttribute('aria-invalid', 'false');
  state.cachePolicyDirty = false;
  $('#cache-policy-dirty').hidden = true;
  refreshCacheToggle(policy);
}

function refreshCacheToggle(policy) {
  const button = $('#toggle-cache-policy');
  if (!button || (button.disabled && button.dataset.label)) return;
  button.disabled = !policy;
  button.textContent = t(policy?.enabled === false || !policy ? 'Activate cache' : 'Deactivate cache');
}

function renderCache(data) {
  $('#cache-loading').hidden = true;
  $('#cache-content').hidden = false;
  const stats = data.stats || {};
  const definitions = [
    [t('Memory'), formatBytes(stats.memory_bytes), t('{count} entries', { count: formatNumber(stats.memory_entries) }), ''],
    [t('Disk'), formatBytes(stats.disk_bytes), t('{count} entries', { count: formatNumber(stats.disk_entries) }), ''],
    [t('Hits'), stats.hits, t('Served from cache'), 'is-good'],
    [t('Misses'), stats.misses, t('Fetched upstream'), ''],
    [t('Evictions'), stats.evictions, t('Capacity or expiry'), ''],
    [t('Errors'), stats.errors, t('Cache operation failures'), Number(stats.errors) ? 'is-error' : ''],
  ];
  $('#cache-metric-grid').replaceChildren(...definitions.map(([label, value, note, style]) => {
    const card = document.createElement('article'); card.className = `metric ${style}`.trim();
    const head = document.createElement('span'); head.className = 'metric-label'; head.textContent = label;
    const number = document.createElement('strong'); number.className = 'metric-value'; number.textContent = typeof value === 'number' ? formatNumber(value) : value;
    const detail = document.createElement('span'); detail.className = 'metric-note'; detail.textContent = note;
    card.append(head, number, detail); return card;
  }));
  const config = data.config;
  $('#cache-state').textContent = data.enabled ? t('Enabled') : t('Disabled');
  $('#cache-state').style.color = data.enabled ? 'var(--green)' : 'var(--muted)';
  $('#cache-memory-policy').textContent = config ? `${formatBytes(config.memory?.max_bytes)} · ${config.memory?.eviction || 'lru'}` : '—';
  $('#cache-disk-policy').textContent = config?.disk ? `${formatBytes(config.disk.max_bytes)} · ${config.disk.eviction || 'lru'}` : t('Disabled');
  $('#cache-active-fills').textContent = formatNumber(data.active_fills);
  // The live generation is only meaningful while a runtime exists; the field mirrors the configured value.
  $('#cache-generation').textContent = data.enabled && data.generation !== undefined && data.generation !== null ? String(data.generation) : data.enabled ? '—' : t('No cache');
  $('#purge-cache').disabled = !data.enabled;
}

/**
 * Cache policy draft: the JSON editor (whole `cache` object, or null) plus a numeric generation
 * field mirrored into it. The field is authoritative for `generation` while it holds a value.
 */
function parseCachePolicy() {
  const editor = $('#cache-policy-editor');
  let value;
  try { value = JSON.parse(editor.value); }
  catch (error) { editor.setAttribute('aria-invalid', 'true'); throw new Error(t('Invalid cache policy JSON: {detail}', { detail: error.message })); }
  if (value !== null && (Array.isArray(value) || typeof value !== 'object')) {
    editor.setAttribute('aria-invalid', 'true');
    throw new Error(t('Cache policy must be a JSON object or null.'));
  }
  editor.setAttribute('aria-invalid', 'false');
  const generation = parseCacheGeneration();
  if (value !== null && generation !== null) value.generation = generation;
  if (value !== null && value.generation !== undefined && !isValidGeneration(value.generation)) {
    editor.setAttribute('aria-invalid', 'true');
    throw new Error(t('Cache generation must be a whole number 0–{maximum}.', { maximum: MAX_GENERATION }));
  }
  return value;
}

function isValidGeneration(value) { return Number.isInteger(value) && value >= 0 && value <= MAX_GENERATION; }

/** The generation field: null when blank (the JSON keeps its value), otherwise a validated integer. */
function parseCacheGeneration() {
  const field = $('#cache-generation-input');
  const raw = field.value.trim();
  if (!raw) { field.setAttribute('aria-invalid', 'false'); return null; }
  if (!/^\d+$/.test(raw) || Number(raw) > MAX_GENERATION) {
    field.setAttribute('aria-invalid', 'true');
    throw new Error(t('Cache generation must be a whole number 0–{maximum}.', { maximum: MAX_GENERATION }));
  }
  field.setAttribute('aria-invalid', 'false');
  return Number(raw);
}

function cachePolicyInput() {
  state.cacheLoadSequence++;
  state.cachePolicyDirty = true;
  $('#cache-policy-dirty').hidden = false;
  message($('#cache-message'));
  // Keep the generation field in step with a hand-edited document without rewriting the editor.
  try {
    const value = JSON.parse($('#cache-policy-editor').value);
    const field = $('#cache-generation-input');
    if (isObject(value) && isValidGeneration(value.generation)) field.value = String(value.generation);
    else if (value === null || (isObject(value) && value.generation === undefined)) field.value = '';
  } catch (_) { /* the editor is mid-edit; the field keeps its value */ }
}

function cacheGenerationInput() {
  state.cacheLoadSequence++;
  state.cachePolicyDirty = true;
  $('#cache-policy-dirty').hidden = false;
  message($('#cache-message'));
  // Mirror a valid field value into the document so the JSON shown is what will be published.
  let generation;
  try { generation = parseCacheGeneration(); } catch (error) { return message($('#cache-message'), error.message, 'error'); }
  try {
    const editor = $('#cache-policy-editor');
    const value = JSON.parse(editor.value);
    if (!isObject(value)) return;
    if (generation === null) delete value.generation; else value.generation = generation;
    editor.value = JSON.stringify(value, null, 2);
    editor.setAttribute('aria-invalid', 'false');
  } catch (_) { /* invalid JSON is reported on apply */ }
}

function formatCachePolicy() {
  try {
    $('#cache-policy-editor').value = JSON.stringify(parseCachePolicy(), null, 2);
    cachePolicyInput();
  } catch (error) { message($('#cache-message'), error.message, 'error'); }
}

function cachePolicyTemplate() {
  // A template keeps the fleet's current generation: resetting it to 0 would itself be an invalidation.
  let generation = 0;
  try { generation = parseCacheGeneration() ?? state.cacheRuntime?.generation ?? 0; } catch (_) { generation = state.cacheRuntime?.generation ?? 0; }
  if (!isValidGeneration(generation)) generation = 0;
  $('#cache-policy-editor').value = JSON.stringify({ memory: { max_bytes: 67108864, max_entries: 10000, eviction: 'lru' }, disk: null, max_object_bytes: 1048576, max_fills: 32, fill_timeout_ms: 5000, generation }, null, 2);
  $('#cache-policy-editor').setAttribute('aria-invalid', 'false');
  cachePolicyInput();
}

/**
 * The write endpoints answer a rejected document with a deliberately generic 422.
 * Re-validating the same draft returns the precise reason as `detail`.
 */
async function validationDetail(draft, fallback) {
  try {
    await api('/v1/config/validate', { method: 'POST', json: draft });
    return `${fallback} ${t('The document passes validation, so activation failed at runtime (for example a TCP listener could not bind or a file could not be read). Check the server log, reload the current revision and retry.')}`;
  } catch (error) {
    if ((error.status === 422 || error.status === 400) && error.message) return error.message;
    return fallback;
  }
}

function isRejection(error) { return error.status === 422 || (error.status === 400 && String(error.message || '').includes('invalid configuration JSON')); }

async function applyCachePolicy() {
  const button = $('#apply-cache-policy');
  state.cacheLoadSequence++;
  message($('#cache-message'));
  let policy;
  try { policy = parseCachePolicy(); }
  catch (error) { return message($('#cache-message'), error.message, 'error'); }
  if (state.configDirty) {
    return message($('#cache-message'), t('The Configuration view has an unsaved document. Apply it or reload it before changing the cache policy.'), 'error');
  }
  setBusy(button, true, t('Applying…'));
  let next = null;
  try {
    const latest = await api('/v1/config');
    next = structuredClone(latest.data);
    next.cache = policy;
    const result = await api('/v1/config', { method: 'PUT', headers: { 'If-Match': latest.etag || `"${latest.data.revision}"` }, json: next });
    state.cacheLoadSequence++;
    state.config = result.data;
    state.configEtag = result.etag || `"${result.data.revision}"`;
    state.configDirty = false;
    showConfigDocument(result.data);
    $('#config-dirty').hidden = true;
    showCachePolicy(result.data.cache ?? null);
    setRevision(result.data.revision);
    let refreshDetail = '';
    try {
      const runtime = await api('/v1/cache');
      state.cacheRuntime = runtime.data;
      renderCache(runtime.data);
    } catch (_) { refreshDetail = t(' Runtime usage could not be refreshed.'); }
    message($('#cache-message'), t('Cache policy is active in revision {revision}.{detail}', { revision: result.data.revision, detail: refreshDetail }), 'success');
    toast(t('Cache policy applied.'));
  } catch (error) {
    if (isRevisionConflict(error)) message($('#cache-message'), t('The configuration changed while the cache policy was being applied. Your cache draft is preserved; review and apply again.'), 'error');
    else if (isIndeterminate(error)) message($('#cache-message'), error.message, 'error', { label: t('Reload current revision'), run: () => rebaseCacheDraft(policy) });
    else if (next && isRejection(error)) message($('#cache-message'), await validationDetail(next, error.message), 'error');
    else message($('#cache-message'), error.message, 'error');
  } finally { setBusy(button, false); }
}

async function toggleCachePolicy() {
  const button = $('#toggle-cache-policy');
  if (state.configDirty || state.cachePolicyDirty) return message($('#cache-message'), t('Apply or reload unsaved configuration and cache drafts before changing cache activation.'), 'error');
  state.cacheLoadSequence++;
  setBusy(button, true, t('Updating cache…'));
  message($('#cache-message'));
  try {
    const latest = await api('/v1/config');
    if (!latest.data.cache) throw new Error(t('Create a cache policy before activating it.'));
    const draft = structuredClone(latest.data);
    const enabled = draft.cache.enabled === false;
    if (enabled) delete draft.cache.enabled; else draft.cache.enabled = false;
    const result = await api('/v1/config', { method: 'PUT', headers: { 'If-Match': latest.etag || `"${latest.data.revision}"` }, json: draft });
    state.cacheLoadSequence++;
    state.config = result.data;
    state.configEtag = result.etag || `"${result.data.revision}"`;
    showConfigDocument(result.data);
    showCachePolicy(result.data.cache);
    setRevision(result.data.revision);
    let detail = '';
    try { const runtime = await api('/v1/cache'); state.cacheRuntime = runtime.data; renderCache(runtime.data); }
    catch (_) { detail = t(' Runtime usage could not be refreshed.'); }
    message($('#cache-message'), t(enabled ? 'Cache activated in revision {revision}.{detail}' : 'Cache deactivated in revision {revision}.{detail}', { revision: result.data.revision, detail }), 'success');
  } catch (error) {
    if (error instanceof StaleSessionError) return;
    if (error.status === 401 || error.status === 403) return logout(t('Your session is no longer authorized.'));
    if (isRevisionConflict(error) || isIndeterminate(error)) {
      try { await loadCache(true); } catch (_) { /* keep the original error */ }
    }
    message($('#cache-message'), isRevisionConflict(error) ? t('The configuration changed on the server. Reloaded cache policy; review its current state before retrying.') : isIndeterminate(error) ? t('The cache activation outcome is unknown. Reloaded cache policy; verify its current state before retrying.') : error.message, 'error');
  } finally { setBusy(button, false); refreshCacheToggle(state.config?.cache ?? null); }
}

/**
 * After an indeterminate write: adopt the server's current revision as the comparison base, keep the
 * draft, and say whether the write landed (the active policy equals the draft) so a retry is informed.
 */
async function rebaseCacheDraft(draft) {
  try {
    const [{ data: runtime }, latest] = await Promise.all([api('/v1/cache'), api('/v1/config')]);
    state.cacheRuntime = runtime; renderCache(runtime);
    adoptConfig(latest);
    const active = latest.data.cache ?? null;
    if (JSON.stringify(active) === JSON.stringify(draft)) {
      showCachePolicy(active);
      message($('#cache-message'), t('Revision {revision} already holds this cache policy: the write was applied.', { revision: latest.data.revision }), 'success');
    } else {
      message($('#cache-message'), t('Revision {revision} is active and its cache policy differs from your draft: the write was not applied. Your draft is preserved; review and apply again.', { revision: latest.data.revision }), 'warning');
    }
  } catch (error) { message($('#cache-message'), error.message, 'error'); }
}

/** Adopt a freshly fetched configuration as the console's base (revision, ETag, clean editors) without discarding drafts. */
function adoptConfig(latest) {
  state.config = latest.data;
  state.configEtag = latest.etag || `"${latest.data.revision}"`;
  setRevision(latest.data.revision);
  if (!state.configDirty) showConfigDocument(latest.data);
  else updateConfigPreview();
  if (!state.cachePolicyDirty) showCachePolicy(latest.data.cache ?? null);
  if (!state.certificateDirty) { $('#certificate-editor').value = JSON.stringify(latest.data.certificates ?? [], null, 2); $('#certificate-editor').setAttribute('aria-invalid', 'false'); }
}

async function purgeCache() {
  const fleet = state.configurationSource === 'shared';
  const accepted = await confirmDialog({
    title: fleet ? t('Purge the cache fleet-wide?') : t('Purge the cache?'),
    body: fleet
      ? t('The shared configuration’s cache.generation is raised through a compare-and-swap, publishing a new revision; every instance drops its memory and disk entries when it activates that revision. Clients are served from upstream until entries are refilled.')
      : t('Every cached response is removed from this instance’s memory and disk. Clients are served from upstream until entries are refilled.'),
    accept: t('Purge'),
  });
  if (!accepted) return;
  const button = $('#purge-cache'); setBusy(button, true, t('Purging…'));
  try {
    const { data, etag } = await api('/v1/cache/purge', { method: 'POST' });
    const scope = data?.scope === 'fleet' ? 'fleet' : 'instance';
    let text;
    if (scope === 'fleet') {
      if (data.generation === null || data.generation === undefined) text = t('Fleet purge: no cache policy is configured, so there was nothing to invalidate.');
      else text = t('Fleet purge published: generation {generation} in revision {revision}. Every instance drops its entries when it activates this revision.', { generation: data.generation, revision: data.revision });
      // A fleet purge is a configuration change: the revision and ETag the console holds advance with it.
      if (data.revision !== undefined && data.revision !== null) {
        try { adoptConfig(await api('/v1/config')); }
        catch (_) { state.configEtag = etag || `"${data.revision}"`; setRevision(data.revision); text += t(' The updated configuration could not be reloaded; reload it before editing.'); }
      }
    } else text = t('Instance purge applied: this process cleared its memory and disk tiers.');
    try {
      const runtime = await api('/v1/cache');
      state.cacheRuntime = runtime.data; renderCache(runtime.data);
    } catch (_) { text += t(' Runtime usage could not be refreshed.'); }
    message($('#cache-message'), text, 'success');
    toast(scope === 'fleet' ? t('Fleet cache purge published.') : t('Cache purged.'));
  } catch (error) {
    if (isIndeterminate(error)) message($('#cache-message'), error.message, 'error', { label: t('Reload current revision'), run: reloadCacheBase });
    else message($('#cache-message'), error.message, 'error');
  }
  finally { setBusy(button, false); }
}

/** Reload the live cache state and the configuration base after a purge whose outcome is unknown. */
async function reloadCacheBase() {
  try {
    const [{ data: runtime }, latest] = await Promise.all([api('/v1/cache'), api('/v1/config')]);
    state.cacheRuntime = runtime; renderCache(runtime);
    adoptConfig(latest);
    const generation = latest.data.cache?.generation;
    message($('#cache-message'), t('Reloaded revision {revision}{generation}. Compare the generation with the value before the purge to see whether it was applied.', { revision: latest.data.revision, generation: generation !== undefined ? t(' (cache generation {generation})', { generation }) : '' }), 'success');
  } catch (error) { message($('#cache-message'), error.message, 'error'); }
}

function startStatusPolling() {
  stopStatusPolling();
  if (!state.token || state.view !== 'status' || document.hidden) return;
  startLive(state.token, renderStatus, () => logout('Your session is no longer authorized.'), isAdmin());
  state.statusTimer = setInterval(() => { if (isLive()) return; loadStatus().catch((error) => {
    if (error.status === 401) logout('Your session is no longer authorized.');
    else setConnection(false, 'Unreachable');
  }); }, 5000);
}
function stopStatusPolling() { stopLive(); if (state.statusTimer) clearInterval(state.statusTimer); state.statusTimer = null; }

function acceptWorkloadMaterials(status) {
  state.workloadMaterials = Array.isArray(status?.workload_materials)
    ? status.workload_materials.filter((item) => item && ['http', 'tcp'].includes(item.kind) && typeof item.id === 'string' && typeof item.ready === 'boolean')
    : null;
  state.workloadMaterialsRevision = status?.revision ?? null;
  refreshWorkloadMaterialBadges();
}

function materialState(kind, id) {
  const revision = kind === 'http' ? state.config?.revision : state.tcpRoutesRevision;
  const active = kind === 'http'
    ? state.config?.workload_http?.find((item) => item.id === id)
    : state.routes.tcp.find((item) => item.id === id);
  if (!active) return 'unknown';
  if (active.enabled === false) return 'inactive';
  if (revision === undefined || revision === null || revision !== state.workloadMaterialsRevision || !state.workloadMaterials) return 'unknown';
  const slot = state.workloadMaterials.find((item) => item.kind === kind && item.id === id);
  return slot ? (slot.ready ? 'ready' : 'blocked') : 'unknown';
}

function refreshWorkloadMaterialBadges() {
  for (const badge of $$('[data-workload-material-kind]')) {
    const condition = materialState(badge.dataset.workloadMaterialKind, badge.dataset.workloadMaterialId);
    badge.textContent = t({ ready: 'Current runtime: ready', blocked: 'Current runtime: blocked', inactive: 'Current runtime: inactive', unknown: 'Current runtime: unknown' }[condition]);
    badge.dataset.materialState = condition;
  }
}

async function refreshWorkloadMaterialStatus() {
  if (!state.token || document.hidden || !['config', 'tcp'].includes(state.view)) return;
  state.workloadMaterialAbort?.abort();
  const controller = new AbortController();
  state.workloadMaterialAbort = controller;
  try {
    const { data } = await api('/v1/status', { signal: controller.signal });
    if (controller.signal.aborted) return;
    acceptWorkloadMaterials(data);
  } catch (error) {
    if (controller.signal.aborted || error instanceof StaleSessionError || !state.token) return;
    if (error.status === 401) return logout(t('Your session is no longer authorized.'));
    state.workloadMaterials = null;
    refreshWorkloadMaterialBadges();
  } finally {
    if (state.workloadMaterialAbort === controller) state.workloadMaterialAbort = null;
  }
}

function startWorkloadMaterialPolling() {
  stopWorkloadMaterialPolling();
  if (!state.token || document.hidden || !['config', 'tcp'].includes(state.view)) return;
  state.workloadMaterialTimer = setInterval(refreshWorkloadMaterialStatus, 5000);
}

function stopWorkloadMaterialPolling() {
  if (state.workloadMaterialTimer) clearInterval(state.workloadMaterialTimer);
  state.workloadMaterialTimer = null;
  state.workloadMaterialAbort?.abort();
  state.workloadMaterialAbort = null;
}

async function loadRoutes(type) {
  const root = $(`#${type}-routes`);
  root.replaceChildren(loadingNode('Loading routes…'));
  try {
    const { data, etag } = await api(`/v1/routes/${type}`);
    state.routes[type] = Array.isArray(data) ? data : (data?.routes || []);
    state.routeEtags[type] = etag || (data?.revision !== undefined ? `"${data.revision}"` : null);
    if (type === 'tcp') state.tcpRoutesRevision = data?.revision ?? null;
    if (data?.revision !== undefined) setRevision(data.revision);
    renderRoutes(type);
  } catch (error) {
    if (error instanceof StaleSessionError || !state.token) return;
    root.replaceChildren(errorNode(error.message, () => loadRoutes(type)));
    throw error;
  }
}

function loadingNode(text) {
  const el = document.createElement('div'); el.className = 'loading-panel';
  const spinner = document.createElement('span'); spinner.className = 'spinner'; el.append(spinner, t(text)); return el;
}
function emptyNode(title, text, buttonText, action) {
  const el = document.createElement('div'); el.className = 'empty-state';
  const box = document.createElement('div'); const h = document.createElement('h2'); copy(h, title); const p = document.createElement('p'); copy(p, text); box.append(h, p);
  if (buttonText) { const b = document.createElement('button'); b.className = 'button button-primary'; copy(b, buttonText); b.addEventListener('click', action); box.append(b); }
  el.append(box); return el;
}
function errorNode(text, retry) {
  const el = document.createElement('div'); el.className = 'error-state'; const box = document.createElement('div');
  const h = document.createElement('h2'); h.textContent = t('Could not load this view'); const p = document.createElement('p'); p.textContent = text; const b = document.createElement('button'); b.className = 'button button-secondary'; b.textContent = t('Try again'); b.addEventListener('click', retry); box.append(h,p,b); el.append(box); return el;
}

function renderRoutes(type) {
  const root = $(`#${type}-routes`);
  if (!state.routes[type].length) {
    root.replaceChildren(emptyNode(`No ${type.toUpperCase()} routes`, 'Create the first route to begin forwarding traffic.', `New ${type.toUpperCase()} route`, () => openRoute(type)));
    return;
  }
  const settings = state.routeInventory[type];
  const inventory = document.createElement('div'); inventory.className = 'route-inventory';
  const toolbar = document.createElement('div'); toolbar.className = 'route-toolbar';
  const search = document.createElement('input'); search.type = 'search'; search.className = 'route-search'; search.placeholder = t('Search host, ID, or upstream'); search.setAttribute('aria-label', t('Search {type} routes', { type: type.toUpperCase() })); search.value = settings.query;
  const policy = routeSelect('route-policy-filter', t('Filter {type} route policies', { type: type.toUpperCase() }), type === 'http'
    ? [['all', 'All policies'], ['domains', 'Domain groups'], ['tls', 'TLS required'], ['auth', 'Authentication'], ['cache', 'Cache'], ['network', 'Network restrictions'], ['advanced', 'Lua or transform'], ['upstream', 'Upstream options']]
    : [['all', 'All policies'], ['sni', 'SNI matching'], ['tls', 'Upstream TLS'], ['network', 'Network restrictions'], ['upstream', 'Upstream options']], settings.policy);
  const sort = routeSelect('route-sort', t('Sort {type} routes', { type: type.toUpperCase() }), [['priority-desc', 'Priority: high to low'], ['priority-asc', 'Priority: low to high'], ['match-asc', 'Match: A to Z'], ['match-desc', 'Match: Z to A'], ['id-asc', 'ID: A to Z'], ['id-desc', 'ID: Z to A'], ['upstream-asc', 'Upstream: A to Z']], settings.sort);
  const pageSize = routeSelect('route-page-size', 'Rows per page', [[25, '25 per page'], [50, '50 per page'], [100, '100 per page']], settings.pageSize);
  const count = document.createElement('span'); count.className = 'route-count'; count.setAttribute('role', 'status'); count.setAttribute('aria-live', 'polite');
  toolbar.append(search, policy, sort, pageSize, count);
  const content = document.createElement('div'); content.className = 'route-results';
  const pagination = document.createElement('nav'); pagination.className = 'route-pagination'; pagination.setAttribute('aria-label', t('{type} route pages', { type: type.toUpperCase() }));
  inventory.append(toolbar, content, pagination); root.replaceChildren(inventory);
  const refresh = () => updateRouteInventory(type, content, pagination, count);
  search.addEventListener('input', () => { settings.query = search.value; settings.page = 1; refresh(); });
  policy.addEventListener('change', () => { settings.policy = policy.value; settings.page = 1; refresh(); });
  sort.addEventListener('change', () => { settings.sort = sort.value; settings.page = 1; refresh(); });
  pageSize.addEventListener('change', () => { settings.pageSize = Number(pageSize.value); settings.page = 1; refresh(); });
  refresh();
}

function routeSelect(className, label, options, selected) {
  const select = document.createElement('select'); select.className = className; select.setAttribute('aria-label', t(label));
  for (const [value, text] of options) { const option = document.createElement('option'); option.value = String(value); option.textContent = t(text); select.append(option); }
  select.value = String(selected);
  return select;
}

function routeMatch(type, route) {
  if (type === 'http') {
    if (route.host_regex) return t('Regex: {pattern}', { pattern: route.host_regex });
    if (route.hosts?.length) return route.hosts.length > 2
      ? t('{hosts} +{count} more hosts', { hosts: route.hosts.slice(0, 2).join(', '), count: route.hosts.length - 2 })
      : route.hosts.join(', ');
    return route.host || '*';
  }
  const names = [...(route.sni?.hosts || []), ...(route.sni?.host_regexes || []).map((name) => t('Regex: {pattern}', { pattern: name }))];
  return names.length ? names.join(', ') : (route.listen || t('Any TCP'));
}

function backendAddress(backend) { return typeof backend === 'string' ? backend : backend?.address || ''; }

function routeSearchText(type, route) {
  return [route.id, routeMatch(type, route), ...(route.hosts || []), route.listen, route.path_prefix, route.upstream_host,
    route.upstream?.connect_address, route.upstream?.unix_socket, ...(route.backends || []).flatMap((backend) => [backendAddress(backend), backend?.id])].filter(Boolean).join(' ').toLowerCase();
}

function routeHasPolicy(type, route, policy) {
  if (policy === 'all') return true;
  if (policy === 'network') return Boolean(route.deny_cidrs?.length || route.max_requests || route.max_connections);
  if (policy === 'upstream') return Boolean(route.upstream?.tls || route.upstream?.socks5 || route.upstream?.connect_address || route.upstream?.unix_socket || route.upstream?.dns_servers?.length);
  if (type === 'http') {
    if (policy === 'domains') return Boolean(route.hosts?.length);
    if (policy === 'tls') return Boolean(route.require_tls);
    if (policy === 'auth') return Boolean(route.auth || route.basic_auth || route.jwt_auth || route.workload_auth);
    if (policy === 'cache') return Boolean(route.cache);
    if (policy === 'advanced') return Boolean(route.lua || route.request_transform || route.response_transform);
  } else {
    if (policy === 'sni') return Boolean(route.sni?.hosts?.length || route.sni?.host_regexes?.length);
    if (policy === 'tls') return Boolean(route.upstream?.tls);
  }
  return false;
}

function updateRouteInventory(type, content, pagination, count) {
  const settings = state.routeInventory[type];
  const query = settings.query.trim().toLowerCase();
  const matches = state.routes[type].map((route, index) => ({ route, index }))
    .filter(({ route }) => routeHasPolicy(type, route, settings.policy) && (!query || routeSearchText(type, route).includes(query)));
  const compareText = (a, b) => String(a || '').localeCompare(String(b || ''), 'en', { sensitivity: 'base', numeric: true });
  matches.sort((a, b) => {
    let order = 0;
    if (settings.sort.startsWith('priority')) order = (Number(a.route.priority) || 0) - (Number(b.route.priority) || 0);
    else if (settings.sort.startsWith('match')) order = compareText(routeMatch(type, a.route), routeMatch(type, b.route));
    else if (settings.sort.startsWith('id')) order = compareText(a.route.id, b.route.id);
    else if (settings.sort.startsWith('upstream')) order = compareText(backendAddress(a.route.backends?.[0]), backendAddress(b.route.backends?.[0]));
    if (settings.sort.endsWith('desc')) order = -order;
    return order || a.index - b.index;
  });
  const pages = Math.max(1, Math.ceil(matches.length / settings.pageSize));
  settings.page = Math.min(settings.page, pages);
  const start = (settings.page - 1) * settings.pageSize;
  const visible = matches.slice(start, start + settings.pageSize);
  const total = state.routes[type].length;
  count.textContent = matches.length === total ? t(total === 1 ? '{count} route' : '{count} routes', { count: total }) : t('{matching} of {total} routes', { matching: matches.length, total });
  if (!matches.length) {
    const empty = document.createElement('div'); empty.className = 'route-empty empty-state';
    const title = document.createElement('h2'); title.textContent = t('No matching routes');
    const detail = document.createElement('p'); detail.textContent = t('Try another host, ID, upstream, or policy.');
    const clear = document.createElement('button'); clear.type = 'button'; clear.className = 'button button-secondary'; clear.textContent = t('Clear filters');
    clear.addEventListener('click', () => { settings.query = ''; settings.policy = 'all'; renderRoutes(type); $(`.route-search`, rootForRoute(type)).focus(); });
    empty.append(title, detail, clear); content.replaceChildren(empty);
  } else {
    const wrap = document.createElement('div'); wrap.className = 'route-table-wrap';
    const table = document.createElement('table'); table.className = 'route-table'; table.setAttribute('aria-label', t('{type} route inventory', { type: type.toUpperCase() }));
    const thead = document.createElement('thead'); const heading = document.createElement('tr');
    for (const label of ['Route', 'Match', 'Upstream', 'Policy', 'Priority', 'Action']) { const th = document.createElement('th'); th.scope = 'col'; th.textContent = t(label); heading.append(th); }
    thead.append(heading);
    const tbody = document.createElement('tbody'); tbody.append(...visible.map(({ route }) => routeRow(type, route)));
    table.append(thead, tbody); wrap.append(table); content.replaceChildren(wrap);
  }
  pagination.replaceChildren();
  if (matches.length) {
    const range = document.createElement('span'); range.className = 'route-page-range'; range.textContent = t('Showing {start}–{end} of {count} · page {page} of {pages}', { start: start + 1, end: start + visible.length, count: matches.length, page: settings.page, pages });
    const previous = document.createElement('button'); previous.type = 'button'; previous.className = 'button button-secondary route-page-prev'; previous.textContent = t('Previous'); previous.disabled = settings.page === 1;
    const next = document.createElement('button'); next.type = 'button'; next.className = 'button button-secondary route-page-next'; next.textContent = t('Next'); next.disabled = settings.page === pages;
    previous.addEventListener('click', () => { settings.page -= 1; updateRouteInventory(type, content, pagination, count); });
    next.addEventListener('click', () => { settings.page += 1; updateRouteInventory(type, content, pagination, count); });
    pagination.append(range, previous, next);
  }
  if (type === 'tcp') refreshWorkloadMaterialBadges();
}

function rootForRoute(type) { return $(`#${type}-routes`); }

function routeSummaryTags(type, route) {
  const tags = [];
  if (route.enabled === false) tags.push(t('Disabled'));
  if (type === 'http') {
    if (['public', 'application', 'protected'].includes(route.access_mode)) tags.push(t('Access: {mode}', { mode: t(route.access_mode) }));
    if (route.require_tls) tags.push(t('TLS required'));
    if (route.path_match && route.path_match !== 'prefix') tags.push(t('Path {mode}', { mode: route.path_match }));
    if (route.auth) tags.push(t('External auth'));
    if (route.basic_auth) tags.push(t('Basic auth'));
    if (route.jwt_auth) tags.push(t('JWT access token'));
    if (route.workload_auth) tags.push(t('Workload mTLS'));
    if (route.cache) tags.push(t('Cache {seconds}s', { seconds: route.cache.ttl_seconds ?? '?' }));
    if (route.retries) tags.push(t('Retries {count}', { count: route.retries }));
    if (route.upstream_timeout_ms) tags.push(t('Timeout {milliseconds} ms', { milliseconds: route.upstream_timeout_ms }));
    if (route.balance?.mode && route.balance.mode !== 'round_robin') tags.push(t(route.balance.mode.replace('_', ' ')));
    if (route.request_transform || route.response_transform) tags.push(t('Body transform'));
    if (route.lua) tags.push('Lua');
  }
  if (route.max_requests) tags.push(t('Max {count} requests', { count: route.max_requests }));
  if (route.max_connections) tags.push(t('Max {count} connections', { count: route.max_connections }));
  if (route.upstream?.tls) tags.push(t('Upstream TLS'));
  if (type === 'tcp' && route.inbound_tls) tags.push(t('Inbound mTLS'));
  if (route.upstream?.socks5) tags.push('SOCKS5');
  if ((route.deny_cidrs || []).length) tags.push(t(route.deny_cidrs.length === 1 ? '{count} denied CIDR' : '{count} denied CIDRs', { count: route.deny_cidrs.length }));
  return tags;
}

function routeRow(type, route) {
  const row = document.createElement('tr'); row.className = 'route-row route-card'; row.dataset.routeId = route.id || '';
  const cell = (primary, secondary = '') => { const td = document.createElement('td'); const main = document.createElement('span'); main.className = 'route-cell-main'; main.textContent = primary; td.append(main); if (secondary) { const detail = document.createElement('small'); detail.className = 'route-cell-detail'; detail.textContent = secondary; td.append(detail); } return td; };
  const identity = document.createElement('th'); identity.scope = 'row'; const title = document.createElement('h2'); title.className = 'route-cell-main'; title.textContent = route.id || t('(unnamed)'); const state = document.createElement('small'); state.className = 'route-cell-detail'; state.textContent = route.enabled === false ? t('Disabled') : t('Enabled'); identity.append(title, state);
  if (type === 'tcp' && route.inbound_tls) {
    const material = document.createElement('small'); material.className = 'route-cell-detail workload-material-state';
    material.dataset.workloadMaterialKind = 'tcp'; material.dataset.workloadMaterialId = route.id;
    identity.append(material);
  }
  const match = routeMatch(type, route);
  const matchDetail = type === 'http' ? `${route.path_match === 'exact' ? t('Exact ') : ''}${route.path_prefix || '/'}` : (route.sni ? t('Listen {address}', { address: route.listen || '—' }) : t('Any TCP connection'));
  const backends = route.backends || [];
  const upstream = cell(backendAddress(backends[0]) || '—', backends.length > 1 ? t(backends.length === 2 ? '+{count} more backend' : '+{count} more backends', { count: backends.length - 1 }) : ''); upstream.className = 'route-upstream-cell';
  const policy = document.createElement('td'); policy.className = 'route-policy-cell'; const tags = routeSummaryTags(type, route); if (type === 'tcp' && route.sni) tags.unshift('SNI');
  policy.append(...tags.slice(0, 3).map(tagNode)); if (tags.length > 3) policy.append(tagNode(`+${tags.length - 3}`)); if (!tags.length) policy.textContent = '—';
  const action = document.createElement('td'); const edit = document.createElement('button'); edit.className = 'button button-secondary'; edit.type = 'button'; edit.textContent = t('Edit'); edit.addEventListener('click', () => openRoute(type, route)); action.append(edit);
  if (isAdmin()) { const toggle = document.createElement('button'); toggle.className = 'button button-quiet route-toggle'; toggle.type = 'button'; toggle.textContent = t(route.enabled === false ? 'Activate' : 'Deactivate'); toggle.addEventListener('click', () => setRouteEnabled(type, route.id, route.enabled === false, toggle)); action.append(toggle); }
  row.append(identity, cell(match, matchDetail), upstream, policy, cell(String(route.priority ?? 0)), action);
  return row;
}
function tagNode(text) { const tag = document.createElement('span'); tag.className = 'tag'; tag.textContent = text; return tag; }

function routeDefaults(type) {
  if (type === 'http') {
    return {
      id: '', priority: 0, host: null, host_regex: null, upstream: structuredClone(DEFAULT_UPSTREAM), upstream_host: null, preserve_host: false,
      max_requests: null, upstream_timeout_ms: null, retries: 0, require_tls: false, cache: null, path_prefix: '/', path_match: 'prefix',
      headers: {}, json: {}, backends: ['http://127.0.0.1:8080'], deny_cidrs: [], lua: null, request_transform: null, response_transform: null,
      auth: null, basic_auth: null, jwt_auth: null, workload_auth: null, balance: { mode: 'round_robin', weights: [], health: null }, response_set_headers: {}, response_remove_headers: [],
    };
  }
  return { id: '', priority: 0, upstream: structuredClone(DEFAULT_UPSTREAM), sni: null, inbound_tls: null, max_connections: null, listen: '0.0.0.0:9001', backends: ['127.0.0.1:8080'], deny_cidrs: [] };
}

async function setRouteEnabled(type, id, enabled, button) {
  const path = `/v1/routes/${type}/${encodeURIComponent(id)}`;
  setBusy(button, true, t(enabled ? 'Activating…' : 'Deactivating…'));
  try {
    // Fetch the entire current route immediately before the CAS write. A list
    // row may be stale and must never replace newer auth or upstream settings.
    const latest = await api(path);
    if ((latest.data.enabled !== false) !== enabled) {
      const etag = latest.etag || state.routeEtags[type];
      if (!etag) throw new Error(t('The current route revision is unavailable. Reload routes before changing it.'));
      const draft = structuredClone(latest.data);
      if (enabled) delete draft.enabled; else draft.enabled = false;
      const result = await api(path, { method: 'PUT', headers: { 'If-Match': etag }, json: draft });
      if (result.etag) state.routeEtags[type] = result.etag;
      if (result.data?.revision !== undefined) setRevision(result.data.revision);
      toast(t(enabled ? '{id} activated.' : '{id} deactivated.', { id }));
    }
    await loadRoutes(type);
  } catch (error) {
    if (error instanceof StaleSessionError) return;
    if (error.status === 401 || error.status === 403) return logout(t('Your session is no longer authorized.'));
    if (isRevisionConflict(error) || isIndeterminate(error)) {
      try { await loadRoutes(type); } catch (_) { /* keep the original write error */ }
    }
    showGlobalError(isRevisionConflict(error) ? t('The route changed on the server. Reloaded routes; review its current state before retrying.') : isIndeterminate(error) ? t('The route update outcome is unknown. Reloaded routes; verify its current state before retrying.') : error.message);
  } finally { setBusy(button, false); }
}

async function openRoute(type, route = null) {
  let value = structuredClone(route || routeDefaults(type));
  let note = '';
  if (route?.id) {
    // The single-route endpoint returns the freshest document and revision ETag.
    try {
      const { data, etag } = await api(`/v1/routes/${type}/${encodeURIComponent(route.id)}`);
      if (isObject(data)) value = data;
      if (etag) state.routeEtags[type] = etag;
    } catch (error) {
      if (error.status === 401) return logout('Your session is no longer authorized.');
      note = `Showing the cached copy of this route; the server could not be asked for the latest version (${error.message}).`;
    }
  }
  state.editing = { type, originalId: route?.id || null, value };
  delete $('#route-form').dataset.invalidNative;
  copy($('#route-dialog-eyebrow'), '{type} route', { type: type.toUpperCase() });
  copy($('#route-dialog-title'), route ? 'Edit {id}' : 'New {type} route', route ? { id: route.id } : { type: type.toUpperCase() });
  copy($('#save-route'), route ? 'Save route' : 'Create route');
  $('#delete-route').hidden = !route;
  message($('#route-message'), note, note ? 'warning' : '');
  destroyLuaEditors();
  $('#route-form-fields').replaceChildren(buildRouteFields(type, value));
  applyGroupToggles($('#route-form'));
  updateBackendModeUi();
  $('#route-json').value = JSON.stringify(value, null, 2);
  $('.advanced-editor', $('#route-dialog')).open = false;
  $('#route-dialog').showModal();
  mountLuaEditors();
  $('#route-form').scrollTop = 0;
  setTimeout(() => $('[name="id"]', $('#route-form')).focus(), 0);
}

function section({ title, note, open, configured, fields }) {
  const details = document.createElement('details'); details.className = 'form-section'; details.open = Boolean(open || configured);
  const summary = document.createElement('summary');
  const name = document.createElement('span'); name.className = 'section-title'; copy(name, title); summary.append(name);
  if (configured) { const badge = document.createElement('span'); badge.className = 'section-state'; copy(badge, 'Configured'); summary.append(badge); }
  details.append(summary);
  const grid = document.createElement('div'); grid.className = 'form-grid';
  if (note) { const p = document.createElement('p'); p.className = 'section-note'; copy(p, note); grid.append(p); }
  grid.append(...fields);
  details.append(grid);
  return details;
}

function span2(element) { element.classList.add('span-2'); return element; }

function dockerButton() {
  const wrap = document.createElement('div'); wrap.className = 'button-row span-2';
  const button = document.createElement('button'); button.type = 'button'; button.className = 'button button-quiet'; copy(button, 'Resolve Docker backend…');
  button.addEventListener('click', () => { message($('#docker-message')); $('#docker-dialog').showModal(); });
  wrap.append(button); return wrap;
}

let memberControlSequence = 0;
const MEMBER_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function memberRow(member = {}, sourceIndex = -1) {
  const row = document.createElement('div'); row.className = 'backend-member-row'; row.dataset.sourceIndex = String(sourceIndex);
  const id = field('Member ID', `member_id_${++memberControlSequence}`, member.id || '', { required: true, maxlength: 64, help: 'Stable within this route; 1–64 ASCII letters, digits, dots, underscores or dashes. Starts with a letter or digit.' });
  const address = field('Member address', `member_address_${memberControlSequence}`, member.address || '', { required: true, help: 'HTTP(S) URL, host:port for TCP, or docker://container/network/port.' });
  const weight = field('Member weight', `member_weight_${memberControlSequence}`, member.weight ?? 1, { type: 'number', min: 1, max: 1000, required: true, help: '1–1,000. Weight 1 is the default.' });
  const state = field('Desired state', `member_state_${memberControlSequence}`, member.desired_state ?? 'serving', { select: [['serving', 'Serving'], ['draining', 'Draining'], ['maintenance', 'Maintenance']], help: 'Draining blocks new admissions while existing work continues. Maintenance also stops probes. These are local instance states, not a fleet drain-completion signal.' });
  id.querySelector('input').classList.add('backend-member-id');
  address.querySelector('input').classList.add('backend-member-address');
  weight.querySelector('input').classList.add('backend-member-weight');
  state.querySelector('select').classList.add('backend-member-state');
  const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'button button-quiet backend-member-remove'; copy(remove, 'Remove member');
  remove.addEventListener('click', () => { row.remove(); syncRouteJsonFromForm(); });
  row.append(id, address, weight, state, remove);
  return row;
}

function nextMemberId(rows) {
  const used = new Set([...rows.querySelectorAll('.backend-member-id')].map((input) => input.value));
  for (let number = 1; number <= 128; number++) if (!used.has(`member-${number}`)) return `member-${number}`;
  throw new Error(t('At most 128 members are allowed'));
}

function updateBackendModeUi() {
  const editor = $('#route-form .backend-editor'); if (!editor) return;
  const named = editor.dataset.mode === 'named';
  editor.querySelector('.backend-legacy').hidden = named;
  editor.querySelector('.backend-named').hidden = !named;
  editor.querySelector('.backend-legacy textarea').disabled = named;
  for (const input of editor.querySelectorAll('.backend-named input, .backend-named select')) input.disabled = !named;
  const convert = editor.querySelector('.backend-convert');
  copy(convert, named ? 'Convert to legacy addresses' : 'Convert to named members');
  const weights = $('#route-form [name="balance_weights"]');
  if (weights) { weights.disabled = named; weights.closest('.field').hidden = named; }
}

function readBackendValues(base) {
  const editor = $('#route-form .backend-editor');
  if (editor?.dataset.mode === 'invalid') throw new Error(t('Backends must be all addresses or all named members'));
  if (editor?.dataset.mode !== 'named') {
    const values = nonemptyLines($('#route-form [name="backends"]').value);
    if (values.length < 1 || values.length > 128) throw new Error(t('Backends must list 1–128 entries'));
    return values;
  }
  const rows = [...editor.querySelectorAll('.backend-member-row')];
  if (rows.length < 1 || rows.length > 128) throw new Error(t('Backends must list 1–128 entries'));
  const ids = new Set(); const addresses = new Set();
  return rows.map((row) => {
    const index = Number(row.dataset.sourceIndex);
    const previous = Number.isInteger(index) && index >= 0 && isObject(base?.[index]) ? base[index] : {};
    const id = row.querySelector('.backend-member-id').value.trim();
    const address = row.querySelector('.backend-member-address').value.trim();
    const rawWeight = row.querySelector('.backend-member-weight').value.trim();
    const desiredState = row.querySelector('.backend-member-state').value;
    if (!MEMBER_ID.test(id)) throw new Error(t('Member ID must be 1–64 ASCII characters, starting with a letter or digit'));
    if (ids.has(id)) throw new Error(t('Member IDs must be unique within a route'));
    if (!address) throw new Error(t('Member address is required'));
    if (addresses.has(address)) throw new Error(t('Member addresses must be unique within a route'));
    if (!/^\d+$/.test(rawWeight) || Number(rawWeight) < 1 || Number(rawWeight) > 1000) throw new Error(t('Member weight must be a whole number from 1 to 1,000'));
    if (!['serving', 'draining', 'maintenance'].includes(desiredState)) throw new Error(t('Choose a valid member state'));
    ids.add(id); addresses.add(address);
    const member = { ...previous, id, address };
    const weight = Number(rawWeight);
    if (weight !== 1 || Object.hasOwn(previous, 'weight')) member.weight = weight;
    if (desiredState !== 'serving' || Object.hasOwn(previous, 'desired_state')) member.desired_state = desiredState;
    return member;
  });
}

function syncBackendControlsFromJson(draft) {
  const editor = $('#route-form .backend-editor'); if (!editor || !Array.isArray(draft.backends)) return;
  const backends = draft.backends;
  const named = backends.length > 0 && backends.every(isObject);
  const legacy = backends.length > 0 && backends.every((value) => typeof value === 'string');
  editor.dataset.mode = named ? 'named' : legacy ? 'legacy' : 'invalid';
  if (named) editor.querySelector('.backend-member-list').replaceChildren(...backends.map((member, index) => memberRow(member, index)));
  if (legacy) editor.querySelector('[name="backends"]').value = backends.join('\n');
  updateBackendModeUi();
}

function backendFields(type, route) {
  const editor = document.createElement('div'); editor.className = 'backend-editor span-2';
  const named = Array.isArray(route.backends) && route.backends.length > 0 && route.backends.every(isObject);
  editor.dataset.mode = named ? 'named' : 'legacy';
  const legacy = field('Backends', 'backends', named ? '' : (route.backends || []).join('\n'), { required: true, textarea: true, help: type === 'http'
    ? 'One http:// or https:// URL per line (or docker://container/network/port); 1–128 entries.'
    : 'One host:port per line (or docker://container/network/port); 1–128 entries.' });
  legacy.classList.add('backend-legacy'); legacy.hidden = named;
  const namedWrap = document.createElement('div'); namedWrap.className = 'backend-named'; namedWrap.hidden = !named;
  const note = document.createElement('p'); note.className = 'field-help-inline'; copy(note, 'Named members keep stable IDs, per-member weights and serving, draining or maintenance state. Local-file configuration authority is required; shared stores reject named members.');
  const rows = document.createElement('div'); rows.className = 'backend-member-list';
  if (named) rows.append(...route.backends.map((member, index) => memberRow(member, index)));
  const add = document.createElement('button'); add.type = 'button'; add.className = 'button button-quiet backend-member-add'; copy(add, 'Add member');
  add.addEventListener('click', () => { try { rows.append(memberRow({ id: nextMemberId(rows), address: '' })); syncRouteJsonFromForm(); } catch (error) { message($('#route-message'), error.message, 'error'); } });
  namedWrap.append(note, rows, add);
  const convert = document.createElement('button'); convert.type = 'button'; convert.className = 'button button-secondary backend-convert'; copy(convert, named ? 'Convert to legacy addresses' : 'Convert to named members');
  const help = document.createElement('p'); help.className = 'field-help-inline'; copy(help, 'Conversion changes member identity and may reset health qualification. String routes remain unchanged until you explicitly convert.');
  convert.addEventListener('click', () => {
    try {
      const draft = JSON.parse($('#route-json').value);
      if (!isObject(draft)) throw new Error(t('A route must be a JSON object.'));
      if (editor.dataset.mode === 'invalid') throw new Error(t('Backends must be all addresses or all named members'));
      if (editor.dataset.mode === 'named') {
        const members = readBackendValues(draft.backends);
        if (members.some((member) => member.desired_state && member.desired_state !== 'serving')) throw new Error(t('Set every member to Serving before converting to legacy addresses'));
        const weights = members.map((member) => member.weight ?? 1);
        if (type === 'tcp' && weights.some((weight) => weight !== 1)) throw new Error(t('TCP member weights cannot be preserved in legacy address mode'));
        draft.backends = members.map((member) => member.address);
        if (type === 'http') draft.balance = { ...(isObject(draft.balance) ? draft.balance : {}), weights: weights.every((weight) => weight === 1) ? [] : weights };
      } else {
        const addresses = nonemptyLines(legacy.querySelector('textarea').value);
        if (addresses.length < 1 || addresses.length > 128) throw new Error(t('Backends must list 1–128 entries'));
        if (new Set(addresses).size !== addresses.length) throw new Error(t('Member addresses must be unique within a route'));
        const weights = type === 'http' ? parseWeights($('#route-form [name="balance_weights"]').value.trim()) : [];
        if (weights.length && weights.length !== addresses.length) throw new Error(t('Backend weights must list exactly {count} values, one per backend', { count: addresses.length }));
        draft.backends = addresses.map((address, index) => ({ id: `member-${index + 1}`, address, ...(weights[index] && weights[index] !== 1 ? { weight: weights[index] } : {}) }));
        if (type === 'http') draft.balance = { ...(isObject(draft.balance) ? draft.balance : {}), weights: [] };
      }
      $('#route-json').value = JSON.stringify(draft, null, 2);
      syncRouteControlsFromJson();
      delete $('#route-form').dataset.invalidNative;
      message($('#route-message'));
    } catch (error) { message($('#route-message'), error.message, 'error'); }
  });
  editor.append(legacy, namedWrap, convert, help);
  return editor;
}

let resourceRuleSequence = 0;
function resourceRuleRow(rule = {}) {
  if (!isObject(rule)) rule = {};
  const row = document.createElement('div'); row.className = 'resource-rule-row';
  const number = ++resourceRuleSequence;
  const subjects = field('Allowed subjects', `resource_subjects_${number}`, Array.isArray(rule.subjects) ? rule.subjects.join('\n') : '', { textarea: true, help: 'Exact principal subjects, one per line (1–32). Workload subjects must be canonical SPIFFE URIs; no wildcard or whitespace trimming.' });
  const methods = field('Allowed methods', `resource_methods_${number}`, Array.isArray(rule.methods) ? rule.methods.join('\n') : '', { textarea: true, help: 'Uppercase HTTP methods, one per line (1–16), or * alone for every method.' });
  subjects.querySelector('textarea').classList.add('resource-rule-subjects');
  methods.querySelector('textarea').classList.add('resource-rule-methods');
  const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'button button-quiet resource-rule-remove'; copy(remove, 'Remove allow rule');
  remove.addEventListener('click', () => { row.remove(); syncRouteJsonFromForm(); });
  row.append(subjects, methods, remove);
  return row;
}

function updateResourcePolicyControls(form) {
  const action = form.elements['resource_policy_action'];
  if (!action) return;
  const configured = action.value === 'configured';
  const section = action.closest('details');
  section?.querySelector('.resource-rule-editor')?.toggleAttribute('hidden', !configured);
  for (const control of section?.querySelectorAll('[data-group="resource_policy"]') || []) control.disabled = !configured;
}

function resourcePolicySection(route) {
  const policy = isObject(route.resource_policy) ? route.resource_policy : null;
  const principal = isObject(policy?.principal) ? policy.principal : {};
  const action = field('Resource policy action', 'resource_policy_action', policy ? 'configured' : 'none', {
    select: [['none', 'No resource policy'], ['configured', 'Configure resource policy'], ['remove', 'Remove resource policy']],
    help: 'To remove an enforced policy, first save it with enforcement off. Reopen the route and remove it in a second revision. A disabled route retains this guard.',
  });
  const rules = document.createElement('div'); rules.className = 'resource-rule-editor span-2';
  const note = document.createElement('p'); note.className = 'field-help-inline'; copy(note, 'Allow rules match exact subjects and HTTP methods. An empty list denies every request while enforced. The resource ID and authenticator must agree across routes sharing this ID.');
  const list = document.createElement('div'); list.className = 'resource-rule-list';
  if (Array.isArray(policy?.allow)) list.append(...policy.allow.slice(0, 33).map(resourceRuleRow));
  const add = document.createElement('button'); add.type = 'button'; add.className = 'button button-quiet resource-rule-add'; copy(add, 'Add allow rule');
  add.addEventListener('click', () => { list.append(resourceRuleRow()); syncRouteJsonFromForm(); });
  rules.append(note, list, add);
  action.querySelector('select').addEventListener('change', () => updateResourcePolicyControls($('#route-form')));
  return section({ title: 'Resource authorization', configured: Boolean(policy),
    note: 'Protect one resource namespace using a Basic username, verified JWT subject, verified workload SPIFFE URI, or copied external identity header. Matching is exact and deny-by-default. Moving an enforced host/path scope requires preserving its old scope or first saving enforcement Off. This is an instance route policy, not a fleet authorization result.', fields: [
      span2(action),
      field('Resource ID', 'resource_policy_id', policy?.resource_id ?? '', { group: 'resource_policy', maxlength: 128, help: 'Opaque ASCII ID, 1–128 characters. Routes sharing it must keep the same policy and authenticator.' }),
      field('Enforce resource policy', 'resource_policy_enforce', policy?.enforce !== false, { group: 'resource_policy', checkbox: true, help: 'Off keeps the policy configured without namespace or subject enforcement; gateway authentication still runs. Save Off before removing a previously enforced policy.' }),
      field('Principal source', 'resource_policy_source', principal.source ?? (route.workload_auth ? 'workload' : route.jwt_auth ? 'jwt' : route.auth && !route.basic_auth ? 'external' : 'basic'), { group: 'resource_policy', select: [['basic', 'Basic username'], ['external', 'External identity header'], ['jwt', 'Verified JWT subject'], ['workload', 'Verified workload SPIFFE URI']], help: 'Requires Protected access and the matching gateway authenticator.' }),
      field('External subject header', 'resource_policy_subject_header', principal.subject_header ?? '', { group: 'resource_policy', maxlength: 128, placeholder: 'x-forwarded-user', help: 'For External only: exact header copied from a successful authorization response onto the upstream request. It must be configured in Identity response headers.' }),
      rules,
    ] });
}

function updateJwtControls(form) {
  const enabled = form.elements['jwt_auth_enabled']?.checked;
  const source = form.elements['jwt_key_source']?.value;
  for (const group of ['jwt_local', 'jwt_remote', 'jwt_remote_jwks']) {
    const active = enabled && (group === 'jwt_local' ? source === 'local' : source === 'remote')
      && (group !== 'jwt_remote_jwks' || form.elements['jwt_endpoint_kind']?.value === 'jwks');
    for (const control of form.querySelectorAll(`[data-group="${group}"]`)) control.disabled = !active;
  }
}

function jwtSection(route) {
  const jwt = isObject(route.jwt_auth) ? route.jwt_auth : null;
  const verification = isObject(jwt?.verification) ? jwt.verification : {};
  const keys = isObject(jwt?.keys) ? jwt.keys : {};
  const remote = isObject(keys.config) ? keys.config : {};
  const endpoint = isObject(remote.endpoint) ? remote.endpoint : {};
  const source = keys.source || 'local';
  const keySource = field('Key source', 'jwt_key_source', source, { group: 'jwt_auth', select: [['local', 'Local public JWKS'], ['remote', 'Remote HTTPS JWKS']], help: 'Keys are public. Never paste signing keys or bearer tokens.' });
  const endpointKind = field('Remote endpoint', 'jwt_endpoint_kind', endpoint.kind || 'oidc', { group: 'jwt_remote', select: [['oidc', 'OIDC discovery from issuer'], ['jwks', 'Explicit JWKS URL']], help: 'Only operator-configured HTTPS endpoints are contacted. Token headers cannot select a URL.' });
  keySource.querySelector('select').addEventListener('change', () => updateJwtControls($('#route-form')));
  endpointKind.querySelector('select').addEventListener('change', () => updateJwtControls($('#route-form')));
  return section({ title: 'JWT access token', configured: Boolean(jwt),
    note: 'Verify signed RFC 9068 OAuth access tokens on every request. This is not browser login or OpenID Connect ID-token acceptance. Protected access can combine JWT with external authorization; Basic and JWT share Authorization and cannot be combined. Remote key failures deny access.', fields: [
      span2(field('Enable JWT authentication', 'jwt_auth_enabled', Boolean(jwt), { checkbox: true, toggles: 'jwt_auth', help: 'When off, the existing route remains unchanged until saved. A configured JWT policy disables route response caching.' })),
      span2(field('Issuer', 'jwt_issuer', verification.issuer ?? '', { group: 'jwt_auth', maxlength: 512, placeholder: 'https://issuer.example.test/', help: 'Exact HTTPS issuer including its path and trailing slash; must equal the signed iss claim.' })),
      span2(field('Audiences', 'jwt_audiences', Array.isArray(verification.audiences) ? verification.audiences.join('\n') : '', { group: 'jwt_auth', textarea: true, help: 'One expected resource audience per line, 1–8 distinct values. The signed aud claim must contain one.' })),
      field('Token profile', 'jwt_profile', verification.profile ?? 'rfc9068', { group: 'jwt_auth', select: [['rfc9068', 'RFC 9068 access token']], help: 'Requires at+jwt type and issuer, audience, subject, expiry, client ID, issue time and token ID.' }),
      field('Allowed algorithms', 'jwt_algorithms', Array.isArray(verification.algorithms) ? verification.algorithms.join('\n') : 'RS256', { group: 'jwt_auth', textarea: true, help: 'One asymmetric algorithm per line: RS256, PS256, ES256 or EdDSA. No HS or none.' }),
      field('Clock leeway (seconds)', 'jwt_leeway_seconds', verification.leeway_seconds ?? 0, { group: 'jwt_auth', type: 'number', min: 0, max: 60, help: '0–60 seconds; default 0.' }),
      field('Maximum token lifetime (seconds)', 'jwt_max_lifetime_seconds', verification.max_lifetime_seconds ?? 3600, { group: 'jwt_auth', type: 'number', min: 1, max: 86400, help: 'Reject exp − iat above this limit (1–86,400 seconds).' }),
      field('Scope claim', 'jwt_scope_claim', verification.scope_claim ?? 'scope', { group: 'jwt_auth', maxlength: 64, help: 'Claim name containing space-delimited OAuth scopes.' }),
      field('Groups claim', 'jwt_groups_claim', verification.groups_claim ?? 'groups', { group: 'jwt_auth', maxlength: 64, help: 'Claim name containing a group array.' }),
      field('Required scopes', 'jwt_required_scopes', Array.isArray(verification.required_scopes) ? verification.required_scopes.join('\n') : '', { group: 'jwt_auth', textarea: true, help: 'One exact scope per line. All listed scopes are required; blank adds no scope condition.' }),
      field('Required groups', 'jwt_required_groups', Array.isArray(verification.required_groups) ? verification.required_groups.join('\n') : '', { group: 'jwt_auth', textarea: true, help: 'One exact group per line. All listed groups are required; blank adds no group condition.' }),
      keySource,
      span2(field('Local public JWKS JSON', 'jwt_local_jwks', keys.source === 'local' && isObject(keys.jwks) ? JSON.stringify(keys.jwks, null, 2) : '', { group: 'jwt_local', textarea: true, help: 'A public {"keys":[...]} document; at most 32 signing keys and 128 KiB. Private JWK fields are rejected by the server.' })),
      endpointKind,
      span2(field('Explicit JWKS URL', 'jwt_jwks_url', endpoint.kind === 'jwks' ? endpoint.url ?? '' : '', { group: 'jwt_remote_jwks', placeholder: 'https://issuer.example.test/keys', help: 'HTTPS URL without credentials, query or fragment. Used only for the Explicit JWKS URL mode.' })),
      field('Key cache TTL (seconds)', 'jwt_cache_ttl_seconds', remote.cache_ttl_seconds ?? 300, { group: 'jwt_remote', type: 'number', min: 1, max: 3600, help: '1–3,600 seconds; keys fail closed at expiry.' }),
      field('Refresh cooldown (seconds)', 'jwt_refresh_cooldown_seconds', remote.refresh_cooldown_seconds ?? 10, { group: 'jwt_remote', type: 'number', min: 1, max: 60, help: '1–60 seconds, no longer than key cache TTL.' }),
      field('Key fetch timeout (ms)', 'jwt_timeout_ms', remote.timeout_ms ?? 3000, { group: 'jwt_remote', type: 'number', min: 1, max: 5000, help: '1–5,000 ms for OIDC discovery and JWKS requests.' }),
      span2(field('Additional public CA PEM', 'jwt_ca_pem', remote.ca_pem ?? '', { group: 'jwt_remote', textarea: true, help: 'Optional public trust anchor for a private issuer. No private keys; at most 128 KiB.' })),
      field('Verified identity header', 'jwt_identity_header', jwt?.identity_header ?? '', { group: 'jwt_auth', maxlength: 128, placeholder: 'x-verified-user', help: 'Optional upstream request header containing the verified sub. Client and Lua writes cannot replace it.' }),
      span2(field('Hide Bearer token from the upstream', 'jwt_hide_credentials', jwt?.hide_credentials !== false, { group: 'jwt_auth', checkbox: true, help: 'Checked by default. The external authorization service can still inspect the verified request before the token is removed.' })),
    ] });
}

function workloadAuthSection(route) {
  const auth = isObject(route.workload_auth) ? route.workload_auth : null;
  return section({ title: 'HTTP workload mTLS', configured: Boolean(auth),
    note: 'Require a verified SPIFFE client certificate from one of the selected dedicated HTTP mTLS listeners, then match an exact URI allowlist. This setting requires Protected access and resource authorization. Other gateway authenticators still run; ordinary public HTTP and HTTPS listeners cannot supply this identity.', fields: [
      span2(field('Require workload identity', 'workload_auth_enabled', Boolean(auth), { checkbox: true, toggles: 'workload_auth', help: 'Listener registrations are managed in Configuration. Enabling this does not turn an ordinary HTTP listener into mTLS.' })),
      span2(field('Workload listener IDs', 'workload_listener_ids', (auth?.listener_ids ?? []).join('\n'), { group: 'workload_auth', textarea: true, help: 'One configured listener ID per line, 1–64 distinct IDs. Only these dedicated HTTP mTLS listeners may enter this route.' })),
      span2(field('Allowed workload SPIFFE URI SANs', 'workload_allowed_uri_sans', (auth?.allowed_uri_sans ?? []).join('\n'), { group: 'workload_auth', textarea: true, help: 'One exact SPIFFE URI per line, 1–128 distinct identities. They must also satisfy the resource allow rules.' })),
      field('Verified workload identity header', 'workload_identity_header', auth?.identity_header ?? '', { group: 'workload_auth', placeholder: 'x-workload-identity', maxlength: 128, help: 'Optional trusted upstream request header containing the verified SPIFFE URI. Client and Lua writes cannot establish this identity.' }),
    ] });
}

function upstreamSection(type, route) {
  const upstream = isObject(route.upstream) ? route.upstream : {};
  const socks = isObject(upstream.socks5) ? upstream.socks5 : {};
  const tls = isObject(upstream.tls) ? upstream.tls : null;
  const configured = Boolean(upstream.connect_address || upstream.unix_socket || (upstream.dns_servers || []).length || upstream.socks5 || tls);
  return section({
    title: 'Upstream connection', configured,
    note: type === 'http' ? 'Optional dialing policy for every backend of this route. HTTP backends derive TLS from their https:// scheme; the TLS options below only tune verification and SNI.' : 'Optional dialing policy for every backend of this route. Enabling TLS wraps the raw TCP stream to the backend in TLS.',
    fields: [
      field('Connect address', 'connect_address', upstream.connect_address || '', { placeholder: '10.0.0.5:8443', help: 'host:port dialed instead of the backend address; the backend name is still used for Host and SNI.' }),
      field('Unix socket', 'unix_socket', upstream.unix_socket || '', { placeholder: '/run/hangang/egress.sock', help: 'Absolute path inside the gateway. Dials this socket instead of TCP; the backend still supplies Host and TLS name. Cannot combine with connect address, DNS servers or SOCKS5.' }),
      field('Upstream DNS servers', 'dns_servers', (upstream.dns_servers || []).join('\n'), { textarea: true, help: 'One ip:port per line, at most 4. Restricts backend hostname resolution to these servers.' }),
      field('SOCKS5 proxy address', 'socks5_address', socks.address || '', { placeholder: '127.0.0.1:1080', help: 'Blank dials backends directly.' }),
      field('SOCKS5 username variable', 'socks5_username_env', socks.username_env || '', { placeholder: 'HANGANG_SOCKS5_USER', help: 'Environment variable name (HANGANG_SOCKS5_…) holding the proxy username; set together with the password variable.' }),
      field('SOCKS5 password variable', 'socks5_password_env', socks.password_env || '', { placeholder: 'HANGANG_SOCKS5_PASSWORD', help: 'Environment variable name (HANGANG_SOCKS5_…) holding the proxy password. Secrets never enter the configuration.' }),
      span2(field(type === 'http' ? 'Configure upstream TLS verification' : 'Enable TLS to the upstream', 'upstream_tls', Boolean(tls), { checkbox: true, toggles: 'tls', help: type === 'http' ? 'Requires every backend to use https://. Unchecked keeps the default verifier.' : 'Unchecked forwards the raw TCP stream unchanged.' })),
      field('TLS server name', 'tls_server_name', tls?.server_name || '', { group: 'tls', placeholder: 'backend.internal', help: 'SNI and certificate name to verify; blank uses the backend host.' }),
      field('TLS CA file', 'tls_ca_file', tls?.ca_file || '', { group: 'tls', placeholder: '/etc/hangang/upstream-ca.pem', help: 'Absolute path to a private CA bundle (at most 16 routes may load one).' }),
      field('TLS maximum fragment size', 'tls_max_fragment_size', tls?.max_fragment_size ?? '', { group: 'tls', type: 'number', min: 128, max: 16389, help: 'Optional, 128–16,389 bytes.' }),
      field('Skip TLS certificate verification', 'tls_insecure_skip_verify', Boolean(tls?.insecure_skip_verify), { group: 'tls', checkbox: true, help: 'Disables verification of the backend certificate. Cannot be combined with a CA file.' }),
    ],
  });
}

function transformSection(direction, route) {
  const key = `${direction}_transform`;
  const label = direction === 'request' ? 'Request' : 'Response';
  const transform = isObject(route[key]) ? route[key] : null;
  const value = { ...DEFAULT_TRANSFORM, ...(transform || {}) };
  return section({
    title: `${label} body transform`, configured: Boolean(transform),
    note: `Buffered or streaming rewrite of the ${direction} body. Streaming modes (lines, ndjson, sse) apply operations and Lua per record; buffered mode needs the whole body within the buffer limit. Lua transforms require limits of at most 16 KiB.`,
    fields: [
      span2(field(`Enable ${direction} body transform`, `${key}_enabled`, Boolean(transform), { checkbox: true, toggles: key, help: 'Unchecked removes the transform from the route.' })),
      field(`${label} transform mode`, `${key}_mode`, value.mode || 'buffered', { group: key, select: [['buffered', 'buffered – whole body'], ['lines', 'lines – newline records'], ['ndjson', 'ndjson – JSON per line'], ['sse', 'sse – server-sent events']] }),
      field(`${label} transform timeout (ms)`, `${key}_timeout_ms`, value.timeout_ms ?? '', { group: key, type: 'number', min: 1, max: 30000, placeholder: '5000', help: '1–30,000 ms per body or record.' }),
      field(`${label} transform buffer limit (bytes)`, `${key}_max_buffer_bytes`, value.max_buffer_bytes ?? '', { group: key, type: 'number', min: 1, max: 1048576, placeholder: '65536', help: '1–1,048,576 bytes of input held at once.' }),
      field(`${label} transform output limit (bytes)`, `${key}_max_output_bytes`, value.max_output_bytes ?? '', { group: key, type: 'number', min: 1, max: 1048576, placeholder: '65536', help: '1–1,048,576 bytes produced per body or record.' }),
      span2(field(`${label} transform operations`, `${key}_operations`, (value.operations || []).length ? JSON.stringify(value.operations, null, 2) : '', { group: key, textarea: true, help: 'JSON array of at most 32 operations: {"op":"replace","from":"a","to":"b"}, {"op":"json_set","pointer":"/k","value":1}, {"op":"json_remove","pointer":"/k"}, {"op":"xml_set_text","path":"/root/node","value":"x"}, {"op":"xml_remove","path":"/root/node"}. JSON and XML operations cannot be mixed.' })),
      span2(field(`${label} transform Lua`, `${key}_lua`, value.lua || '', { group: key, textarea: true, help: 'Optional Lua after operations, at most 16 KiB. Completion offers body, phase and JSON helpers; routing and header helpers are unavailable. Ctrl+Space (macOS: Alt+i) opens suggestions; Ctrl/⌘+Z undoes; Tab moves focus.' })),
      field(`${label} transform set headers`, `${key}_set_headers`, pairsToLines(value.set_headers), { group: key, textarea: true, help: 'One name: value per line; framing and hop-by-hop names are rejected.' }),
      field(`${label} transform remove headers`, `${key}_remove_headers`, (value.remove_headers || []).join('\n'), { group: key, textarea: true, help: 'One header name per line; at most 32 header mutations in total.' }),
    ],
  });
}

function hostMatchFields(route) {
  const selected = route.host_regex ? 'regex' : route.hosts?.length ? 'group' : 'single';
  const mode = field('Host selection mode', 'host_mode', selected, {
    select: [['single', 'Single host or any'], ['group', 'Domain group'], ['regex', 'Regular expression']],
    help: 'A domain group applies this one route’s backends and policies to every listed host.',
  });
  const single = field('Host match', 'host', route.host || '', {
    placeholder: '*.foo.com or f??.bar.com',
    help: 'One exact host or label-local glob. Leave blank to match any host.',
  });
  const group = field('Domain group hosts', 'hosts', (route.hosts || []).join('\n'), {
    textarea: true,
    help: 'One exact DNS host or label-local glob per line; 1–32 distinct hosts. All share this route’s path, upstreams and policies.',
  });
  const regex = field('Host regular expression', 'host_regex', route.host_regex || '', {
    placeholder: '^api[0-9]+[.]example[.]com$',
    help: 'One whole-host ASCII regex, case-insensitive by default.',
  });
  const show = () => {
    const value = mode.querySelector('select').value;
    single.hidden = value !== 'single';
    group.hidden = value !== 'group';
    regex.hidden = value !== 'regex';
  };
  mode.querySelector('select').addEventListener('change', show);
  show();
  // Inactive controls stay mounted so a switch between modes keeps drafts.
  return [mode, single, group, regex];
}

function httpSections(route) {
  const editing = Boolean(state.editing.originalId);
  const auth = isObject(route.auth) ? route.auth : null;
  const basic = isObject(route.basic_auth) ? route.basic_auth : null;
  const balance = isObject(route.balance) ? route.balance : {};
  const health = isObject(balance.health) ? balance.health : null;
  const activeHealth = isObject(balance.active_health) ? balance.active_health : null;
  const passiveHealth = isObject(balance.passive_health) ? balance.passive_health : null;
  return [
    section({ title: 'Matching', open: true, fields: [
      field('Route ID', 'id', route.id || '', { required: true, pattern: '[A-Za-z0-9._-]+', maxlength: 128, readonly: editing, help: editing ? 'Route IDs cannot be renamed in place.' : 'Letters, digits, dots, underscores and dashes; at most 128 characters.' }),
      span2(field('Route enabled', 'enabled', route.enabled !== false, { checkbox: true, help: 'Disabled routes keep their settings but do not match new traffic. Re-enabling validates the route again.' })),
      field('Matching priority', 'priority', route.priority ?? 0, { type: 'number', min: -2147483648, max: 2147483647, help: 'Higher numbers match first; default 0. Equal HTTP priorities retain configuration order.' }),
      ...hostMatchFields(route),
      field('Path prefix', 'path_prefix', route.path_prefix || '', { placeholder: '/v1/', help: 'Must start with /. Blank matches every path.' }),
      field('Path match mode', 'path_match', route.path_match || 'prefix', { select: [['prefix', 'prefix – byte prefix'], ['exact', 'exact – whole path only'], ['segment_prefix', 'segment_prefix – path or its / descendants']], help: 'Ignored when the path prefix is blank.' }),
      field('Header matches', 'headers', pairsToLines(route.headers), { textarea: true, help: 'One name: value per line; at most 64.' }),
      field('JSON matches', 'json', jsonPairsToLines(route.json), { textarea: true, help: 'One RFC 6901 pointer = JSON value per line; at most 64. Disables route caching.' }),
      span2(field('Denied CIDRs', 'deny_cidrs', (route.deny_cidrs || []).join('\n'), { textarea: true, help: 'One IPv4 or IPv6 network per line (192.0.2.0/24, 2001:db8::/32); at most 1,024.' })),
      span2(field('Require TLS', 'require_tls', Boolean(route.require_tls), { checkbox: true, help: 'Plaintext requests (by terminated transport or, behind a trusted proxy, X-Forwarded-Proto) are answered with the HTTPS redirect configured by --https-redirect-code instead of being proxied.' })),
    ] }),
    section({ title: 'Backends', open: true, fields: [
      backendFields('http', route),
      field('Upstream Host override', 'upstream_host', route.upstream_host || '', { placeholder: 'foo.bar', help: 'HTTP Host / HTTP/2 authority sent upstream; TLS SNI is configured under Upstream connection.' }),
      field('Concurrent request limit', 'max_requests', route.max_requests ?? '', { type: 'number', min: 1, max: 1000000, help: 'Optional, 1–1,000,000. Blank uses only the global limit.' }),
      field('Upstream timeout (ms)', 'upstream_timeout_ms', route.upstream_timeout_ms ?? '', { type: 'number', min: 1, max: 86400000, help: 'Time budget for the upstream to return response headers (upload plus first byte), 1–86,400,000 ms. Blank uses --upstream-timeout-seconds.' }),
      field('Retries', 'retries', route.retries ?? 0, { type: 'number', min: 0, max: 16, help: 'Extra attempts on a freshly selected backend after a pre-response connection error, 0–16. Only safely replayable requests (bodyless GET/HEAD/OPTIONS/DELETE without transform or upgrade) are retried.' }),
      span2(field('Preserve incoming Host', 'preserve_host', Boolean(route.preserve_host), { checkbox: true, help: 'Forward the client Host header unchanged; conflicts with an explicit upstream Host.' })),
      dockerButton(),
    ] }),
    section({ title: 'Load balancing', configured: Boolean((balance.mode && balance.mode !== 'round_robin') || (balance.weights || []).length || health), note: 'Legacy failure cooldown conflicts with active health checks. Clear both legacy health fields before enabling active probes.', fields: [
      field('Balancing mode', 'balance_mode', balance.mode || 'round_robin', { select: [['round_robin', 'Round robin (weighted)'], ['least_connections', 'Least connections (weighted)']] }),
      field('Backend weights', 'balance_weights', (balance.weights || []).join(', '), { placeholder: '3, 1, 1', help: 'Legacy address mode only. Comma-separated, one per backend in order, 1–1,000 each. Named members carry their own weights.' }),
      field('Failure threshold', 'health_failure_threshold', health?.failure_threshold ?? '', { type: 'number', min: 1, max: 100, help: 'Consecutive connection failures or HTTP 5xx responses before a backend is skipped (1–100). Both legacy health fields are required together.' }),
      field('Cooldown (ms)', 'health_cooldown_ms', health?.cooldown_ms ?? '', { type: 'number', min: 10, max: 300000, help: 'How long a failed backend stays skipped, 10–300,000 ms.' }),
    ] }),
    section({ title: 'Active health checks', configured: Boolean(activeHealth), note: 'Active probes support HTTP, HTTPS and discovered Docker backends. A checking startup waits for healthy probes from the current endpoint generation; container replacement resets that evidence.', fields: [
      span2(field('Enable active health checks', 'active_health_enabled', Boolean(activeHealth), { checkbox: true, toggles: 'active_health', help: 'Requires a probe path and status sets; conflicts with legacy failure cooldown.' })),
      field('Initial probe state', 'active_health_initial_state', activeHealth?.initial_state || 'healthy', { group: 'active_health', select: [['healthy', 'Healthy — existing startup behavior'], ['checking', 'Checking — wait for healthy probes']], help: 'Healthy preserves existing startup behavior. Checking excludes each backend until it reaches the configured consecutive healthy-probe threshold; failures and passive reports cannot release it.' }),
      field('Probe path', 'active_health_path', activeHealth?.path ?? '', { group: 'active_health', placeholder: '/health', help: 'Required printable absolute path without query or fragment; GET is used.' }),
      field('Probe Host', 'active_health_host', activeHealth?.host ?? '', { group: 'active_health', placeholder: 'backend.internal', help: 'Optional bare Host without a port; blank uses the backend host.' }),
      field('Probe interval (ms)', 'active_health_interval_ms', activeHealth?.interval_ms ?? 3000, { group: 'active_health', type: 'number', min: 100, max: 300000, help: '100–300,000 ms between active probes.' }),
      field('Probe timeout (ms)', 'active_health_timeout_ms', activeHealth?.timeout_ms ?? 2000, { group: 'active_health', type: 'number', min: 100, max: 60000, help: '100–60,000 ms, no longer than the probe interval.' }),
      field('Healthy HTTP statuses', 'active_health_healthy_statuses', (activeHealth?.healthy_statuses ?? [200]).join(', '), { group: 'active_health', help: 'Comma- or space-separated HTTP status codes, 100–599; 1–64 unique values.' }),
      field('Unhealthy HTTP statuses', 'active_health_unhealthy_statuses', (activeHealth?.unhealthy_statuses ?? [429, 500, 503]).join(', '), { group: 'active_health', help: 'Disjoint from healthy statuses; 1–64 unique HTTP codes.' }),
      field('Healthy probe successes', 'active_health_healthy_successes', activeHealth?.healthy_successes ?? 1, { group: 'active_health', type: 'number', min: 1, max: 100, help: 'Successful probes required to release checking startup or recover an unhealthy backend. Checking requires consecutive successes; Healthy preserves existing neutral-status behavior.' }),
      field('Unhealthy HTTP failures', 'active_health_unhealthy_http_failures', activeHealth?.unhealthy_http_failures ?? 2, { group: 'active_health', type: 'number', min: 1, max: 100, help: 'Consecutive unhealthy HTTP probe results before exclusion.' }),
      field('Unhealthy TCP failures', 'active_health_unhealthy_tcp_failures', activeHealth?.unhealthy_tcp_failures ?? 2, { group: 'active_health', type: 'number', min: 1, max: 100, help: 'Consecutive probe connection failures before exclusion.' }),
      field('Unhealthy probe timeouts', 'active_health_unhealthy_timeouts', activeHealth?.unhealthy_timeouts ?? 2, { group: 'active_health', type: 'number', min: 1, max: 100, help: 'Consecutive probe timeouts before exclusion.' }),
    ] }),
    section({ title: 'Passive health checks', configured: Boolean(passiveHealth), note: 'Passive checks observe admitted requests. They require active checks and cannot release a checking startup gate. Healthy passive responses do not reset failure counters or recover excluded backends; successful active probes clear passive quarantine.', fields: [
      span2(field('Enable passive health checks', 'passive_health_enabled', Boolean(passiveHealth), { checkbox: true, toggles: 'passive_health', group: 'active_health', help: 'Requires active health checks; disabling active checks also disables passive checks.' })),
      field('Passive healthy statuses', 'passive_health_healthy_statuses', (passiveHealth?.healthy_statuses ?? [200, 201]).join(', '), { group: 'passive_health', help: 'Comma- or space-separated HTTP status codes, 100–599; 1–64 unique values.' }),
      field('Passive unhealthy statuses', 'passive_health_unhealthy_statuses', (passiveHealth?.unhealthy_statuses ?? [429, 500, 503]).join(', '), { group: 'passive_health', help: 'Disjoint from passive healthy statuses; 1–64 unique HTTP codes.' }),
      field('Passive HTTP failures', 'passive_health_unhealthy_http_failures', passiveHealth?.unhealthy_http_failures ?? 2, { group: 'passive_health', type: 'number', min: 1, max: 100, help: 'Consecutive unhealthy responses from admitted requests before exclusion.' }),
      field('Passive TCP failures', 'passive_health_unhealthy_tcp_failures', passiveHealth?.unhealthy_tcp_failures ?? 2, { group: 'passive_health', type: 'number', min: 1, max: 100, help: 'Consecutive upstream connection failures before exclusion.' }),
      field('Passive timeouts', 'passive_health_unhealthy_timeouts', passiveHealth?.unhealthy_timeouts ?? 2, { group: 'passive_health', type: 'number', min: 1, max: 100, help: 'Consecutive upstream timeouts before exclusion.' }),
    ] }),
    upstreamSection('http', route),
    section({ title: 'Access policy', configured: Boolean(route.access_mode && route.access_mode !== 'legacy'),
      note: 'Declare who owns access control. Legacy preserves existing behavior without declaring the route protected. Public is intentionally anonymous at the gateway; Application delegates login to the application; Protected requires Basic, JWT, workload mTLS or external authorization on every request. This label is not a complete Zero Trust assessment.', fields: [
        span2(field('Access mode', 'access_mode', route.access_mode || 'legacy', {
          select: [['legacy', 'Legacy — existing behavior'], ['public', 'Public — anonymous at gateway'], ['application', 'Application — app owns login'], ['protected', 'Protected — gateway auth required']],
          help: 'Public and Application cannot configure gateway Basic, JWT, workload mTLS or external auth. Protected needs at least one. Workload mTLS also requires resource authorization. JWT can combine with external authorization but not Basic. An existing Protected route cannot return to Legacy; choose Public or Application and clear auth explicitly. Lua transforms remain available in every mode.',
        })),
      ] }),
    section({ title: 'External authorization', configured: Boolean(auth), note: 'Every request is first sent to an authorization service. A 2xx answer allows the request; a denial answers the client without contacting the backend. The service always receives the generated request context from the trusted-proxy resolution: x-forwarded-method, x-forwarded-uri, x-forwarded-proto, x-forwarded-host, x-forwarded-port, x-forwarded-for, x-real-ip, x-original-url and the x-original-method/uri/client-ip compatibility names. These names cannot be listed below; the identity names x-forwarded-user, x-forwarded-email, x-forwarded-groups, x-forwarded-preferred-username and x-forwarded-access-token may be copied from the response only. On a 2xx answer with “Forward denial responses” enabled, the service’s Set-Cookie headers reach the client.', fields: [
      span2(field('Authorization URL', 'auth_url', auth?.url || '', { placeholder: 'https://auth.internal/check', help: 'http:// or https:// without credentials or fragment. Blank disables external authorization. Disables route caching.' })),
      field('Forwarded request headers', 'auth_request_headers', (auth?.request_headers || []).join('\n'), { textarea: true, help: 'Client request headers copied to the authorization request, one per line; at most 32. Generated context names (every x-forwarded-*, forwarded, x-real-ip, x-original-method/uri/url/client-ip) and hop-by-hop names are rejected.' }),
      field('Identity response headers', 'auth_response_headers', (auth?.response_headers || []).join('\n'), { textarea: true, help: 'Headers copied from an allowing authorization response onto the upstream request, one per line; at most 32. Clients can never supply them. Accepted identity names: x-forwarded-user, x-forwarded-email, x-forwarded-groups, x-forwarded-preferred-username, x-forwarded-access-token. Other x-forwarded-*, forwarded, x-real-ip, x-original-* and hop-by-hop names are rejected.' }),
      field('Authorization timeout (ms)', 'auth_timeout_ms', auth?.timeout_ms ?? '', { type: 'number', min: 1, max: 5000, placeholder: '1000', help: '1–5,000 ms; blank uses 1,000.' }),
      field('Forward denial responses', 'auth_forward_response', Boolean(auth?.forward_response), { checkbox: true, help: 'Send 3xx/401/403 authorization responses (status, Location, Set-Cookie, WWW-Authenticate, Content-Type, Cache-Control and a bounded body) to the client for SSO login flows, and pass the Set-Cookie headers of an allowing 2xx answer (at most 16, 16 KiB) to the client. Other failures still answer 503.' }),
    ] }),
    section({ title: 'Basic authentication', configured: Boolean(basic), note: 'Native HTTP Basic authentication. Generate each credential line below (POST /v1/util/hash-password) or with: hangang --hash-password <username> <password>  (prints username:salt_hex:sha256_hex). Passwords are never stored.', fields: [
      span2(field('Credentials', 'basic_auth_credentials', (basic?.credentials || []).join('\n'), { textarea: true, help: 'One username:salt_hex:sha256_hex line per user, 1–4,096 unique usernames. Blank disables basic authentication.' })),
      ...credentialGenerator(),
      field('Realm', 'basic_auth_realm', basic?.realm || '', { placeholder: 'restricted', help: 'Shown in the WWW-Authenticate challenge; no control characters or double quotes. Blank uses “restricted”.' }),
      field('Identity header', 'basic_auth_identity_header', basic?.identity_header || '', { placeholder: 'x-authenticated-user', help: 'Optional request header set to the authenticated username for the upstream.' }),
      span2(field('Hide credentials from the upstream', 'basic_auth_hide_credentials', Boolean(basic?.hide_credentials), { checkbox: true, help: 'Removes the Authorization header before forwarding.' })),
    ] }),
    jwtSection(route),
    workloadAuthSection(route),
    resourcePolicySection(route),
    section({ title: 'Response headers', configured: Boolean(Object.keys(route.response_set_headers || {}).length || (route.response_remove_headers || []).length), note: 'Streaming-safe header edits applied to every upstream response head; framing and hop-by-hop names are rejected.', fields: [
      field('Set response headers', 'response_set_headers', pairsToLines(route.response_set_headers), { textarea: true, help: 'One name: value per line; replaces an existing header of the same name.' }),
      field('Remove response headers', 'response_remove_headers', (route.response_remove_headers || []).join('\n'), { textarea: true, help: 'One header name per line, for example server.' }),
    ] }),
    section({ title: 'Cache', configured: Boolean(route.cache), note: 'Route caching needs the global cache policy (Cache view) and is disabled by authorization, Lua policy, JSON matches and request transforms.', fields: [
      field('Cache TTL seconds', 'cache_ttl_seconds', route.cache?.ttl_seconds ?? '', { type: 'number', min: 1, max: 86400, help: 'Leave both cache TTL fields blank to disable this route cache.' }),
      field('Maximum cache TTL seconds', 'cache_max_ttl_seconds', route.cache?.max_ttl_seconds ?? '', { type: 'number', min: 1, max: 86400, help: 'Must be at least the cache TTL and no more than 86,400.' }),
    ] }),
    transformSection('request', route),
    transformSection('response', route),
    section({ title: 'Lua policy', configured: Boolean(route.lua), fields: [
      span2(field('Lua policy', 'lua', route.lua || '', { textarea: true, help: 'Optional request policy Lua, at most 16 KiB. Completion offers request, header, backend and reject helpers; body helpers are unavailable. Disables route caching. Ctrl+Space (macOS: Alt+i) opens suggestions; Ctrl/⌘+Z undoes; Tab moves focus.' })),
    ] }),
  ];
}

function tcpSections(route) {
  const editing = Boolean(state.editing.originalId);
  const sni = isObject(route.sni) ? route.sni : null;
  const inboundTls = isObject(route.inbound_tls) ? route.inbound_tls : null;
  const health = isObject(route.health) ? route.health : null;
  return [
    section({ title: 'Listener and matching', open: true, fields: [
      field('Route ID', 'id', route.id || '', { required: true, pattern: '[A-Za-z0-9._-]+', maxlength: 128, readonly: editing, help: editing ? 'Route IDs cannot be renamed in place.' : 'Letters, digits, dots, underscores and dashes; at most 128 characters.' }),
      span2(field('Route enabled', 'enabled', route.enabled !== false, { checkbox: true, help: 'Disabled routes keep their settings but do not accept new connections. Existing connections drain when the listener is removed.' })),
      field('Matching priority', 'priority', route.priority ?? 0, { type: 'number', min: -2147483648, max: 2147483647, help: 'Higher numbers match first on a shared SNI listener; default 0.' }),
      field('Listen address', 'listen', route.listen || '', { required: true, placeholder: '0.0.0.0:9001', help: 'Binds inside the Hangang runtime. Host networking binds directly; bridge networking requires a published port. Allow it through the host firewall as needed. Several routes may share a listener when every one matches SNI.' }),
      field('Concurrent connection limit', 'max_connections', route.max_connections ?? '', { type: 'number', min: 1, max: 1000000, help: 'Optional, 1–1,000,000. Blank uses only the global limit.' }),
      span2(field('Denied CIDRs', 'deny_cidrs', (route.deny_cidrs || []).join('\n'), { textarea: true, help: 'One IPv4 or IPv6 network per line (192.0.2.0/24, 2001:db8::/32); at most 1,024.' })),
    ] }),
    section({ title: 'TLS SNI routing', configured: Boolean(sni), note: 'Inspect the TLS ClientHello without terminating TLS and pick this route by server name. Blank hostname fields accept any TCP connection without inspection.', fields: [
      field('SNI hostname patterns', 'sni_hosts', (sni?.hosts || []).join('\n'), { textarea: true, help: 'One exact DNS name or label-local glob per line (db.example.test, *.tenant.example.test).' }),
      field('SNI hostname regexes', 'sni_host_regexes', (sni?.host_regexes || []).join('\n'), { textarea: true, help: 'One whole-host regex per line; hostnames and regexes together may hold 1–128 patterns.' }),
      field('ClientHello size limit (bytes)', 'sni_max_client_hello_bytes', sni?.max_client_hello_bytes ?? '', { type: 'number', min: 1, max: 1048576, placeholder: '65536', help: '1–1,048,576; routes sharing a listener need identical limits.' }),
      field('ClientHello timeout (ms)', 'sni_hello_timeout_ms', sni?.hello_timeout_ms ?? '', { type: 'number', min: 1, max: 30000, placeholder: '3000', help: '1–30,000 ms to receive the ClientHello.' }),
    ] }),
    section({ title: 'Inbound mutual TLS', configured: Boolean(inboundTls), note: 'Terminate TLS on this TCP listener and require a client certificate with an exact allowed SPIFFE URI SAN before connecting upstream. Configure server certificate and trust files by absolute path; do not paste PEM or private keys. Cannot be combined with SNI passthrough.', fields: [
      span2(field('Require inbound client certificate', 'inbound_tls_enabled', Boolean(inboundTls), { checkbox: true, toggles: 'inbound_tls', help: 'Enables TLS termination and client-certificate verification on this dedicated listener. Empty or disabled preserves TCP passthrough. Disable and save an active route before removing inbound mTLS from its listener.' })),
      field('Server certificate file', 'inbound_tls_cert_file', inboundTls?.cert_file ?? '', { group: 'inbound_tls', placeholder: '/etc/hangang/server.crt', help: 'Absolute path to the public server certificate file.' }),
      field('Server private key file', 'inbound_tls_key_file', inboundTls?.key_file ?? '', { group: 'inbound_tls', placeholder: '/etc/hangang/server.key', help: 'Absolute path to a private key file held by the runtime. Enter a path, never the key itself.' }),
      field('Trusted client CA file', 'inbound_tls_client_ca_file', inboundTls?.client_ca_file ?? '', { group: 'inbound_tls', placeholder: '/etc/hangang/client-ca.crt', help: 'Absolute path to the CA bundle used to verify client certificates.' }),
      field('Client revocation list file', 'inbound_tls_client_crl_file', inboundTls?.client_crl_file ?? '', { group: 'inbound_tls', placeholder: '/etc/hangang/client.crl', help: 'Optional absolute path to a client certificate revocation list.' }),
      span2(field('Allowed client SPIFFE URI SANs', 'inbound_tls_allowed_uri_sans', (inboundTls?.allowed_uri_sans ?? []).join('\n'), { group: 'inbound_tls', textarea: true, placeholder: 'spiffe://example.test/ns/default/sa/service', help: 'One exact SPIFFE URI per line; 1–128 distinct values, at most 2,048 bytes each. Other URI SANs are denied.' })),
      field('Inbound TLS handshake timeout (ms)', 'inbound_tls_handshake_timeout_ms', inboundTls?.handshake_timeout_ms ?? 5000, { group: 'inbound_tls', type: 'number', min: 1, max: 10000, help: '1–10,000 ms; default 5,000. The client certificate and URI SAN are checked before any upstream dial.' }),
    ] }),
    section({ title: 'Backends', open: true, fields: [
      backendFields('tcp', route),
      dockerButton(),
    ] }),
    section({ title: 'TCP connection health checks', configured: Boolean(health), note: 'A probe opens an outbound connection (including configured DNS, SOCKS5 and TLS handshake), then closes it without sending application bytes. It checks transport reachability, not application health.', fields: [
      span2(field('Enable TCP health checks', 'tcp_health_enabled', Boolean(health), { checkbox: true, toggles: 'tcp_health', help: 'Optional per-backend connection probes. Disabling keeps other route settings.' })),
      field('Initial TCP probe state', 'tcp_health_initial_state', health?.initial_state || 'healthy', { group: 'tcp_health', select: [['healthy', 'Healthy — existing startup behavior'], ['checking', 'Checking — wait for successful connections']], help: 'Healthy preserves immediate startup eligibility. Checking excludes each backend until it reaches the consecutive successful connection threshold.' }),
      field('TCP probe interval (ms)', 'tcp_health_interval_ms', health?.interval_ms ?? 3000, { group: 'tcp_health', type: 'number', min: 100, max: 300000, help: '100–300,000 ms between connection probes.' }),
      field('TCP probe timeout (ms)', 'tcp_health_timeout_ms', health?.timeout_ms ?? 2000, { group: 'tcp_health', type: 'number', min: 100, max: 60000, help: '100–60,000 ms, no longer than the TCP probe interval.' }),
      field('Healthy TCP probe successes', 'tcp_health_healthy_successes', health?.healthy_successes ?? 1, { group: 'tcp_health', type: 'number', min: 1, max: 100, help: 'Consecutive successful connections required to release checking startup or recover an excluded backend.' }),
      field('Unhealthy TCP probe failures', 'tcp_health_unhealthy_failures', health?.unhealthy_failures ?? 2, { group: 'tcp_health', type: 'number', min: 1, max: 100, help: 'Consecutive failed connections or handshakes before a backend is excluded.' }),
    ] }),
    upstreamSection('tcp', route),
  ];
}

/**
 * Username + password controls that ask the proxy for a `username:salt_hex:sha256_hex` line
 * (POST /v1/util/hash-password) and append it to the credentials list. The password only ever
 * travels in that request: it is not part of the route draft and the field is cleared after use.
 */
function credentialGenerator() {
  const control = (labelText, name, type, autocomplete, help) => {
    const wrap = document.createElement('div'); wrap.className = 'field';
    const input = document.createElement('input'); input.type = type; input.id = `route-field-${name}`; input.autocomplete = autocomplete; input.spellcheck = false; input.setAttribute('autocapitalize', 'none'); input.dataset.credentialInput = name;
    const label = document.createElement('label'); label.htmlFor = input.id; copy(label, labelText);
    const hint = document.createElement('span'); hint.className = 'field-help-inline'; hint.id = `${input.id}-help`; copy(hint, help); input.setAttribute('aria-describedby', hint.id);
    wrap.append(label, input, hint);
    return [wrap, input];
  };
  const [userField, user] = control('New credential username', 'hash_username', 'text', 'username', 'No colon, surrounding whitespace or control characters; 1–255 characters.');
  const [passwordField, password] = control('New credential password', 'hash_password', 'password', 'new-password', 'Hashed by the proxy with a fresh random salt and discarded; never stored or mirrored into the route JSON. 1–1,024 characters.');
  const row = document.createElement('div'); row.className = 'button-row span-2';
  const button = document.createElement('button'); button.type = 'button'; button.className = 'button button-secondary'; button.id = 'add-credential'; copy(button, 'Add credential');
  const note = document.createElement('div'); note.className = 'inline-message'; note.id = 'credential-message'; note.setAttribute('aria-live', 'polite');
  row.append(button, note);
  button.addEventListener('click', () => addCredential(user, password, note, button));
  // Enter in either control generates the credential rather than submitting (saving) the route.
  for (const input of [user, password]) input.addEventListener('keydown', (event) => { if (event.key === 'Enter') { event.preventDefault(); addCredential(user, password, note, button); } });
  return [userField, passwordField, row];
}

async function addCredential(userInput, passwordInput, note, button) {
  const username = userInput.value.trim();
  const password = passwordInput.value;
  message(note);
  if (!username || !password) return message(note, t('Enter a username and a password to generate a credential line.'), 'error');
  if (username.length > 255 || username.includes(':') || /[\x00-\x1f\x7f]/.test(username)) return message(note, t('Username cannot contain a colon or control characters and must be 1–255 characters.'), 'error');
  if (password.length > 1024) return message(note, t('Password must be at most 1,024 characters.'), 'error');
  setBusy(button, true, t('Hashing…'));
  try {
    const { data } = await api('/v1/util/hash-password', { method: 'POST', json: { username, password } });
    if (!isObject(data) || typeof data.credential !== 'string') throw new Error(t('The proxy did not return a credential line.'));
    const field = $('#route-form [name="basic_auth_credentials"]');
    const lines = nonemptyLines(field.value);
    const existing = lines.findIndex((line) => { const at = line.indexOf(':'); return at > 0 && line.slice(0, at) === data.username; });
    if (existing >= 0) lines[existing] = data.credential; else lines.push(data.credential);
    field.value = lines.join('\n');
    syncRouteJsonFromForm();
    userInput.value = '';
    message(note, existing >= 0 ? t('Replaced the credential line for {username}. Save the route to publish it.', { username: data.username }) : t('Added a credential line for {username}. Save the route to publish it.', { username: data.username }), 'success');
  } catch (error) {
    if (error.status === 401) return logout('Your session is no longer authorized.');
    message(note, error.status === 404 || error.status === 405 ? t('This proxy does not offer password hashing; use hangang --hash-password instead.') : error.message, 'error');
  } finally {
    passwordInput.value = '';
    setBusy(button, false);
  }
}

function buildRouteFields(type, route) {
  const frag = document.createDocumentFragment();
  frag.append(...(type === 'http' ? httpSections(route) : tcpSections(route)));
  return frag;
}

function field(labelText, name, value, opts = {}) {
  const wrap = document.createElement('div'); wrap.className = opts.checkbox ? 'field check-field' : 'field';
  let control;
  if (opts.select) {
    control = document.createElement('select');
    for (const [optionValue, optionText] of opts.select) { const option = document.createElement('option'); option.value = optionValue; copy(option, optionText); control.append(option); }
  } else control = opts.textarea ? document.createElement('textarea') : document.createElement('input');
  control.name = name; control.id = `route-field-${name}`;
  const label = document.createElement('label'); label.htmlFor = control.id; copy(label, labelText);
  let help = null;
  if (opts.help) { help = document.createElement('span'); help.className = 'field-help-inline'; help.id = `${control.id}-help`; copy(help, opts.help); control.setAttribute('aria-describedby', help.id); }
  if (opts.checkbox) {
    control.type = 'checkbox'; control.checked = Boolean(value);
    const text = document.createElement('span'); text.className = 'check-text'; text.append(label); if (help) text.append(help);
    wrap.append(control, text);
  } else {
    if (opts.type) control.type = opts.type;
    wrap.append(label, control); if (help) wrap.append(help);
    control.value = value === null || value === undefined ? '' : String(value);
  }
  if (opts.required) control.required = true;
  if (opts.pattern) control.pattern = opts.pattern;
  if (opts.placeholder) { control.dataset.appI18nPlaceholder = opts.placeholder; control.placeholder = t(opts.placeholder); }
  if (opts.min !== undefined) control.min = String(opts.min);
  if (opts.max !== undefined) control.max = String(opts.max);
  if (opts.maxlength !== undefined) control.maxLength = opts.maxlength;
  if (opts.readonly) control.readOnly = true;
  if (opts.group) control.dataset.group = opts.group;
  if (opts.toggles) { control.dataset.toggles = opts.toggles; control.addEventListener('change', () => applyGroupToggles(control.form)); }
  control.addEventListener('input', syncRouteJsonFromForm);
  control.addEventListener('change', syncRouteJsonFromForm);
  return wrap;
}

/** Controls that belong to an optional object are disabled while its enabling checkbox is unchecked. */
function applyGroupToggles(form) {
  const active = form.elements['active_health_enabled'];
  const passive = form.elements['passive_health_enabled'];
  if (active && passive && !active.checked) passive.checked = false;
  for (const toggle of $$('[data-toggles]', form)) {
    for (const control of $$(`[data-group="${toggle.dataset.toggles}"]`, form)) {
      control.disabled = toggle.disabled || !toggle.checked;
      luaEditors.get(control)?.editor.setDisabled(control.disabled);
    }
  }
  updateResourcePolicyControls(form);
  updateJwtControls(form);
}

function nonemptyLines(value) { return value.split('\n').map((v) => v.trim()).filter(Boolean); }
function validInboundTlsPath(value) {
  return value.startsWith('/') && value !== '/' && new TextEncoder().encode(value).length <= 4096
    && !/[\0\r\n\\]/.test(value)
    && value.slice(1).split('/').every((segment) => segment !== '' && segment !== '.' && segment !== '..');
}
function validSpiffeIdentity(uri) {
  if (uri.length > 2048 || !/^[\x00-\x7f]*$/.test(uri) || !uri.startsWith('spiffe://')) return false;
  const rest = uri.slice('spiffe://'.length);
  if (/[?#%@:]/.test(rest)) return false;
  const slash = rest.indexOf('/');
  const domain = slash < 0 ? rest : rest.slice(0, slash);
  const path = slash < 0 ? null : rest.slice(slash + 1);
  if (!domain || domain.length > 255 || !/^[a-z0-9._-]+$/.test(domain)) return false;
  if (path === null) return true;
  return Boolean(path) && path.split('/').every((segment) => segment !== '.' && segment !== '..' && /^[A-Za-z0-9._-]+$/.test(segment));
}
function pairsToLines(obj = {}) { return Object.entries(obj || {}).map(([k,v]) => `${k}: ${v}`).join('\n'); }
function jsonPairsToLines(obj = {}) { return Object.entries(obj || {}).map(([k,v]) => `${k} = ${JSON.stringify(v)}`).join('\n'); }
function parseHeaderLines(value, what = 'Header') { return Object.fromEntries(nonemptyLines(value).map((line) => { const at = line.indexOf(':'); if (at < 1) throw new Error(t('{field} needs “name: value”: {line}', { field: t(what), line })); const name = line.slice(0, at).trim(); if (!HEADER_NAME.test(name)) throw new Error(t('{field} name is invalid: {name}', { field: t(what), name })); return [name, line.slice(at + 1).trim()]; })); }
function parseJsonLines(value) { return Object.fromEntries(nonemptyLines(value).map((line) => { const at = line.indexOf('='); if (at < 0) throw new Error(t('JSON match needs “pointer = value”: {line}', { line })); const key = line.slice(0, at).trim(); if (key && !key.startsWith('/')) throw new Error(t('JSON match pointer must start with /: {pointer}', { pointer: key })); return [key, JSON.parse(line.slice(at + 1).trim())]; })); }
function parseWeights(value) { return value.split(/[\s,]+/).filter(Boolean).map((part) => { if (!/^\d+$/.test(part) || Number(part) < 1 || Number(part) > 1000) throw new Error(t('Backend weights must be whole numbers 1–1,000: {value}', { value: part })); return Number(part); }); }
function headerNames(lines, what) { for (const name of lines) if (!HEADER_NAME.test(name)) throw new Error(t('{field} name is invalid: {name}', { field: t(what), name })); return lines; }
/**
 * Client-side hint mirroring the server's authorization header rules: generated context names
 * (x-forwarded-*, forwarded, x-real-ip, x-original-method/uri/url/client-ip) and hop-by-hop names
 * are reserved in both lists; the response list may additionally carry the SSO identity names.
 */
function authHeaderNames(lines, what, identity) {
  for (const raw of headerNames(lines, what)) {
    const name = raw.toLowerCase();
    if (identity && AUTH_IDENTITY_HEADERS.includes(name)) continue;
    if (AUTH_RESERVED_HEADERS.includes(name) || name.startsWith('x-forwarded-')) {
      throw new Error(identity
        ? t('{field} {name} is generated by the proxy; only the identity names {names} may be copied from the authorization response', { field: t(what), name: raw, names: AUTH_IDENTITY_HEADERS.join(', ') })
        : t('{field} {name} is generated by the proxy from the trusted-proxy resolution and cannot be copied from the client', { field: t(what), name: raw }));
    }
  }
  return lines;
}
function parseJsonField(text, label) { try { return JSON.parse(text); } catch (error) { throw new Error(t('{field} is not valid JSON: {detail}', { field: t(label), detail: error.message })); } }

function readInteger(form, name, label, { min, max, optional = false, fallback = null } = {}) {
  const control = form.elements[name];
  const raw = control.disabled ? '' : control.value.trim();
  if (!raw) { if (optional) return fallback; throw new Error(t('{field} is required', { field: t(label) })); }
  if (!/^-?\d+$/.test(raw)) throw new Error(t('{field} must be a whole number', { field: t(label) }));
  const value = Number(raw);
  if ((min !== undefined && value < min) || (max !== undefined && value > max)) throw new Error(t('{field} must be {minimum}–{maximum}', { field: t(label), minimum: formatNumber(min), maximum: formatNumber(max) }));
  return value;
}

function readStatusCodes(form, name, label) {
  const parts = form.elements[name].value.split(/[\s,]+/).filter(Boolean);
  if (parts.length < 1 || parts.length > 64 || parts.some((part) => !/^\d{3}$/.test(part) || Number(part) < 100 || Number(part) > 599)
    || new Set(parts).size !== parts.length) {
    throw new Error(t('{field} must list 1–64 unique HTTP statuses from 100–599', { field: t(label) }));
  }
  return parts.map(Number);
}

function ensureDisjointStatuses(healthy, unhealthy, healthyLabel, unhealthyLabel) {
  if (healthy.some((status) => unhealthy.includes(status))) {
    throw new Error(t('{healthy} and {unhealthy} cannot overlap', { healthy: t(healthyLabel), unhealthy: t(unhealthyLabel) }));
  }
}

function jwtIdentityHeader(name) {
  if (!HEADER_NAME.test(name) || new TextEncoder().encode(name).length > 128) return false;
  const lower = name.toLowerCase();
  return !['host', 'authorization', 'proxy-authorization', 'proxy-authenticate', 'proxy-connection',
    'cookie', 'set-cookie', 'forwarded', 'x-real-ip', 'x-hangang-auth-terminal'].includes(lower)
    && !lower.startsWith('x-forwarded-') && !lower.startsWith('x-original-') && !lower.startsWith('sec-websocket-')
    && !AUTH_RESERVED_HEADERS.includes(lower);
}

function jwtFromForm(form, previous) {
  if (!form.elements['jwt_auth_enabled'].checked) return null;
  const value = (name) => form.elements[name].value.trim();
  const list = (name) => nonemptyLines(form.elements[name].value);
  const issuer = value('jwt_issuer');
  let issuerUrl;
  try { issuerUrl = new URL(issuer); } catch { throw new Error(t('JWT issuer must be an HTTPS URL without credentials, query or fragment')); }
  if (issuer.length > 512 || issuerUrl.protocol !== 'https:' || issuerUrl.username || issuerUrl.password || issuer.includes('?') || issuer.includes('#'))
    throw new Error(t('JWT issuer must be an HTTPS URL without credentials, query or fragment'));
  const audiences = list('jwt_audiences');
  if (!audiences.length || audiences.length > 8 || new Set(audiences).size !== audiences.length || audiences.some((item) => new TextEncoder().encode(item).length > 255))
    throw new Error(t('JWT audiences need 1–8 distinct values of at most 255 bytes'));
  const algorithms = list('jwt_algorithms');
  if (!algorithms.length || algorithms.length > 4 || new Set(algorithms).size !== algorithms.length || algorithms.some((item) => !['RS256', 'PS256', 'ES256', 'EdDSA'].includes(item)))
    throw new Error(t('JWT algorithms must list 1–4 distinct asymmetric choices'));
  const profile = value('jwt_profile');
  if (profile !== 'rfc9068') throw new Error(t('Only the RFC 9068 access-token profile is supported'));
  const scopeClaim = value('jwt_scope_claim');
  const groupsClaim = value('jwt_groups_claim');
  const claimName = /^[A-Za-z0-9_.-]{1,64}$/;
  if (!claimName.test(scopeClaim) || !claimName.test(groupsClaim) || scopeClaim === groupsClaim ||
      ['iss', 'aud', 'exp', 'sub', 'iat', 'nbf', 'jti', 'client_id'].includes(scopeClaim) ||
      ['iss', 'aud', 'exp', 'sub', 'iat', 'nbf', 'jti', 'client_id'].includes(groupsClaim))
    throw new Error(t('JWT scope and group claim names must be distinct, bounded nonstandard names'));
  const requiredScopes = list('jwt_required_scopes');
  const requiredGroups = list('jwt_required_groups');
  if ([requiredScopes, requiredGroups].some((items) => items.length > 32 || new Set(items).size !== items.length || items.some((item) => new TextEncoder().encode(item).length > 128)))
    throw new Error(t('JWT required scopes and groups allow at most 32 distinct values of 128 bytes each'));
  const verification = { ...(isObject(previous?.verification) ? previous.verification : {}),
    issuer, audiences, profile, algorithms,
    leeway_seconds: readInteger(form, 'jwt_leeway_seconds', 'Clock leeway', { min: 0, max: 60 }),
    max_lifetime_seconds: readInteger(form, 'jwt_max_lifetime_seconds', 'Maximum token lifetime', { min: 1, max: 86400 }),
    scope_claim: scopeClaim, groups_claim: groupsClaim,
    required_scopes: requiredScopes, required_groups: requiredGroups };
  const source = value('jwt_key_source');
  let keys;
  if (source === 'local') {
    const jwks = parseJsonField(form.elements['jwt_local_jwks'].value, 'Local public JWKS JSON');
    if (!isObject(jwks) || !Array.isArray(jwks.keys) || !jwks.keys.length || jwks.keys.length > 32 ||
      new TextEncoder().encode(form.elements['jwt_local_jwks'].value).length > 131072)
      throw new Error(t('Local public JWKS needs 1–32 keys within 128 KiB'));
    keys = { ...(previous?.keys?.source === 'local' ? previous.keys : {}), source, jwks };
  } else if (source === 'remote') {
    const kind = value('jwt_endpoint_kind');
    let endpoint;
    if (kind === 'oidc') endpoint = { ...(previous?.keys?.source === 'remote' && previous.keys.config?.endpoint?.kind === 'oidc' ? previous.keys.config.endpoint : {}), kind };
    else if (kind === 'jwks') {
      const url = value('jwt_jwks_url');
      let parsed;
      try { parsed = new URL(url); } catch { throw new Error(t('Explicit JWKS URL must be HTTPS without credentials, query or fragment')); }
      if (url.length > 2048 || parsed.protocol !== 'https:' || parsed.username || parsed.password || url.includes('?') || url.includes('#'))
        throw new Error(t('Explicit JWKS URL must be HTTPS without credentials, query or fragment'));
      endpoint = { ...(previous?.keys?.source === 'remote' && previous.keys.config?.endpoint?.kind === 'jwks' ? previous.keys.config.endpoint : {}), kind, url };
    } else throw new Error(t('Choose a valid JWT key source'));
    const ttl = readInteger(form, 'jwt_cache_ttl_seconds', 'Key cache TTL', { min: 1, max: 3600 });
    const cooldown = readInteger(form, 'jwt_refresh_cooldown_seconds', 'Refresh cooldown', { min: 1, max: 60 });
    if (cooldown > ttl) throw new Error(t('JWT refresh cooldown cannot exceed cache TTL'));
    const caPem = form.elements['jwt_ca_pem'].value.trim() || null;
    if (caPem && (new TextEncoder().encode(caPem).length > 131072 || caPem.includes('PRIVATE KEY')))
      throw new Error(t('JWT public CA PEM cannot contain a private key or exceed 128 KiB'));
    const config = { ...(previous?.keys?.source === 'remote' && isObject(previous.keys.config) ? previous.keys.config : {}),
      endpoint, cache_ttl_seconds: ttl, refresh_cooldown_seconds: cooldown,
      timeout_ms: readInteger(form, 'jwt_timeout_ms', 'Key fetch timeout', { min: 1, max: 5000 }), ca_pem: caPem };
    keys = { ...(previous?.keys?.source === 'remote' ? previous.keys : {}), source, config };
  } else throw new Error(t('Choose a valid JWT key source'));
  const identity = value('jwt_identity_header') || null;
  if (identity && !jwtIdentityHeader(identity)) throw new Error(t('JWT verified identity header is reserved or invalid'));
  return { ...(isObject(previous) ? previous : {}), verification, keys,
    hide_credentials: form.elements['jwt_hide_credentials'].checked, identity_header: identity };
}

function routeFromForm() {
  const form = $('#route-form'); const type = state.editing.type;
  let route = structuredClone(state.editing.value);
  try {
    const advanced = JSON.parse($('#route-json').value);
    if (isObject(advanced)) route = advanced;
  } catch (_) { /* native fields can repair the generated JSON */ }
  if (type === 'http' && route.resource_policy !== undefined && route.resource_policy !== null) {
    const policy = route.resource_policy;
    if (!isObject(policy) || typeof policy.resource_id !== 'string' || (policy.enforce !== undefined && typeof policy.enforce !== 'boolean')
      || !isObject(policy.principal) || typeof policy.principal.source !== 'string' || !Array.isArray(policy.allow)
      || policy.allow.length > 32
      || !policy.allow.every((rule) => isObject(rule) && Array.isArray(rule.subjects) && rule.subjects.length <= 32
        && rule.subjects.every((value) => typeof value === 'string' && new TextEncoder().encode(value).length <= (policy.principal.source === 'workload' ? 2048 : 255))
        && Array.isArray(rule.methods) && rule.methods.length <= 16
        && rule.methods.every((value) => typeof value === 'string' && value.length <= 32))) {
      throw new Error(t('Advanced resource policy JSON must contain an ID, principal and allow-rule arrays'));
    }
  }
  if (type === 'http' && route.jwt_auth !== undefined && route.jwt_auth !== null &&
      (!isObject(route.jwt_auth) || !isObject(route.jwt_auth.verification) || !isObject(route.jwt_auth.keys))) {
    throw new Error(t('Advanced JWT JSON must contain verification and keys objects'));
  }
  if (type === 'http' && route.workload_auth !== undefined && route.workload_auth !== null &&
      (!isObject(route.workload_auth) || !Array.isArray(route.workload_auth.listener_ids) || !Array.isArray(route.workload_auth.allowed_uri_sans))) {
    throw new Error(t('Advanced workload authentication JSON needs listener_ids and allowed_uri_sans arrays'));
  }
  if (type === 'tcp' && route.inbound_tls !== undefined && route.inbound_tls !== null &&
      (!isObject(route.inbound_tls) || !Array.isArray(route.inbound_tls.allowed_uri_sans))) {
    throw new Error(t('Advanced inbound TLS JSON must contain an object with allowed_uri_sans array'));
  }
  const raw = (name) => form.elements[name].value;
  const text = (name) => raw(name).trim();
  const optionalText = (name) => text(name) || null;
  const checked = (name) => form.elements[name].checked;
  const lines = (name) => nonemptyLines(raw(name));
  const integer = (name, label, opts) => readInteger(form, name, label, opts);

  route.id = text('id');
  if (checked('enabled')) delete route.enabled; else route.enabled = false;
  route.priority = integer('priority', 'Matching priority', { min: -2147483648, max: 2147483647 });
  route.backends = readBackendValues(route.backends);
  route.deny_cidrs = lines('deny_cidrs');
  if (route.deny_cidrs.length > 1024) throw new Error(t('At most 1,024 denied CIDRs are allowed'));
  for (const cidr of route.deny_cidrs) if (!/^[0-9a-fA-F:.]+\/\d{1,3}$/.test(cidr)) throw new Error(t('Denied CIDR must be address/prefix: {cidr}', { cidr }));

  const upstream = isObject(route.upstream) ? route.upstream : {};
  upstream.connect_address = optionalText('connect_address');
  upstream.unix_socket = optionalText('unix_socket');
  upstream.dns_servers = lines('dns_servers');
  if (upstream.dns_servers.length > 4) throw new Error(t('At most four upstream DNS servers may be configured'));
  const socksAddress = optionalText('socks5_address');
  const socksUser = optionalText('socks5_username_env');
  const socksPassword = optionalText('socks5_password_env');
  if (!socksAddress && (socksUser || socksPassword)) throw new Error(t('SOCKS5 proxy address is required when SOCKS5 credential variables are set'));
  if (Boolean(socksUser) !== Boolean(socksPassword)) throw new Error(t('SOCKS5 username and password variables must be configured together'));
  for (const variable of [socksUser, socksPassword]) if (variable && !/^HANGANG_SOCKS5_[A-Z0-9_]*$/.test(variable)) throw new Error(t('SOCKS5 credential variables must be named HANGANG_SOCKS5_… using A-Z, 0-9 and _: {variable}', { variable }));
  upstream.socks5 = socksAddress ? { ...(isObject(upstream.socks5) ? upstream.socks5 : {}), address: socksAddress, username_env: socksUser, password_env: socksPassword } : null;
  if (upstream.unix_socket) {
    if (!upstream.unix_socket.startsWith('/') || upstream.unix_socket.split('/').some(part => part === '.' || part === '..') || new TextEncoder().encode(upstream.unix_socket).length > 107) throw new Error(t('Unix socket must be an absolute, normalized path of at most 107 bytes'));
    if (upstream.connect_address || upstream.socks5 || upstream.dns_servers.length) throw new Error(t('Unix socket cannot be combined with connect address, SOCKS5 or DNS servers'));
  }
  if (checked('upstream_tls')) {
    const tls = isObject(upstream.tls) ? upstream.tls : {};
    tls.server_name = optionalText('tls_server_name');
    tls.insecure_skip_verify = checked('tls_insecure_skip_verify');
    tls.ca_file = optionalText('tls_ca_file');
    if (tls.ca_file && !tls.ca_file.startsWith('/')) throw new Error(t('Upstream TLS CA file must be an absolute path'));
    if (tls.ca_file && tls.insecure_skip_verify) throw new Error(t('Upstream TLS CA file cannot be combined with skipped certificate verification'));
    tls.max_fragment_size = integer('tls_max_fragment_size', 'TLS maximum fragment size', { min: 128, max: 16389, optional: true });
    upstream.tls = tls;
    if (type === 'http' && !route.backends.every((backend) => backendAddress(backend).startsWith('https://'))) throw new Error(t('Upstream TLS options require every backend to use https://'));
  } else upstream.tls = null;
  route.upstream = upstream;

  if (type === 'http') {
    const hostMode = raw('host_mode');
    route.host = hostMode === 'single' ? optionalText('host') : null;
    if (hostMode === 'group') route.hosts = lines('hosts');
    else delete route.hosts;
    route.host_regex = hostMode === 'regex' ? raw('host_regex') || null : null;
    if (hostMode === 'group') {
      if (!route.hosts.length || route.hosts.length > 32) throw new Error(t('Domain groups need 1–32 hosts'));
      if (new Set(route.hosts.map(host => host.toLowerCase())).size !== route.hosts.length) throw new Error(t('Domain group hosts must be distinct, ignoring case'));
    }
    if (hostMode === 'regex' && !route.host_regex?.trim()) throw new Error(t('Enter a host regular expression'));
    route.path_prefix = optionalText('path_prefix');
    if (route.path_prefix && !route.path_prefix.startsWith('/')) throw new Error(t('Path prefix must start with /'));
    route.path_match = raw('path_match');
    route.headers = parseHeaderLines(raw('headers'), 'Header match');
    route.json = parseJsonLines(raw('json'));
    if (Object.keys(route.headers).length > 64 || Object.keys(route.json).length > 64) throw new Error(t('At most 64 header matches and 64 JSON matches are allowed'));
    route.require_tls = checked('require_tls');
    route.upstream_host = optionalText('upstream_host');
    route.preserve_host = checked('preserve_host');
    if (route.preserve_host && route.upstream_host) throw new Error(t('Preserve incoming Host conflicts with an explicit upstream Host'));
    route.max_requests = integer('max_requests', 'Concurrent request limit', { min: 1, max: 1000000, optional: true });
    route.upstream_timeout_ms = integer('upstream_timeout_ms', 'Upstream timeout', { min: 1, max: 86400000, optional: true });
    route.retries = integer('retries', 'Retries', { min: 0, max: 16, optional: true, fallback: 0 });
    route.lua = raw('lua') || null;

    const balance = isObject(route.balance) ? route.balance : {};
    balance.mode = raw('balance_mode');
    if ($('#route-form .backend-editor').dataset.mode === 'named') {
      if (Array.isArray(balance.weights) && balance.weights.length) throw new Error(t('Named members cannot also use legacy backend weights'));
      balance.weights = [];
    } else {
      balance.weights = parseWeights(text('balance_weights'));
      if (balance.weights.length && balance.weights.length !== route.backends.length) throw new Error(t(route.backends.length === 1 ? 'Backend weights must list exactly {count} value, one per backend' : 'Backend weights must list exactly {count} values, one per backend', { count: route.backends.length }));
    }
    const threshold = integer('health_failure_threshold', 'Failure threshold', { min: 1, max: 100, optional: true });
    const cooldown = integer('health_cooldown_ms', 'Cooldown', { min: 10, max: 300000, optional: true });
    if ((threshold === null) !== (cooldown === null)) throw new Error(t('Passive health needs both a failure threshold and a cooldown'));
    balance.health = threshold === null ? null : { failure_threshold: threshold, cooldown_ms: cooldown };
    const activeEnabled = checked('active_health_enabled');
    const passiveEnabled = checked('passive_health_enabled');
    if (activeEnabled && balance.health) throw new Error(t('Active health checks conflict with legacy failure cooldown; clear both legacy fields'));
    if (passiveEnabled && !activeEnabled) throw new Error(t('Passive health checks require active health checks'));
    if (activeEnabled) {
      const active = isObject(balance.active_health) ? balance.active_health : {};
      const initial = raw('active_health_initial_state');
      if (initial === 'checking') active.initial_state = 'checking';
      else if (initial === 'healthy') delete active.initial_state;
      else throw new Error(t('Select a valid initial probe state'));
      active.path = text('active_health_path');
      if (active.path.length > 256 || !/^\/[\x21-\x7e]*$/.test(active.path) || /[?#]/.test(active.path)) throw new Error(t('Probe path must be a printable absolute path without query or fragment'));
      active.host = optionalText('active_health_host');
      active.interval_ms = integer('active_health_interval_ms', 'Probe interval', { min: 100, max: 300000 });
      active.timeout_ms = integer('active_health_timeout_ms', 'Probe timeout', { min: 100, max: 60000 });
      if (active.timeout_ms > active.interval_ms) throw new Error(t('Probe timeout cannot exceed interval'));
      active.healthy_statuses = readStatusCodes(form, 'active_health_healthy_statuses', 'Healthy HTTP statuses');
      active.unhealthy_statuses = readStatusCodes(form, 'active_health_unhealthy_statuses', 'Unhealthy HTTP statuses');
      ensureDisjointStatuses(active.healthy_statuses, active.unhealthy_statuses, 'Healthy HTTP statuses', 'Unhealthy HTTP statuses');
      active.healthy_successes = integer('active_health_healthy_successes', 'Healthy probe successes', { min: 1, max: 100 });
      active.unhealthy_http_failures = integer('active_health_unhealthy_http_failures', 'Unhealthy HTTP failures', { min: 1, max: 100 });
      active.unhealthy_tcp_failures = integer('active_health_unhealthy_tcp_failures', 'Unhealthy TCP failures', { min: 1, max: 100 });
      active.unhealthy_timeouts = integer('active_health_unhealthy_timeouts', 'Unhealthy probe timeouts', { min: 1, max: 100 });
      balance.active_health = active;
    } else if (Object.hasOwn(balance, 'active_health')) balance.active_health = null;
    if (passiveEnabled) {
      const passive = isObject(balance.passive_health) ? balance.passive_health : {};
      passive.healthy_statuses = readStatusCodes(form, 'passive_health_healthy_statuses', 'Passive healthy statuses');
      passive.unhealthy_statuses = readStatusCodes(form, 'passive_health_unhealthy_statuses', 'Passive unhealthy statuses');
      ensureDisjointStatuses(passive.healthy_statuses, passive.unhealthy_statuses, 'Passive healthy statuses', 'Passive unhealthy statuses');
      passive.unhealthy_http_failures = integer('passive_health_unhealthy_http_failures', 'Passive HTTP failures', { min: 1, max: 100 });
      passive.unhealthy_tcp_failures = integer('passive_health_unhealthy_tcp_failures', 'Passive TCP failures', { min: 1, max: 100 });
      passive.unhealthy_timeouts = integer('passive_health_unhealthy_timeouts', 'Passive timeouts', { min: 1, max: 100 });
      balance.passive_health = passive;
    } else if (Object.hasOwn(balance, 'passive_health')) balance.passive_health = null;
    route.balance = balance;

    const authUrl = optionalText('auth_url');
    const authRequest = authHeaderNames(lines('auth_request_headers'), 'Forwarded request header', false);
    const authResponse = authHeaderNames(lines('auth_response_headers'), 'Identity response header', true);
    const authTimeout = integer('auth_timeout_ms', 'Authorization timeout', { min: 1, max: 5000, optional: true });
    const authForward = checked('auth_forward_response');
    if (!authUrl) {
      if (authRequest.length || authResponse.length || authTimeout !== null || authForward) throw new Error(t('External authorization needs an Authorization URL; clear the other authorization fields to disable it'));
      route.auth = null;
    } else {
      if (!/^https?:\/\/[^\s/?#@]+/i.test(authUrl) || authUrl.includes('#')) throw new Error(t('Authorization URL must be an http:// or https:// URL without credentials or fragment'));
      if (authRequest.length > 32 || authResponse.length > 32) throw new Error(t('At most 32 authorization headers are allowed per list'));
      route.auth = { ...(isObject(route.auth) ? route.auth : {}), url: authUrl, request_headers: authRequest, response_headers: authResponse, timeout_ms: authTimeout ?? 1000, forward_response: authForward };
    }

    const credentials = lines('basic_auth_credentials');
    const realm = text('basic_auth_realm');
    const identity = optionalText('basic_auth_identity_header');
    const hide = checked('basic_auth_hide_credentials');
    if (!credentials.length) {
      if ((realm && realm !== 'restricted') || identity || hide) throw new Error(t('Basic authentication needs at least one credential; clear the realm, identity header and hide option to disable it'));
      route.basic_auth = null;
    } else {
      if (credentials.length > 4096) throw new Error(t('At most 4,096 basic-auth credentials are allowed'));
      const usernames = new Set();
      for (const entry of credentials) {
        const parts = /^([^:\s][^:]*[^:\s]|[^:\s]):([0-9a-fA-F]{32,128}):([0-9a-fA-F]{64})$/.exec(entry);
        if (!parts || parts[2].length % 2) throw new Error(t('Credential must be username:salt_hex:sha256_hex from hangang --hash-password: {entry}', { entry: entry.length > 48 ? `${entry.slice(0, 45)}…` : entry }));
        if (usernames.has(parts[1])) throw new Error(t('Duplicate basic-auth username: {username}', { username: parts[1] }));
        usernames.add(parts[1]);
      }
      if (/[\x00-\x1f\x7f"]/.test(realm)) throw new Error(t('Realm cannot contain control characters or double quotes'));
      if (identity && !HEADER_NAME.test(identity)) throw new Error(t('Identity header name is invalid: {name}', { name: identity }));
      route.basic_auth = { ...(isObject(route.basic_auth) ? route.basic_auth : {}), realm: realm || 'restricted', credentials, hide_credentials: hide, identity_header: identity };
    }

    route.jwt_auth = jwtFromForm(form, route.jwt_auth);
    if (route.jwt_auth && route.basic_auth) throw new Error(t('JWT and Basic authentication cannot share Authorization'));
    if (route.jwt_auth?.identity_header && authResponse.some((name) => name.toLowerCase() === route.jwt_auth.identity_header.toLowerCase()))
      throw new Error(t('JWT identity header conflicts with an external authorization response header'));
    if (checked('workload_auth_enabled')) {
      const listenerIds = lines('workload_listener_ids');
      const allowed = lines('workload_allowed_uri_sans');
      const identity = optionalText('workload_identity_header');
      if (!listenerIds.length || listenerIds.length > 64 || new Set(listenerIds).size !== listenerIds.length || listenerIds.some((id) => !/^[A-Za-z0-9._:-]{1,128}$/.test(id)))
        throw new Error(t('Workload authentication needs 1–64 distinct configured listener IDs'));
      if (!allowed.length || allowed.length > 128 || new Set(allowed).size !== allowed.length || allowed.some((uri) => !validSpiffeIdentity(uri)))
        throw new Error(t('Workload authentication needs 1–128 distinct canonical SPIFFE URIs'));
      if (identity && !jwtIdentityHeader(identity)) throw new Error(t('Workload identity header is reserved or invalid'));
      if (identity && [route.basic_auth?.identity_header, route.jwt_auth?.identity_header, ...authResponse].some((header) => header?.toLowerCase() === identity.toLowerCase()))
        throw new Error(t('Workload identity header conflicts with another verified identity header'));
      route.workload_auth = { ...(isObject(route.workload_auth) ? route.workload_auth : {}), listener_ids: listenerIds, allowed_uri_sans: allowed, identity_header: identity };
    } else if (Object.hasOwn(route, 'workload_auth')) route.workload_auth = null;

    const accessMode = raw('access_mode');
    if (state.editing.originalId && state.editing.value.access_mode === 'protected' && accessMode === 'legacy') {
      throw new Error(t('A protected route cannot return to Legacy. Choose Public or Application and clear gateway auth explicitly.'));
    }
    if (accessMode === 'legacy') {
      if (route.access_mode !== 'legacy') delete route.access_mode;
    } else if (['public', 'application', 'protected'].includes(accessMode)) route.access_mode = accessMode;
    else throw new Error(t('Select a valid access mode'));
    if (accessMode === 'protected' && !route.auth && !route.basic_auth && !route.jwt_auth && !route.workload_auth) throw new Error(t('Protected access requires Basic, JWT, workload mTLS or external authorization'));
    if ((accessMode === 'public' || accessMode === 'application') && (route.auth || route.basic_auth || route.jwt_auth || route.workload_auth)) {
      throw new Error(t('{mode} access cannot configure gateway Basic, JWT, workload mTLS or external authorization', { mode: t(accessMode) }));
    }

    const policyAction = raw('resource_policy_action');
    const originalPolicy = isObject(state.editing.value.resource_policy) ? state.editing.value.resource_policy : null;
    if (originalPolicy?.enforce !== false && originalPolicy && policyAction !== 'configured') {
      throw new Error(t('Save enforcement Off first, then reopen the route to remove its policy'));
    }
    if (originalPolicy && policyAction === 'none') throw new Error(t('Use Remove resource policy to delete an existing policy'));
    if (policyAction === 'none' || policyAction === 'remove') {
      delete route.resource_policy;
    } else if (policyAction === 'configured') {
      if (accessMode !== 'protected') throw new Error(t('Resource authorization requires Protected access'));
      if (route.auth?.terminal_response === true) throw new Error(t('Resource authorization cannot use terminal external authorization responses'));
      const resourceId = raw('resource_policy_id');
      if (!/^[A-Za-z0-9._:-]{1,128}$/.test(resourceId)) throw new Error(t('Resource ID must be 1–128 ASCII letters, digits, dots, underscores, colons or dashes'));
      const source = raw('resource_policy_source');
      const subjectHeader = raw('resource_policy_subject_header');
      let principal;
      if (source === 'basic') {
        if (!route.basic_auth) throw new Error(t('Basic principal source requires Basic authentication'));
        if (subjectHeader) throw new Error(t('Clear the external subject header when using a Basic principal'));
        principal = { source: 'basic' };
      } else if (source === 'external') {
        if (!route.auth) throw new Error(t('External principal source requires external authorization'));
        if (!HEADER_NAME.test(subjectHeader) || new TextEncoder().encode(subjectHeader).length > 128) throw new Error(t('External subject header must be a valid header name of at most 128 bytes'));
        if (!authResponse.some((name) => name.toLowerCase() === subjectHeader.toLowerCase())) throw new Error(t('External subject header must be in Identity response headers'));
        principal = { source: 'external', subject_header: subjectHeader };
      } else if (source === 'jwt') {
        if (!route.jwt_auth) throw new Error(t('JWT principal source requires JWT authentication'));
        if (subjectHeader) throw new Error(t('Clear the external subject header when using a JWT principal'));
        principal = { source: 'jwt' };
      } else if (source === 'workload') {
        if (!route.workload_auth) throw new Error(t('Workload principal source requires workload authentication'));
        if (subjectHeader) throw new Error(t('Clear the external subject header when using a workload principal'));
        principal = { source: 'workload' };
      } else throw new Error(t('Choose a valid principal source'));
      const ruleRows = [...form.querySelectorAll('.resource-rule-row')];
      if (ruleRows.length > 32) throw new Error(t('At most 32 resource allow rules are allowed'));
      let entries = 0; let textBytes = resourceId.length;
      const allow = ruleRows.map((row) => {
        const subjects = row.querySelector('.resource-rule-subjects').value.split('\n').filter((value) => value !== '');
        const methods = row.querySelector('.resource-rule-methods').value.split('\n').filter((value) => value !== '');
        if (!subjects.length || subjects.length > 32) throw new Error(t('Each allow rule needs 1–32 subjects'));
        if (!methods.length || methods.length > 16) throw new Error(t('Each allow rule needs 1–16 methods'));
        if (new Set(subjects).size !== subjects.length) throw new Error(t('Subjects must be unique within each allow rule'));
        if (new Set(methods).size !== methods.length) throw new Error(t('Methods must be unique within each allow rule'));
        for (const subject of subjects) {
          const bytes = new TextEncoder().encode(subject).length;
          if (source === 'workload') {
            if (!validSpiffeIdentity(subject)) throw new Error(t('Workload subjects must be exact canonical SPIFFE URIs of at most 2,048 bytes'));
          } else if (subject !== subject.trim() || /\p{Cc}/u.test(subject) || bytes < 1 || bytes > 255) throw new Error(t('Subjects must be exact 1–255 byte UTF-8 strings without surrounding whitespace or controls'));
          if (source === 'external' && subject.includes(',')) throw new Error(t('External subjects cannot contain commas'));
          textBytes += bytes;
        }
        for (const method of methods) {
          if (!/^(?:\*|[A-Z0-9-]{1,32})$/.test(method)) throw new Error(t('Methods must be uppercase ASCII tokens of at most 32 characters or * alone'));
          textBytes += method.length;
        }
        if (methods.includes('*') && methods.length !== 1) throw new Error(t('The * method must be the only method in its rule'));
        entries += subjects.length + methods.length;
        return { subjects, methods };
      });
      if (entries > 512 || textBytes > 32768) throw new Error(t('Resource allow rules exceed the aggregate size limit'));
      const previous = isObject(route.resource_policy) ? route.resource_policy : {};
      const policy = { ...previous, resource_id: resourceId, principal, allow };
      if (!checked('resource_policy_enforce')) policy.enforce = false;
      else if (Object.hasOwn(previous, 'enforce')) policy.enforce = true;
      else delete policy.enforce;
      route.resource_policy = policy;
    } else throw new Error(t('Choose a valid resource policy action'));
    if (route.workload_auth && !route.resource_policy) throw new Error(t('Workload authentication requires resource authorization'));

    route.response_set_headers = parseHeaderLines(raw('response_set_headers'), 'Response header');
    route.response_remove_headers = headerNames(lines('response_remove_headers'), 'Removed response header');

    const ttl = text('cache_ttl_seconds');
    const maxTtl = text('cache_max_ttl_seconds');
    if (Boolean(ttl) !== Boolean(maxTtl)) throw new Error(t('Both cache TTL fields are required when route caching is enabled'));
    if (ttl) {
      if (!/^\d+$/.test(ttl) || !/^\d+$/.test(maxTtl)) throw new Error(t('Cache TTL values must be whole seconds'));
      const ttlSeconds = Number(ttl); const maxTtlSeconds = Number(maxTtl);
      if (ttlSeconds < 1 || ttlSeconds > maxTtlSeconds || maxTtlSeconds > 86400) throw new Error(t('Cache TTL must satisfy 1 ≤ TTL ≤ maximum TTL ≤ 86,400'));
      route.cache = { ttl_seconds: ttlSeconds, max_ttl_seconds: maxTtlSeconds };
    } else route.cache = null;

    for (const direction of ['request', 'response']) {
      const key = `${direction}_transform`;
      const label = `${direction === 'request' ? 'Request' : 'Response'} transform`;
      if (!checked(`${key}_enabled`)) { route[key] = null; continue; }
      const transform = isObject(route[key]) ? route[key] : {};
      transform.mode = raw(`${key}_mode`);
      const operations = text(`${key}_operations`);
      transform.operations = operations ? parseJsonField(operations, `${label} operations`) : [];
      if (!Array.isArray(transform.operations)) throw new Error(t('{field} operations must be a JSON array', { field: t(label) }));
      if (transform.operations.length > 32) throw new Error(t('{field} allows at most 32 operations', { field: t(label) }));
      transform.lua = raw(`${key}_lua`) || null;
      transform.max_buffer_bytes = integer(`${key}_max_buffer_bytes`, `${label} buffer limit`, { min: 1, max: 1048576, optional: true, fallback: 65536 });
      transform.max_output_bytes = integer(`${key}_max_output_bytes`, `${label} output limit`, { min: 1, max: 1048576, optional: true, fallback: 65536 });
      transform.timeout_ms = integer(`${key}_timeout_ms`, `${label} timeout`, { min: 1, max: 30000, optional: true, fallback: 5000 });
      if (transform.lua && (transform.max_buffer_bytes > 16384 || transform.max_output_bytes > 16384)) throw new Error(t('{field} with Lua requires buffer and output limits of at most 16,384 bytes', { field: t(label) }));
      transform.set_headers = parseHeaderLines(raw(`${key}_set_headers`), `${label} header`);
      transform.remove_headers = headerNames(lines(`${key}_remove_headers`), `${label} removed header`);
      if (Object.keys(transform.set_headers).length + transform.remove_headers.length > 32) throw new Error(t('{field} allows at most 32 header mutations', { field: t(label) }));
      route[key] = transform;
    }
  } else {
    route.listen = text('listen');
    const listen = /^(?:\[[0-9a-fA-F:.]+\]|[0-9.]+):(\d{1,5})$/.exec(route.listen);
    if (!listen || Number(listen[1]) < 1 || Number(listen[1]) > 65535) throw new Error(t('Listen address must be ip:port (IPv6 in brackets) with a port of 1–65,535'));
    route.max_connections = integer('max_connections', 'Concurrent connection limit', { min: 1, max: 1000000, optional: true });
    if (checked('tcp_health_enabled')) {
      const health = isObject(route.health) ? route.health : {};
      const initial = raw('tcp_health_initial_state');
      if (initial === 'checking') health.initial_state = 'checking';
      else if (initial === 'healthy') delete health.initial_state;
      else throw new Error(t('Select a valid initial TCP probe state'));
      health.interval_ms = integer('tcp_health_interval_ms', 'TCP probe interval', { min: 100, max: 300000 });
      health.timeout_ms = integer('tcp_health_timeout_ms', 'TCP probe timeout', { min: 100, max: 60000 });
      if (health.timeout_ms > health.interval_ms) throw new Error(t('TCP probe timeout cannot exceed interval'));
      health.healthy_successes = integer('tcp_health_healthy_successes', 'Healthy TCP probe successes', { min: 1, max: 100 });
      health.unhealthy_failures = integer('tcp_health_unhealthy_failures', 'Unhealthy TCP probe failures', { min: 1, max: 100 });
      route.health = health;
    } else if (Object.hasOwn(route, 'health')) route.health = null;
    const hosts = lines('sni_hosts');
    const regexes = lines('sni_host_regexes');
    const helloBytes = integer('sni_max_client_hello_bytes', 'ClientHello size limit', { min: 1, max: 1048576, optional: true });
    const helloTimeout = integer('sni_hello_timeout_ms', 'ClientHello timeout', { min: 1, max: 30000, optional: true });
    if (!hosts.length && !regexes.length) {
      if (helloBytes !== null || helloTimeout !== null) throw new Error(t('ClientHello limits need at least one SNI hostname pattern or regex; clear them to disable SNI routing'));
      route.sni = null;
    } else {
      if (hosts.length + regexes.length > 128) throw new Error(t('SNI hostnames and regexes together allow at most 128 patterns'));
      route.sni = { ...(isObject(route.sni) ? route.sni : {}), hosts, host_regexes: regexes, max_client_hello_bytes: helloBytes ?? 65536, hello_timeout_ms: helloTimeout ?? 3000 };
    }
    if (checked('inbound_tls_enabled')) {
      if (route.sni) throw new Error(t('Inbound mutual TLS cannot be combined with SNI passthrough'));
      const filePath = (name, label, optional = false) => {
        const value = text(name);
        if (!value && optional) return null;
        if (!validInboundTlsPath(value))
          throw new Error(t('{field} must be an absolute normalized file path', { field: t(label) }));
        return value;
      };
      const allowed = lines('inbound_tls_allowed_uri_sans');
      if (!allowed.length || allowed.length > 128 || new Set(allowed).size !== allowed.length || allowed.some((uri) => !validSpiffeIdentity(uri)))
        throw new Error(t('Allowed client identities need 1–128 distinct exact SPIFFE URIs of at most 2,048 bytes'));
      route.inbound_tls = { ...(isObject(route.inbound_tls) ? route.inbound_tls : {}),
        cert_file: filePath('inbound_tls_cert_file', 'Server certificate file'),
        key_file: filePath('inbound_tls_key_file', 'Server private key file'),
        client_ca_file: filePath('inbound_tls_client_ca_file', 'Trusted client CA file'),
        client_crl_file: filePath('inbound_tls_client_crl_file', 'Client revocation list file', true),
        allowed_uri_sans: allowed,
        handshake_timeout_ms: integer('inbound_tls_handshake_timeout_ms', 'Inbound TLS handshake timeout', { min: 1, max: 10000 }) };
    } else if (Object.hasOwn(route, 'inbound_tls')) route.inbound_tls = null;
  }
  return route;
}
function syncRouteJsonFromForm() {
  try {
    $('#route-json').value = JSON.stringify(routeFromForm(), null, 2);
    // Subsequent edits use the newly serialized array as their preservation
    // basis. After a removal its positions differ from the original document.
    const editor = $('#route-form .backend-editor');
    if (editor?.dataset.mode === 'named') for (const [index, row] of [...editor.querySelectorAll('.backend-member-row')].entries()) row.dataset.sourceIndex = String(index);
    delete $('#route-form').dataset.invalidNative;
    message($('#route-message'));
  } catch (error) { $('#route-form').dataset.invalidNative = error.message; message($('#route-message'), error.message, 'error'); }
}

function syncRouteControlsFromJson() {
  let draft;
  try { draft = JSON.parse($('#route-json').value); } catch { return; }
  if (!isObject(draft)) return;
  syncBackendControlsFromJson(draft);
  const form = $('#route-form');
  if (form.elements['access_mode'] && (draft.access_mode === undefined || typeof draft.access_mode === 'string'))
    form.elements['access_mode'].value = draft.access_mode || 'legacy';
  // Authorization is a single native editing unit. A JSON switch from Basic
  // to JWT (or a JWT plus external auth) must survive the next native edit.
  if (form.elements['basic_auth_credentials'] && (draft.basic_auth === null || draft.basic_auth === undefined || isObject(draft.basic_auth))) {
    const basic = isObject(draft.basic_auth) ? draft.basic_auth : null;
    form.elements['basic_auth_credentials'].value = Array.isArray(basic?.credentials) ? basic.credentials.join('\n') : '';
    form.elements['basic_auth_realm'].value = basic?.realm ?? '';
    form.elements['basic_auth_identity_header'].value = basic?.identity_header ?? '';
    form.elements['basic_auth_hide_credentials'].checked = Boolean(basic?.hide_credentials);
  }
  if (form.elements['auth_url'] && (draft.auth === null || draft.auth === undefined || isObject(draft.auth))) {
    const auth = isObject(draft.auth) ? draft.auth : null;
    form.elements['auth_url'].value = auth?.url ?? '';
    form.elements['auth_request_headers'].value = Array.isArray(auth?.request_headers) ? auth.request_headers.join('\n') : '';
    form.elements['auth_response_headers'].value = Array.isArray(auth?.response_headers) ? auth.response_headers.join('\n') : '';
    form.elements['auth_timeout_ms'].value = auth?.timeout_ms ?? '';
    form.elements['auth_forward_response'].checked = Boolean(auth?.forward_response);
  }
  if (form.elements['jwt_auth_enabled'] && (draft.jwt_auth === null || draft.jwt_auth === undefined || isObject(draft.jwt_auth))) {
    const jwt = isObject(draft.jwt_auth) ? draft.jwt_auth : null;
    const verification = isObject(jwt?.verification) ? jwt.verification : {};
    const keys = isObject(jwt?.keys) ? jwt.keys : {};
    const remote = isObject(keys.config) ? keys.config : {};
    const endpoint = isObject(remote.endpoint) ? remote.endpoint : {};
    const set = (name, value) => { form.elements[name].value = value === null || value === undefined ? '' : String(value); };
    form.elements['jwt_auth_enabled'].checked = Boolean(jwt);
    set('jwt_issuer', verification.issuer);
    set('jwt_audiences', Array.isArray(verification.audiences) ? verification.audiences.join('\n') : verification.audiences);
    set('jwt_profile', verification.profile ?? 'rfc9068');
    set('jwt_algorithms', Array.isArray(verification.algorithms) ? verification.algorithms.join('\n') : verification.algorithms ?? 'RS256');
    set('jwt_leeway_seconds', verification.leeway_seconds ?? 0);
    set('jwt_max_lifetime_seconds', verification.max_lifetime_seconds ?? 3600);
    set('jwt_scope_claim', verification.scope_claim ?? 'scope');
    set('jwt_groups_claim', verification.groups_claim ?? 'groups');
    set('jwt_required_scopes', Array.isArray(verification.required_scopes) ? verification.required_scopes.join('\n') : verification.required_scopes);
    set('jwt_required_groups', Array.isArray(verification.required_groups) ? verification.required_groups.join('\n') : verification.required_groups);
    set('jwt_key_source', keys.source ?? 'local');
    set('jwt_local_jwks', keys.jwks === undefined ? '' : JSON.stringify(keys.jwks, null, 2));
    set('jwt_endpoint_kind', endpoint.kind ?? 'oidc');
    set('jwt_jwks_url', endpoint.url);
    set('jwt_cache_ttl_seconds', remote.cache_ttl_seconds ?? 300);
    set('jwt_refresh_cooldown_seconds', remote.refresh_cooldown_seconds ?? 10);
    set('jwt_timeout_ms', remote.timeout_ms ?? 3000);
    set('jwt_ca_pem', remote.ca_pem);
    set('jwt_identity_header', jwt?.identity_header);
    form.elements['jwt_hide_credentials'].checked = jwt?.hide_credentials !== false;
  }
  if (form.elements['workload_auth_enabled'] && (draft.workload_auth === null || draft.workload_auth === undefined || isObject(draft.workload_auth))) {
    const auth = isObject(draft.workload_auth) ? draft.workload_auth : null;
    form.elements['workload_auth_enabled'].checked = Boolean(auth);
    form.elements['workload_listener_ids'].value = Array.isArray(auth?.listener_ids) ? auth.listener_ids.join('\n') : '';
    form.elements['workload_allowed_uri_sans'].value = Array.isArray(auth?.allowed_uri_sans) ? auth.allowed_uri_sans.join('\n') : '';
    form.elements['workload_identity_header'].value = auth?.identity_header ?? '';
  }
  if (form.elements['resource_policy_action'] && (draft.resource_policy === null || draft.resource_policy === undefined || isObject(draft.resource_policy))) {
    const policy = isObject(draft.resource_policy) ? draft.resource_policy : null;
    const principal = isObject(policy?.principal) ? policy.principal : {};
    form.elements['resource_policy_action'].value = policy ? 'configured' : 'none';
    form.elements['resource_policy_id'].value = policy?.resource_id ?? '';
    form.elements['resource_policy_enforce'].checked = policy?.enforce !== false;
    form.elements['resource_policy_source'].value = principal.source ?? (draft.workload_auth ? 'workload' : draft.jwt_auth ? 'jwt' : draft.auth && !draft.basic_auth ? 'external' : 'basic');
    form.elements['resource_policy_subject_header'].value = principal.subject_header ?? '';
    const allow = Array.isArray(policy?.allow) ? policy.allow : [];
    form.querySelector('.resource-rule-list').replaceChildren(...allow.slice(0, 33).map(resourceRuleRow));
  }
  if (form.elements['tcp_health_enabled'] && (draft.health === null || draft.health === undefined || isObject(draft.health))) {
    const health = isObject(draft.health) ? draft.health : null;
    form.elements['tcp_health_enabled'].checked = Boolean(health);
    const policy = health || { interval_ms: 3000, timeout_ms: 2000, healthy_successes: 1, unhealthy_failures: 2 };
    for (const name of ['interval_ms', 'timeout_ms', 'healthy_successes', 'unhealthy_failures'])
      form.elements[`tcp_health_${name}`].value = policy[name] === null || policy[name] === undefined ? '' : String(policy[name]);
    form.elements['tcp_health_initial_state'].value = policy.initial_state ?? 'healthy';
  }
  if (form.elements['inbound_tls_enabled'] && (draft.inbound_tls === null || draft.inbound_tls === undefined || isObject(draft.inbound_tls))) {
    const tls = isObject(draft.inbound_tls) ? draft.inbound_tls : null;
    form.elements['inbound_tls_enabled'].checked = Boolean(tls);
    for (const name of ['cert_file', 'key_file', 'client_ca_file', 'client_crl_file'])
      form.elements[`inbound_tls_${name}`].value = tls?.[name] ?? '';
    form.elements['inbound_tls_allowed_uri_sans'].value = Array.isArray(tls?.allowed_uri_sans) ? tls.allowed_uri_sans.join('\n') : '';
    form.elements['inbound_tls_handshake_timeout_ms'].value = tls?.handshake_timeout_ms ?? 5000;
  }
  if (form.elements['balance_mode'] && (draft.balance === null || draft.balance === undefined || isObject(draft.balance))) {
    const balance = isObject(draft.balance) ? draft.balance : {};
    const setBalance = (name, value) => { form.elements[name].value = value === null || value === undefined ? '' : String(value); };
    const statuses = (value) => Array.isArray(value) ? value.join(', ') : value === null || value === undefined ? '' : JSON.stringify(value);
    setBalance('balance_mode', balance.mode ?? 'round_robin');
    setBalance('balance_weights', Array.isArray(balance.weights) ? balance.weights.join(', ') : balance.weights ?? '');
    setBalance('health_failure_threshold', balance.health?.failure_threshold);
    setBalance('health_cooldown_ms', balance.health?.cooldown_ms);
    for (const [name, source, defaults] of [
      ['active_health', balance.active_health, { path: '', host: '', interval_ms: 3000, timeout_ms: 2000, healthy_statuses: [200], unhealthy_statuses: [429, 500, 503], healthy_successes: 1, unhealthy_http_failures: 2, unhealthy_tcp_failures: 2, unhealthy_timeouts: 2 }],
      ['passive_health', balance.passive_health, { healthy_statuses: [200, 201], unhealthy_statuses: [429, 500, 503], unhealthy_http_failures: 2, unhealthy_tcp_failures: 2, unhealthy_timeouts: 2 }],
    ]) {
      if (source !== null && source !== undefined && !isObject(source)) continue;
      form.elements[`${name}_enabled`].checked = Boolean(source);
      const policy = isObject(source) ? source : defaults;
      if (name === 'active_health') {
        setBalance(`${name}_initial_state`, policy.initial_state ?? 'healthy');
        setBalance(`${name}_path`, policy.path);
        setBalance(`${name}_host`, policy.host);
        setBalance(`${name}_interval_ms`, policy.interval_ms);
        setBalance(`${name}_timeout_ms`, policy.timeout_ms);
        setBalance(`${name}_healthy_successes`, policy.healthy_successes);
      }
      setBalance(`${name}_healthy_statuses`, statuses(policy.healthy_statuses));
      setBalance(`${name}_unhealthy_statuses`, statuses(policy.unhealthy_statuses));
      setBalance(`${name}_unhealthy_http_failures`, policy.unhealthy_http_failures);
      setBalance(`${name}_unhealthy_tcp_failures`, policy.unhealthy_tcp_failures);
      setBalance(`${name}_unhealthy_timeouts`, policy.unhealthy_timeouts);
    }
  }
  const setText = (name, value) => {
    const textarea = form.elements[name];
    if (!textarea || (value !== null && value !== undefined && typeof value !== 'string')) return;
    textarea.value = value || '';
    luaEditors.get(textarea)?.editor.syncFromTextarea();
  };
  setText('lua', draft.lua);
  for (const direction of ['request', 'response']) {
    const key = `${direction}_transform`;
    const raw = draft[key];
    if (raw !== null && raw !== undefined && !isObject(raw)) continue;
    const enabled = Boolean(raw);
    const toggle = form.elements[`${key}_enabled`];
    if (!toggle) continue;
    toggle.checked = enabled;
    const transform = enabled ? raw : DEFAULT_TRANSFORM;
    const set = (suffix, value) => { form.elements[`${key}_${suffix}`].value = value === null || value === undefined ? '' : String(value); };
    set('mode', transform.mode ?? 'buffered');
    set('timeout_ms', transform.timeout_ms ?? 5000);
    set('max_buffer_bytes', transform.max_buffer_bytes ?? 65536);
    set('max_output_bytes', transform.max_output_bytes ?? 65536);
    set('operations', (transform.operations || []).length ? JSON.stringify(transform.operations, null, 2) : '');
    setText(`${key}_lua`, transform.lua);
    set('set_headers', pairsToLines(transform.set_headers));
    set('remove_headers', Array.isArray(transform.remove_headers) ? transform.remove_headers.join('\n') : transform.remove_headers ?? '');
  }
  applyGroupToggles(form);
}

/** Rebuild the full document with this route in place and ask the validator for the precise rejection. */
async function explainRouteRejection(type, route, originalId, fallback) {
  try {
    const latest = await api('/v1/config');
    const draft = structuredClone(latest.data);
    const list = Array.isArray(draft[type]) ? draft[type] : [];
    const index = list.findIndex((item) => item && item.id === (originalId ?? route.id));
    if (index >= 0) list[index] = route; else list.push(route);
    draft[type] = list;
    return await validationDetail(draft, fallback);
  } catch (_) { return fallback; }
}

async function saveRoute(event) {
  event.preventDefault();
  const button = $('#save-route'); message($('#route-message'));
  if ($('#route-form').dataset.invalidNative) { message($('#route-message'), $('#route-form').dataset.invalidNative, 'error'); return; }
  let route;
  try { route = JSON.parse($('#route-json').value); } catch (error) { message($('#route-message'), t('Advanced JSON is invalid: {detail}', { detail: error.message }), 'error'); $('#route-json').focus(); return; }
  if (!isObject(route)) { message($('#route-message'), t('A route must be a JSON object.'), 'error'); return; }
  const { type, originalId } = state.editing; const editing = originalId !== null;
  const path = editing ? `/v1/routes/${type}/${encodeURIComponent(originalId)}` : `/v1/routes/${type}`;
  const headers = {}; if (state.routeEtags[type]) headers['If-Match'] = state.routeEtags[type];
  setBusy(button, true, editing ? t('Saving…') : t('Creating…'));
  try {
    const result = await api(path, { method: editing ? 'PUT' : 'POST', headers, json: route });
    if (result.etag) state.routeEtags[type] = result.etag;
    if (result.data?.revision !== undefined) setRevision(result.data.revision);
    $('#route-dialog').close(); toast(t(editing ? '{id} updated.' : '{id} created.', { id: route.id || t('Route') })); await loadRoutes(type);
  } catch (error) {
    if (isRevisionConflict(error)) { message($('#route-message'), `${error.message === 'route id already exists' ? t('A route with this ID already exists.') : t('The configuration changed on the server. The latest routes were loaded; your edits remain here.')} ${t('Review and save again.')}`, 'error'); await refreshRoutesKeepingDialog(type); }
    else if (isIndeterminate(error)) message($('#route-message'), error.message, 'error', { label: t('Reload routes'), run: () => reloadRoutesAfterIndeterminate(type, route.id, editing) });
    else if (error.status === 422) message($('#route-message'), await explainRouteRejection(type, route, originalId, error.message), 'error');
    else message($('#route-message'), error.message, 'error');
  } finally { setBusy(button, false); }
}

/** After an indeterminate route write: refresh the list and ETag behind the dialog, keep the draft, and say what the server holds now. */
async function reloadRoutesAfterIndeterminate(type, id, editing) {
  await refreshRoutesKeepingDialog(type);
  const present = state.routes[type].some((item) => item && item.id === id);
  const outcome = editing ? t('Compare the list behind this dialog with your draft before saving again.') : present ? t('A route “{id}” now exists: the write was applied, so saving again would answer “already exists”.', { id }) : t('No route “{id}” exists: the write was not applied. Save again.', { id });
  message($('#route-message'), t('Routes were reloaded from revision {revision}; your draft is preserved. {outcome}', { revision: state.revision, outcome }), present && !editing ? 'success' : 'warning');
}

async function refreshRoutesKeepingDialog(type) {
  const draft = $('#route-json').value;
  try { const { data, etag } = await api(`/v1/routes/${type}`); state.routes[type] = data?.routes || []; state.routeEtags[type] = etag || (data?.revision !== undefined ? `"${data.revision}"` : null); if (data?.revision !== undefined) setRevision(data.revision); renderRoutes(type); } catch (_) { /* original error remains actionable */ }
  $('#route-json').value = draft;
}

async function deleteRoute() {
  const { type, originalId } = state.editing; if (!originalId) return;
  const accepted = await confirmDialog({ title: t('Delete route?'), body: t('Route “{id}” will stop matching new traffic.', { id: originalId }), accept: t('Delete') });
  if (!accepted) return;
  const button = $('#delete-route'); setBusy(button, true, t('Deleting…'));
  try {
    const headers = state.routeEtags[type] ? { 'If-Match': state.routeEtags[type] } : {};
    const result = await api(`/v1/routes/${type}/${encodeURIComponent(originalId)}`, { method: 'DELETE', headers });
    if (result.etag) state.routeEtags[type] = result.etag;
    $('#route-dialog').close(); toast(t('{id} deleted.', { id: originalId })); await loadRoutes(type);
  } catch (error) {
    if (isRevisionConflict(error)) { message($('#route-message'), t('The configuration changed on the server. Routes were refreshed; confirm deletion again.'), 'error'); await refreshRoutesKeepingDialog(type); }
    else if (isIndeterminate(error)) message($('#route-message'), error.message, 'error', { label: t('Reload routes'), run: () => reloadRoutesAfterIndeterminate(type, originalId, true) });
    else message($('#route-message'), error.message, 'error');
  }
  finally { setBusy(button, false); }
}

async function resolveDocker(event) {
  event.preventDefault(); const button = $('#docker-form [type="submit"]'); message($('#docker-message')); setBusy(button, true, t('Resolving…'));
  const values = new FormData(event.currentTarget);
  try {
    const { data } = await api('/v1/docker/resolve', { method: 'POST', json: { container: values.get('container'), network: values.get('network'), port: Number(values.get('port')) } });
    const backend = state.editing.type === 'http' ? data.http_backend : data.tcp_backend;
    const editor = $('#route-form .backend-editor');
    if (editor.dataset.mode === 'named') {
      const rows = editor.querySelector('.backend-member-list');
      if (backend && ![...rows.querySelectorAll('.backend-member-address')].some((input) => input.value === backend)) rows.append(memberRow({ id: nextMemberId(rows), address: backend }));
    } else {
      const field = $('#route-form [name="backends"]'); const lines = nonemptyLines(field.value); if (backend && !lines.includes(backend)) lines.push(backend); field.value = lines.join('\n');
    }
    syncRouteJsonFromForm(); $('#docker-dialog').close(); toast(t('Docker backend added to the route.'));
  } catch (error) { message($('#docker-message'), error.status === 404 ? t('Docker integration is disabled on this proxy.') : error.message, 'error'); }
  finally { setBusy(button, false); }
}

function certificateDate(value) {
  if (!Number.isFinite(value)) return '—';
  return `${new Intl.DateTimeFormat(getLocale() === 'ko' ? 'ko-KR' : 'en-US', { dateStyle: 'medium', timeZone: 'UTC' }).format(new Date(value))} UTC`;
}

function certificateExpiry(certificate, serverTime) {
  if (!Number.isFinite(serverTime) || !Number.isFinite(certificate.not_after_unix_ms)) return t('Expiration unknown');
  if (Number.isFinite(certificate.not_before_unix_ms) && certificate.not_before_unix_ms > serverTime) return t('Not yet valid');
  const remaining = certificate.not_after_unix_ms - serverTime;
  if (remaining <= 0) return t('Expired');
  if (remaining <= 30 * 86400000) return t('Expires within 30 days');
  return t('Valid by certificate dates');
}

function certificateNames(names) {
  if (!Array.isArray(names) || !names.length) return '—';
  const visible = names.slice(0, 6).join(', ');
  return names.length > 6 ? t('{names} +{count} more', { names: visible, count: names.length - 6 }) : visible;
}

function certificateDetail(card, label, value) {
  const term = document.createElement('dt'); term.textContent = t(label);
  const detail = document.createElement('dd'); detail.textContent = value;
  card.append(term, detail);
}

function renderCertificateInventory(data) {
  const root = $('#certificate-inventory');
  const pages = $('#certificate-inventory-pages');
  const acme = $('#certificate-acme-state');
  const certificates = Array.isArray(data.certificates) ? data.certificates : [];
  const total = Number(data.total) || 0;
  const offset = Number(data.offset) || 0;
  const limit = Number(data.limit) || 32;
  $('#certificate-inventory-count').textContent = t('{count} configured certificate files', { count: total });
  acme.replaceChildren();
  if (data.in_process_acme) {
    const panel = document.createElement('article'); panel.className = 'certificate-inventory-card';
    const title = document.createElement('h3'); title.textContent = t('In-process ACME');
    const details = document.createElement('dl');
    certificateDetail(details, 'Enabled', data.in_process_acme.enabled ? t('Yes') : t('No'));
    certificateDetail(details, 'Domains', certificateNames(data.in_process_acme.domains));
    certificateDetail(details, 'Issuer phase', String(data.in_process_acme.phase || '—'));
    certificateDetail(details, 'Certificate expires', certificateDate(data.in_process_acme.expires_unix_ms));
    certificateDetail(details, 'In-process TLS available', data.in_process_acme.tls_available ? t('Yes') : t('No'));
    panel.append(title, details); acme.append(panel);
  }
  root.replaceChildren();
  const groups = [
    [t('ACME-managed file references'), certificates.filter(item => item.source === 'standalone_acme')],
    [t('Manually configured files · issuer unverified'), certificates.filter(item => item.read_state === 'ok' && item.source !== 'standalone_acme')],
    [t('Unreadable or invalid'), certificates.filter(item => item.read_state !== 'ok' && item.source !== 'standalone_acme')],
  ];
  for (const [label, items] of groups) {
    if (!items.length) continue;
    const section = document.createElement('section'); section.className = 'certificate-inventory-group';
    const heading = document.createElement('h3'); heading.textContent = t('{group} ({count})', { group: label, count: items.length });
    const grid = document.createElement('div'); grid.className = 'certificate-inventory-grid';
    for (const certificate of items) {
      const card = document.createElement('article'); card.className = 'certificate-inventory-card';
      const title = document.createElement('h4'); title.textContent = certificate.id || t('(unnamed)');
      if (certificate.default) { const tag = document.createElement('span'); tag.className = 'tag'; tag.textContent = t('Default certificate'); card.append(tag); }
      const details = document.createElement('dl');
      certificateDetail(details, 'Configured hosts', certificateNames(certificate.configured_hosts));
      certificateDetail(details, 'Configuration state', certificate.enabled === false ? t('Disabled') : t('Enabled'));
      certificateDetail(details, 'Certificate domains', certificateNames(certificate.san_dns));
      certificateDetail(details, 'Issuer', certificate.issuer || t('Unknown issuer'));
      certificateDetail(details, 'Expires', certificateDate(certificate.not_after_unix_ms));
      certificateDetail(details, 'Date status', certificateExpiry(certificate, data.server_time_unix_ms));
      certificateDetail(details, 'File state', certificate.read_state === 'ok' ? t('Readable') : certificate.read_state === 'invalid' ? t('Invalid') : t('Unavailable'));
      certificateDetail(details, 'TLS binding', certificate.tls_binding === 'disabled' ? t('Disabled') : certificate.tls_binding === 'configured' ? t('TLS resolver configured') : t('Unknown binding'));
      if (certificate.fingerprint_sha256) certificateDetail(details, 'SHA-256 fingerprint', certificate.fingerprint_sha256);
      const renewal = certificate.renewal;
      certificateDetail(details, 'Renewal observation', renewal ? t('Issuer-reported: {state}', { state: t(renewal.state) }) : t('No verified renewal report'));
      if (renewal) {
        certificateDetail(details, 'Challenge', renewal.challenge || '—');
        certificateDetail(details, 'Issuer report checked', certificateDate(renewal.checked_at_unix_ms));
        if (Number.isFinite(renewal.renew_before_unix_ms)) certificateDetail(details, 'Renewal eligibility begins', certificateDate(renewal.renew_before_unix_ms));
        if (renewal.retry_next_unix_ms !== null) certificateDetail(details, 'Next reported retry', certificateDate(renewal.retry_next_unix_ms));
      }
      card.append(title, details); grid.append(card);
    }
    section.append(heading, grid); root.append(section);
  }
  if (!certificates.length) root.append(emptyNode('No certificate files on this page', total ? 'Use Previous or Next to inspect another page.' : 'No file-backed certificates are configured on this instance.'));
  pages.replaceChildren();
  if (total > limit) {
    const range = document.createElement('span'); range.textContent = t('Showing {start}–{end} of {total}', { start: offset + 1, end: offset + certificates.length, total });
    const previous = document.createElement('button'); previous.type = 'button'; previous.className = 'button button-secondary'; previous.textContent = t('Previous'); previous.disabled = offset === 0;
    const next = document.createElement('button'); next.type = 'button'; next.className = 'button button-secondary'; next.textContent = t('Next'); next.disabled = !certificates.length || offset + certificates.length >= total;
    previous.addEventListener('click', () => { loadCertificateInventory(Math.max(0, offset - limit)).catch(() => {}); });
    next.addEventListener('click', () => { loadCertificateInventory(offset + certificates.length).catch(() => {}); });
    pages.append(range, previous, next);
  }
}

async function loadCertificateInventory(offset = state.certificateInventoryOffset, quiet = false) {
  const sequence = ++state.certificateInventoryLoadSequence;
  const root = $('#certificate-inventory');
  if (!quiet) root.replaceChildren(loadingNode('Loading certificate inventory…'));
  try {
    const { data } = await api(`/v1/certificates?offset=${offset}&limit=32`);
    if (sequence !== state.certificateInventoryLoadSequence) return;
    state.certificateInventoryOffset = offset;
    state.certificateInventory = data;
    renderCertificateInventory(data);
  } catch (error) {
    if (sequence !== state.certificateInventoryLoadSequence) return;
    if (error instanceof StaleSessionError) throw error;
    if (error.status === 401 || error.status === 403) { logout(t('Your session is no longer authorized.')); throw new StaleSessionError(); }
    state.certificateInventory = null;
    $('#certificate-inventory-count').textContent = '—';
    root.replaceChildren(errorNode(error.status === 404 ? t('Certificate inventory is unavailable on this server.') : error.message, () => loadCertificateInventory(offset)));
  }
}

function startCertificatePolling() {
  stopCertificatePolling();
  if (!state.token || state.view !== 'certificates' || document.hidden) return;
  state.certificateTimer = setInterval(() => {
    if (state.view === 'certificates' && state.token && !document.hidden) loadCertificateInventory(state.certificateInventoryOffset, true).catch(() => {});
  }, 30000);
}

function stopCertificatePolling() {
  if (state.certificateTimer) clearInterval(state.certificateTimer);
  state.certificateTimer = null;
}

async function loadCertificates(force) {
  const sequence = ++state.certificateLoadSequence;
  await loadCertificateInventory();
  if (!state.token) return;
  if (state.certificateDirty && !force) return;
  const list = $('#certificate-list');
  list.replaceChildren(loadingNode('Loading certificate paths…'));
  const latest = await api('/v1/config');
  if (sequence !== state.certificateLoadSequence) return;
  if (!state.configDirty) {
    state.config = latest.data;
    state.configEtag = latest.etag || `"${latest.data.revision}"`;
    showConfigDocument(latest.data);
    setRevision(latest.data.revision);
  }
  const certificates = latest.data.certificates ?? [];
  $('#certificate-editor').value = JSON.stringify(certificates, null, 2);
  $('#certificate-editor').setAttribute('aria-invalid', 'false');
  state.certificateDirty = false;
  $('#certificate-dirty').hidden = true;
  message($('#certificate-message'));
  renderCertificates(certificates);
}

function renderCertificates(certificates) {
  const root = $('#certificate-list');
  if (!certificates.length) {
    root.replaceChildren(emptyNode('No file certificates', 'Add certificate paths before serving TLS with --config-tls.'));
    return;
  }
  root.replaceChildren(...certificates.map((certificate) => {
    const card = document.createElement('article'); card.className = 'route-card';
    const identity = document.createElement('div'); const tag = document.createElement('span'); tag.className = 'route-type'; tag.textContent = 'TLS'; const title = document.createElement('h2'); title.textContent = certificate.id; identity.append(tag, title);
    const hosts = document.createElement('div'); const hostTitle = document.createElement('p'); copy(hostTitle, certificate.hosts.length === 1 ? '{count} host' : '{count} hosts', { count: certificate.hosts.length }); hosts.append(hostTitle); certificate.hosts.slice(0, 2).forEach((host) => hosts.append(tagNode(host)));
    const files = document.createElement('div'); const fileTitle = document.createElement('p'); copy(fileTitle, 'Files'); files.append(fileTitle, tagNode(certificate.cert_file), tagNode(certificate.key_file));
    const action = document.createElement('div'); const state = document.createElement('span'); state.className = 'tag'; state.textContent = t(certificate.enabled === false ? 'Disabled' : 'Enabled'); action.append(state);
    if (isAdmin()) { const toggle = document.createElement('button'); toggle.className = 'button button-secondary'; toggle.type = 'button'; toggle.textContent = t(certificate.enabled === false ? 'Activate' : 'Deactivate'); toggle.addEventListener('click', () => setCertificateEnabled(certificate.id, certificate.enabled === false, toggle)); action.append(toggle); }
    card.append(identity, hosts, files, action); return card;
  }));
}

async function setCertificateEnabled(id, enabled, button) {
  if (state.configDirty || state.certificateDirty) return message($('#certificate-message'), t('Apply or reload unsaved configuration and certificate drafts before changing certificate activation.'), 'error');
  setBusy(button, true, t(enabled ? 'Activating…' : 'Deactivating…'));
  state.certificateLoadSequence++;
  try {
    const latest = await api('/v1/config');
    let current = latest.data;
    const draft = structuredClone(latest.data);
    const certificate = (draft.certificates || []).find(item => item.id === id);
    if (!certificate) throw new Error(t('Certificate “{id}” is no longer configured. Reload the list.', { id }));
    if ((certificate.enabled !== false) !== enabled) {
      if (enabled) delete certificate.enabled; else certificate.enabled = false;
      const etag = latest.etag || `"${latest.data.revision}"`;
      const result = await api('/v1/config', { method: 'PUT', headers: { 'If-Match': etag }, json: draft });
      current = result.data;
      state.certificateLoadSequence++;
      state.config = result.data;
      state.configEtag = result.etag || `"${result.data.revision}"`;
      showConfigDocument(result.data);
      setRevision(result.data.revision);
      toast(t(enabled ? 'Certificate “{id}” activated.' : 'Certificate “{id}” deactivated.', { id }));
    } else adoptConfig(latest);
    const active = current.certificates || [];
    $('#certificate-editor').value = JSON.stringify(active, null, 2);
    renderCertificates(active);
    await loadCertificateInventory();
    message($('#certificate-message'));
  } catch (error) {
    if (error instanceof StaleSessionError) return;
    if (error.status === 401 || error.status === 403) return logout(t('Your session is no longer authorized.'));
    if (isRevisionConflict(error) || isIndeterminate(error)) {
      try { await loadCertificates(false); } catch (_) { /* keep original error */ }
    }
    message($('#certificate-message'), isRevisionConflict(error) ? t('The configuration changed on the server. Reloaded certificates; review their current state before retrying.') : isIndeterminate(error) ? t('The certificate activation outcome is unknown. Reloaded certificates; verify their current state before retrying.') : error.message, 'error');
  } finally { setBusy(button, false); }
}

function parseCertificates() {
  const editor = $('#certificate-editor');
  let certificates;
  try { certificates = JSON.parse(editor.value); }
  catch (error) { editor.setAttribute('aria-invalid', 'true'); throw new Error(t('Invalid certificate JSON: {detail}', { detail: error.message })); }
  if (!Array.isArray(certificates)) {
    editor.setAttribute('aria-invalid', 'true');
    throw new Error(t('Certificate set must be a JSON array.'));
  }
  if (certificates.length > 1024) throw new Error(t('Certificate set cannot contain more than 1,024 entries.'));
  const allowed = new Set(['id', 'hosts', 'default', 'enabled', 'cert_file', 'key_file', 'issuer_status_file']);
  certificates.forEach((certificate, index) => {
    if (!certificate || Array.isArray(certificate) || typeof certificate !== 'object') throw new Error(t('Certificate {index} must be an object.', { index: index + 1 }));
    const unknown = Object.keys(certificate).find((key) => !allowed.has(key));
    if (unknown) throw new Error(t('Certificate {index} has unsupported field “{field}”. Use file paths only; PEM fields are not accepted.', { index: index + 1, field: unknown }));
    if (!/^[A-Za-z0-9._-]{1,128}$/.test(certificate.id || '')) throw new Error(t('Certificate {index} needs a valid id.', { index: index + 1 }));
    if (certificate.default !== undefined && typeof certificate.default !== 'boolean') throw new Error(t('Certificate {index} default must be true or false.', { index: index + 1 }));
    if (!Array.isArray(certificate.hosts) || certificate.hosts.length > 128 || certificate.hosts.some((host) => typeof host !== 'string' || !host)) throw new Error(t('Certificate {index} hosts must contain 1–128 names.', { index: index + 1 }));
    if (certificate.default === true && certificate.hosts.length !== 0) throw new Error(t('Default certificate {index} must not claim SNI hosts.', { index: index + 1 }));
    if (certificate.default !== true && certificate.hosts.length === 0) throw new Error(t('Certificate {index} hosts must contain 1–128 names.', { index: index + 1 }));
    if (certificate.enabled !== undefined && typeof certificate.enabled !== 'boolean') throw new Error(t('Certificate {index} enabled must be true or false.', { index: index + 1 }));
    for (const field of ['cert_file', 'key_file']) if (typeof certificate[field] !== 'string' || !certificate[field].startsWith('/')) throw new Error(t('Certificate {index} {field} must be an absolute path.', { index: index + 1, field }));
    if (certificate.issuer_status_file != null && (typeof certificate.issuer_status_file !== 'string' || !certificate.issuer_status_file.startsWith('/'))) throw new Error(t('Certificate {index} {field} must be an absolute path.', { index: index + 1, field: 'issuer_status_file' }));
  });
  editor.setAttribute('aria-invalid', 'false');
  return certificates;
}

function certificateInput() {
  state.certificateLoadSequence++;
  state.certificateDirty = true;
  $('#certificate-dirty').hidden = false;
  message($('#certificate-message'));
}

function formatCertificates() {
  try {
    $('#certificate-editor').value = JSON.stringify(parseCertificates(), null, 2);
    certificateInput();
  } catch (error) { message($('#certificate-message'), error.message, 'error'); }
}

function addCertificateTemplate() {
  try {
    const certificates = parseCertificates();
    certificates.push({ id: 'site', hosts: ['site.example.test'], cert_file: '/run/secrets/site.crt', key_file: '/run/secrets/site.key' });
    $('#certificate-editor').value = JSON.stringify(certificates, null, 2);
    certificateInput();
  } catch (error) { message($('#certificate-message'), error.message, 'error'); }
}

async function applyCertificates() {
  const button = $('#apply-certificates');
  state.certificateLoadSequence++;
  let certificates;
  try { certificates = parseCertificates(); }
  catch (error) { return message($('#certificate-message'), error.message, 'error'); }
  if (state.configDirty) return message($('#certificate-message'), t('The Configuration view has an unsaved document. Apply it or reload it before changing certificates.'), 'error');
  setBusy(button, true, t('Applying…'));
  let next = null;
  try {
    const latest = await api('/v1/config');
    next = structuredClone(latest.data); next.certificates = certificates;
    const result = await api('/v1/config', { method: 'PUT', headers: { 'If-Match': latest.etag || `"${latest.data.revision}"` }, json: next });
    state.certificateLoadSequence++;
    state.config = result.data;
    state.configEtag = result.etag || `"${result.data.revision}"`;
    state.configDirty = false;
    state.certificateDirty = false;
    showConfigDocument(result.data);
    $('#config-dirty').hidden = true;
    const active = result.data.certificates ?? [];
    $('#certificate-editor').value = JSON.stringify(active, null, 2);
    $('#certificate-dirty').hidden = true;
    setRevision(result.data.revision);
    renderCertificates(active);
    message($('#certificate-message'), t('Certificate paths are active in revision {revision}.', { revision: result.data.revision }), 'success');
    toast(t('Certificate paths applied.'));
  } catch (error) {
    if (isRevisionConflict(error)) message($('#certificate-message'), t('The configuration changed while certificates were being applied. Your draft is preserved; review and apply again.'), 'error');
    else if (isIndeterminate(error)) message($('#certificate-message'), error.message, 'error', { label: t('Reload current revision'), run: () => rebaseCertificateDraft(certificates) });
    else if (next && isRejection(error)) message($('#certificate-message'), await validationDetail(next, error.message), 'error');
    else message($('#certificate-message'), error.message, 'error');
  } finally { setBusy(button, false); }
}

/** After an indeterminate certificate write: adopt the latest revision, keep the draft, and say whether it landed. */
async function rebaseCertificateDraft(draft) {
  try {
    const latest = await api('/v1/config');
    adoptConfig(latest);
    const active = latest.data.certificates ?? [];
    if (JSON.stringify(active) === JSON.stringify(draft)) {
      $('#certificate-editor').value = JSON.stringify(active, null, 2); state.certificateDirty = false; $('#certificate-dirty').hidden = true; renderCertificates(active);
      message($('#certificate-message'), t('Revision {revision} already holds these certificate paths: the write was applied.', { revision: latest.data.revision }), 'success');
    } else message($('#certificate-message'), t('Revision {revision} is active and its certificate set differs from your draft: the write was not applied. Your draft is preserved; review and apply again.', { revision: latest.data.revision }), 'warning');
  } catch (error) { message($('#certificate-message'), error.message, 'error'); }
}

function workloadListenerControl(form, label, name, { textarea = false, checkbox = false, placeholder = '', help = '' } = {}) {
  const wrapper = document.createElement('div'); wrapper.className = 'field';
  const title = document.createElement('label'); title.htmlFor = `workload-http-${name}`; copy(title, label);
  const control = document.createElement(textarea ? 'textarea' : 'input');
  control.id = title.htmlFor; control.name = name;
  if (!textarea) control.type = checkbox ? 'checkbox' : 'text';
  if (placeholder) { control.placeholder = placeholder; control.dataset.appI18nPlaceholder = placeholder; }
  wrapper.append(title, control);
  if (help) { const note = document.createElement('span'); note.className = 'field-help-inline'; copy(note, help); wrapper.append(note); }
  form.append(wrapper);
  return control;
}

function ensureWorkloadListenersPanel() {
  if ($('#workload-http-panel')) return;
  const panel = document.createElement('details'); panel.className = 'form-section'; panel.id = 'workload-http-panel';
  const summary = document.createElement('summary'); const title = document.createElement('span'); title.className = 'section-title'; copy(title, 'Dedicated HTTP workload mTLS listeners'); summary.append(title);
  const note = document.createElement('p'); note.className = 'section-note'; copy(note, 'These listeners require a verified client certificate before serving HTTP/1 or HTTP/2. Paths refer to files on this instance. Changes are only staged in the JSON draft until Apply configuration publishes the full document. Ordinary HTTP/HTTPS and ACME listeners remain separate.');
  const runtimeNote = document.createElement('p'); runtimeNote.className = 'workload-runtime-note'; copy(runtimeNote, 'Current runtime material is local to this instance. Ready means verified material is loaded; client and route authorization still apply. Blocked means current material is not verified. Unknown means status is unavailable, a binding is unpublished, or revisions differ. File metadata is checked every 500 ms and full contents every 5 s. An invalid client CA or CRL closes admission and existing streams; new bindings remain pending until verification after publication.');
  const list = document.createElement('div'); list.id = 'workload-http-list';
  const add = document.createElement('button'); add.type = 'button'; add.id = 'workload-http-add'; add.className = 'button button-secondary'; copy(add, 'Add workload listener'); add.addEventListener('click', () => openWorkloadListener(-1));
  const messageBox = document.createElement('div'); messageBox.id = 'workload-http-message'; messageBox.className = 'inline-message'; messageBox.setAttribute('aria-live', 'polite');
  const form = document.createElement('form'); form.id = 'workload-http-form'; form.className = 'form-grid'; form.hidden = true;
  workloadListenerControl(form, 'Listener ID', 'id', { help: 'Stable ASCII ID, 1–128 letters, digits, dots, underscores, colons or dashes. Routes refer to this ID.' });
  workloadListenerControl(form, 'Workload listen address', 'listen', { placeholder: '0.0.0.0:9443', help: 'Dedicated IP:port socket; not the ordinary public HTTP or HTTPS listener.' });
  workloadListenerControl(form, 'Listener enabled', 'enabled', { checkbox: true, help: 'Disabled retains the listener policy but does not bind or accept new connections.' });
  workloadListenerControl(form, 'Server certificate file', 'cert_file', { placeholder: '/etc/hangang/workload/server.pem', help: 'Absolute normalized path to a public server certificate file. No PEM content in the browser.' });
  workloadListenerControl(form, 'Server private key file', 'key_file', { placeholder: '/etc/hangang/workload/server-key.pem', help: 'Absolute normalized path to the runtime-owned private key file; never paste the key.' });
  workloadListenerControl(form, 'Trusted client CA file', 'client_ca_file', { placeholder: '/etc/hangang/workload/client-ca.pem', help: 'Absolute normalized path to the mandatory client trust roots.' });
  workloadListenerControl(form, 'Client revocation list file', 'client_crl_file', { placeholder: '/etc/hangang/workload/client.crl.pem', help: 'Optional absolute normalized path to a client CRL.' });
  workloadListenerControl(form, 'Allowed client SPIFFE URI SANs', 'allowed_uri_sans', { textarea: true, placeholder: 'spiffe://example.test/services/orders', help: 'One exact canonical SPIFFE URI per line, 1–128 distinct identities.' });
  workloadListenerControl(form, 'Inbound TLS handshake timeout (ms)', 'handshake_timeout_ms', { help: '1–10,000 ms; default 5,000.' });
  const actions = document.createElement('div'); actions.className = 'button-row span-2';
  const stage = document.createElement('button'); stage.type = 'submit'; stage.className = 'button button-primary'; copy(stage, 'Stage listener in document');
  const cancel = document.createElement('button'); cancel.type = 'button'; cancel.className = 'button button-secondary'; copy(cancel, 'Cancel listener edit'); cancel.addEventListener('click', () => { form.hidden = true; message(messageBox); });
  actions.append(stage, cancel); form.append(actions);
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    try {
      const index = Number(form.dataset.editIndex);
      const listener = workloadListenerFromForm(form);
      mutateWorkloadListeners((items) => {
        if (items.some((item, position) => position !== index && item?.id === listener.id)) throw new Error(t('Workload listener ID already exists'));
        if (index < 0) items.push(listener); else items[index] = { ...(isObject(items[index]) ? items[index] : {}), ...listener };
      });
      message(messageBox, t('Listener staged. Apply configuration to publish it.'), 'success');
    } catch (error) { message(messageBox, error.message, 'error'); }
  });
  panel.append(summary, note, runtimeNote, list, add, form, messageBox);
  $('#settings-section').after(panel);
}

function workloadListenerFromForm(form) {
  const value = (name) => form.elements[name].value.trim();
  const id = value('id');
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(id)) throw new Error(t('Workload listener ID must be 1–128 ASCII letters, digits, dots, underscores, colons or dashes'));
  const listen = value('listen');
  const socket = /^(?:\[[0-9a-fA-F:.]+\]|[0-9.]+):(\d{1,5})$/.exec(listen);
  if (!socket || Number(socket[1]) < 1 || Number(socket[1]) > 65535) throw new Error(t('Workload listen address must be ip:port with a nonzero port'));
  const file = (name, optional = false) => {
    const path = value(name);
    if (!path && optional) return null;
    if (!validInboundTlsPath(path)) throw new Error(t('{field} must be an absolute normalized file path', { field: t(form.elements[name].previousElementSibling?.dataset.appI18n ?? name) }));
    return path;
  };
  const identities = nonemptyLines(form.elements.allowed_uri_sans.value);
  if (!identities.length || identities.length > 128 || new Set(identities).size !== identities.length || identities.some((uri) => !validSpiffeIdentity(uri)))
    throw new Error(t('Workload listener needs 1–128 distinct canonical SPIFFE URIs'));
  const timeout = Number(value('handshake_timeout_ms'));
  if (!/^[0-9]+$/.test(value('handshake_timeout_ms')) || timeout < 1 || timeout > 10000)
    throw new Error(t('Inbound TLS handshake timeout must be 1–10,000 ms'));
  return { id, listen, ...(form.elements.enabled.checked ? {} : { enabled: false }), tls: {
    cert_file: file('cert_file'), key_file: file('key_file'), client_ca_file: file('client_ca_file'),
    client_crl_file: file('client_crl_file', true), allowed_uri_sans: identities, handshake_timeout_ms: timeout,
  } };
}

function mutateWorkloadListeners(change) {
  const draft = parseConfigEditor();
  if (!isObject(draft) || (draft.workload_http !== undefined && !Array.isArray(draft.workload_http))) throw new Error(t('Document workload_http must be an array'));
  const items = structuredClone(draft.workload_http ?? []);
  change(items);
  draft.workload_http = items;
  $('#config-editor').value = JSON.stringify(draft, null, 2);
  configInput(); updateConfigPreview(); renderWorkloadListeners(draft);
}

function openWorkloadListener(index) {
  try {
    const draft = parseConfigEditor();
    const items = Array.isArray(draft?.workload_http) ? draft.workload_http : [];
    const item = index < 0 ? null : items[index];
    if (index >= 0 && !isObject(item)) throw new Error(t('Reload the workload listener list before editing'));
    const form = $('#workload-http-form'); form.dataset.editIndex = String(index); form.hidden = false;
    form.elements.id.value = item?.id ?? '';
    form.elements.listen.value = item?.listen ?? '';
    form.elements.enabled.checked = item?.enabled !== false;
    for (const name of ['cert_file', 'key_file', 'client_ca_file', 'client_crl_file']) form.elements[name].value = item?.tls?.[name] ?? '';
    form.elements.allowed_uri_sans.value = Array.isArray(item?.tls?.allowed_uri_sans) ? item.tls.allowed_uri_sans.join('\n') : '';
    form.elements.handshake_timeout_ms.value = item?.tls?.handshake_timeout_ms ?? 5000;
    form.elements.id.focus();
  } catch (error) { message($('#workload-http-message'), error.message, 'error'); }
}

function renderWorkloadListeners(draft) {
  ensureWorkloadListenersPanel();
  const list = $('#workload-http-list'); list.replaceChildren(); $('#workload-http-form').hidden = true;
  if (!isObject(draft) || !Array.isArray(draft.workload_http) || !draft.workload_http.length) {
    const empty = document.createElement('p'); copy(empty, 'No dedicated HTTP workload listeners in this document.'); list.append(empty); return;
  }
  draft.workload_http.forEach((item, index) => {
    const row = document.createElement('div'); row.className = 'button-row workload-http-row'; row.dataset.workloadId = typeof item?.id === 'string' ? item.id : '';
    const title = document.createElement('strong'); title.textContent = `${item?.id ?? '?'} · ${item?.listen ?? '?'}`;
    const state = document.createElement('span'); copy(state, item?.enabled === false ? 'Inactive' : 'Enabled');
    const material = document.createElement('span'); material.className = 'workload-material-state';
    material.dataset.workloadMaterialKind = 'http'; material.dataset.workloadMaterialId = typeof item?.id === 'string' ? item.id : '';
    const edit = document.createElement('button'); edit.type = 'button'; edit.className = 'button button-secondary'; copy(edit, 'Edit'); edit.addEventListener('click', () => openWorkloadListener(index));
    const toggle = document.createElement('button'); toggle.type = 'button'; toggle.className = 'button button-quiet'; copy(toggle, item?.enabled === false ? 'Activate' : 'Deactivate');
    toggle.addEventListener('click', () => { try { mutateWorkloadListeners((items) => { if (items[index]?.enabled === false) delete items[index].enabled; else items[index].enabled = false; }); message($('#workload-http-message'), t('Listener activation staged. Apply configuration to publish it.'), 'success'); } catch (error) { message($('#workload-http-message'), error.message, 'error'); } });
    const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'button button-quiet'; copy(remove, 'Remove');
    remove.addEventListener('click', () => { try { mutateWorkloadListeners((items) => items.splice(index, 1)); message($('#workload-http-message'), t('Listener removal staged. Apply configuration to publish it.'), 'success'); } catch (error) { message($('#workload-http-message'), error.message, 'error'); } });
    row.append(title, state, material, edit, toggle, remove); list.append(row);
  });
  refreshWorkloadMaterialBadges();
}

async function loadConfig(force) {
  if (state.configDirty && !force && state.config) return;
  const editor = $('#config-editor'); editor.disabled = true; message($('#config-message'), t('Loading active configuration…'));
  try {
    const { data, etag } = await api('/v1/config');
    state.config = data; state.configEtag = etag || `"${data.revision}"`; state.configDirty = false; setRevision(data.revision);
    showConfigDocument(data); $('#config-dirty').hidden = true; message($('#config-message'), t('Loaded revision {revision}.', { revision: data.revision }), 'success'); updateConfigPreview();
  } finally { editor.disabled = false; }
}

/** Show an active document in the JSON editor and mirror its `settings` block into the fleet-settings controls. */
function showConfigDocument(data) {
  const editor = $('#config-editor');
  editor.value = JSON.stringify(data, null, 2);
  editor.setAttribute('aria-invalid', 'false');
  showSettings(isObject(data) ? data.settings : undefined);
  renderWorkloadListeners(data);
}

function parseConfigEditor() {
  const editor = $('#config-editor');
  try { const value = JSON.parse(editor.value); editor.setAttribute('aria-invalid', 'false'); return value; }
  catch (error) { editor.setAttribute('aria-invalid', 'true'); throw new Error(t('Invalid JSON: {detail}', { detail: error.message })); }
}
function configInput() { state.configDirty = true; $('#config-dirty').hidden = false; message($('#config-message')); }
/** A hand-edited document drives the fleet-settings controls (the reverse direction is syncSettingsToDocument). */
function configEditorInput() {
  configInput();
  try { const value = JSON.parse($('#config-editor').value); if (isObject(value)) { showSettings(value.settings); renderWorkloadListeners(value); } } catch (_) { /* mid-edit; the controls keep their values */ }
}

const SETTINGS_FIELDS = ['trusted_proxy_cidrs', 'remove_response_headers', 'https_redirect_code', 'upstream_timeout_ms', 'allow_dot_segments', 'health_path'];
/** Response headers no rule or setting may remove (framing and hop-by-hop; the server rejects them too). */
const PROTECTED_RESPONSE_HEADERS = new Set(['content-length', 'content-encoding', 'transfer-encoding', 'connection', 'keep-alive', 'trailer', 'upgrade', 'te', 'content-range']);

/** Fill the fleet-settings controls from a document's `settings` block; absent, {} or a blank field means "inherit the process default". */
function showSettings(settings) {
  const value = isObject(settings) ? settings : {};
  const present = (key) => value[key] !== undefined && value[key] !== null;
  $('#setting-trusted_proxy_cidrs').value = Array.isArray(value.trusted_proxy_cidrs) ? value.trusted_proxy_cidrs.join('\n') : '';
  $('#setting-remove_response_headers').value = Array.isArray(value.remove_response_headers) ? value.remove_response_headers.join('\n') : '';
  $('#setting-https_redirect_code').value = present('https_redirect_code') ? String(value.https_redirect_code) : '';
  $('#setting-upstream_timeout_ms').value = present('upstream_timeout_ms') ? String(value.upstream_timeout_ms) : '';
  $('#setting-allow_dot_segments').value = typeof value.allow_dot_segments === 'boolean' ? String(value.allow_dot_segments) : '';
  $('#setting-health_path').value = typeof value.health_path === 'string' ? value.health_path : '';
  for (const control of $$('#settings-form [name]')) control.setAttribute('aria-invalid', 'false');
  $('#settings-state').hidden = !SETTINGS_FIELDS.some(present);
  state.settingsError = null;
  message($('#settings-message'));
}

/** Read the fleet-settings controls into a `settings` object ({} when every field inherits); throws on an invalid draft. */
function settingsFromForm() {
  const settings = {};
  const invalid = (id, text) => { $(`#setting-${id}`).setAttribute('aria-invalid', 'true'); return new Error(text); };
  for (const control of $$('#settings-form [name]')) control.setAttribute('aria-invalid', 'false');
  const cidrs = nonemptyLines($('#setting-trusted_proxy_cidrs').value);
  if (cidrs.length) {
    if (cidrs.length > 1024) throw invalid('trusted_proxy_cidrs', t('Trusted proxy CIDRs allow at most 1,024 entries'));
    for (const cidr of cidrs) if (!/^[0-9a-fA-F:.]+\/\d{1,3}$/.test(cidr)) throw invalid('trusted_proxy_cidrs', t('Trusted proxy CIDR must be address/prefix: {cidr}', { cidr }));
    settings.trusted_proxy_cidrs = cidrs;
  }
  const names = nonemptyLines($('#setting-remove_response_headers').value);
  if (names.length) {
    if (names.length > 64) throw invalid('remove_response_headers', t('Remove response headers allows at most 64 names'));
    for (const name of names) {
      if (!HEADER_NAME.test(name) || name.length > 128) throw invalid('remove_response_headers', t('Removed response header name is invalid: {name}', { name }));
      if (PROTECTED_RESPONSE_HEADERS.has(name.toLowerCase())) throw invalid('remove_response_headers', t('Removed response header is a protected framing or hop-by-hop header: {name}', { name }));
    }
    settings.remove_response_headers = names;
  }
  const code = $('#setting-https_redirect_code').value;
  if (code) {
    if (![301, 302, 307, 308, 426].includes(Number(code))) throw invalid('https_redirect_code', t('HTTPS redirect code must be 301, 302, 307, 308 or 426'));
    settings.https_redirect_code = Number(code);
  }
  const timeout = $('#setting-upstream_timeout_ms').value.trim();
  if (timeout) {
    if (!/^\d+$/.test(timeout) || Number(timeout) < 1 || Number(timeout) > 86400000) throw invalid('upstream_timeout_ms', t('Default upstream timeout must be 1–86,400,000 ms'));
    settings.upstream_timeout_ms = Number(timeout);
  }
  const dots = $('#setting-allow_dot_segments').value;
  if (dots) settings.allow_dot_segments = dots === 'true';
  const health = $('#setting-health_path').value.trim();
  if (health) {
    if (!health.startsWith('/') || health.length > 256 || !/^[\x21-\x7e]+$/.test(health) || /[?#]/.test(health)) throw invalid('health_path', t('Health path must be an absolute path of printable ASCII without query, fragment or whitespace (at most 256 characters)'));
    settings.health_path = health;
  }
  return settings;
}

/** Mirror the fleet-settings controls into the JSON document (a fully blank form removes the `settings` block). */
function syncSettingsToDocument() {
  let settings;
  try { settings = settingsFromForm(); }
  catch (error) { state.settingsError = error.message; message($('#settings-message'), error.message, 'error'); return; }
  state.settingsError = null;
  $('#settings-state').hidden = !Object.keys(settings).length;
  let value;
  try { value = parseConfigEditor(); }
  catch (error) { state.settingsError = t('the JSON document is invalid, so the settings could not be mirrored ({detail})', { detail: error.message }); message($('#settings-message'), state.settingsError, 'error'); return; }
  if (!isObject(value)) { state.settingsError = t('the JSON document must be an object'); message($('#settings-message'), state.settingsError, 'error'); return; }
  if (Object.keys(settings).length) value.settings = settings; else delete value.settings;
  $('#config-editor').value = JSON.stringify(value, null, 2);
  message($('#settings-message'));
  configInput();
  updateConfigPreview();
}

/** Active fleet settings echoed by GET /v1/status: each field shows its override or "Process default". */
function renderSettings(settings) {
  const value = isObject(settings) ? settings : {};
  const list = (items) => !Array.isArray(items) ? null : !items.length ? t('None (empty override)') : `${items.slice(0, 4).join(', ')}${items.length > 4 ? t(' +{count} more', { count: items.length - 4 }) : ''}`;
  const shown = {
    trusted_proxy_cidrs: list(value.trusted_proxy_cidrs),
    remove_response_headers: list(value.remove_response_headers),
    https_redirect_code: value.https_redirect_code !== undefined && value.https_redirect_code !== null ? String(value.https_redirect_code) : null,
    upstream_timeout_ms: value.upstream_timeout_ms !== undefined && value.upstream_timeout_ms !== null ? `${Number(value.upstream_timeout_ms).toLocaleString(getLocale())} ms` : null,
    allow_dot_segments: typeof value.allow_dot_segments === 'boolean' ? (value.allow_dot_segments ? t('Allowed') : t('Rejected')) : null,
    health_path: typeof value.health_path === 'string' ? value.health_path : null,
  };
  for (const key of SETTINGS_FIELDS) {
    const el = $(`#setting-active-${key}`);
    el.textContent = shown[key] ?? t('Process default');
    el.style.color = shown[key] === null ? 'var(--muted)' : '';
  }
}
function formatConfig() { try { $('#config-editor').value = JSON.stringify(parseConfigEditor(), null, 2); configInput(); updateConfigPreview(); } catch (error) { message($('#config-message'), error.message, 'error'); } }
async function validateConfig() {
  const button = $('#validate-config'); let value; try { value = parseConfigEditor(); } catch (error) { return message($('#config-message'), error.message, 'error'); }
  if (state.settingsError) return message($('#config-message'), t('Fleet settings: {detail}', { detail: state.settingsError }), 'error');
  setBusy(button, true, t('Validating…'));
  try { const { data } = await api('/v1/config/validate', { method: 'POST', json: value }); message($('#config-message'), t('Valid configuration{revision}.', { revision: data?.revision !== undefined ? t(' for revision {revision}', { revision: data.revision }) : '' }), 'success'); }
  catch (error) { message($('#config-message'), error.message, 'error'); }
  finally { setBusy(button, false); }
}
function updateConfigPreview() {
  let next; try { next = parseConfigEditor(); } catch (error) { $('#config-diff').textContent = error.message; $('#preview-count').textContent = t('Invalid JSON'); return; }
  const changes = diffValues(state.config, next);
  $('#config-diff').textContent = changes.length ? changes.join('\n') : t('No differences from the active configuration.');
  $('#preview-count').textContent = changes.length ? t(changes.length === 1 ? '{count} change' : '{count} changes', { count: changes.length }) : t('No changes');
}
function diffValues(before, after, path = '$') {
  if (JSON.stringify(before) === JSON.stringify(after)) return [];
  if (before === null || after === null || typeof before !== 'object' || typeof after !== 'object' || Array.isArray(before) !== Array.isArray(after)) return [`~ ${path}\n  from: ${compact(before)}\n  to:   ${compact(after)}`];
  if (Array.isArray(before)) {
    const out = []; const max = Math.max(before.length, after.length);
    for (let i = 0; i < max; i++) { if (i >= before.length) out.push(`+ ${path}[${i}] ${compact(after[i])}`); else if (i >= after.length) out.push(`- ${path}[${i}] ${compact(before[i])}`); else out.push(...diffValues(before[i], after[i], `${path}[${i}]`)); } return out;
  }
  const out = []; const keys = new Set([...Object.keys(before || {}), ...Object.keys(after || {})]);
  for (const key of keys) { const child = `${path}.${key}`; if (!(key in (before || {}))) out.push(`+ ${child} ${compact(after[key])}`); else if (!(key in (after || {}))) out.push(`- ${child} ${compact(before[key])}`); else out.push(...diffValues(before[key], after[key], child)); } return out;
}
function compact(value) { const text = JSON.stringify(value); return text && text.length > 140 ? `${text.slice(0, 137)}…` : text; }

async function applyConfig() {
  const button = $('#apply-config'); let value; try { value = parseConfigEditor(); } catch (error) { return message($('#config-message'), error.message, 'error'); }
  if (state.settingsError) return message($('#config-message'), t('Fleet settings: {detail}', { detail: state.settingsError }), 'error');
  if (!state.configEtag) return message($('#config-message'), t('Reload the active configuration before applying changes.'), 'error');
  updateConfigPreview(); setBusy(button, true, t('Applying…'));
  try {
    const { data, etag } = await api('/v1/config', { method: 'PUT', headers: { 'If-Match': state.configEtag }, json: value });
    state.config = data; state.configEtag = etag || `"${data.revision}"`; state.configDirty = false; showConfigDocument(data); $('#config-dirty').hidden = true; setRevision(data.revision); updateConfigPreview(); message($('#config-message'), t('Revision {revision} is active.', { revision: data.revision }), 'success'); toast(t('Configuration applied.'));
  } catch (error) {
    if (isRevisionConflict(error)) {
      await rebaseConfigDraft();
      message($('#config-message'), t('Revision conflict. The latest server revision is now the comparison base; your unsaved document is preserved. Review the preview and apply again.'), 'error');
    } else if (isIndeterminate(error)) {
      message($('#config-message'), error.message, 'error', { label: t('Reload current revision'), run: async () => {
        const revision = await rebaseConfigDraft();
        if (revision === null) return;
        const applied = !diffValues(state.config, value).length;
        message($('#config-message'), applied ? t('Revision {revision} already holds this document: the write was applied.', { revision }) : t('Revision {revision} is the comparison base and differs from your draft: the write was not applied. Review the preview and apply again.', { revision }), applied ? 'success' : 'warning');
      } });
    } else if (isRejection(error)) message($('#config-message'), await validationDetail(value, error.message), 'error');
    else message($('#config-message'), error.message, 'error');
  } finally { setBusy(button, false); }
}

/** Fetch the latest revision as the comparison base while keeping the editor draft; returns the revision or null. */
async function rebaseConfigDraft() {
  const draft = $('#config-editor').value;
  let revision = null;
  try { const latest = await api('/v1/config'); state.config = latest.data; state.configEtag = latest.etag || `"${latest.data.revision}"`; setRevision(latest.data.revision); revision = latest.data.revision; }
  catch (error) { message($('#config-message'), error.message, 'error'); }
  $('#config-editor').value = draft; state.configDirty = true; $('#config-dirty').hidden = false; updateConfigPreview();
  return revision;
}

async function loadDocs() {
  const content = $('#docs-content');
  if (!state.openapi) content.replaceChildren(loadingNode('Loading OpenAPI document…'));
  try { const { data } = await api('/openapi.json'); state.openapi = data; renderDocs(data); }
  catch (error) { content.replaceChildren(errorNode(error.message, () => loadDocs())); throw error; }
}
function renderDocs(spec) {
  const nav = $('#docs-nav'); const content = $('#docs-content'); nav.replaceChildren(); content.replaceChildren();
  const title = document.createElement('div'); title.className = 'panel-head'; const strong = document.createElement('strong'); strong.textContent = spec.info?.title || 'Hangang API'; const ver = document.createElement('span'); ver.textContent = spec.info?.version || ''; title.append(strong, ver); nav.append(title);
  let count = 0;
  for (const [path, operations] of Object.entries(spec.paths || {})) for (const [method, operation] of Object.entries(operations || {})) {
    if (!['get','post','put','patch','delete','head','options'].includes(method)) continue; const id = `endpoint-${count++}`;
    const link = document.createElement('a'); link.href = `#${id}`; const badge = document.createElement('span'); badge.className = `method ${method}`; badge.textContent = method.toUpperCase(); const linkPath = document.createElement('span'); linkPath.textContent = path; link.append(badge, linkPath); nav.append(link);
    const card = document.createElement('article'); card.className = 'endpoint'; card.id = id; const heading = document.createElement('h2'); const methodText = document.createElement('span'); methodText.className = `method ${method}`; methodText.textContent = method.toUpperCase(); heading.append(methodText, document.createTextNode(` ${path}`)); const summary = document.createElement('p'); summary.textContent = operation.summary || operation.description || t('No description provided.'); card.append(heading, summary);
    const details = { operationId: operation.operationId, tags: operation.tags, parameters: operation.parameters, requestBody: operation.requestBody, responses: operation.responses }; const pre = document.createElement('code'); pre.textContent = JSON.stringify(details, null, 2); card.append(pre); content.append(card);
  }
  const schemas = spec.components?.schemas || {};
  if (Object.keys(schemas).length) { const heading = document.createElement('h2'); heading.textContent = t('Schemas'); content.append(heading); for (const [name, schema] of Object.entries(schemas)) { const card = document.createElement('article'); card.className = 'schema-card'; const h = document.createElement('h2'); h.textContent = name; const pre = document.createElement('pre'); pre.textContent = JSON.stringify(schema, null, 2); card.append(h, pre); content.append(card); } }
  if (!count && !Object.keys(schemas).length) content.replaceChildren(emptyNode('No API operations', 'The OpenAPI document did not publish any paths or schemas.'));
}

async function refreshSelf() {
  if (!state.accountAuthAvailable || state.authMode === 'token') return;
  try {
    const { data } = await api('/v1/auth/me');
    state.user = data.user;
    updateAccess();
    if (!isAdmin() && state.view !== 'status') location.hash = '#status';
  } catch (error) {
    if (error.status === 401) logout('Your session is no longer authorized.');
    else throw error;
  }
}

async function loadUsers() {
  if (!isAdmin()) return;
  const { data } = await api('/v1/users');
  const list = $('#user-list');
  list.replaceChildren();
  for (const user of data.users || []) {
    const card = document.createElement('article'); card.className = 'panel user-card';
    const heading = document.createElement('div'); heading.className = 'user-card-head';
    const name = document.createElement('h2'); name.textContent = user.username;
    const badge = document.createElement('span'); badge.className = 'user-role'; copy(badge, user.enabled ? '{role}' : '{role} · disabled', { role: user.role });
    heading.append(name, badge);
    const form = document.createElement('form'); form.className = 'user-form';
    const roleLabel = document.createElement('label'); copy(roleLabel, 'Role');
    const role = document.createElement('select'); role.name = 'role';
    for (const value of ['viewer', 'admin']) { const option = document.createElement('option'); option.value = value; copy(option, value === 'admin' ? 'Administrator' : 'Viewer'); role.append(option); }
    role.value = user.role; roleLabel.append(role);
    const enabledLabel = document.createElement('label'); enabledLabel.className = 'user-enabled';
    const enabled = document.createElement('input'); enabled.type = 'checkbox'; enabled.name = 'enabled'; enabled.checked = Boolean(user.enabled);
    const enabledText = document.createElement('span'); copy(enabledText, ' Enabled'); enabledLabel.append(enabled, enabledText);
    const passwordLabel = document.createElement('label'); copy(passwordLabel, 'New password (optional)');
    const password = document.createElement('input'); password.type = 'password'; password.name = 'password'; password.minLength = 12; password.maxLength = 1024; password.autocomplete = 'new-password'; passwordLabel.append(password);
    const actions = document.createElement('div'); actions.className = 'button-row';
    const save = document.createElement('button'); save.type = 'submit'; save.className = 'button button-secondary'; copy(save, 'Save changes');
    const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'button button-danger'; copy(remove, 'Delete user');
    actions.append(remove, save); form.append(roleLabel, enabledLabel, passwordLabel, actions);
    form.addEventListener('submit', async (event) => {
      event.preventDefault(); setBusy(save, true, t('Saving…')); message($('#users-message'));
      try {
        const changes = { role: role.value, enabled: enabled.checked };
        if (password.value) changes.password = password.value;
        await api(`/v1/users/${encodeURIComponent(user.id)}`, { method: 'PUT', json: changes });
        password.value = '';
        await refreshSelf();
        if (isAdmin()) await loadUsers();
        toast(t('User updated.'));
      } catch (error) { message($('#users-message'), error.message, 'error'); }
      finally { setBusy(save, false); }
    });
    remove.addEventListener('click', async () => {
      const accepted = await confirmDialog({ title: t('Delete user?'), body: t('Delete {username}? Their sessions will no longer be authorized.', { username: user.username }), accept: t('Delete user') });
      if (!accepted) return;
      setBusy(remove, true, t('Deleting…')); message($('#users-message'));
      try {
        await api(`/v1/users/${encodeURIComponent(user.id)}`, { method: 'DELETE' });
        await refreshSelf();
        if (isAdmin()) await loadUsers();
        toast(t('User deleted.'));
      } catch (error) { message($('#users-message'), error.message, 'error'); }
      finally { setBusy(remove, false); }
    });
    card.append(heading, form); list.append(card);
  }
  if (!list.childElementCount) list.append(emptyNode('No users', 'Create an account above.'));
}

async function createUser(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector('[type="submit"]');
  const values = new FormData(form);
  setBusy(button, true, t('Creating…')); message($('#users-message'));
  try {
    await api('/v1/users', { method: 'POST', json: { username: String(values.get('username')).trim(), password: String(values.get('password')), role: String(values.get('role')) } });
    form.reset();
    await loadUsers();
    toast(t('User created.'));
  } catch (error) { message($('#users-message'), error.message, 'error'); }
  finally { form.elements.password.value = ''; setBusy(button, false); }
}

async function generateUtilityCredential(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector('[type="submit"]');
  const output = $('#utility-credential');
  const copyButton = $('#utility-copy-credential');
  const note = $('#utility-hash-message');
  output.value = '';
  copyButton.disabled = true;
  message(note);
  const username = form.elements.username.value.trim();
  const password = form.elements.password.value;
  setBusy(button, true, t('Hashing…'));
  try {
    const { data } = await api('/v1/util/hash-password', { method: 'POST', json: { username, password } });
    if (!isObject(data) || typeof data.credential !== 'string') throw new Error(t('The proxy did not return a credential line.'));
    output.value = data.credential;
    copyButton.disabled = false;
    message(note, t('Credential generated. Copy it into an HTTP route and save the route to publish it.'), 'success');
  } catch (error) {
    if (error instanceof StaleSessionError) return;
    if (error.status === 401 || error.status === 403) return logout(t('Your session is no longer authorized.'));
    message(note, error.status === 404 || error.status === 405 ? t('This proxy does not offer password hashing; use hangang --hash-password instead.') : error.message, 'error');
  } finally {
    form.elements.password.value = '';
    setBusy(button, false);
  }
}

async function copyUtilityCredential() {
  const output = $('#utility-credential');
  if (!output.value) return;
  try {
    await navigator.clipboard.writeText(output.value);
    message($('#utility-hash-message'), t('Credential line copied.'), 'success');
  } catch {
    output.focus();
    output.select();
    message($('#utility-hash-message'), t('Clipboard unavailable; the credential line is selected for manual copying.'), 'warning');
  }
}

$('#login-form').addEventListener('submit', login);
$('#switch-to-token').addEventListener('click', () => { setLoginMode('token'); showLogin(); });
$('#switch-to-account').addEventListener('click', () => { setLoginMode('account'); showLogin(); });
$('#create-user-form').addEventListener('submit', createUser);
$('#utility-hash-form').addEventListener('submit', generateUtilityCredential);
$('#utility-copy-credential').addEventListener('click', copyUtilityCredential);
$('#verify-session').addEventListener('click', verifySession);
$('#refresh-users').addEventListener('click', () => loadUsers().catch((error) => message($('#users-message'), error.message, 'error')));
$('#toggle-token').addEventListener('click', () => { const input = $('#token-input'); input.type = input.type === 'password' ? 'text' : 'password'; refreshTokenToggle(); });
$('#logout-button').addEventListener('click', () => logout());
$('#refresh-security').addEventListener('click', () => loadView('security'));
$('#refresh-status').addEventListener('click', () => loadView('status'));
$('#check-health').addEventListener('click', checkHealth);
$('#load-metrics').addEventListener('click', loadMetrics);
$('#refresh-cache').addEventListener('click', () => {
  if (state.cachePolicyDirty && !confirm('Discard the unsaved cache policy and reload the active policy?')) return;
  loadCache(true).catch((error) => showGlobalError(error.message));
});
$('#cache-policy-editor').addEventListener('input', cachePolicyInput);
$('#format-cache-policy').addEventListener('click', formatCachePolicy);
$('#cache-policy-template').addEventListener('click', cachePolicyTemplate);
$('#apply-cache-policy').addEventListener('click', applyCachePolicy);
$('#toggle-cache-policy').addEventListener('click', toggleCachePolicy);
$('#purge-cache').addEventListener('click', purgeCache);
$('#reload-certificates').addEventListener('click', () => {
  if (state.certificateDirty && !confirm('Discard the unsaved certificate paths and reload the active set?')) return;
  loadCertificates(true).catch((error) => showGlobalError(error.message));
});
$('#certificate-editor').addEventListener('input', certificateInput);
$('#add-certificate-template').addEventListener('click', addCertificateTemplate);
$('#format-certificates').addEventListener('click', formatCertificates);
$('#apply-certificates').addEventListener('click', applyCertificates);
$('#reload-config').addEventListener('click', () => { if (state.configDirty && !confirm('Discard the unsaved document and reload the active configuration?')) return; state.configDirty = false; loadConfig(true).catch((error) => showGlobalError(error.message)); });
$('#config-editor').addEventListener('input', configEditorInput);
$('#settings-form').addEventListener('input', syncSettingsToDocument);
$('#settings-form').addEventListener('change', syncSettingsToDocument);
$('#cache-generation-input').addEventListener('input', cacheGenerationInput);
$('#copy-epoch').addEventListener('click', copyEpoch);
$('#format-config').addEventListener('click', formatConfig);
$('#validate-config').addEventListener('click', validateConfig);
$('#preview-config').addEventListener('click', updateConfigPreview);
$('#apply-config').addEventListener('click', applyConfig);
$('#reload-docs').addEventListener('click', () => { state.openapi = null; loadDocs().catch((error) => showGlobalError(error.message)); });
$$('[data-new-route]').forEach((button) => button.addEventListener('click', () => openRoute(button.dataset.newRoute)));
$$('[data-close-dialog]').forEach((button) => button.addEventListener('click', () => $('#route-dialog').close()));
$('#route-dialog').addEventListener('close', destroyLuaEditors);
$('[data-close-docker]').addEventListener('click', () => $('#docker-dialog').close());
$('#route-form').addEventListener('submit', saveRoute);
// A control the browser refuses to submit must be visible, so its section opens before the validation bubble.
$('#route-form').addEventListener('invalid', (event) => { const details = event.target.closest('details'); if (details) details.open = true; }, true);
// An explicit advanced-document edit becomes the draft's source of truth.
$('#route-json').addEventListener('input', () => { delete $('#route-form').dataset.invalidNative; syncRouteControlsFromJson(); });
$('#delete-route').addEventListener('click', deleteRoute);
$('#docker-form').addEventListener('submit', resolveDocker);
window.addEventListener('hashchange', switchView);
window.addEventListener('hangang:localechange', refreshAppCopy);
document.addEventListener('visibilitychange', () => {
  if (document.hidden) { stopStatusPolling(); stopCertificatePolling(); stopWorkloadMaterialPolling(); }
  else if (state.token && state.view === 'status') { loadStatus().catch(() => {}); startStatusPolling(); }
  else if (state.token && state.view === 'certificates') { loadCertificateInventory(state.certificateInventoryOffset, true).catch(() => {}); startCertificatePolling(); }
  else if (state.token && ['config', 'tcp'].includes(state.view)) { refreshWorkloadMaterialStatus(); startWorkloadMaterialPolling(); }
});
window.addEventListener('beforeunload', () => { state.token = ''; stopStatusPolling(); stopWorkloadMaterialPolling(); });

initLocale();
state.view = normalizeView(location.hash);
if (!location.hash) history.replaceState(null, '', '#status');
switchView();
restoreAccountSession();

$('#restart-server').addEventListener('click', async () => {
  const accepted = await confirmDialog({ title: t('Restart the proxy?'), body: t('The supervisor starts a fresh process that inherits the listeners, then this process drains its existing connections. Traffic keeps flowing; in-flight administrative work in other tabs may see a brief revision change.'), accept: t('Restart') });
  if (!accepted) return;
  const button = $('#restart-server'); button.disabled = true;
  try { await api('/v1/lifecycle/restart', { method: 'POST' }); toast(t('Restart requested. Existing connections will drain.')); }
  catch (error) { toast(error.message, 'error'); }
  finally { button.disabled = false; }
});

$('#check-update').addEventListener('click', async () => {
  const accepted = await confirmDialog({ title: t('Check for a signed update?'), body: t('The supervisor downloads the release manifest, verifies its signature against the pinned public key and, when a newer release is available, replaces the binary and performs a listener-preserving restart.'), accept: t('Check and apply'), danger: false });
  if (!accepted) return;
  const button = $('#check-update'); button.disabled = true;
  try { await api('/v1/update/check', { method: 'POST' }); toast(t('Signed update check requested.')); }
  catch (error) { toast(error.message, 'error'); }
  finally { button.disabled = false; }
});
