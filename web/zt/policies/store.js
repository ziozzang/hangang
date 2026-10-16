// Policy source, draft and publication state for the Policies section.
// The draft survives navigation and locale changes in memory and refreshes
// in session storage, bound to the base revision it was made against.
import { clone, emptyPolicy } from './model.js';

const STORAGE = 'hangang-policies-draft';
let state = null;

export function policyState() { return state; }

export function resetPolicyState() {
  state = null;
}

function readStoredDraft(key) {
  try {
    const stored = JSON.parse(sessionStorage.getItem(STORAGE) || 'null');
    return stored && stored.key === key ? stored.draft : null;
  } catch { return null; }
}

function writeStoredDraft() {
  try {
    if (state?.draft) sessionStorage.setItem(STORAGE, JSON.stringify({ key: state.key, draft: state.draft }));
    else sessionStorage.removeItem(STORAGE);
  } catch { /* Draft persistence is a convenience. */ }
}

/**
 * Loads the authoritative policy. Independent authority: GET
 * /v1/pumgye/policy ({revision, policy}) with the Hangang authority scope
 * revision; embedded: the `pumgye` member of /v1/config.
 */
export async function loadPolicy(cx, { force = false } = {}) {
  if (state && !force) return state;
  const configResult = await cx.api('/v1/config');
  const config = configResult.data;
  let next;
  if (config?.pumgye_authority) {
    const [policy, status, audit] = await Promise.all([
      cx.api('/v1/pumgye/policy'), cx.api('/v1/pumgye/status'),
      cx.api('/v1/pumgye/audit').catch(error => { if (error?.status === 401) throw error; return { data: null, error }; }),
    ]);
    const owner = ['native', 'kubernetes'].includes(status.data?.policy_source) ? status.data.policy_source : 'unknown';
    next = {
      independent: true, owner, managed: owner !== 'native',
      revision: policy.data.revision, etag: policy.etag || `"${policy.data.revision}"`,
      authorityRevision: policy.response?.headers?.get('x-hangang-config-revision') || null,
      base: policy.data.policy || emptyPolicy(), status: status.data,
      publications: Array.isArray(audit.data) ? audit.data : audit.data?.records || [], auditError: audit.error || null,
    };
  } else {
    const result = configResult;
    next = {
      independent: false, owner: 'native', managed: false,
      revision: result.data.revision, etag: result.etag || `"${result.data.revision}"`, authorityRevision: null,
      base: result.data.pumgye || emptyPolicy(), configDocument: result.data, status: null, publications: [], auditError: null,
    };
  }
  next.key = `${next.independent ? 'pumgye' : 'config'}:${next.revision}`;
  // A refresh discards an in-memory draft only when explicitly forced.
  const carried = state && state.key === next.key ? state.draft : readStoredDraft(next.key);
  next.draft = force ? null : carried;
  next.outcomeUnknown = false;
  state = next;
  writeStoredDraft();
  return state;
}

/** Working document: the draft if one exists, else the published policy. */
export function working() { return state?.draft || state?.base; }

/** Applies `mutate` to a copy of the working document as the new draft. */
export function edit(mutate) {
  if (!state || state.managed) return false;
  const next = clone(working());
  if (mutate(next) === false) return false;
  state.draft = next;
  writeStoredDraft();
  window.dispatchEvent(new CustomEvent('hangang:policydraft'));
  return true;
}

export function replaceDraft(document) {
  state.draft = document;
  writeStoredDraft();
  window.dispatchEvent(new CustomEvent('hangang:policydraft'));
}

export function discardDraft() {
  if (!state) return;
  state.draft = null;
  writeStoredDraft();
  window.dispatchEvent(new CustomEvent('hangang:policydraft'));
}

/**
 * Compare-and-swap publication with the base revision. Returns
 * `{ok}`, `{conflict}` on 409 or throws; an unknown outcome is recorded.
 */
export async function publish(cx, reason) {
  const draft = state.draft;
  const headers = { 'If-Match': state.etag, 'x-hangang-change-reason': encodeURIComponent(reason) };
  try {
    let result;
    if (state.independent) {
      if (!state.authorityRevision) throw Object.assign(Error('reload'), { status: 428 });
      headers['x-hangang-config-revision'] = state.authorityRevision;
      result = await cx.api('/v1/pumgye/policy', { method: 'PUT', headers, json: { revision: state.revision, policy: draft } });
    } else {
      const next = clone(state.configDocument); next.pumgye = draft;
      result = await cx.api('/v1/config', { method: 'PUT', headers, json: next });
    }
    state.draft = null;
    writeStoredDraft();
    return { ok: true, revision: result.data?.revision };
  } catch (error) {
    if (error?.status === 409) return { conflict: true };
    if (!error?.status || error.status >= 500) state.outcomeUnknown = true;
    throw error;
  }
}
