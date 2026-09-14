import { formatDateLocale, formatNumberLocale, t } from './i18n.js';

const $ = (selector) => document.querySelector(selector);
const PAGE_SIZE = 100;
const RETIRED_PAGE_SIZE = 64;
let apiCall = null;
let onUnauthorized = null;
let page = null;
let offset = 0;
let requestGeneration = 0;
let loading = false;
let loadedAt = null;
let retiredPage = null;
let retiredOffset = 0;
let retiredRequestGeneration = 0;
let retiredLoading = false;
let observerRequestGeneration = 0;
let observerViewActive = false;
let observerLoading = false;
let observer = null;
let fleetGeneration = 0;
let fleetActive = false;
let fleetLoading = false;
let fleetTimer = null;
let fleetSnapshot = null;
let fleetRequestedAt = 0;
let fleetError = '';
let fleetFilter = 'all';
const FLEET_POLL_MS = 5000;
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const finiteInteger = (value, max) => Number.isSafeInteger(value) && value >= 0 && value <= max;
const hex16 = value => typeof value === 'string' && /^[a-f0-9]{16}$(?![\s\S])/.test(value);
const safeCode = value => value === null || ['transport', 'http_status', 'body_too_large', 'invalid_observation', 'identity_mismatch'].includes(value);
const safeEndpoint = value => {
  if (typeof value !== 'string' || value.length > 2048) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.origin === value && !url.username && !url.password;
  } catch { return false; }
};
const safeEpoch = value => value === null || (typeof value === 'string' && value.length >= 1
  && value.length <= 128 && /^[\x20-\x7e]+$(?![\s\S])/.test(value));
const exactKeys = (value, keys) => isObject(value) && Object.keys(value).length === keys.length
  && keys.every(key => Object.hasOwn(value, key));
function fleetObservation(value, id) {
  if (value === null) return null;
  if (!exactKeys(value, ['schema_version', 'node_id', 'observer_generation', 'instance_id',
    'configuration_source', 'revision', 'config_digest', 'ready', 'store_epoch'])
    || value.schema_version !== 1 || value.node_id !== id
    || !observerDecimal(value.observer_generation) || !hex16(value.instance_id)
    || !['file', 'shared', 'kubernetes'].includes(value.configuration_source)
    || !observerDecimal(value.revision) || !hex16(value.config_digest)
    || typeof value.ready !== 'boolean' || !safeEpoch(value.store_epoch)) return undefined;
  return value;
}
function fleetState(data) {
  if (!exactKeys(data, ['configured', 'available', 'generation', 'observer_instance_id', 'expected_nodes', 'fresh_nodes',
    'stale_after_seconds', 'nodes']) || typeof data.configured !== 'boolean' || typeof data.available !== 'boolean'
    || !hex16(data.observer_instance_id) || data.stale_after_seconds !== 60 || !Array.isArray(data.nodes) || data.nodes.length > 64) return null;
  const generation = data.generation === null ? null : observerDecimal(data.generation) ? data.generation : undefined;
  if (generation === undefined) return null;
  if (!data.configured) return !data.available && generation === null && data.expected_nodes === 0
    && data.fresh_nodes === 0 && data.nodes.length === 0 ? { kind: 'disabled', generation, process: data.observer_instance_id, nodes: [] } : null;
  if (generation === null) return null;
  // A failed inventory reload cannot certify either the expected roster or its coverage.
  if (!data.available) return data.expected_nodes === null && data.fresh_nodes === null
    && data.nodes.length === 0 ? { kind: 'unavailable', generation, process: data.observer_instance_id, nodes: [] } : null;
  if (!finiteInteger(data.expected_nodes, 64) || !finiteInteger(data.fresh_nodes, 64)
    || data.fresh_nodes > data.expected_nodes || data.nodes.length !== data.expected_nodes) return null;
  const seen = new Set();
  const origins = new Set();
  const nodes = [];
  for (const row of data.nodes) {
    if (!exactKeys(row, ['node_id', 'endpoint', 'group_id', 'role', 'condition', 'last_error', 'age_seconds', 'observation'])
      || !observerNodeId(row.node_id) || seen.has(row.node_id)
      || !(row.group_id === null || observerNodeId(row.group_id))
      || !(row.role === null || observerNodeId(row.role))
      || !safeEndpoint(row.endpoint) || origins.has(row.endpoint)
      || !['unknown', 'fresh', 'stale', 'unavailable', 'identity_mismatch'].includes(row.condition)
      || !safeCode(row.last_error) || !(row.age_seconds === null || finiteInteger(row.age_seconds, Number.MAX_SAFE_INTEGER))
      || (row.observation === null) !== (row.age_seconds === null)
      || (row.condition === 'unknown' && (row.observation !== null || row.last_error !== null))
      || (row.condition === 'fresh' && (row.observation === null || row.age_seconds >= 60 || row.last_error !== null))
      || (row.condition === 'stale' && (row.observation === null || row.age_seconds < 60 || row.last_error !== null))
      || (row.condition === 'unavailable' && !['transport', 'http_status', 'body_too_large', 'invalid_observation'].includes(row.last_error))
      || (row.condition === 'identity_mismatch' && row.last_error !== 'identity_mismatch')) return null;
    const observation = fleetObservation(row.observation, row.node_id);
    if (observation === undefined) return null;
    seen.add(row.node_id);
    origins.add(row.endpoint);
    nodes.push({ node_id: row.node_id, endpoint: row.endpoint, group_id: row.group_id, role: row.role, condition: row.condition,
      last_error: row.last_error, age_seconds: row.age_seconds, observation });
  }
  if (nodes.filter(row => row.condition === 'fresh').length !== data.fresh_nodes) return null;
  return { kind: 'available', generation, process: data.observer_instance_id, nodes, expected: data.expected_nodes };
}
function fleetCondition(row) {
  if (row.condition !== 'fresh' || fleetError) return row.condition === 'fresh' && fleetError ? 'stale' : row.condition;
  return row.age_seconds + Math.max(0, (performance.now() - fleetRequestedAt) / 1000) >= 60 ? 'stale' : 'fresh';
}
function renderFleet() {
  const state = fleetSnapshot?.kind ?? 'unknown';
  $('#fleet-observations-state').textContent = t(({ disabled: 'Disabled', available: 'Inventory available',
    unavailable: 'Inventory unavailable', unknown: 'Unknown' })[state]);
  $('#fleet-observations-generation').textContent = fleetSnapshot?.generation === null || fleetSnapshot?.generation === undefined
    ? '—' : formatNumberLocale(BigInt(fleetSnapshot.generation));
  $('#fleet-observations-process').textContent = fleetSnapshot?.process ?? '—';
  const allRows = fleetSnapshot?.nodes ?? [];
  const groups = [...new Set(allRows.map(row => row.group_id).filter(group => group !== null))].sort();
  const choices = $('#fleet-observations-group');
  choices.replaceChildren(new Option(t('All observer peers'), 'all'));
  if (allRows.some(row => row.group_id === null)) choices.add(new Option(t('Ungrouped observer peers'), 'ungrouped'));
  for (const group of groups) choices.add(new Option(t('Group {id}', { id: group }), `group:${group}`));
  if (![...choices.options].some(option => option.value === fleetFilter)) fleetFilter = 'all';
  choices.value = fleetFilter;
  choices.disabled = fleetSnapshot?.kind !== 'available';
  const rows = fleetFilter === 'all' ? allRows : allRows.filter(row => fleetFilter === 'ungrouped'
    ? row.group_id === null : row.group_id === fleetFilter.slice('group:'.length));
  const fresh = allRows.filter(row => fleetCondition(row) === 'fresh').length;
  const selectedFresh = rows.filter(row => fleetCondition(row) === 'fresh').length;
  $('#fleet-observations-selected-coverage').textContent = fleetSnapshot?.kind === 'available'
    ? t('Selected reporting: {fresh} of {expected} fresh', {
      fresh: formatNumberLocale(selectedFresh), expected: formatNumberLocale(rows.length),
    }) : t('Selected reporting unavailable');
  $('#fleet-observations-coverage').textContent = fleetSnapshot?.kind === 'disabled' ? t('Disabled')
    : fleetSnapshot?.expected === undefined ? '—'
      : t('{fresh} of {expected} fresh', { fresh: formatNumberLocale(fresh), expected: formatNumberLocale(fleetSnapshot.expected) });
  $('#fleet-observations-message').textContent = fleetError ? t(fleetError) : '';
  $('#fleet-observations-refresh').disabled = fleetLoading;
  const body = $('#fleet-observations-rows');
  body.replaceChildren();
  for (const row of rows) {
    const condition = fleetCondition(row);
    const tr = node('tr');
    const identity = node('td');
    identity.append(node('strong', '', row.node_id), node('div', 'field-help', row.endpoint));
    identity.append(node('div', 'field-help', t('Inventory group: {id}', { id: row.group_id ?? t('Unassigned') })));
    identity.append(node('div', 'field-help', t('Inventory role: {id}', { id: row.role ?? t('Unassigned') })));
    const status = node('td');
    status.append(node('strong', '', t(({ unknown: 'Unknown', fresh: 'Fresh', stale: 'Stale',
      unavailable: 'Unavailable', identity_mismatch: 'Identity mismatch' })[condition])));
    status.append(node('div', 'field-help', row.age_seconds === null ? t('Age unknown')
      : t('{seconds} seconds at last read', { seconds: formatNumberLocale(row.age_seconds) })));
    const sample = node('td');
    if (row.observation) {
      sample.append(node('strong', '', condition === 'fresh' ? t('Reported ready: {state}', { state: t(row.observation.ready ? 'Yes' : 'No') })
        : t('Historical reported ready: {state}', { state: t(row.observation.ready ? 'Yes' : 'No') })));
      sample.append(node('div', 'field-help', t('Process {instance}; revision {revision}; digest {digest}', {
        instance: row.observation.instance_id, revision: row.observation.revision, digest: row.observation.config_digest,
      })));
      sample.append(node('div', 'field-help', t('Source {source}; store epoch {epoch}; observer generation {generation}', {
        source: row.observation.configuration_source, epoch: row.observation.store_epoch ?? '—',
        generation: row.observation.observer_generation,
      })));
    } else sample.textContent = '—';
    tr.append(identity, status, sample, node('td', '', row.last_error ?? '—'));
    body.append(tr);
  }
  $('#fleet-observations-empty').hidden = rows.length > 0 || state !== 'disabled' && state !== 'available';
}
async function fetchFleet() {
  if (!apiCall || !fleetActive || fleetLoading || document.hidden) return;
  const generation = ++fleetGeneration;
  fleetLoading = true;
  renderFleet();
  const requestedAt = performance.now();
  try {
    const { data } = await apiCall('/v1/fleet/observations');
    if (generation !== fleetGeneration || !fleetActive) return;
    const parsed = fleetState(data);
    if (parsed) {
      fleetSnapshot = parsed;
      if (parsed.kind !== 'available') fleetFilter = 'all';
      fleetRequestedAt = requestedAt - 1000; // Server ages are truncated to whole seconds.
      fleetError = '';
    } else fleetError = 'Fleet observations response is invalid; showing historical data if available.';
  } catch (error) {
    if (generation !== fleetGeneration || !fleetActive) return;
    if (error.status === 401 || error.status === 403) {
      const callback = onUnauthorized;
      resetOperations();
      callback?.();
      return;
    }
    fleetError = error.status === 404 ? 'Fleet observations are not reported by this server.'
      : 'Fleet observations could not be refreshed; showing historical data if available.';
  } finally {
    if (generation === fleetGeneration && fleetActive) { fleetLoading = false; renderFleet(); }
  }
}
function startFleet() {
  fleetActive = true;
  if (fleetTimer !== null) clearInterval(fleetTimer);
  fleetTimer = setInterval(() => { renderFleet(); fetchFleet(); }, FLEET_POLL_MS);
  fetchFleet();
}
function pauseFleet() {
  fleetActive = false;
  fleetGeneration += 1;
  fleetLoading = false;
  if (fleetTimer !== null) clearInterval(fleetTimer);
  fleetTimer = null;
}


const observerDecimal = value => typeof value === 'string' && /^(?:0|[1-9][0-9]{0,19})$(?![\s\S])/.test(value)
  && BigInt(value) <= 18446744073709551615n;
const observerNodeId = value => typeof value === 'string'
  && /^[A-Za-z0-9._-]{1,64}$(?![\s\S])/.test(value);

function observerState(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data) || typeof data.configured !== 'boolean'
    || typeof data.available !== 'boolean' || !Object.hasOwn(data, 'node_id') || !Object.hasOwn(data, 'generation')) return null;
  const node = data.node_id === null ? null : observerNodeId(data.node_id) ? data.node_id : undefined;
  const generation = data.generation === null ? null : observerDecimal(data.generation) ? data.generation : undefined;
  if (node === undefined || generation === undefined) return null;
  if (!data.configured && !data.available && node === null && generation === null)
    return { kind: 'disabled', node: null, generation: null };
  if (data.configured && data.available && node !== null && generation !== null)
    return { kind: 'available', node, generation };
  if (data.configured && !data.available && node !== null && generation !== null)
    return { kind: 'unavailable', node, generation };
  return null;
}

function renderObserver() {
  const state = observer?.kind ?? 'unknown';
  $('#observer-identity-state').textContent = t(({ disabled: 'Disabled', available: 'Available',
    unavailable: 'Unavailable', error: 'Observer read error', unknown: 'Unknown' })[state]);
  $('#observer-identity-node').textContent = observer?.node ?? '—';
  $('#observer-identity-generation').textContent = observer?.generation === null || observer?.generation === undefined
    ? '—' : formatNumberLocale(BigInt(observer.generation));
  $('#observer-identity-refresh').disabled = observerLoading;
}

async function fetchObserver() {
  if (!apiCall || !observerViewActive) return;
  const generation = ++observerRequestGeneration;
  observerLoading = true;
  observer = null;
  renderObserver();
  $('#observer-identity-message').textContent = t('Loading node observation identity…');
  try {
    const { data } = await apiCall('/v1/fleet/observer-status');
    if (generation !== observerRequestGeneration || !observerViewActive) return;
    observer = observerState(data);
    $('#observer-identity-message').textContent = observer ? '' : t('Node observation identity response is invalid.');
  } catch (error) {
    if (generation !== observerRequestGeneration || !observerViewActive) return;
    if (error.status === 401 || error.status === 403) {
      const callback = onUnauthorized;
      resetOperations();
      callback?.();
      return;
    }
    observer = { kind: error.status === 404 ? 'unknown' : 'error', node: null, generation: null };
    $('#observer-identity-message').textContent = error.status === 404
      ? t('Node observation identity is not reported by this server.')
      : t('Node observation identity could not be refreshed.');
  } finally {
    if (generation === observerRequestGeneration && observerViewActive) {
      observerLoading = false;
      renderObserver();
    }
  }
}

export function pauseObserver() {
  observerViewActive = false;
  observerRequestGeneration += 1;
  observerLoading = false;
  pauseFleet();
}

function node(tag, className, content) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (content !== undefined) element.textContent = content;
  return element;
}

function appendDetail(parent, title, detail, className = '') {
  const card = node('article', `operations-capability ${className}`.trim());
  card.append(node('h2', '', title), node('p', '', detail));
  parent.append(card);
}

function modeLabel(mode) {
  if (mode === 'least_connections') return t('Least connections');
  if (mode === 'round_robin') return t('Round robin');
  return t('Balance mode unavailable');
}

function healthLabel(row) {
  if (row.health_mode === 'active_tcp') return t('TCP connection checks');
  if (row.health_mode === 'active_passive') return t('Active + passive checks');
  if (row.health_mode === 'active') return t('Active checks');
  if (row.health_mode === 'cooldown') return t('Failure cooldown');
  return row.health_mode === 'unmonitored' ? t('Unmonitored') : t('Health mode unavailable');
}

function desiredStateLabel(state) {
  if (state === 'serving') return t('Serving');
  if (state === 'draining') return t('Draining');
  if (state === 'maintenance') return t('Maintenance');
  return t('State unavailable');
}

function renderCapabilities(value) {
  const capabilities = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  const evidence = (key, enabled, disabled) => capabilities[key] === true ? t(enabled)
    : capabilities[key] === false ? t(disabled) : t('Capability not reported by this instance.');
  const root = $('#operations-capabilities');
  root.replaceChildren();
  appendDetail(root, t('Docker backend resolution'), evidence('docker_enabled',
    'Enabled for configured docker:// targets. Resolved IPs are not shown here; edit references in HTTP or TCP routes.',
    'Disabled on this process. Configured docker:// targets cannot resolve here.'),
  capabilities.docker_enabled === true ? 'is-enabled' : capabilities.docker_enabled === false ? 'is-disabled' : '');
  const source = capabilities.configuration_source;
  const sourceDetail = source === 'shared'
    ? t('A shared configuration store is authoritative for this instance. This page does not enumerate fleet peers.')
    : source === 'kubernetes'
      ? t('A Kubernetes controller manages this instance. This page does not enumerate cluster members.')
      : source === 'file' ? t('This instance uses a local configuration file. No fleet membership is implied.')
        : t('Configuration authority is not reported or is not recognized.');
  appendDetail(root, t('Configuration authority'), sourceDetail);
  appendDetail(root, t('Graceful self-restart'), evidence('self_restart_enabled',
    'Available through the supervised process. Use the Status page to request it.',
    'Unavailable because this process has no supervisor control channel.'),
  capabilities.self_restart_enabled === true ? 'is-enabled' : capabilities.self_restart_enabled === false ? 'is-disabled' : '');
  appendDetail(root, t('Signed updates'), evidence('signed_updates_enabled',
    'Signed update checks are configured. Use the Status page to check and apply.',
    'Unavailable on this process. A signed manifest and supervisor are required.'),
  capabilities.signed_updates_enabled === true ? 'is-enabled' : capabilities.signed_updates_enabled === false ? 'is-disabled' : '');
}

function renderRows(rows) {
  const body = $('#operations-rows');
  body.replaceChildren(...rows.map((row) => {
    const tr = node('tr');
    const route = node('td');
    route.append(node('strong', 'operations-primary', row.route_id || '—'));
    route.append(node('span', 'operations-secondary', row.protocol === 'tcp'
      ? `${t('TCP listener')} · ${row.listen || '—'}`
      : row.match_host || t('Any host')));
    const target = node('td');
    target.append(node('code', 'operations-address', row.address || '—'));
    target.append(node('span', 'operations-secondary', row.member_id
      ? t('Member {id} · #{index}', { id: row.member_id, index: Number(row.backend_index) + 1 })
      : `${String(row.protocol || '').toUpperCase()} · #${Number(row.backend_index) + 1}`));
    const selection = node('td');
    const inactive = row.enabled === false;
    const admissionOpen = row.admission_open;
    selection.append(node('span', `operations-eligibility ${!inactive && admissionOpen !== false && row.available ? 'is-eligible' : 'is-excluded'}`,
      inactive ? t('Inactive') : admissionOpen === false ? t('Admission closed') : row.available ? t('Eligible') : t('Excluded')));
    selection.append(node('span', 'operations-secondary', t('Desired: {state}', { state: desiredStateLabel(row.desired_state) })));
    selection.append(node('span', 'operations-secondary', admissionOpen === true ? t('Member gate open')
      : admissionOpen === false ? t('Member gate closed') : t('Member gate state unavailable')));
    selection.append(node('span', 'operations-secondary',
      t('{mode} · weight {weight}', { mode: modeLabel(row.balance_mode), weight: formatNumberLocale(row.weight) })));
    const health = node('td');
    const suspended = row.desired_state === 'maintenance' && ['active', 'active_passive', 'active_tcp'].includes(row.health_mode);
    health.append(node('span', 'operations-primary', inactive ? t('Route inactive')
      : suspended ? t('Probes suspended') : healthLabel(row)));
    health.append(node('span', 'operations-secondary', inactive ? t('No health checks while inactive')
      : suspended ? t('Probes suspended for maintenance; existing work continues')
        : row.desired_state === 'maintenance' ? t('No active probes configured; maintenance blocks new admissions')
          : row.desired_state === 'draining' ? t('Draining closes new admissions; configured probes continue')
            : admissionOpen === false ? t('Member gate closed; this does not imply a probe failure')
        : row.initial_check_pending === true ? t(row.protocol === 'tcp' ? 'Checking — waiting for successful connection probes' : 'Checking — waiting for healthy probes')
        : row.initial_check_pending === false && row.probe_observed === true && !row.available
          ? t(row.protocol === 'tcp' ? 'Excluded after observed connection failures' : 'Excluded after observed health evidence')
          : row.probe_observed === null ? t('No active probe evidence')
            : row.probe_observed ? t(row.protocol === 'tcp' ? 'Connection probe result observed' : 'Active probe result observed')
              : t(row.protocol === 'tcp' ? 'Awaiting first connection probe' : 'Awaiting first active probe')));
    const load = node('td');
    load.append(node('span', 'operations-primary', row.protocol === 'tcp'
      ? t('{count} active route connections', { count: formatNumberLocale(row.route_active_connections ?? 0) })
      : row.active_requests == null ? t('Not tracked')
        : t('{count} active requests', { count: formatNumberLocale(row.active_requests) })));
    load.append(node('span', 'operations-secondary', Number.isSafeInteger(row.active_admissions) && row.active_admissions >= 0
      ? t('{count} active admission leases', { count: formatNumberLocale(row.active_admissions) })
      : t('Admission count unavailable')));
    load.append(node('span', 'operations-secondary', t(row.protocol === 'tcp'
      ? 'Current TCP member leases include pending dials; retired generations are listed separately. Zero does not prove drain completion.'
      : 'Current HTTP member leases include in-flight requests; retired generations are listed separately. Zero does not prove drain completion.')));
    if (row.protocol === 'tcp') {
      if (row.member_id) {
        const count = row.member_active_streams;
        load.append(node('span', 'operations-secondary', Number.isSafeInteger(count) && count >= 0
          ? t('{count} established member streams', { count: formatNumberLocale(count) })
          : t('Member stream count unavailable')));
        load.append(node('span', 'operations-secondary', t('Instance-local; includes old endpoints, excludes pending dials. Not a drain-complete signal.')));
      } else load.append(node('span', 'operations-secondary', t('Route-wide, not per target')));
    }
    tr.append(route, target, selection, health, load);
    return tr;
  }));
  $('#operations-empty').hidden = rows.length > 0;
}

function render() {
  if (!page) return;
  const total = Number(page.total) || 0;
  const start = total && page.rows.length ? Number(page.offset) + 1 : 0;
  const end = Number(page.offset) + page.rows.length;
  $('#operations-instance').textContent = t('Instance {id} · revision {revision}', {
    id: page.instance_id || '—', revision: formatNumberLocale(page.revision),
  });
  $('#operations-updated').textContent = loadedAt
    ? t('Loaded {time}', { time: formatDateLocale(loadedAt, { hour: 'numeric', minute: '2-digit', second: '2-digit' }) })
    : '';
  renderCapabilities(page.capabilities);
  renderRows(page.rows);
  $('#operations-range').textContent = t('{start}–{end} of {total} configured targets', {
    start: formatNumberLocale(start), end: formatNumberLocale(end), total: formatNumberLocale(total),
  });
  $('#operations-prev').disabled = loading || offset === 0;
  $('#operations-next').disabled = loading || offset + page.limit >= total;
  $('#operations-refresh').disabled = loading;
}

function renderRetiredRows(rows) {
  $('#retired-rows').replaceChildren(...rows.map((row) => {
    const tr = node('tr');
    const id = node('td');
    id.append(node('strong', 'operations-primary', Number.isSafeInteger(row.retirement_id) && row.retirement_id >= 0
      ? `#${formatNumberLocale(row.retirement_id)}` : '—'));
    const route = node('td');
    route.append(node('strong', 'operations-primary', row.route_id));
    route.append(node('span', 'operations-secondary', `${row.protocol.toUpperCase()} · ${row.member_id === null
      ? t('Legacy target') : t('Member {id}', { id: row.member_id })}`));
    const address = node('td');
    address.append(node('code', 'operations-address', row.address));
    const active = node('td');
    active.append(node('strong', 'operations-primary', Number.isSafeInteger(row.active_admissions) && row.active_admissions >= 0
      ? t('{count} admission leases', { count: formatNumberLocale(row.active_admissions) }) : '—'));
    tr.append(id, route, address, active);
    return tr;
  }));
  $('#retired-empty').hidden = rows.length > 0;
}

function renderRetired() {
  if (!retiredPage) return;
  const { total, rows } = retiredPage;
  const start = total && rows.length ? retiredOffset + 1 : 0;
  renderRetiredRows(rows);
  $('#retired-range').textContent = t('{start}–{end} of {total} active retired generations', {
    start: formatNumberLocale(start), end: formatNumberLocale(rows.length ? retiredOffset + rows.length : 0),
    total: formatNumberLocale(total),
  });
  $('#retired-capacity').textContent = t('Registry capacity {count}', {
    count: formatNumberLocale(retiredPage.capacity),
  });
  $('#retired-prev').disabled = retiredLoading || retiredOffset === 0;
  $('#retired-next').disabled = retiredLoading || retiredOffset + retiredPage.limit >= total;
  $('#retired-refresh').disabled = retiredLoading;
}

async function fetchRetiredPage(nextOffset, allowCorrection = true) {
  if (!apiCall) return;
  const generation = ++retiredRequestGeneration;
  retiredLoading = true;
  if (retiredPage) renderRetired();
  $('#retired-refresh').disabled = true;
  $('#retired-empty').hidden = true;
  $('#retired-message').textContent = t('Loading retired members…');
  try {
    const { data } = await apiCall(`/v1/retired-members?offset=${nextOffset}&limit=${RETIRED_PAGE_SIZE}`);
    if (generation !== retiredRequestGeneration) return;
    if (!data || !Array.isArray(data.rows) || data.rows.length > RETIRED_PAGE_SIZE
      || !Number.isSafeInteger(data.total) || data.total < 0
      || data.offset !== nextOffset || data.limit !== RETIRED_PAGE_SIZE
      || data.capacity !== 4096
      || data.rows.length > Math.max(0, data.total - nextOffset)
      || data.rows.some((row) => !row || !['http', 'tcp'].includes(row.protocol)
        || typeof row.route_id !== 'string' || typeof row.address !== 'string'
        || (row.member_id !== null && typeof row.member_id !== 'string')
        || !Number.isInteger(row.retirement_id) || row.retirement_id < 0
        || !Number.isInteger(row.active_admissions) || row.active_admissions < 0)) {
      throw new Error(t('Invalid retired members response.'));
    }
    if (allowCorrection && data.total > 0 && nextOffset >= data.total) {
      retiredLoading = false;
      return fetchRetiredPage(Math.floor((data.total - 1) / RETIRED_PAGE_SIZE) * RETIRED_PAGE_SIZE, false);
    }
    retiredOffset = data.total === 0 ? 0 : nextOffset;
    retiredPage = data;
    $('#retired-message').textContent = '';
  } catch (error) {
    if (generation !== retiredRequestGeneration) return;
    if (error.status === 401 || error.status === 403) {
      const callback = onUnauthorized;
      resetOperations();
      callback?.();
      return;
    }
    const detail = error.message || t('Could not load retired members.');
    $('#retired-message').textContent = retiredPage
      ? t('Refresh failed; showing last loaded retired members. {error}', { error: detail })
      : detail;
  } finally {
    if (generation === retiredRequestGeneration) {
      retiredLoading = false;
      $('#retired-refresh').disabled = false;
      if (retiredPage) renderRetired();
      else $('#retired-empty').hidden = true;
    }
  }
}

async function fetchPage(nextOffset, allowCorrection = true) {
  if (!apiCall) return;
  const generation = ++requestGeneration;
  loading = true;
  if (page) render();
  $('#operations-message').textContent = t('Loading configured targets…');
  try {
    const { data } = await apiCall(`/v1/operations?offset=${nextOffset}&limit=${PAGE_SIZE}`);
    if (generation !== requestGeneration) return;
    if (!data || !Array.isArray(data.rows) || data.rows.length > PAGE_SIZE
      || !Number.isSafeInteger(data.total) || data.total < 0
      || data.offset !== nextOffset || data.limit !== PAGE_SIZE
      || data.rows.length > Math.max(0, data.total - nextOffset)
      || data.rows.some((row) => !row || !['http', 'tcp'].includes(row.protocol)
        || typeof row.route_id !== 'string' || typeof row.address !== 'string')) {
      throw new Error(t('Invalid operations response.'));
    }
    if (allowCorrection && data.total > 0 && nextOffset >= data.total) {
      loading = false;
      return fetchPage(Math.floor((data.total - 1) / PAGE_SIZE) * PAGE_SIZE, false);
    }
    offset = data.total === 0 ? 0 : nextOffset;
    page = data.total === 0 ? { ...data, offset: 0 } : data;
    loadedAt = new Date();
    $('#operations-message').textContent = '';
  } catch (error) {
    if (generation !== requestGeneration) return;
    if (error.status === 401 || error.status === 403) {
      const callback = onUnauthorized;
      resetOperations();
      callback?.();
      return;
    }
    const detail = error.message || t('Could not load operations.');
    $('#operations-message').textContent = page
      ? t('Refresh failed; showing last loaded snapshot. {error}', { error: detail })
      : detail;
  } finally {
    if (generation === requestGeneration) {
      loading = false;
      render();
    }
  }
}

export async function loadOperations(api, unauthorized) {
  apiCall = api;
  onUnauthorized = unauthorized;
  observerViewActive = true;
  startFleet();
  await Promise.all([fetchPage(offset), fetchRetiredPage(retiredOffset), fetchObserver()]);
}

export function refreshOperationsCopy() {
  if (page) render();
  if (retiredPage) renderRetired();
  renderObserver();
  renderFleet();
}

export function resetOperations() {
  pauseObserver();
  requestGeneration += 1;
  retiredRequestGeneration += 1;
  apiCall = null;
  onUnauthorized = null;
  page = null;
  loadedAt = null;
  offset = 0;
  loading = false;
  retiredPage = null;
  retiredOffset = 0;
  retiredLoading = false;
  observer = null;
  fleetSnapshot = null;
  fleetFilter = 'all';
  fleetError = '';
  renderFleet();
  $('#observer-identity-message').textContent = '';
  renderObserver();
  $('#operations-message').textContent = '';
  $('#operations-capabilities').replaceChildren();
  $('#operations-rows').replaceChildren();
  $('#operations-instance').textContent = '';
  $('#operations-updated').textContent = '';
  $('#operations-range').textContent = '';
  $('#operations-empty').hidden = false;
  $('#operations-prev').disabled = true;
  $('#operations-next').disabled = true;
  $('#operations-refresh').disabled = false;
  $('#retired-message').textContent = '';
  $('#retired-rows').replaceChildren();
  $('#retired-range').textContent = '';
  $('#retired-capacity').textContent = '';
  $('#retired-empty').hidden = false;
  $('#retired-prev').disabled = true;
  $('#retired-next').disabled = true;
  $('#retired-refresh').disabled = false;
}

$('#operations-refresh').addEventListener('click', () => { if (!loading) fetchPage(offset); });
$('#operations-prev').addEventListener('click', () => { if (!loading && offset > 0) fetchPage(Math.max(0, offset - PAGE_SIZE)); });
$('#operations-next').addEventListener('click', () => { if (!loading && page && offset + PAGE_SIZE < page.total) fetchPage(offset + PAGE_SIZE); });
$('#retired-refresh').addEventListener('click', () => { if (!retiredLoading) fetchRetiredPage(retiredOffset); });
$('#retired-prev').addEventListener('click', () => { if (!retiredLoading && retiredOffset > 0) fetchRetiredPage(Math.max(0, retiredOffset - RETIRED_PAGE_SIZE)); });
$('#retired-next').addEventListener('click', () => { if (!retiredLoading && retiredPage && retiredOffset + RETIRED_PAGE_SIZE < retiredPage.total) fetchRetiredPage(retiredOffset + RETIRED_PAGE_SIZE); });
$('#observer-identity-refresh').addEventListener('click', () => { if (!observerLoading) fetchObserver(); });

$('#fleet-observations-refresh').addEventListener('click', () => { if (!fleetLoading) fetchFleet(); });
document.addEventListener('visibilitychange', () => { if (fleetActive && !document.hidden) { renderFleet(); fetchFleet(); } });

$('#fleet-observations-group').addEventListener('change', event => { fleetFilter = event.target.value; renderFleet(); });
