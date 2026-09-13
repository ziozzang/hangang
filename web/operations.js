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
  return mode === 'least_connections' ? t('Least connections') : t('Round robin');
}

function healthLabel(row) {
  if (row.health_mode === 'active_tcp') return t('TCP connection checks');
  if (row.health_mode === 'active_passive') return t('Active + passive checks');
  if (row.health_mode === 'active') return t('Active checks');
  if (row.health_mode === 'cooldown') return t('Failure cooldown');
  return t('Unmonitored');
}

function renderCapabilities(capabilities = {}) {
  const root = $('#operations-capabilities');
  root.replaceChildren();
  appendDetail(root, t('Docker backend resolution'), capabilities.docker_enabled
    ? t('Enabled for configured docker:// targets. Resolved IPs are not shown here; edit references in HTTP or TCP routes.')
    : t('Disabled on this process. Configured docker:// targets cannot resolve here.'),
  capabilities.docker_enabled ? 'is-enabled' : 'is-disabled');
  const source = capabilities.configuration_source;
  const sourceDetail = source === 'shared'
    ? t('A shared configuration store is authoritative for this instance. This page does not enumerate fleet peers.')
    : source === 'kubernetes'
      ? t('A Kubernetes controller manages this instance. This page does not enumerate cluster members.')
      : t('This instance uses a local configuration file. No fleet membership is implied.');
  appendDetail(root, t('Configuration authority'), sourceDetail);
  appendDetail(root, t('Graceful self-restart'), capabilities.self_restart_enabled
    ? t('Available through the supervised process. Use the Status page to request it.')
    : t('Unavailable because this process has no supervisor control channel.'),
  capabilities.self_restart_enabled ? 'is-enabled' : 'is-disabled');
  appendDetail(root, t('Signed updates'), capabilities.signed_updates_enabled
    ? t('Signed update checks are configured. Use the Status page to check and apply.')
    : t('Unavailable on this process. A signed manifest and supervisor are required.'),
  capabilities.signed_updates_enabled ? 'is-enabled' : 'is-disabled');
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
    selection.append(node('span', `operations-eligibility ${!inactive && row.available ? 'is-eligible' : 'is-excluded'}`,
      inactive ? t('Inactive') : row.available ? t('Eligible') : t('Excluded')));
    selection.append(node('span', 'operations-secondary',
      t('{mode} · weight {weight}', { mode: modeLabel(row.balance_mode), weight: formatNumberLocale(row.weight) })));
    const health = node('td');
    health.append(node('span', 'operations-primary', inactive ? t('Route inactive') : healthLabel(row)));
    health.append(node('span', 'operations-secondary', inactive ? t('No health checks while inactive')
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
    start: formatNumberLocale(start), end: formatNumberLocale(retiredOffset + rows.length),
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
    retiredOffset = nextOffset;
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
      || !Number.isSafeInteger(data.total) || data.total < 0) {
      throw new Error(t('Invalid operations response.'));
    }
    if (allowCorrection && data.total > 0 && nextOffset >= data.total) {
      loading = false;
      return fetchPage(Math.floor((data.total - 1) / PAGE_SIZE) * PAGE_SIZE, false);
    }
    offset = nextOffset;
    page = data;
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
  await Promise.all([fetchPage(offset), fetchRetiredPage(retiredOffset)]);
}

export function refreshOperationsCopy() {
  if (page) render();
  if (retiredPage) renderRetired();
}

export function resetOperations() {
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
