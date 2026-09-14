import { t, getLocale, formatNumberLocale } from './i18n.js';
// Console presentation and bounded live telemetry. Credentials never enter URLs or storage.
const $ = (selector) => document.querySelector(selector);
const number = (value) => formatNumberLocale(value, { maximumFractionDigits: 1 });
let previous = null;
let samples = [];
let records = [];
let retention = 60;
let paused = false;
let streamAbort = null;
let reconnectTimer = null;
let streamGeneration = 0;
let connected = false;
let expiryTimer = null;
let lastStreamSample = 0;
let commandSelection = 0;
let commandOpener = null;
let dropped = 0;
let securitySummary = null;
let trafficSummary = null;
let metricsSummary = null;
let tcpActive = [];
let tcpRecent = [];
let tcpActiveBatch = null;
let tcpRecentBatch = null;
let tcpProcess = null;
let tcpPaused = false;
let tcpFrozenActive = null;
let tcpFrozenRecent = null;
let tcpFrozenActiveBatch = null;
let tcpFrozenRecentBatch = null;
let tcpFrozenPage = 1;
let tcpActivePageAfter = null;
let tcpActivePage = 1;
let tcpStreamVersion = 0;
let tcpActiveRequestVersion = 0;
let tcpRecentRequestVersion = 0;
let tcpRefresh = null;
let tcpFirstPage = null;
let tcpNextPage = null;
const tcpFetches = new Set();
const localizedDisplays = new Map();
function display(selector, value) {
  const el = $(selector);
  delete el.dataset.i18n;
  localizedDisplays.set(selector, value);
  el.textContent = value();
}

export function isLive() { return connected && Date.now() - lastStreamSample < 4500; }
function setStream(text, stale = false) {
  display('#stream-state', text);
  $('#stream-state').classList.toggle('is-stale', stale);
  if (stale) { $('#traffic-flow').classList.remove('is-flowing'); display('#flow-mode', () => t("Paused")); }
}
export function stopLive() {
  localizedDisplays.clear();
  trafficSummary = null;
  streamGeneration += 1;
  resetTcpHistory();
  streamAbort?.abort(); streamAbort = null;
  clearTimeout(reconnectTimer); reconnectTimer = null;
  clearInterval(expiryTimer); expiryTimer = null;
  connected = false;
  previous = null;
  records = [];
  $('#activity-rows').replaceChildren();
  $('#activity-empty').hidden = false;
  display('#activity-empty', () => t("Live history is paused. Reopen this view to load recent requests."));
  display('#activity-count', () => t("History cleared"));
  $('#traffic-flow').classList.remove('is-flowing');
  setStream(() => t("Stream paused"), true);
}
export function resetConsole() {
  stopLive(); securitySummary = null; metricsSummary = null; samples = []; records = []; previous = null; paused = false; dropped = 0;
  for (const id of ['traffic-rate', 'flow-active', 'flow-errors', 'chart-max']) $(`#${id}`).textContent = '—';
  for (const id of ['traffic-line', 'traffic-area', 'error-line']) $(`#${id}`).setAttribute('d', '');
  $('#chart-empty').hidden = false; display('#chart-start', () => t("Waiting for samples")); display('#chart-latest', () => t("Now"));
  $('#activity-rows').replaceChildren(); $('#activity-empty').hidden = false; display('#activity-empty', () => t("Waiting for the live request stream."));
  display('#activity-count', () => t("Waiting for request metadata")); display('#activity-updated', () => '—'); $('#activity-search').value = '';
  display('#activity-pause', () => t("Pause view")); $('#activity-pause').setAttribute('aria-pressed', 'false');
  display('#activity-note', () => t("Only this instance. Buffered records expire automatically."));
  $('#tcp-active-filter').value = ''; $('#tcp-recent-filter').value = '';
  tcpPaused = false; $('#tcp-history-pause').setAttribute('aria-pressed', 'false');
  display('#tcp-history-pause', () => t('Pause TCP view'));
  $('#prometheus-rows').replaceChildren(); $('#geoip-metrics')?.remove(); $('#security-content').replaceChildren();
  display('#overview-health', () => t("Connecting to gateway")); display('#overview-detail', () => t("Waiting for runtime telemetry")); display('#flow-mode', () => t("Waiting"));
  if ($('#command-dialog').open) $('#command-dialog').close();
}

// Fetch allows Authorization headers, unlike native EventSource. Parsing is bounded even
// when a proxy or unexpected server sends incomplete frames; each attempt owns an AbortController.
export function startLive(token, onStatus, onUnauthorized, admin) {
  stopLive();
  const generation = streamGeneration;
  const active = () => generation === streamGeneration;
  let failures = 0;
  expiryTimer = setInterval(() => {
    renderActivity();
    renderTcpHistory();
    if (connected && !isLive()) { connected = false; setStream(() => t("Stream delayed · reconnecting"), true); streamAbort?.abort(); }
  }, 1000);
  if (admin) {
    fetch('/v1/traffic?limit=128', { headers: { Authorization: `Bearer ${token}` }, cache: 'no-store' })
      .then(async (response) => {
        if (response.status === 401 && active()) return onUnauthorized();
        if (!response.ok) return;
        const body = await response.json(); if (active()) recordTraffic(body);
      }).catch(() => {});
    tcpRefresh = () => fetchTcpHistory(token, onUnauthorized, active);
    tcpFirstPage = () => fetchTcpActive(token, onUnauthorized, active);
    tcpNextPage = () => fetchTcpActive(token, onUnauthorized, active, tcpActiveBatch?.next_after ?? null);
    tcpRefresh();
  }
  const connect = async () => {
    if (!active()) return;
    const controller = new AbortController(); streamAbort = controller;
    connected = false; previous = null;
    setStream(() => failures ? t("Reconnecting · polling fallback") : t("Connecting live stream"), Boolean(failures));
    let reader;
    let tcpCaughtUp = false;
    let deadline = setTimeout(() => controller.abort(), 8000);
    try {
      const response = await fetch('/v1/events', { headers: { Authorization: `Bearer ${token}`, Accept: 'text/event-stream' }, cache: 'no-store', signal: controller.signal });
      if (!active()) return;
      if (response.status === 401) { onUnauthorized(); return; }
      if (!response.ok || !response.headers.get('content-type')?.includes('text/event-stream')) throw new Error('SSE unavailable');
      reader = response.body.getReader();
      const decoder = new TextDecoder(); let buffer = '';
      while (active()) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!active()) return;
        buffer += decoder.decode(value, { stream: true });
        if (buffer.length > 1_048_576) throw new Error('Event frame exceeds limit');
        // SSE accepts CRLF and LF; retain partial CRLF across network chunks.
        buffer = buffer.replace(/\r\n/g, '\n');
        let end;
        while ((end = buffer.indexOf('\n\n')) !== -1) {
          const frame = buffer.slice(0, end); buffer = buffer.slice(end + 2);
          let event = 'message'; const lines = [];
          for (const line of frame.split('\n')) {
            if (line.startsWith('event:')) event = line.slice(6).trim();
            if (line.startsWith('data:')) lines.push(line.slice(5).replace(/^ /, ''));
          }
          if (!active()) return;
          if (event === 'auth_expired') { onUnauthorized(); return; }
          if (!lines.length) continue;
          const data = JSON.parse(lines.join('\n'));
          if (event === 'status') {
            clearTimeout(deadline); deadline = setTimeout(() => controller.abort(), 8000);
            connected = true; lastStreamSample = Date.now(); failures = 0; setStream(() => t("Live · SSE · 1s")); onStatus(data);
            // The SSE completion cursor starts at stream connection time. One
            // bounded latest-page read closes the initial GET/connect window.
            if (admin && active() && !tcpCaughtUp) {
              tcpCaughtUp = true;
              fetchTcpPage('/v1/connections/tcp/recent?limit=128', token, onUnauthorized, active,
                batch => recordTcpRecent(batch, false), 'recent', true);
            }
          } else if (event === 'traffic' && admin) recordTraffic(data);
          else if (event === 'tcp_connections' && admin) {
            tcpStreamVersion += 1;
            if (data?.active && tcpActivePageAfter === null) recordTcpActive(data.active);
            if (data?.recent) recordTcpRecent(data.recent, false);
          }
        }
      }
    } catch (_) { /* Preserve data and clearly identify fallback; never display transport secrets. */ }
    finally {
      clearTimeout(deadline);
      reader?.cancel().catch(() => {});
      controller.abort();
      if (active()) {
        connected = false; previous = null; setStream(() => t("Reconnecting · polling fallback"), true);
        failures += 1; reconnectTimer = setTimeout(connect, Math.min(15000, 1000 * 2 ** Math.min(failures, 4)));
      }
    }
  };
  connect();
}

export function recordStatus(data) {
  const metrics = data.metrics || {};
  const instance = data.instance?.id || `${data.process_id ?? ''}:${data.version ?? ''}`;
  if (tcpProcess && data.instance?.id && tcpProcess !== data.instance.id) resetTcpHistory(true);
  const now = Date.now();
  const uptime = Number(data.uptime_seconds);
  if (previous && (instance !== previous.instance || uptime < previous.uptime || Number(metrics.requests_total) < Number(previous.metrics.requests_total))) {
    samples = []; records = []; previous = null; dropped = 0; trafficSummary = null; retention = 60;
    display('#activity-updated', () => '—');
    display('#activity-retention', () => t('Up to {seconds}s', { seconds: retention }));
    display('#activity-note', () => t('Only this instance. Buffered records expire automatically.'));
    renderActivity();
  }
  const dt = previous ? (uptime - previous.uptime || (now - previous.time) / 1000) : 0;
  const usable = previous && dt >= .2 && dt <= 15;
  const rates = {};
  for (const [key, value] of Object.entries(metrics)) {
    if (key.endsWith('_total') && usable && Number.isFinite(value) && Number.isFinite(previous.metrics[key]) && value >= previous.metrics[key]) rates[key] = (value - previous.metrics[key]) / dt;
  }
  if (!previous || uptime > previous.uptime || now - previous.time >= 200) {
    if (usable && Number.isFinite(rates.requests_total)) {
      samples.push({ time: now, requests: rates.requests_total, errors: rates.errors_total ?? 0 });
      if (samples.length > 60) samples.shift();
    }
    previous = { time: now, uptime, instance, metrics: { ...metrics } };
  }
  const rate = rates.requests_total;
  display('#traffic-rate', () => Number.isFinite(rate) ? number(rate) : '—');
  display('#flow-active', () => number(metrics.active_connections ?? 0));
  display('#flow-errors', () => Number.isFinite(rates.errors_total) ? number(rates.errors_total) : '—');
  $('#traffic-flow').classList.toggle('is-flowing', Number.isFinite(rate) && rate > 0);
  display('#flow-mode', () => !Number.isFinite(rate) ? t("Collecting") : rate > 0 ? t("Traffic observed") : t("Idle"));
  const ready = data.state?.ready !== false;
  display('#overview-health', () => data.state?.draining ? t("Gateway is draining") : ready ? t("Gateway is accepting traffic") : t("Gateway is not ready"));
  display('#overview-detail', () => t("HTTP routes: {http} \u00b7 TCP routes: {tcp}", { http: number(data.http_routes ?? 0), tcp: number(data.tcp_routes ?? 0) }));
  if (!connected) setStream(() => t("Polling · 5s fallback"), true);
  metricsSummary = { metrics, rates, geoip: data.geoip_metrics };
  renderChart(); renderPrometheus(metrics, rates); renderGeoMetrics(metricsSummary.geoip);
}
function renderChart() {
  const empty = !samples.length; $('#chart-empty').hidden = !empty;
  if (empty) { for (const id of ['traffic-line','traffic-area','error-line']) $(`#${id}`).setAttribute('d',''); return; }
  const max = Math.max(1, ...samples.flatMap((sample) => [sample.requests, sample.errors]));
  const x = (i) => 40 + i / Math.max(1, samples.length - 1) * 660;
  const y = (v) => 155 - v / max * 130;
  const line = (key) => samples.map((sample, i) => `${i ? 'L' : 'M'}${x(i).toFixed(2)},${y(sample[key]).toFixed(2)}`).join(' ');
  $('#traffic-line').setAttribute('d',line('requests'));
  $('#traffic-area').setAttribute('d',`${line('requests')} L${x(samples.length - 1)},155 L40,155 Z`);
  $('#error-line').setAttribute('d', samples.some(sample => sample.errors > 0) ? line('errors') : '');
  display('#chart-max', () => number(max));
  $('#traffic-chart').setAttribute('aria-label',t("Recent request rates, {count} observed samples, latest {rate} requests per second", { count: samples.length, rate: number(samples.at(-1).requests) }));
  display('#chart-start', () => new Date(samples[0]?.time || 0).toLocaleTimeString(getLocale() === 'ko' ? 'ko-KR' : 'en-US'));
  display('#chart-latest', () => new Date(samples.at(-1)?.time || 0).toLocaleTimeString(getLocale() === 'ko' ? 'ko-KR' : 'en-US'));
}
function renderPrometheus(metrics, rates) {
  const rows = Object.entries(metrics).map(([key, value]) => {
    const row = document.createElement('tr');
    for (const text of [`hangang_${key}`, key.endsWith('_total') ? 'counter' : 'gauge', number(value), Number.isFinite(rates[key]) ? number(rates[key]) : '—']) {
      const td = document.createElement('td'); td.textContent = text; row.append(td);
    }
    return row;
  });
  $('#prometheus-rows').replaceChildren(...rows);
}
function validGeoMetrics(value) {
  if (!value || typeof value !== 'object') return false;
  const count = (n) => Number.isSafeInteger(n) && n >= 0;
  for (const protocol of ['http', 'tcp']) {
    const entry = value[protocol];
    if (!entry || typeof entry !== 'object' || !entry.countries || typeof entry.countries !== 'object') return false;
    if (!['known','unknown','unavailable','allowed','denied','admission_unavailable'].every(key => count(entry[key]))) return false;
    const countries = Object.entries(entry.countries);
    if (countries.length > 677 || !countries.every(([country, total]) => (country === 'unknown' || /^[A-Z]{2}$/.test(country)) && count(total))) return false;
  }
  return true;
}
function renderGeoMetrics(geoip) {
  $('#geoip-metrics')?.remove();
  if (!validGeoMetrics(geoip)) return; // Old servers do not report these counters.
  const section = document.createElement('section'); section.id = 'geoip-metrics';
  const heading = document.createElement('h3'); heading.textContent = t('GeoIP observations · this instance');
  const note = document.createElement('p'); note.textContent = t('Approximate country lookups. Unavailable lookup and enforced policy denial are different outcomes.');
  section.append(heading, note);
  const grid = document.createElement('div'); grid.className = 'metric-grid';
  for (const [key, label] of [['http', 'HTTP'], ['tcp', 'TCP']]) {
    const entry = geoip[key];
    const card = document.createElement('article'); card.className = 'metric';
    const title = document.createElement('h4'); title.textContent = label;
    const lookup = document.createElement('p'); lookup.textContent = t('Lookups · known {known} · unknown {unknown} · unavailable {unavailable}', {
      known: number(entry.known), unknown: number(entry.unknown), unavailable: number(entry.unavailable),
    });
    const admission = document.createElement('p'); admission.textContent = t('Enforced policy · allowed {allowed} · denied {denied} · unavailable {unavailable}', {
      allowed: number(entry.allowed), denied: number(entry.denied), unavailable: number(entry.admission_unavailable),
    });
    const top = Object.entries(entry.countries).filter(([country]) => country !== 'unknown')
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 10);
    const breakdown = document.createElement('p'); breakdown.textContent = top.length
      ? t('Top observed countries: {countries}', { countries: top.map(([country, total]) => `${country} ${number(total)}`).join(' · ') })
      : t('No known-country observations yet.');
    const omitted = Object.keys(entry.countries).filter(country => country !== 'unknown').length - top.length;
    card.append(title, lookup, admission, breakdown);
    if (omitted > 0) { const more = document.createElement('p'); more.textContent = t('{count} more country codes in /metrics', { count: number(omitted) }); card.append(more); }
    grid.append(card);
  }
  section.append(grid);
  $('.prometheus-table-wrap').before(section);
}
const publicListenerId = /^[A-Za-z0-9._-]{1,64}$/;
const workloadListenerId = /^[A-Za-z0-9._:-]{1,128}$/;
function normalizeTrafficListener(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return { kind: 'unknown', id: null };
  if (value.kind === 'default' && value.id === 'default') return { kind: 'default', id: 'default' };
  if (value.kind === 'public' && typeof value.id === 'string' && value.id !== 'default' && publicListenerId.test(value.id)) return { kind: 'public', id: value.id };
  if (value.kind === 'workload' && typeof value.id === 'string' && workloadListenerId.test(value.id)) return { kind: 'workload', id: value.id };
  return { kind: 'unknown', id: null };
}
function trafficListenerLabel(listener) {
  if (listener.kind === 'default') return t('Default CLI listener');
  if (listener.kind === 'public') return t('Public listener: {id}', { id: listener.id });
  if (listener.kind === 'workload') return t('Workload mTLS listener: {id}', { id: listener.id });
  return t('Listener unknown');
}
function trafficRequestDetail(record) {
  return `${record.protocol || '—'}${record.tls ? ' · TLS' : ''} · ${trafficListenerLabel(record.listener)}`;
}

function recordTraffic(batch) {
  if (!Array.isArray(batch?.records)) return;
  retention = Math.max(1, Math.min(3600, Number(batch.retention_seconds) || 60));
  dropped = Number(batch.dropped_total) || 0;
  const merged = new Map(records.map(record => [record.id, record]));
  const receivedAt = performance.now();
  const serverNow = Number(batch.server_time_unix_ms);
  for (const source of batch.records.slice(0, 128)) {
    if (!source || typeof source !== 'object') continue;
    // Old peers may return an absolute target or query-bearing path. Keep only a path
    // in this browser's bounded ring, and never retain unrecognized raw-host fields.
    const path = typeof source.path === 'string' && source.path.startsWith('/') && !source.path.startsWith('//')
      ? source.path.split(/[?#]/, 1)[0].slice(0, 256) : '/';
    const record = { id: source.id, timestamp_unix_ms: source.timestamp_unix_ms,
      peer_ip: source.peer_ip, peer_port: source.peer_port, client_ip: source.client_ip,
      method: source.method, path, route_id: source.route_id, status: source.status,
      response_head_ms: source.response_head_ms, protocol: source.protocol, tls: source.tls,
      geoip: source.geoip, listener: normalizeTrafficListener(source.listener),
      policy_revision: Number.isSafeInteger(source.policy_revision) && source.policy_revision >= 0 ? source.policy_revision : null };
    const age = Number.isFinite(serverNow) ? Math.max(0, serverNow - Number(record.timestamp_unix_ms)) : 0;
    const expiresAt = receivedAt + Math.max(0, retention * 1000 - age);
    const old = merged.get(record.id);
    merged.set(record.id, { ...record, expiresAt: old ? Math.min(old.expiresAt, expiresAt) : expiresAt });
  }
  records = [...merged.values()].sort((a,b) => b.id - a.id).slice(0, 128);
  trafficSummary = { gap: Boolean(batch.gap), updated: Date.now(),
    filteredTotal: Number.isSafeInteger(batch.filtered_total) && batch.filtered_total >= 0 ? batch.filtered_total : null };
  renderTrafficSummary();
  renderActivity();
}

const tcpPhases = new Set(['accepted', 'inspecting', 'authenticating', 'dialing', 'forwarding']);
const tcpOutcomes = new Set(['eof', 'idle_timeout', 'shutdown', 'identity_revoked', 'interrupted', 'no_route', 'ip_denied', 'capacity', 'sni_rejected', 'sni_timeout', 'country_denied', 'country_unavailable', 'mtls_rejected', 'no_backend', 'member_unavailable', 'dial_failed', 'endpoint_changed', 'io_error']);
const tcpPhaseLabels = { accepted: 'Accepted', inspecting: 'Inspecting', authenticating: 'Authenticating', dialing: 'Dialing', forwarding: 'Forwarding' };
const tcpOutcomeLabels = { eof: 'Normal EOF', idle_timeout: 'Idle timeout', shutdown: 'Shutdown', identity_revoked: 'Identity revoked', interrupted: 'Interrupted', no_route: 'No route', ip_denied: 'IP denied', capacity: 'Capacity rejected', sni_rejected: 'SNI rejected', sni_timeout: 'SNI timeout', country_denied: 'Country denied', country_unavailable: 'Country unavailable', mtls_rejected: 'mTLS rejected', no_backend: 'No backend', member_unavailable: 'Member unavailable', dial_failed: 'Dial failed', endpoint_changed: 'Endpoint changed', io_error: 'I/O error' };
const decimalU64 = (value) => typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) <= 18446744073709551615n;
const safeCount = (value) => decimalU64(value)
  ? new Intl.NumberFormat(getLocale() === 'ko' ? 'ko-KR' : 'en-US').format(BigInt(value))
  : Number.isSafeInteger(value) && value >= 0 ? number(value) : '—';
const tcpText = (value, limit) => value == null ? null : typeof value === 'string' && value.length <= limit ? value : null;
const tcpTime = (value) => Number.isSafeInteger(value) && value >= 0;
const tcpBytes = (value) => decimalU64(value) ? new Intl.NumberFormat(getLocale() === 'ko' ? 'ko-KR' : 'en-US').format(BigInt(value)) : '—';
function tcpRecord(value, recent) {
  if (!value || typeof value !== 'object' || !decimalU64(value.connection_id) || value.connection_id === '0'
    || !tcpTime(value.started_at_unix_ms) || !tcpText(value.peer_ip, 64) || !Number.isInteger(value.peer_port)
    || value.peer_port < 0 || value.peer_port > 65535 || !tcpText(value.listen, 256)
    || !tcpPhases.has(value.phase) || !decimalU64(value.bytes_upstream) || !decimalU64(value.bytes_downstream)
    || (value.route_id != null && tcpText(value.route_id, 128) == null)
    || (value.member_id != null && tcpText(value.member_id, 128) == null)) return null;
  if (recent) {
    if (!decimalU64(value.event_id) || value.event_id === '0' || !tcpTime(value.ended_at_unix_ms)
      || !tcpTime(value.duration_ms) || !tcpOutcomes.has(value.outcome)) return null;
  } else if (!tcpTime(value.elapsed_ms)) return null;
  return value;
}
function resetTcpHistory(keepRefresh = false) {
  for (const controller of tcpFetches) controller.abort(); tcpFetches.clear();
  tcpActiveRequestVersion += 1; tcpRecentRequestVersion += 1;
  tcpActive = []; tcpRecent = []; tcpActiveBatch = null; tcpRecentBatch = null; tcpProcess = null;
  tcpActivePageAfter = null; tcpActivePage = 1; tcpFrozenActive = null; tcpFrozenRecent = null;
  tcpFrozenActiveBatch = null; tcpFrozenRecentBatch = null; tcpFrozenPage = 1;
  tcpPaused = false; $('#tcp-history-pause').setAttribute('aria-pressed', 'false');
  display('#tcp-history-pause', () => t('Pause TCP view'));
  $('#tcp-active-filter').value = ''; $('#tcp-recent-filter').value = '';
  tcpStreamVersion += 1;
  if (!keepRefresh) { tcpRefresh = null; tcpFirstPage = null; tcpNextPage = null; }
  $('#tcp-active-rows').replaceChildren(); $('#tcp-recent-rows').replaceChildren();
  display('#tcp-active-note', () => t('TCP active history cleared.'));
  display('#tcp-recent-note', () => t('TCP recent history cleared.'));
  $('#tcp-active-first').hidden = true; $('#tcp-active-next').hidden = true;
}
function tcpProcessMatches(process) {
  if (typeof process !== 'string' || !/^[0-9a-f]{16}$/.test(process)) return false;
  if (tcpProcess && tcpProcess !== process) resetTcpHistory(true);
  tcpProcess = process;
  return true;
}
function recordTcpActive(batch, pageAfter = null) {
  if (!batch || !tcpProcessMatches(batch.process_id) || !Array.isArray(batch.records)
    || batch.records.length > 128 || batch.best_effort !== true || !tcpTime(batch.server_time_unix_ms)
    || !decimalU64(batch.next_after) || !decimalU64(batch.latest_connection_id)) return;
  const rows = batch.records.map(value => tcpRecord(value, false));
  if (rows.some(value => !value)) return;
  tcpActive = rows;
  tcpActiveBatch = { ...batch, updatedAt: performance.now() };
  tcpActivePageAfter = pageAfter;
  if (pageAfter === null) tcpActivePage = 1;
  else tcpActivePage += 1;
  renderTcpHistory();
}
function recordTcpRecent(batch, replace) {
  if (!batch || !tcpProcessMatches(batch.process_id) || !Array.isArray(batch.records)
    || batch.records.length > 128 || !tcpTime(batch.server_time_unix_ms)
    || !decimalU64(batch.next_after) || !decimalU64(batch.latest_event_id)) return;
  const retention = Math.max(1, Math.min(3600, Number(batch.retention_seconds) || 60));
  const receivedAt = performance.now();
  const rows = batch.records.map(value => tcpRecord(value, true));
  if (rows.some(value => !value)) return;
  const merged = new Map((replace ? [] : tcpRecent).map(value => [value.event_id, value]));
  for (const row of rows) {
    const age = Math.max(0, batch.server_time_unix_ms - row.ended_at_unix_ms);
    const expiry = receivedAt + Math.max(0, retention * 1000 - age);
    const previous = merged.get(row.event_id);
    merged.set(row.event_id, { ...row, expiresAt: previous ? Math.min(previous.expiresAt, expiry) : expiry });
  }
  tcpRecent = [...merged.values()].sort((a, b) => BigInt(a.event_id) > BigInt(b.event_id) ? -1 : 1).slice(0, 256);
  tcpRecentBatch = { ...batch, retention, updatedAt: receivedAt };
  renderTcpHistory();
}
async function fetchTcpPage(path, token, onUnauthorized, active, onBatch, requestKind, manualPage = false) {
  const controller = new AbortController(); tcpFetches.add(controller);
  const generation = requestKind === 'active' ? ++tcpActiveRequestVersion : ++tcpRecentRequestVersion;
  const streamVersion = tcpStreamVersion;
  const requestedProcess = tcpProcess;
  try {
    const response = await fetch(path, { headers: { Authorization: `Bearer ${token}` }, cache: 'no-store', signal: controller.signal });
    if (!active() || controller.signal.aborted) return;
    if (response.status === 401 || response.status === 403) { resetTcpHistory(); onUnauthorized(); return; }
    const current = requestKind === 'active' ? tcpActiveRequestVersion : tcpRecentRequestVersion;
    if (generation !== current) return;
    if (response.status === 404) {
      display(requestKind === 'active' ? '#tcp-active-note' : '#tcp-recent-note', () => t('TCP history is unavailable on this server.'));
      return;
    }
    if (!response.ok) throw new Error('TCP history unavailable');
    const batch = await response.json();
    // Manual pages and the one-time catch-up may outlive an SSE incarnation
    // change. Never let their old process ID replace a newer live process.
    if (requestedProcess !== tcpProcess && (requestedProcess !== null || batch?.process_id !== tcpProcess)) return;
    if (active() && !controller.signal.aborted && generation === (requestKind === 'active' ? tcpActiveRequestVersion : tcpRecentRequestVersion)
      && (manualPage || streamVersion === tcpStreamVersion)) onBatch(batch);
  } catch (_) {
    if (active() && !controller.signal.aborted) display(requestKind === 'active' ? '#tcp-active-note' : '#tcp-recent-note', () => t('TCP history could not be refreshed. Displayed records may be stale.'));
  } finally { tcpFetches.delete(controller); }
}
function fetchTcpActive(token, onUnauthorized, active, after = null) {
  if (after !== null && !decimalU64(after)) return;
  const query = after === null ? '?limit=128' : `?after=${after}&limit=128`;
  return fetchTcpPage(`/v1/connections/tcp/active${query}`, token, onUnauthorized, active,
    batch => recordTcpActive(batch, after), 'active', after !== null);
}
function fetchTcpHistory(token, onUnauthorized, active) {
  return Promise.all([
    fetchTcpActive(token, onUnauthorized, active),
    fetchTcpPage('/v1/connections/tcp/recent?limit=128', token, onUnauthorized, active,
      batch => recordTcpRecent(batch, true), 'recent'),
  ]);
}
function tcpFieldFilter(row, query, kind) {
  const country = countryObservation(row).country;
  if (query.startsWith('country:')) return country?.toLowerCase() === query.slice(8).trim();
  if (query.startsWith('phase:')) return row.phase === query.slice(6).trim();
  if (query.startsWith('outcome:')) return kind === 'recent' && row.outcome === query.slice(8).trim();
  return [row.peer_ip, row.listen, row.route_id, row.member_id, row.phase, row.outcome, country, countryLabel(countryObservation(row))]
    .join(' ').toLowerCase().includes(query);
}
function tcpRow(record, recent) {
  const tr = document.createElement('tr'); tr.dataset.id = recent ? record.event_id : record.connection_id;
  const cell = value => { const td = document.createElement('td'); td.textContent = value; tr.append(td); return td; };
  cell(recent ? new Date(record.ended_at_unix_ms).toLocaleTimeString(getLocale() === 'ko' ? 'ko-KR' : 'en-US') : `#${record.connection_id}`);
  cell(t(recent ? tcpOutcomeLabels[record.outcome] : tcpPhaseLabels[record.phase]));
  const peer = cell(`${record.peer_ip.includes(':') ? `[${record.peer_ip}]` : record.peer_ip}:${record.peer_port}`);
  const country = document.createElement('small'); country.textContent = countryLabel(countryObservation(record)); peer.append(country);
  cell([record.route_id, record.member_id].filter(Boolean).join(' / ') || '—');
  cell(record.listen);
  const duration = recent ? record.duration_ms : record.elapsed_ms;
  const bytes = cell(t('{duration} ms · upstream {up} B · downstream {down} B', {
    duration: number(duration), up: tcpBytes(record.bytes_upstream), down: tcpBytes(record.bytes_downstream),
  }));
  bytes.title = t('Bytes delivered toward upstream/downstream; no wire overhead.');
  return tr;
}
function renderTcpHistory() {
  tcpRecent = tcpRecent.filter(row => performance.now() < row.expiresAt);
  if (tcpFrozenRecent) tcpFrozenRecent = tcpFrozenRecent.filter(row => performance.now() < row.expiresAt);
  const activeRows = tcpFrozenActive || tcpActive;
  const recentRows = tcpFrozenRecent || tcpRecent;
  const activeMeta = tcpFrozenActiveBatch || tcpActiveBatch;
  const recentMeta = tcpFrozenRecentBatch || tcpRecentBatch;
  const activeQuery = $('#tcp-active-filter').value.trim().toLowerCase();
  const recentQuery = $('#tcp-recent-filter').value.trim().toLowerCase();
  const shownActive = activeRows.filter(row => tcpFieldFilter(row, activeQuery, 'active'));
  const shownRecent = recentRows.filter(row => tcpFieldFilter(row, recentQuery, 'recent'));
  $('#tcp-active-rows').replaceChildren(...shownActive.map(row => tcpRow(row, false)));
  $('#tcp-recent-rows').replaceChildren(...shownRecent.map(row => tcpRow(row, true)));
  if (activeMeta) display('#tcp-active-note', () => t('Page {page} · showing {shown} of {tracked} tracked (capacity {capacity}) · {untracked} untracked at sample · {omitted} omitted total · best-effort{stale}', {
    page: number(tcpPaused ? tcpFrozenPage : tcpActivePage), shown: number(shownActive.length), tracked: safeCount(activeMeta.active_tracked),
    capacity: safeCount(activeMeta.capacity), untracked: safeCount(activeMeta.active_untracked), omitted: safeCount(activeMeta.omitted_total),
    stale: tcpPaused ? t(' · paused snapshot') : !isLive() || tcpActivePageAfter !== null ? t(' · snapshot may be stale') : '',
  }));
  if (recentMeta) display('#tcp-recent-note', () => t('Latest bounded view: {shown} recent · up to {seconds}s · {dropped} expired/evicted · {omitted} omitted{gap}{stale}', {
    shown: number(shownRecent.length), seconds: number(recentMeta.retention),
    dropped: safeCount(recentMeta.dropped_total), omitted: safeCount(recentMeta.omitted_total),
    gap: recentMeta.gap ? t(' · cursor gap') : '', stale: tcpPaused ? t(' · paused snapshot') : !isLive() ? t(' · stream delayed') : '',
  }));
  $('#tcp-active-first').hidden = tcpActivePageAfter === null;
  $('#tcp-active-next').hidden = !tcpActiveBatch || tcpActive.length < 128 ||
    (Number.isSafeInteger(tcpActiveBatch.active_tracked) && tcpActiveBatch.active_tracked <= tcpActivePage * 128);
  $('#tcp-active-first').disabled = tcpPaused; $('#tcp-active-next').disabled = tcpPaused;
}
function renderTrafficSummary() {
  if (!trafficSummary) return;
  display('#activity-retention', () => t('Up to {seconds}s', { seconds: retention }));
  display('#activity-note', () => {
    const ring = trafficSummary?.gap
      ? t('Buffer gap: some records were overwritten or expired before delivery. Showing available records.')
      : t('Latest 128 records in view · up to {seconds}s retention · {dropped} expired / evicted at server', { seconds: retention, dropped: number(dropped) });
    const coverage = trafficSummary.filteredTotal === null
      ? t('Recording-filter coverage is unknown on this server.')
      : trafficSummary.filteredTotal > 0
        ? t('{count} HTTP response records intentionally omitted by recording policy on this instance; this is partial history.', { count: number(trafficSummary.filteredTotal) })
        : t('No HTTP response records have been intentionally omitted by recording policy on this instance.');
    return `${ring} · ${coverage}`;
  });
  display('#activity-updated', () => t('Updated {time}', { time: new Date(trafficSummary?.updated || 0).toLocaleTimeString(getLocale() === 'ko' ? 'ko-KR' : 'en-US') }));
}
function renderActivityCount(count, total, filtered) {
  display('#activity-count', () => t(filtered ? 'Recent requests: {count} of {total}' : 'Recent requests: {count}', { count: number(count), total: number(total) }));
}

// Older servers omit geoip. Treat that as unobserved, never as a country miss.
// Bound and validate every value before it reaches a label or search text.
function countryObservation(record) {
  const value = record.geoip;
  const absent = { state: 'not_checked', country: null, digest: null, error: null };
  if (!value || typeof value !== 'object') return absent;
  const { state, country, generation_sha256: digest, error_code: error } = value;
  if (state === 'not_checked' || state === 'not_configured') {
    return country == null && digest == null && error == null
      ? { state, country: null, digest: null, error: null } : absent;
  }
  if (state === 'known' || state === 'unknown') {
    if (!/^[0-9a-f]{64}$/.test(digest || '') || error != null) return absent;
    if (state === 'known' && /^[A-Z]{2}$/.test(country || '')) return { state, country, digest, error: null };
    if (state === 'unknown' && country == null) return { state, country: null, digest, error: null };
    return absent;
  }
  if (state === 'unavailable' && country == null && (digest == null || /^[0-9a-f]{64}$/.test(digest)) && /^[a-z_]{1,40}$/.test(error || '')) {
    return { state, country: null, digest, error };
  }
  return absent;
}

function countryLabel(observation) {
  switch (observation.state) {
    case 'known': return t('Country estimate: {country}', { country: observation.country });
    case 'unknown': return t('Country estimate: unknown');
    case 'unavailable': return t('GeoIP unavailable ({code})', { code: observation.error });
    case 'not_configured': return t('GeoIP not configured');
    default: return t('GeoIP not checked');
  }
}

function renderCountry(cell, record) {
  const observation = countryObservation(record);
  let detail = cell.querySelector('.geoip-observation');
  if (!detail) { detail = document.createElement('span'); detail.className = 'geoip-observation'; cell.append(detail); }
  detail.textContent = countryLabel(observation);
  detail.title = observation.digest ? t('Database generation SHA-256: {digest}', { digest: observation.digest }) : '';
}

function renderRecordingRevision(cell, record) {
  cell.textContent = record.route_id || t('Unmatched');
  const detail = document.createElement('small');
  detail.textContent = record.policy_revision === null
    ? t('Recording policy revision unreported')
    : t('Recording policy at configuration revision #{revision}', { revision: record.policy_revision });
  cell.append(detail);
  const listener = document.createElement('small'); listener.className = 'traffic-listener';
  listener.textContent = trafficListenerLabel(record.listener); cell.append(listener);
}

function renderActivity() {
  records = records.filter(record => performance.now() < record.expiresAt);
  if (paused) {
    // Never keep expired sensitive metadata visible simply because the view is paused.
    const valid = new Map(records.map(record => [String(record.id), record]));
    for (const row of $('#activity-rows').children) {
      if (!valid.has(row.dataset.id)) { row.remove(); continue; }
      const record = valid.get(row.dataset.id);
      row.cells[0].textContent = new Date(record.timestamp_unix_ms).toLocaleTimeString(getLocale() === 'ko' ? 'ko-KR' : 'en-US');
      row.cells[1].querySelector('small').textContent = t('peer {address}', { address: `${record.peer_ip}:${record.peer_port}` });
      renderCountry(row.cells[1], record);
      renderRecordingRevision(row.cells[3], record);
      row.cells[2].title = trafficRequestDetail(record);
      row.cells[5].textContent = `${number(record.response_head_ms)} ms`;
    }
    const visible = $('#activity-rows').children.length;
    $('#activity-empty').hidden = visible > 0;
    renderActivityCount(visible, visible, false);
    return;
  }
  const query = $('#activity-search').value.trim().toLowerCase();
  const filtered = records.filter(record => {
    const geo = countryObservation(record);
    if (query.startsWith('country:')) return geo.country?.toLowerCase() === query.slice(8).trim();
    if (query.startsWith('state:')) return geo.state === query.slice(6).trim();
    return [record.client_ip,record.peer_ip,record.method,record.path,record.route_id,record.status,
      record.listener.kind,record.listener.id,record.listener.id && `listener:${record.listener.id}`,trafficListenerLabel(record.listener),
      geo.country,geo.state,countryLabel(geo)]
      .join(' ').toLowerCase().includes(query);
  });
  $('#activity-rows').replaceChildren(...filtered.map(record => {
    const tr = document.createElement('tr'); tr.dataset.id = String(record.id);
    const cell = (text) => { const td = document.createElement('td'); td.textContent = text; tr.append(td); return td; };
    cell(new Date(record.timestamp_unix_ms).toLocaleTimeString(getLocale() === 'ko' ? 'ko-KR' : 'en-US'));
    const ip = cell(record.client_ip || record.peer_ip || '—');
    const peer = document.createElement('small'); peer.textContent = t("peer {address}", { address: `${record.peer_ip}:${record.peer_port}` }); ip.append(peer);
    renderCountry(ip, record);
    const request = cell(''); const method = document.createElement('span'); method.className = 'http-method'; method.textContent = record.method; request.append(method, document.createTextNode(record.path || '/')); request.title = trafficRequestDetail(record);
    renderRecordingRevision(cell(''), record);
    const status = cell(''); const badge = document.createElement('span'); badge.className = `status-code${record.status >= 500 ? ' is-error' : record.status >= 400 ? ' is-warning' : ''}`; badge.textContent = String(record.status); status.append(badge);
    cell(`${number(record.response_head_ms)} ms`);
    return tr;
  }));
  renderActivityCount(filtered.length, records.length, Boolean(query));
  $('#activity-empty').hidden = filtered.length > 0;
  display('#activity-empty', () => query ? t("No recent requests match this filter.") : t("No recent requests in the available window. New response headers appear here live."));
}
export function renderSecurity(config) {
  const routes = config.http || [];
  const authenticated = routes.filter(route => route.auth || route.basic_auth).length;
  const modes = { protected: 0, public: 0, application: 0, legacy: 0 };
  for (const route of routes) modes[Object.hasOwn(modes, route.access_mode) ? route.access_mode : 'legacy'] += 1;
  const tls = routes.filter(route => route.require_tls).length;
  const bypass = [...routes, ...(config.tcp || [])].filter(route => route.upstream?.tls?.insecure_skip_verify || route.upstream?.tls?.insecure).length;
  securitySummary = { count: routes.length, authenticated, modes, tls, bypass, trusted: (config.settings?.trusted_proxy_cidrs || []).length, explicit: Boolean(config.settings?.trusted_proxy_cidrs) };
  renderSecuritySummary();
}
function renderSecuritySummary() {
  if (!securitySummary) return;
  const { count, authenticated, modes, tls, bypass, trusted, explicit } = securitySummary;
  const root = $('#security-content'); root.replaceChildren();
  const grid = document.createElement('div'); grid.className = 'metric-grid';
  for (const [label,value,note] of [[t("Gateway authentication"), authenticated,t("of {count} HTTP routes", { count: count })], [t("TLS required"),tls,t("of {count} HTTP routes", { count: count })], [t("Verification bypass"),bypass,t("Explicit upstream TLS bypasses")], [t("Trusted proxy networks"),trusted,t("Explicit document settings")]]) {
    const card = document.createElement('article'); card.className = 'metric';
    for (const [tag,klass,text] of [['span','metric-label',label],['strong','metric-value',String(value)],['span','metric-note',note]]) { const el = document.createElement(tag); el.className = klass; el.textContent = text; card.append(el); }
    grid.append(card);
  }
  const checks = document.createElement('div'); checks.className = 'panel security-checks';
  const definitions = [
    [t("Declared route access"),t("{protected} protected · {public} public · {application} application-owned · {legacy} legacy. Legacy preserves existing controls without declaring a protected policy.", modes)],
    [t("Identity-aware access"),t("{authenticated} routes configure Basic Auth or an external authorization service. {open} routes do not configure gateway authentication. These are inferred control counts, not proof of identity or device posture.", { authenticated, open: count - authenticated })],
    [t("Transport verification"),bypass ? t("{count} route policies explicitly bypass upstream certificate verification. Review whether a private CA can replace the bypass.", { count: bypass }) : t("No explicit certificate-verification bypass was found in route policy. This is a configuration inventory, not a live upstream TLS audit.")],
    [t("Trusted proxy boundary"),explicit ? t("Trusted proxy networks are set in the shared document. Only list peers authorized to assert forwarded identity.") : t("Trusted proxy settings inherit process defaults. Review Runtime & configuration for the active values.")],
    [t("Console access"),t("Administrator and viewer roles are enforced server-side. Console sessions are instance-local and revocable. Use the Users page to review access.")],
  ];
  for (const [title,detail] of definitions) { const row = document.createElement('div'); row.className = 'security-check'; const icon = document.createElement('span'); icon.textContent = '◇'; const body = document.createElement('div'); const heading = document.createElement('h2'); heading.textContent = title; const text = document.createElement('p'); text.textContent = detail; body.append(heading,text); row.append(icon,body); checks.append(row); }
  root.append(grid,checks);
}

function renderCommands() {
  const query = $('#command-search').value.toLowerCase().trim();
  const links = [...document.querySelectorAll('.nav-link')].filter(link => !link.hidden && `${link.textContent} ${link.querySelector('[data-i18n]')?.dataset.i18n || ''}`.toLowerCase().includes(query));
  commandSelection = Math.max(0, Math.min(commandSelection, links.length - 1));
  $('#command-results').replaceChildren(...links.map((link,index) => {
    const button = document.createElement('button'); button.type = 'button'; button.className = `command-result${index === commandSelection ? ' is-selected' : ''}`;
    const name = document.createElement('span'); name.textContent = (link.querySelector('bdi')?.textContent || link.textContent).trim(); const hint = document.createElement('small'); hint.textContent = t("Go to page"); button.append(name,hint);
    button.addEventListener('click',() => { $('#command-dialog').close(); location.hash = link.hash; }); return button;
  }));
  if (!links.length) { const empty = document.createElement('p'); empty.className = 'command-empty'; empty.textContent = t("No matching pages"); $('#command-results').append(empty); }
}
function openCommands() {
  if ($('#login-dialog').open || [...document.querySelectorAll('dialog[open]')].length) return;
  commandOpener = document.activeElement; commandSelection = 0; $('#command-search').value = ''; renderCommands(); $('#command-dialog').showModal(); $('#command-search').focus();
}
const themeButton = $('#theme-toggle');
function applyTheme(theme) { document.documentElement.dataset.theme = theme; themeButton.setAttribute('aria-label',t(theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme')); }
try { const saved = localStorage.getItem('hangang-theme'); if (saved === 'dark' || saved === 'light') applyTheme(saved); } catch (_) { /* storage may be disabled */ }
themeButton.addEventListener('click',() => { const theme = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'; applyTheme(theme); try { localStorage.setItem('hangang-theme',theme); } catch (_) {} });
display('#workspace-host', () => location.host); display('#sidebar-endpoint', () => location.host);
$('#command-open').addEventListener('click',openCommands);
$('#command-close').addEventListener('click',() => $('#command-dialog').close());
$('#command-dialog').addEventListener('close',() => { if (commandOpener?.isConnected) commandOpener.focus(); });
$('#command-search').addEventListener('input',() => { commandSelection = 0; renderCommands(); });
$('#command-search').addEventListener('keydown',(event) => {
  if (event.key === 'ArrowDown' || event.key === 'ArrowUp') { event.preventDefault(); commandSelection += event.key === 'ArrowDown' ? 1 : -1; renderCommands(); $('.command-result.is-selected')?.scrollIntoView({block:'nearest'}); }
  if (event.key === 'Enter') { event.preventDefault(); $('.command-result.is-selected')?.click(); }
});
document.addEventListener('keydown',(event) => { if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); openCommands(); } });
$('#activity-search').addEventListener('input',renderActivity);
$('#activity-pause').addEventListener('click',() => { paused = !paused; display('#activity-pause', () => paused ? t("Resume view") : t("Pause view")); $('#activity-pause').setAttribute('aria-pressed',String(paused)); renderActivity(); });
$('#tcp-active-filter').addEventListener('input', renderTcpHistory);
$('#tcp-recent-filter').addEventListener('input', renderTcpHistory);
$('#tcp-history-refresh').addEventListener('click', () => tcpRefresh?.());
$('#tcp-active-first').addEventListener('click', () => tcpFirstPage?.());
$('#tcp-active-next').addEventListener('click', () => tcpNextPage?.());
$('#tcp-history-pause').addEventListener('click', () => {
  tcpPaused = !tcpPaused;
  tcpFrozenActive = tcpPaused ? tcpActive.slice() : null;
  tcpFrozenRecent = tcpPaused ? tcpRecent.slice() : null;
  tcpFrozenActiveBatch = tcpPaused ? tcpActiveBatch : null;
  tcpFrozenRecentBatch = tcpPaused ? tcpRecentBatch : null;
  tcpFrozenPage = tcpActivePage;
  display('#tcp-history-pause', () => t(tcpPaused ? 'Resume TCP view' : 'Pause TCP view'));
  $('#tcp-history-pause').setAttribute('aria-pressed', String(tcpPaused));
  renderTcpHistory();
});

window.addEventListener('hangang:localechange', () => {
  for (const [selector, value] of localizedDisplays) { const el = $(selector); if (el) el.textContent = value(); }
  renderChart();
  if (expiryTimer) renderActivity();
  renderSecuritySummary();
  if (metricsSummary) { renderPrometheus(metricsSummary.metrics, metricsSummary.rates); renderGeoMetrics(metricsSummary.geoip); }
  renderTcpHistory();
  applyTheme(document.documentElement.dataset.theme || 'light');
  if ($('#command-dialog').open) renderCommands();
});
