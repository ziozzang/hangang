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
  $('#prometheus-rows').replaceChildren(); $('#security-content').replaceChildren();
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
    if (connected && !isLive()) { connected = false; setStream(() => t("Stream delayed · reconnecting"), true); streamAbort?.abort(); }
  }, 1000);
  if (admin) {
    fetch('/v1/traffic?limit=128', { headers: { Authorization: `Bearer ${token}` }, cache: 'no-store' })
      .then(async (response) => {
        if (response.status === 401 && active()) return onUnauthorized();
        if (!response.ok) return;
        const body = await response.json(); if (active()) recordTraffic(body);
      }).catch(() => {});
  }
  const connect = async () => {
    if (!active()) return;
    const controller = new AbortController(); streamAbort = controller;
    connected = false; previous = null;
    setStream(() => failures ? t("Reconnecting · polling fallback") : t("Connecting live stream"), Boolean(failures));
    let reader;
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
          } else if (event === 'traffic' && admin) recordTraffic(data);
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
  metricsSummary = { metrics, rates };
  renderChart(); renderPrometheus(metrics, rates);
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
function recordTraffic(batch) {
  if (!Array.isArray(batch?.records)) return;
  retention = Math.max(1, Math.min(3600, Number(batch.retention_seconds) || 60));
  dropped = Number(batch.dropped_total) || 0;
  const merged = new Map(records.map(record => [record.id, record]));
  const receivedAt = performance.now();
  const serverNow = Number(batch.server_time_unix_ms);
  for (const record of batch.records.slice(0, 128)) {
    const age = Number.isFinite(serverNow) ? Math.max(0, serverNow - Number(record.timestamp_unix_ms)) : 0;
    const expiresAt = receivedAt + Math.max(0, retention * 1000 - age);
    const old = merged.get(record.id);
    merged.set(record.id, { ...record, expiresAt: old ? Math.min(old.expiresAt, expiresAt) : expiresAt });
  }
  records = [...merged.values()].sort((a,b) => b.id - a.id).slice(0, 128);
  trafficSummary = { gap: Boolean(batch.gap), updated: Date.now() };
  renderTrafficSummary();
  renderActivity();
}
function renderTrafficSummary() {
  if (!trafficSummary) return;
  display('#activity-retention', () => t('Up to {seconds}s', { seconds: retention }));
  display('#activity-note', () => trafficSummary?.gap
    ? t('Buffer gap: some records were overwritten or expired before delivery. Showing available records.')
    : t('Latest 128 records in view · up to {seconds}s retention · {dropped} expired / evicted at server', { seconds: retention, dropped: number(dropped) }));
  display('#activity-updated', () => t('Updated {time}', { time: new Date(trafficSummary?.updated || 0).toLocaleTimeString(getLocale() === 'ko' ? 'ko-KR' : 'en-US') }));
}
function renderActivityCount(count, total, filtered) {
  display('#activity-count', () => t(filtered ? 'Recent requests: {count} of {total}' : 'Recent requests: {count}', { count: number(count), total: number(total) }));
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
      if (!record.route_id) row.cells[3].textContent = t('Unmatched');
      row.cells[5].textContent = `${number(record.response_head_ms)} ms`;
    }
    const visible = $('#activity-rows').children.length;
    $('#activity-empty').hidden = visible > 0;
    renderActivityCount(visible, visible, false);
    return;
  }
  const query = $('#activity-search').value.trim().toLowerCase();
  const filtered = records.filter(record => [record.client_ip,record.peer_ip,record.method,record.path,record.route_id,record.status].join(' ').toLowerCase().includes(query));
  $('#activity-rows').replaceChildren(...filtered.map(record => {
    const tr = document.createElement('tr'); tr.dataset.id = String(record.id);
    const cell = (text) => { const td = document.createElement('td'); td.textContent = text; tr.append(td); return td; };
    cell(new Date(record.timestamp_unix_ms).toLocaleTimeString(getLocale() === 'ko' ? 'ko-KR' : 'en-US'));
    const ip = cell(record.client_ip || record.peer_ip || '—');
    const peer = document.createElement('small'); peer.textContent = t("peer {address}", { address: `${record.peer_ip}:${record.peer_port}` }); ip.append(peer);
    const request = cell(''); const method = document.createElement('span'); method.className = 'http-method'; method.textContent = record.method; request.append(method, document.createTextNode(record.path || '/')); request.title = `${record.protocol}${record.tls ? ' · TLS' : ''}`;
    cell(record.route_id || t("Unmatched"));
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

window.addEventListener('hangang:localechange', () => {
  for (const [selector, value] of localizedDisplays) { const el = $(selector); if (el) el.textContent = value(); }
  renderChart();
  if (expiryTimer) renderActivity();
  renderSecuritySummary();
  if (metricsSummary) renderPrometheus(metricsSummary.metrics, metricsSummary.rates);
  applyTheme(document.documentElement.dataset.theme || 'light');
  if ($('#command-dialog').open) renderCommands();
});
