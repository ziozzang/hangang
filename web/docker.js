import { t } from './i18n.js';

const $ = selector => document.querySelector(selector);
let apiCall = null;
let unauthorized = null;
let generation = 0;
let revision = null;
let snapshot = null;
let dirty = false;
let busy = false;
let initialized = false;
const copy = new Map();
function label(element, source, params = {}) {
  copy.set(element, { source, params }); element.textContent = t(source, params); return element;
}
function element(tag, className, text) {
  const node = document.createElement(tag); if (className) node.className = className;
  if (text) label(node, text); return node;
}
function field(form, name, title, placeholder = '') {
  const wrapper = element('div', 'field');
  const caption = label(document.createElement('label'), title);caption.htmlFor = `docker-connection-${name}`;
  const input = document.createElement('input');input.id = `docker-connection-${name}`;input.name = name;input.type = 'text';input.autocomplete = 'off';input.spellcheck = false;input.placeholder = placeholder;
  wrapper.append(caption,input);form.append(wrapper);return wrapper;
}
function button(id, title, action, className = 'button button-secondary') {
  const node = element('button', className, title);node.id = id;node.type = 'button';node.addEventListener('click', action);return node;
}
function message(source = '', params = {}, error = false) {
  label($('#docker-connection-message'), source, params);
  $('#docker-connection-message').className = `inline-message${error ? ' is-error' : ''}`;
}
function refreshMode() {
  const mode = $('#docker-connection-transport').value;
  $('#docker-unix-fields').hidden = mode !== 'unix';$('#docker-https-fields').hidden = mode !== 'https';
}
function renderSummary() {
  if (!snapshot) return;
  label($('#docker-connection-state'), snapshot.enabled ? 'Docker connection configured' : 'Docker connection disabled');
  label($('#docker-connection-source'), 'Source: {source} · revision {revision}', { source: t(snapshot.source === 'managed' ? 'Saved connection' : snapshot.source === 'cli' ? 'Process option' : 'Disabled'), revision: snapshot.revision });
  $('#docker-connection-state').classList.toggle('is-enabled', Boolean(snapshot.enabled));
}
function setBusy(value) {
  busy = value;
  for (const control of $('#docker-panel').querySelectorAll('button,input,select')) control.disabled = value;
  $('#docker-connection-save').disabled = value || revision === null;
  $('#docker-connection-reset').disabled = value || revision === null;
}
function connection() {
  const transport = $('#docker-connection-transport').value;
  const value = name => $(`#docker-connection-${name}`).value.trim();
  if (transport === 'disabled') return { transport };
  if (transport === 'unix') {
    if (!value('socket_path').startsWith('/')) throw new Error(t('Enter an absolute socket path visible to the gateway.'));
    return { transport, socket_path: value('socket_path') };
  }
  let url;try { url = new URL(value('url')); } catch (_) { throw new Error(t('Enter a valid HTTPS Docker endpoint.')); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || (url.pathname !== '/' && url.pathname !== '')) throw new Error(t('Use an HTTPS origin without credentials, a path, or a query.'));
  const config = { transport, url: url.origin };
  for (const name of ['ca_file','client_cert_file','client_key_file']) {
    if (!value(name).startsWith('/')) throw new Error(t('Certificate and key references must be absolute server file paths.'));
    config[name] = value(name);
  }
  return config;
}
function populate(data) {
  snapshot = data;revision = data.revision;
  $('#docker-inspect-result').textContent = '';
  const config = data.config || { transport: 'disabled' };
  $('#docker-connection-transport').value = config.transport || 'disabled';
  for (const name of ['socket_path','url','ca_file','client_cert_file','client_key_file']) $(`#docker-connection-${name}`).value = config[name] || '';
  dirty = false;refreshMode();renderSummary();
}
function handleError(error) {
  if (error.status === 401 || error.status === 403) {
    const expired = unauthorized;resetDockerPanel();expired?.();return;
  }
  if (error.status === 409 || error.status === 412) message('Connection changed elsewhere. Reload before saving; your draft is preserved.', {}, true);
  else message(error.message || 'Docker request failed.', {}, true);
}
async function perform(task) {
  if (!apiCall || busy) return;
  const current = generation;setBusy(true);message();
  try { await task(current); } catch (error) { if (current === generation) handleError(error); }
  finally { if (current === generation) setBusy(false); }
}
async function load(force = false) {
  if (dirty && !force) { message('Unsaved connection changes are preserved. Save them or reload explicitly.');return; }
  return perform(async current => {
    const { data } = await apiCall('/v1/docker/connection');if (current !== generation) return;
    populate(data);message('Connection settings loaded. Use Test connection to check reachability.');
  });
}
async function save() {
  return perform(async current => {
    const config = connection();
    const { data } = await apiCall('/v1/docker/connection', { method: 'PUT', headers: { 'If-Match': `"${revision}"` }, json: config });
    if (current !== generation) return;populate(data);message('Connection saved. New Docker lookups use this configuration.');
  });
}
async function testConnection() {
  return perform(async current => {
    const config = connection();if (config.transport === 'disabled') throw new Error(t('Choose Unix socket or HTTPS before testing.'));
    await apiCall('/v1/docker/connection/test', { method: 'POST', json: config });
    if (current === generation) message('Docker responded to the connection test. The draft has not been saved.');
  });
}
async function reset() {
  return perform(async current => {
    const { data } = await apiCall('/v1/docker/connection', { method: 'DELETE', headers: { 'If-Match': `"${revision}"` } });
    if (current !== generation) return;populate(data);message('Saved override removed. The process connection default is active.');
  });
}
async function resolve() {
  return perform(async current => {
    const container = $('#docker-inspect-container').value.trim();const network = $('#docker-inspect-network').value.trim();const port = Number($('#docker-inspect-port').value);
    if (!container || !network || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error(t('Enter a container, network and port from 1 to 65535.'));
    const { data } = await apiCall('/v1/docker/resolve', { method: 'POST', json: { container, network, port } });
    if (current !== generation) return;
    $('#docker-inspect-result').textContent = `HTTP: ${data.http_backend}\nTCP: ${data.tcp_backend}\ndocker://${container}/${network}/${port}`;
    message('Address resolved through the saved connection. Backend reachability is not tested.');
  });
}
function initialize() {
  if (initialized) return;
  initialized = true;const root = $('#docker-panel');
  const head = element('div', 'page-header');const intro = element('div');intro.append(element('h1', '', 'Docker connections'),element('p', '', 'Connect a Docker engine, test access and resolve container backends.'));head.append(intro);intro.querySelector('h1').id = 'docker-panel-title';
  const status = element('div', 'panel docker-connection-status');const badge = element('strong');badge.id = 'docker-connection-state';const source = element('p');source.id = 'docker-connection-source';status.append(badge,source);
  const form = element('form', 'panel docker-connection-form');form.id = 'docker-connection-form';form.addEventListener('submit', event => { event.preventDefault();save(); });
  form.append(element('h2', '', 'Connection settings'),element('p', '', 'Paths refer to files or sockets inside this gateway. Remote Docker uses verified HTTPS and client certificates.'));
  const modeWrap = element('div','field');const modeLabel = label(document.createElement('label'),'Connection type');modeLabel.htmlFor='docker-connection-transport';
  const mode = document.createElement('select');mode.id='docker-connection-transport';
  for (const [value,title] of [['disabled','Disabled'],['unix','Local Unix socket'],['https','Remote HTTPS with mTLS']]) { const option = label(document.createElement('option'),title);option.value=value;mode.append(option); }
  modeWrap.append(modeLabel,mode);form.append(modeWrap);
  const unix = element('div','docker-connection-fields');unix.id='docker-unix-fields';field(unix,'socket_path','Socket path','/run/hangang/docker/docker.sock');form.append(unix);
  const https = element('div','docker-connection-fields');https.id='docker-https-fields';
  field(https,'url','Docker HTTPS endpoint','https://docker.example.com:2376');field(https,'ca_file','Server CA file','/data/docker-tls/ca.pem');field(https,'client_cert_file','Client certificate file','/data/docker-tls/cert.pem');field(https,'client_key_file','Client private key file','/data/docker-tls/key.pem');form.append(https);
  form.addEventListener('input', () => { dirty=true; });mode.addEventListener('change', () => { dirty=true;refreshMode(); });
  const actions = element('div','docker-connection-actions');actions.append(button('docker-connection-test','Test connection',testConnection),button('docker-connection-save','Save connection',save,'button button-primary'),button('docker-connection-reload','Reload saved settings',()=>load(true)),button('docker-connection-reset','Use process default',reset));form.append(actions);
  form.append(element('p','','To disable Docker even when a process default exists, choose Disabled and save. Use process default removes the saved override.'));
  const feedback = element('p','inline-message');feedback.id='docker-connection-message';feedback.setAttribute('role','status');
  const inspect = element('form','panel docker-inspect-form');inspect.addEventListener('submit',event=>{event.preventDefault();resolve();});inspect.append(element('h2','','Resolve a container backend'),element('p','','Uses the saved connection. The gateway must be able to reach the returned container address.'));
  for (const [name,title,hint] of [['container','Container name or ID','api'],['network','Docker network','edge'],['port','Container port','8080']]) {
    const wrap=element('div','field');const caption=label(document.createElement('label'),title);caption.htmlFor=`docker-inspect-${name}`;const input=document.createElement('input');input.id=`docker-inspect-${name}`;input.placeholder=hint;input.autocomplete='off';if(name==='port'){input.type='number';input.min='1';input.max='65535';}wrap.append(caption,input);inspect.append(wrap);
  }
  inspect.append(button('docker-inspect-submit','Resolve backend',resolve));const result=element('pre','docker-inspect-result');result.id='docker-inspect-result';inspect.append(result);
  root.append(head,status,form,feedback,inspect);refreshMode();setBusy(false);
}
export async function loadDockerPanel(api, onUnauthorized) { initialize();apiCall=api;unauthorized=onUnauthorized;await load(); }
export function refreshDockerCopy() { for (const [node,{source,params}] of copy) if (node.isConnected) node.textContent=t(source,params);renderSummary(); }
export function resetDockerPanel() {
  generation++;apiCall=null;unauthorized=null;revision=null;snapshot=null;dirty=false;busy=false;
  if (!initialized) return;
  for (const input of $('#docker-panel').querySelectorAll('input')) input.value='';
  $('#docker-connection-transport').value='disabled';$('#docker-inspect-result').textContent='';
  label($('#docker-connection-state'),'');label($('#docker-connection-source'),'');message();refreshMode();setBusy(false);
}
