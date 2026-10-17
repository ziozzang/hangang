// Devices & Workloads section router (ADR 0020 §6). Routes:
//   #workloads[/workloads][?q=&namespace=&status=]   workload principals
//   #workloads/w/{principal}                       workload detail
//   #workloads/routes[?state=]                     Kubernetes protected routes
//   #workloads/devices                             device posture (not configured)
import { renderWorkloads, renderWorkload } from './workloads.js';
import { renderRoutes } from './routes.js';
import { sectionPage } from './common.js';

function renderDevices(cx, root) {
  const { t, ui } = cx;
  const { content } = sectionPage(cx, root, { active: 'devices', title: t('workloads.page.devices'), owner: t('workloads.devices.owner') });
  content.append(ui.emptyState(t, { title: 'workloads.devices.title', body: 'workloads.devices.body' }),
    ui.el('section', { class: 'panel zt-panel', attrs: { 'aria-label': t('workloads.devices.what') } }, ui.el('div', { class: 'zt-panel-head' }, ui.el('h2', { text: t('workloads.devices.what') })),
      ui.el('ul', { class: 'zt-device-list' }, ['inventory', 'posture', 'binding'].map(key => ui.el('li', { text: t(`workloads.devices.item.${key}`) }))),
      ui.el('p', { class: 'kit-help', text: t('workloads.devices.meanwhile') }),
      ui.el('p', { class: 'button-row' }, ui.el('a', { class: 'button button-quiet', href: '#workloads/workloads', text: t('workloads.page.workloads') }), ui.el('a', { class: 'button button-quiet', href: '#tcp', text: t('section.link.tcp_routes') }))));
}

export async function renderWorkloadsSection(cx, root, route) {
  const [page, id] = route.parts;
  if (page === 'w' && id) return renderWorkload(cx, root, id);
  if (page === 'routes') return renderRoutes(cx, root, route.params);
  if (page === 'devices') return renderDevices(cx, root);
  return renderWorkloads(cx, root, route.params);
}
