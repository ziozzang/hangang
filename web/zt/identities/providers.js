// Identities ▸ Providers: Hopae `status` providers as cards with health,
// kind, management source, reauthentication capability and redirect URI.
import { can, hopae, failure, sectionPage, notConnected, capabilities, facts } from './common.js';

const KINDS = Object.freeze(['oidc', 'oauth2', 'email_link', 'password', 'ldap']);
const HEALTH = Object.freeze({ ok: ['healthy', 'identities.provider.health.ok'], degraded: ['stale', 'identities.provider.health.degraded'], disabled: ['disabled', 'identities.provider.health.disabled'] });
const REAUTH = Object.freeze(['max_age', 'unsupported']);

/** Portal origin when Hopae reports it (not yet in `status`); else null. */
function portalOrigin(data) {
  const value = data?.portal?.public_url || data?.config?.portal_public_url || null;
  return typeof value === 'string' && /^https?:\/\/[^/]+$/.test(value) ? value : null;
}

export async function renderProviders(cx, root) {
  const { t, ui } = cx;
  const caps = await capabilities(cx);
  if (cx.signal.aborted) return;
  const { content } = sectionPage(cx, root, { active: 'providers', title: t('identities.page.providers'), owner: t('identities.providers.owner') });
  if (!caps.installed || !can(caps, 'status')) { content.append(notConnected(cx, caps, 'status')); return; }
  const body = ui.el('div', {}, ui.loadingState(t));
  content.append(body);
  async function load() {
    let data;
    try { ({ data } = await hopae(cx, 'status')); }
    catch (error) { ui.clear(body, failure(cx, error, load)); return; }
    if (cx.signal.aborted) return;
    const providers = Array.isArray(data?.providers) ? data.providers : [];
    if (!providers.length) { ui.clear(body, ui.emptyState(t, { title: 'identities.providers.empty', body: 'identities.providers.empty.body' })); return; }
    const origin = portalOrigin(data);
    const healthy = providers.filter(provider => provider.health === 'ok').length;
    const portal = data?.portal || null;
    const summary = ui.el('div', { class: 'zt-provider-summary' }, ui.el('p', { class: 'zt-summary', text: t('identities.providers.summary', { count: providers.length, healthy }) }),
      portal ? ui.el('p', { class: 'zt-summary' }, ui.el('span', { text: t('identities.providers.portal') }), ' ', ui.el('code', { class: 'kit-mono', text: portal.public_url || '—' }), ' · ',
        ui.statusBadge(t, portal.passkeys ? 'healthy' : 'disabled', portal.passkeys ? (portal.passwordless ? 'identities.providers.passkeys.passwordless' : 'identities.providers.passkeys.on') : 'identities.providers.passkeys.off')) : null);
    const grid = ui.el('div', { class: 'zt-provider-grid' });
    for (const provider of providers) {
      const [kind, label] = HEALTH[provider.health] || ['unknown', 'identities.provider.health.unknown'];
      const redirect = `${origin || ''}/callback/${provider.provider_id}`;
      const redirectRow = ui.el('span', { class: 'zt-redirect' }, ui.el('code', { class: 'kit-mono', text: origin ? redirect : t('identities.provider.redirect.relative', { path: redirect }) }), ui.copyButton(t, redirect),
        origin ? null : ui.el('span', { class: 'kit-action-off', tabIndex: 0, attrs: { 'aria-label': t('identities.gap.portal_url') } }, ui.el('span', { class: 'kit-info', text: 'ⓘ', attrs: { 'aria-hidden': 'true' } }), ui.el('span', { class: 'kit-tip', text: t('identities.gap.portal_url'), attrs: { role: 'tooltip' } })));
      const secret = provider.client_secret_env === null || provider.client_secret_env === undefined ? null
        : ui.statusBadge(t, provider.secret_present ? 'healthy' : 'error', provider.secret_present ? 'identities.provider.secret.present' : 'identities.provider.secret.missing');
      const card = ui.el('article', { class: `zt-card zt-provider zt-provider-${kind}`, attrs: { 'aria-label': provider.display_name || provider.provider_id } },
        ui.el('div', { class: 'zt-card-head' }, ui.el('div', { class: 'zt-stack' }, ui.el('strong', { text: provider.display_name || provider.provider_id }), ui.el('span', { class: 'kit-entity-id', text: provider.provider_id })), ui.statusBadge(t, kind, label)),
        provider.health === 'degraded' && provider.reason ? ui.el('p', { class: 'zt-provider-error', attrs: { role: 'note' } }, ui.el('strong', { text: t('identities.provider.last_error') }), ' ', ui.el('span', { class: 'kit-mono', text: String(provider.reason) })) : null,
        facts(cx, [
          ['identities.provider.kind', t(KINDS.includes(provider.kind) ? `identities.provider.kind.${provider.kind}` : 'identities.provider.kind.other')],
          ['identities.provider.enabled', t(provider.enabled ? 'identities.yes' : 'identities.no')],
          ['identities.provider.managed_by', t(provider.managed_by === 'api' ? 'identities.provider.managed.api' : 'identities.provider.managed.file')],
          ['identities.provider.reauth', t(REAUTH.includes(provider.reauth) ? `identities.provider.reauth.${provider.reauth}` : 'identities.provider.reauth.other')],
          ['identities.provider.secret', secret],
          ['identities.provider.redirect', provider.kind === 'ldap' ? null : redirectRow],
        ]),
        ui.el('div', { class: 'button-row' }, ui.el('a', { class: 'button button-quiet', href: cx.hashFor('identities', ['groups'], new URLSearchParams({ source: provider.kind === 'ldap' ? 'ldap' : 'oidc' })), text: t('identities.provider.groups') })));
      grid.append(card);
    }
    ui.clear(body, summary, grid);
  }
  await load();
}
