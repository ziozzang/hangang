#!/usr/bin/env node
// Key-based i18n lint for the console kit and Zero Trust sections (ADR 0020):
//  1. EN and KO catalogs have identical key sets and non-empty messages.
//  2. Every message key literal used by the code exists.
//  3. Every dynamic key family the code builds is complete.
//  4. Every registered decision reason code has a message and a remediation.
//  5. No string literal is rendered directly through textContent, innerHTML,
//     title, placeholder, aria-* or the kit's `text:` property.
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const failures = [];
const repo = path.resolve(web, '..');
// Host catalogs plus section catalogs (`<prefix>.<locale>.json`); the
// pumgye.* catalog is seeded verbatim from Pumgye's own contract-tested set.
const PREFIXES_FILES = ['', 'policies.', 'pumgye.'];
const read = file => JSON.parse(readFileSync(path.join(web, 'zt/messages', file), 'utf8'));
const en = {}, ko = {};
for (const prefix of PREFIXES_FILES) {
  const a = read(`${prefix}en.json`), b = read(`${prefix}ko.json`);
  for (const key of Object.keys(a)) if (!Object.hasOwn(b, key)) failures.push(`${prefix}en has ${key}; ${prefix}ko does not`);
  for (const key of Object.keys(b)) if (!Object.hasOwn(a, key)) failures.push(`${prefix}ko has ${key}; ${prefix}en does not`);
  for (const key of Object.keys(a)) if (Object.hasOwn(en, key)) failures.push(`${key} is defined in more than one catalog`);
  Object.assign(en, a); Object.assign(ko, b);
}
// Sections with their own catalog directory (zt/<section>/messages/{en,ko}.json).
const SECTION_CATALOGS = ['zt/identities/messages', 'zt/network/messages'];
for (const dir of SECTION_CATALOGS) {
  const a = JSON.parse(readFileSync(path.join(web, dir, 'en.json'), 'utf8')), b = JSON.parse(readFileSync(path.join(web, dir, 'ko.json'), 'utf8'));
  for (const key of Object.keys(a)) if (Object.hasOwn(en, key)) failures.push(`${key} is defined in more than one catalog`);
  Object.assign(en, a); Object.assign(ko, b);
}
const flat = value => typeof value === 'object' ? Object.values(value) : [value];

for (const [name, a, b] of [['en', en, ko], ['ko', ko, en]]) {
  for (const key of Object.keys(a)) {
    if (!Object.hasOwn(b, key)) failures.push(`${name} has ${key}; the other catalog does not`);
    if (flat(a[key]).some(message => typeof message !== 'string' || !message.trim())) failures.push(`${name}:${key} is empty`);
  }
}
// Product and protocol names stay in their original form in Korean.
const PROPER_NAMES = /^(OpenID Connect|LDAP|OAuth 2\.0|Kubernetes TokenReview|https:\/\/[a-z0-9.\/-]+)$/;
for (const [key, value] of Object.entries(ko)) {
  if (key.startsWith('pumgye.') || /Kubernetes|Human|AAL/.test(flat(value).join(''))) continue;
  if (flat(value).every(message => /^[\x20-\x7e]*$/.test(message)) && flat(en[key] ?? []).every(message => /[a-z]{4,}/i.test(message)) && !/\{|µs|AAL|ASN|HTTP|AS\{/.test(flat(value).join('')) && !['decision.authority.catalog'].includes(key) && !PROPER_NAMES.test(flat(value).join(''))) {
    failures.push(`ko:${key} looks untranslated`);
  }
}

const SOURCE_DIRS = ['kit', 'zt', 'zt/identities', 'zt/policies', 'zt/network'];
const sources = SOURCE_DIRS.flatMap(dir => readdirSync(path.join(web, dir)).filter(file => file.endsWith('.js')).map(file => path.join(dir, file)));
const KEY = /^(ui|nav|access|audit|decision|entity|overview|request|section|system|identities|policies|network)\.[A-Za-z0-9_.-]+$/;
const PREFIXES = new Set(['decision.stage', 'decision.principal', 'decision.result']);
const literal = /(['"`])((?:\\.|(?!\1)[^\\])*)\1/g;
const forbidden = [
  /\.(textContent|innerHTML|innerText|title|placeholder)\s*=\s*(['"`])(?!\$\{)[^'"`]*[A-Za-z][^'"`]*\2/,
  /\btext:\s*(['"`])(?!\$\{)[^'"`]*[A-Za-z][^'"`]*\1/,
  /setAttribute\(\s*['"](aria-[a-z-]+|title|placeholder)['"]\s*,\s*(['"`])(?!\$\{)[^'"`]*[A-Za-z][^'"`]*\2/,
];
for (const file of sources) {
  const text = readFileSync(path.join(web, file), 'utf8');
  text.split('\n').forEach((line, index) => {
    if (/^\s*\/\//.test(line)) return;
    for (const pattern of forbidden) {
      const hit = line.match(pattern);
      // ARIA state tokens are not prose.
      if (hit && !/^['"`](true|false|polite|assertive|page|location|list|both|none|listbox)['"`]$/.test(hit[0].slice(hit[0].search(/['"`][^'"`]*['"`]$/)))) failures.push(`${file}:${index + 1}: literal UI text; use a message key`);
    }
    for (const match of line.matchAll(literal)) {
      const value = match[2];
      if (match[1] === '`' || !KEY.test(value) || PREFIXES.has(value)) continue;
      if (!Object.hasOwn(en, value)) failures.push(`${file}:${index + 1}: missing message key ${value}`);
    }
  });
}

const families = {
  'nav': ['overview', 'access', 'identities', 'policies', 'network', 'workloads', 'audit', 'system', 'components'],
  'ui.status': ['allow', 'healthy', 'deny', 'challenge', 'error', 'unavailable', 'stale', 'disabled', 'unknown', 'simulation', 'pending', 'committed', 'refused', 'uncertain'],
  'ui.entity': ['request', 'user', 'ip', 'service'],
  'decision.stage': ['network', 'identity', 'authorization', 'enforcement'],
  'decision.result': ['allow', 'deny', 'challenge', 'error', 'unavailable', 'unknown'],
  'decision.verdict': ['allow', 'deny', 'observe', 'unavailable', 'unspecified', 'authenticated', 'anonymous', 'challenge', 'denied', 'refused', 'challenged', 'forwarded', 'redirected', 'Allow', 'UnknownService', 'Guest', 'NetworkGuest', 'PermissionDenied', 'ClassDenied', 'AssuranceDenied', 'GuardDenied', 'GuardUnavailable', 'UnknownResource', 'UnknownAction', 'Unavailable', 'NotMapped', 'Unspecified'],
  'decision.authority': ['sumunjang', 'hopae', 'pumgye', 'hangang', 'catalog', 'unspecified'],
  'decision.kind': ['enforced', 'simulation', 'shadow', 'unspecified'],
  'decision.principal': ['human', 'service', 'workload', 'unspecified'],
  'decision.mode': ['observe', 'enforce', 'unspecified'],
  'decision.factor': ['password', 'federated', 'otp', 'webauthn', 'certificate', 'bearer', 'unspecified'],
  'decision.fence': ['ok', 'stale_owner', 'revision_regressed', 'expired', 'unspecified'],
  'access.range': ['1h', '24h', '7d', '30d'],
  'audit.source': ['accounts', 'plugins', 'pumgye', 'hopae', 'sumunjang'],
  'audit.record_id': ['accounts', 'plugins', 'pumgye', 'hopae', 'sumunjang'],
  'audit.actor': ['system', 'account', 'unknown'],
  'system.profile': ['off', 'strict', 'standard'],
  'audit.summary.account': ['baseline', 'bootstrap', 'prune', 'config_operations_prune', 'policy_change'],
  'audit.summary.admin': ['user_disable', 'user_enable', 'session_terminate', 'sessions_terminate', 'grant', 'revoke', 'denied'],
  'ui.subject.status': ['active', 'disabled', 'deleted', 'unknown'],
  'ui.subject.reason': ['credential_expired', 'not_found', 'unrecognized', 'human_subjects_not_configured', 'index_incomplete', 'not_enumerable'],
  'system.drop': ['ring_full_deny', 'ring_full_allow', 'exporter_unavailable', 'no_key', 'invalid'],
};
for (const name of ['identities', 'policies', 'network', 'workloads']) families[`section.${name}`] = ['owner', 'planned', 'body'];
// Identities section (zt/identities): dynamic key families built from Hopae values.
const identityModule = name => readFileSync(path.join(web, 'zt/identities', name), 'utf8');
const frozenList = (source, name) => JSON.parse(source.match(new RegExp(`${name} = Object\\.freeze\\((\\[[^\\]]*\\])`))[1].replace(/'/g, '"'));
Object.assign(families, {
  'identities.page': ['users', 'sessions', 'groups', 'providers', 'authentication', 'projections'],
  'identities.user.tab': frozenList(identityModule('user.js'), 'TABS'),
  'identities.event': frozenList(identityModule('user.js'), 'EVENT_KINDS'),
  'identities.event.outcome': ['success', 'failure', 'info'],
  'identities.explain.reason': frozenList(identityModule('explain.js'), 'EXPLAIN_REASONS'),
  'identities.explain.check': [...frozenList(identityModule('explain.js'), 'EXPLAIN_CHECKS'), 'other'],
  'identities.explain.outcome': ['allow', 'login', 'step_up', 'reauth', 'deny', 'unavailable', 'indeterminate', 'not_applicable'],
  'identities.explain.result': ['pass', 'fail', 'skip', 'info'],
  'identities.explain.input': ['session', 'subject', 'anonymous'],
  'identities.factor': ['totp', 'webauthn', 'external', 'recovery', 'federated', 'password', 'otp', 'certificate', 'bearer'],
  'identities.group.source': ['local', 'ldap', 'oidc', 'unknown'],
  'identities.aal.help': ['0', '1', '2', '3'],
  'identities.provider.kind': ['oidc', 'oauth2', 'email_link', 'password', 'ldap', 'other'],
  'identities.provider.reauth': ['max_age', 'unsupported', 'other'],
  'identities.provider.health': ['ok', 'degraded', 'disabled', 'unknown'],
  'identities.circuit': ['closed', 'open', 'half_open', 'quarantined', 'unavailable'],
  'identities.projection.credential': ['identity_header', 'bearer_reference'],
  'identities.access.via': ['user', 'human', 'workload', 'group'],
  'identities.auth.tab': ['profiles', 'test'],
  'identities.diff': ['add', 'remove', 'change'],
  'identities.outcome': ['committed', 'refused', 'uncertain'],
  'identities.error.code': [...identityModule('common.js').match(/HOPAE_CODES = new Set\((\[[^\]]*\])/)[1].matchAll(/'([a-z_]+)'/g)].map(match => match[1]),
  'ui.trace': ['pass', 'deny', 'warn', 'not_evaluated', 'unknown'],
  'policies.context': ['network_and_guard', 'kubernetes_api'],
  'policies.kind': ['user', 'human', 'workload', 'kubernetes_api'],
  'policies.tab': ['overview', 'resources', 'roles', 'assignments', 'simulate', 'history'],
  'policies.aal.option': ['0', '1', '2', '3'],
  'policies.sim.target': ['permission', 'resource'],
  'policies.sim.guard': ['enforced_allow', 'observe', 'deny', 'unavailable'],
  'policies.sim.source': ['published', 'candidate'],
  'policies.impact.entity': ['information_classes', 'service', 'assignment', 'network', 'resource'],
  'policies.impact.change': ['added', 'removed', 'modified'],
  'policies.source': ['independent', 'embedded', 'kubernetes', 'unknown'],
  'policies.subject.invalid': ['user', 'human', 'workload', 'kubernetes'],
  'pumgye.reason': ['allow', 'unknown_service', 'guest', 'network_guest', 'permission_denied', 'class_denied', 'assurance_denied', 'guard_denied', 'guard_unavailable', 'unknown_resource', 'unknown_action', 'unavailable'],
});
// Network section (zt/network): dynamic key families built from Sumunjang values.
const sumunjang = name => JSON.parse(readFileSync(path.join(web, 'zt/network/messages', `${name}.json`), 'utf8'));
Object.assign(families, {
  'network.page': ['overview', 'threats', 'blocks', 'zones', 'rules', 'policy', 'asn'],
  'network.mode': ['observe', 'enforce', 'unknown', 'observe.body', 'enforce.body', 'unknown.body'],
  'network.suspicion': ['normal', 'watch', 'suspicious', 'high', 'blocked'],
  'network.verdict': ['allow', 'deny', 'observe'],
  'network.outcome': ['committed', 'refused', 'uncertain'],
  'network.block.kind': ['manual', 'approved', 'automatic'],
  'network.block.reason': ['manual', 'approved', 'automatic'],
  'network.rule.action': ['allow', 'deny', 'observe'],
  'network.trace.stage': ['mode', 'zone', 'allowlist', 'geo', 'rules', 'blocklist', 'outcome', 'score', 'auto_block'],
  'network.asn_source': ['geoip', 'catalog', 'none'],
  'network.duration': ['15m', '1h', '24h', '7d', '30d'],
  'network.signal': ['honeypot', 'scanner', 'auth_failure', 'invalid_request'],
  'network.diff': ['add', 'remove', 'change'],
  'network.ip.trace': ['published', 'enforce'],
  'network.rules.tab': ['json', 'lua'],
  'network.blocks.tab': ['blocks', 'allowlist'],
  // Every code Sumunjang's catalog registers needs both messages (codes from guard-core messages).
  'network.code': Object.keys(sumunjang('en')).filter(key => key.startsWith('network.code.sumunjang.')).map(key => key.slice('network.code.'.length)),
});
for (const [prefix, suffixes] of Object.entries(families)) for (const suffix of suffixes) if (!Object.hasOwn(en, `${prefix}.${suffix}`)) failures.push(`missing family key ${prefix}.${suffix}`);

const registry = readFileSync(path.join(repo, 'crates/hangang-decision-event/src/reasons.rs'), 'utf8');
const codes = [...registry.matchAll(/\(\s*"((?:sumunjang|hopae|pumgye|hangang)\.[a-z0-9_]+)",/g)].map(match => match[1]);
if (codes.length < 40) failures.push('reason registry not found');
for (const code of codes) for (const prefix of ['decision.reason', 'decision.fix']) if (!Object.hasOwn(en, `${prefix}.${code}`)) failures.push(`missing ${prefix}.${code}`);

const html = readFileSync(path.join(web, 'index.html'), 'utf8');
for (const match of html.matchAll(/data-zt-label="([^"]+)"/g)) if (!Object.hasOwn(en, match[1])) failures.push(`index.html: missing message key ${match[1]}`);

if (failures.length) {
  for (const failure of failures) console.error(`i18n: ${failure}`);
  process.exit(1);
}
console.log(`i18n: ${Object.keys(en).length} keys, ${codes.length} reason codes, ${sources.length} modules checked`);
