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
const flat = value => typeof value === 'object' ? Object.values(value) : [value];

for (const [name, a, b] of [['en', en, ko], ['ko', ko, en]]) {
  for (const key of Object.keys(a)) {
    if (!Object.hasOwn(b, key)) failures.push(`${name} has ${key}; the other catalog does not`);
    if (flat(a[key]).some(message => typeof message !== 'string' || !message.trim())) failures.push(`${name}:${key} is empty`);
  }
}
for (const [key, value] of Object.entries(ko)) {
  if (key.startsWith('pumgye.') || /Kubernetes|Human|AAL/.test(flat(value).join(''))) continue;
  if (flat(value).every(message => /^[\x20-\x7e]*$/.test(message)) && flat(en[key] ?? []).every(message => /[a-z]{4,}/i.test(message)) && !/\{|µs|AAL|ASN|HTTP|AS\{/.test(flat(value).join('')) && !['decision.authority.catalog'].includes(key)) {
    failures.push(`ko:${key} looks untranslated`);
  }
}

const sources = ['kit', 'zt', 'zt/policies'].flatMap(dir => readdirSync(path.join(web, dir)).filter(file => file.endsWith('.js')).map(file => path.join(dir, file)));
const KEY = /^(ui|nav|access|audit|decision|entity|overview|request|section|system|policies)\.[A-Za-z0-9_.-]+$/;
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
Object.assign(families, {
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
