// Pure helpers over the Pumgye policy document version 1 (no DOM).

export const MAPS = Object.freeze([
  { field: 'users', kind: 'user' },
  { field: 'human_users', kind: 'human' },
  { field: 'workload_users', kind: 'workload' },
]);
export const CONTEXTS = Object.freeze(['network_and_guard', 'kubernetes_api']);
export const IDENT = /^[A-Za-z0-9_.:-]{1,128}$/;

export function emptyPolicy() {
  return { version: 1, information_classes: ['public', 'internal', 'confidential', 'restricted'], services: {} };
}

export function clone(value) { return JSON.parse(JSON.stringify(value)); }

export function contextOf(service) { return service?.authorization_context === 'kubernetes_api' ? 'kubernetes_api' : 'network_and_guard'; }

/** Assignment kinds a service context accepts (enforcement never mixes them). */
export function kindsFor(service) {
  return contextOf(service) === 'kubernetes_api' ? ['kubernetes_api'] : ['user', 'human', 'workload'];
}

export function fieldFor(kind) { return kind === 'human' ? 'human_users' : kind === 'workload' ? 'workload_users' : 'users'; }

/** Validates a subject reference for an assignment kind; returns a message key or null. */
export function subjectProblem(kind, id) {
  if (kind === 'human') return /^human1:[0-9a-f]{64}$/.test(id) ? null : 'policies.subject.invalid.human';
  if (kind === 'workload') return /^s_[0-9a-f]{48}$/.test(id) ? null : 'policies.subject.invalid.workload';
  if (kind === 'kubernetes_api') return id.length <= 128 && /^k8sapi:[A-Za-z0-9_.:-]+$/.test(id) ? null : 'policies.subject.invalid.kubernetes';
  return IDENT.test(id) ? null : 'policies.subject.invalid.user';
}

/** Every assignment of a service as rows. */
export function assignments(service) {
  const rows = [];
  const api = contextOf(service) === 'kubernetes_api';
  for (const { field, kind } of MAPS) {
    for (const [subject, roles] of Object.entries(service?.[field] || {})) rows.push({ subject, kind: api && field === 'users' ? 'kubernetes_api' : kind, field, roles: Array.isArray(roles) ? roles : [] });
  }
  return rows;
}

/** Roles reachable from `names` through `inherits` (cycle-safe). */
export function expandRoles(service, names) {
  const seen = new Set();
  const stack = [...names];
  while (stack.length) {
    const name = stack.pop();
    if (seen.has(name) || !service?.roles?.[name]) continue;
    seen.add(name);
    for (const parent of service.roles[name].inherits || []) stack.push(parent);
  }
  return seen;
}

/** Effective rights of a role set: union of permissions/classes, max minimum AAL. */
export function effectiveRights(service, names) {
  const permissions = new Set(), classes = new Set();
  let aal = 0;
  for (const name of expandRoles(service, names)) {
    const role = service.roles[name];
    for (const permission of role.permissions || []) permissions.add(permission);
    for (const information of role.information_classes || []) classes.add(information);
    aal = Math.max(aal, role.minimum_aal || 0);
  }
  return { permissions: [...permissions].sort(), classes: [...classes], minimumAal: aal };
}

/** Highest class (by policy order) among a set, or null. */
export function highestClass(policy, classes) {
  const order = policy?.information_classes || [];
  let best = -1;
  for (const information of classes) best = Math.max(best, order.indexOf(information));
  return best >= 0 ? order[best] : null;
}

export function serviceSummary(policy, id) {
  const service = policy.services[id];
  const rows = assignments(service);
  const classes = Object.values(service.roles || {}).flatMap(role => role.information_classes || []);
  return {
    id, context: contextOf(service), requireGuard: service.require_guard !== false,
    roles: Object.keys(service.roles || {}).length, assignments: rows.length, networks: (service.networks || []).length,
    highestClass: highestClass(policy, classes),
    resources: Object.values(policy.resources || {}).filter(resource => resource.service === id).length,
  };
}

/** Subjects holding a role directly or through inheritance. */
export function roleHolders(service, role) {
  return assignments(service).filter(row => expandRoles(service, row.roles).has(role)).length;
}

/** True when giving `role` the parents `inherits` would create a cycle. */
export function wouldCycle(service, role, inherits) {
  const trial = { ...service, roles: { ...service.roles, [role]: { ...(service.roles[role] || {}), inherits } } };
  const visit = (name, path) => {
    if (path.has(name)) return true;
    const next = new Set(path); next.add(name);
    return (trial.roles[name]?.inherits || []).some(parent => visit(parent, next));
  };
  return visit(role, new Set());
}

function flatten(value, prefix, out) {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const keys = Object.keys(value);
    if (!keys.length && prefix) out.set(prefix, {});
    for (const key of keys) flatten(value[key], prefix ? `${prefix}\u0000${key}` : key, out);
  } else out.set(prefix, value);
  return out;
}

/** Leaf paths that differ between two documents. */
export function changedPaths(before, after) {
  const a = flatten(before, '', new Map()), b = flatten(after, '', new Map());
  const paths = new Set();
  for (const key of new Set([...a.keys(), ...b.keys()])) if (JSON.stringify(a.get(key)) !== JSON.stringify(b.get(key))) paths.add(key);
  return paths;
}

export function countChanges(before, after) { return changedPaths(before, after).size; }

function setPath(target, parts, value) {
  let node = target;
  for (let index = 0; index < parts.length - 1; index++) {
    if (!node[parts[index]] || typeof node[parts[index]] !== 'object' || Array.isArray(node[parts[index]])) node[parts[index]] = {};
    node = node[parts[index]];
  }
  if (value === undefined) delete node[parts.at(-1)]; else node[parts.at(-1)] = clone(value);
}

/**
 * Three-way rebase for a 409: replays the draft's own changes (base → mine)
 * onto the newer published document (theirs). Paths both sides changed to
 * different values are conflicts; `preferMine` decides them.
 */
export function rebase(base, mine, theirs, preferMine = true) {
  const minePaths = changedPaths(base, mine), theirPaths = changedPaths(base, theirs);
  const mineFlat = flatten(mine, '', new Map()), theirFlat = flatten(theirs, '', new Map());
  const conflicts = [...minePaths].filter(path => theirPaths.has(path) && JSON.stringify(mineFlat.get(path)) !== JSON.stringify(theirFlat.get(path)));
  const result = clone(theirs);
  for (const path of minePaths) {
    if (conflicts.includes(path) && !preferMine) continue;
    setPath(result, path.split('\u0000'), mineFlat.get(path));
  }
  return { result, conflicts: conflicts.map(path => path.split('\u0000').join('.')) };
}

/** First host address of a CIDR (for synthesized impact cases). */
export function sampleAddress(cidr) {
  const [address] = String(cidr).split('/');
  return address || null;
}

/**
 * Impact cases for the batch what-if: every changed `users` assignment
 * against each permission and class either side grants (≤256 cases).
 */
export function impactCases(base, draft, changes) {
  const cases = [];
  for (const change of changes || []) {
    if (change.entity !== 'assignment' || change.map !== 'users') continue;
    const service = draft.services?.[change.service] || base.services?.[change.service];
    if (!service || contextOf(service) !== 'network_and_guard') continue;
    const permissions = new Set([...(change.before?.permissions || []), ...(change.after?.permissions || [])]);
    const classes = new Set([...(change.before?.information_classes || []), ...(change.after?.information_classes || [])]);
    const ip = sampleAddress(service.networks?.[0]?.cidr) || '192.0.2.1';
    for (const permission of permissions) for (const information of classes) {
      if (cases.length >= 256) return cases;
      cases.push({ label: `c${cases.length}`, subject: { id: change.subject, kind: 'user' }, service: change.service, permission, information_class: information, ip, aal: 3, guard: 'enforced_allow' });
    }
  }
  return cases;
}

/** Services touched by a draft and whether any touches the top class. */
export function touched(base, draft) {
  const services = new Set();
  for (const path of changedPaths(base, draft)) {
    const parts = path.split('\u0000');
    if (parts[0] === 'services' && parts[1]) services.add(parts[1]);
    if (parts[0] === 'resources' && parts[1]) services.add((draft.resources?.[parts[1]] || base.resources?.[parts[1]])?.service);
  }
  services.delete(undefined);
  const top = (draft.information_classes || []).at(-1);
  const restricted = [...services].some(id => {
    const service = draft.services?.[id] || base.services?.[id];
    return Object.values(service?.roles || {}).some(role => (role.information_classes || []).includes(top));
  });
  return { services: [...services], restricted };
}
