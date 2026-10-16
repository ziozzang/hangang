# Zero Trust console sections and the shared UI kit

[Documentation](README.md) · [한국어](ko/ZERO_TRUST_CONSOLE.md)

The management console groups zero-trust work by operator task (ADR 0020 P0):
Overview, Access, Identities, Policies, Network, Devices & Workloads, Audit and
System. Component pages (Pumgye, installed Hopae and Sumunjang packages) remain
under *Component pages* until their task pages ship. All sections are
administrator-only and read data through the existing management API.

## Sections

| Section | Route | Content |
| --- | --- | --- |
| Overview | `#overview` | Authority health (Hangang, Hopae, Sumunjang, Pumgye, decision exporter), decision KPIs and deny-rate trend for 1 h, 24 h or 7 d, top deny reasons, routes and countries, recent administrative changes; refreshes every 30 s while visible |
| Access | `#access/decisions` | Decision log with server-side filters held in the URL, cursor pagination, time-order toggle, request/user/IP search and a bounded live tail |
| Access | `#access/requests/{request_id}` | Request detail: stage timeline with the deciding stage, localized reason and remediation, revision vector with *changed since* |
| Identities | `#identities/users/{id}` | Subject resolved through Hopae `subjects/resolve` when available, otherwise the opaque ID; recent decisions by forward lookup |
| Network | `#network/ip/{ip}` | GeoIP country and recent decisions for the address |
| Policies | `#policies` | Pumgye service catalog (context, Sumunjang requirement, role, assignment, network and resource counts, highest class), access matrix and advanced JSON |
| Policies | `#policies/services/{id}` | Service detail tabs: overview, resources and actions, roles, assignments, access simulator and change history |
| Policies | `#policies/publish` | Review and publish: structured diff, what-if impact, required reason, typed confirmation and conflict resolution |
| Audit | `#audit` | Unified administrative audit from console accounts, console package operations and Pumgye publications; failed sources are labelled; account changes show a structured before/after diff. Console-account audit retention, policy and export moved to `#account-audit`; earlier `#audit-trail` links redirect |
| System | `#system` | Components, packages, decision events, exporter and privacy profile; raw JSON only behind *View raw diagnostics* |

Identities, Network and Devices & Workloads otherwise show an entity
opener and links to the current component pages. When decision events are off,
every decision view states *Decision events disabled* instead of showing an
empty list. Actions that need later phases (simulator, reveal) are shown
disabled with the reason.

## Policies

The Policies section replaces the former embedded Pumgye page; `#pumgye` links
redirect to `#policies` (`#pumgye/policy` to `#policies/advanced`). It edits the
policy version 1 document of the independent Pumgye authority (or the `pumgye`
member of the Hangang configuration when no authority is configured).

- **Draft.** Every edit (services, permissions, roles with permissions, class
  ceiling, minimum AAL and inheritance, assignments, network rules, resources
  and actions) changes a draft bound to the base revision. The draft survives
  navigation, locale changes and page refresh in the same tab.
- **Roles.** The editor shows effective rights through inheritance and how
  many subjects hold the role, refuses inheritance cycles and refuses deleting a
  role that is still used.
- **Assignments.** Subjects are picked through Hopae `subjects/search` and
  shown with resolved names; user, Human, workload and Kubernetes API subjects
  are validated per service context; selected assignments can be revoked in bulk
  with typed confirmation.
- **Access simulator.** Runs Pumgye `POST /v1/explain` for the published policy
  or the draft as a candidate and shows the decision, localized reason,
  remediation and the ordered evaluation trace. Pumgye validation errors are
  shown on the offending field.
- **Review and publish.** Shows a structured diff grouped by service, the
  compiled-rights diff (`/v1/explain/diff`) and an allow→deny / deny→allow
  impact over cases synthesized from changed user assignments
  (`/v1/explain/batch`). Publishing is a compare-and-swap with the Pumgye and
  Hangang authority revisions and requires a reason (recorded in the Hangang
  audit log with the actor and resulting revision). A change that turns an
  allowed case into a denial, or touches a service granting the highest class,
  requires typing the service name. A 409 opens a three-way view (published
  since, your draft, conflicting paths) and rebases the draft.
- **Advanced JSON** is read-only until *Edit JSON*; applied JSON becomes a draft
  and goes through the same review.
- A Kubernetes-owned or unreported policy source is shown read-only.

The management API brokers Pumgye simulation for the console:
`POST /v1/pumgye/explain`, `/v1/pumgye/explain/batch`, `/v1/pumgye/explain/diff`
and `GET /v1/pumgye/audit/simulations`. They are administrator-only, rate
limited per console account (burst 20, 2 per second) before Pumgye's own bucket,
set `on_behalf_of` to `console:<account>` from the session and relay Pumgye's
structured errors.

## Shared UI kit

`web/kit/ui.js` (`@hangang/console-ui` kit 1) provides `el`, `dataTable`,
`entityLink`, `statusBadge`, `freshnessBadge`, `stageTimeline`,
`structuredDiff`, `confirmDialog` (typed target plus required reason),
`emptyState`, `errorState`, `loadingState`, `field` and `subjectResolver`.
Components render untrusted values as text nodes, respect the host CSP, use the
River theme tokens in light and dark, and become card lists below 720 px.

Console packages receive the kit additively in their mount context as
`context.ui`, together with the key-based translator `context.t`,
`context.navigate(hash)` and `context.link({type, id})`. Version 1 packages that
ignore these fields are unaffected.

## Messages and lint

The sections use key-based catalogs `web/zt/messages/en.json` and `ko.json`
through `web/kit/i18n.js`; missing keys fall back to English and are recorded.
`npm run lint:i18n` (also run by `npm test`) fails when:

- the English and Korean key sets differ or a message is empty or untranslated;
- a used message key or a dynamic key family is missing;
- a registered decision reason code lacks its message or remediation;
- a string literal is rendered directly through `textContent`, `innerHTML`,
  `title`, `placeholder`, `aria-*` or the kit's `text` property.

```sh
cd web
npm run lint:i18n
npx playwright test tests/zero_trust.spec.js
```

## Limitations

Subject display follows the Hopae subject directory contract (Hopae
`docs/SUBJECT_DIRECTORY.md`): `subjects/resolve` (at most 100 IDs) and
`subjects/search` for the subject picker, with `active`, `disabled`, `deleted`
(tombstone, no personal data) and `unknown` (with its reason) shown distinctly.
The Hopae console package must list `subjects/resolve`, `subjects/search`,
`subjects/lifecycle`, `subjects/lifecycle/snapshot` and
`explain/authentication` as `POST` routes with `"mutation": false`; the broker
then forwards them to `/v1/<path>` with the signed actor assertion over the
exact body, does not record them as mutations, and Hopae's delegation verifier
applies its JSON API rule. Without those routes, or when Hopae is rate limited,
user pages show the opaque ID. Hopae
`admin.*` events (`events/query`) and Sumunjang policy-change audit
(`audit/query`, `sumunjang.audit.v1`) join the unified audit through their
console packages; a source whose package does not declare the operation is
shown as not connected, and a failing source is labelled, never shown as no
activity. The simulator, impact analysis, reveal, saved views
and CSV export arrive with ADR 0020 P1 and P2. Legacy pages keep their
English-sentence dictionaries until they are migrated.
