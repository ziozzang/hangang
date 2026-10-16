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
| Identities | `#identities/…` | Users, user detail, sessions, groups, providers, authentication policies and credential projections through the Hopae package (see below) |
| Network | `#network/…` | Overview, threat queue, IP detail, blocks & allowlist, rules, policy and ASN pools through the Sumunjang package (see below) |
| Policies | `#policies` | Pumgye service catalog (context, Sumunjang requirement, role, assignment, network and resource counts, highest class), access matrix and advanced JSON |
| Policies | `#policies/services/{id}` | Service detail tabs: overview, resources and actions, roles, assignments, access simulator and change history |
| Policies | `#policies/publish` | Review and publish: structured diff, what-if impact, required reason, typed confirmation and conflict resolution |
| Policies | `#policies/simulate?subject={id}` | Cross-section simulator entry (used by Identities): redirects to the service's simulator tab when `service` is given or only one exists, otherwise picks a service (assigned ones first), keeping the subject |
| Audit | `#audit` | Unified administrative audit from console accounts, console package operations and Pumgye publications; failed sources are labelled; account changes show a structured before/after diff. Console-account audit retention, policy and export moved to `#account-audit`; earlier `#audit-trail` links redirect |
| System | `#system` | Components, packages, decision events, exporter and privacy profile; raw JSON only behind *View raw diagnostics* |

Network and Devices & Workloads otherwise show an entity
opener and links to the current component pages. When decision events are off,
every decision view states *Decision events disabled* instead of showing an
empty list. Actions that need later phases (simulator, reveal) are shown
disabled with the reason.

## Identities

All Identities pages call the Hopae console package through the host broker
(`/v1/plugins/hopae/<route>`); package discovery lists each package's declared
routes, so an operation the installed package does not declare is shown
disabled with the reason instead of failing.

| Route | Page | Hopae routes |
| --- | --- | --- |
| `#identities/users?q=&status=&group=` | Users: server search, group filter, bulk disable (typed count + reason) | `users/query`, `subjects/search`, `subjects/resolve` (`include_groups`), `groups/get`, `users/disable` |
| `#identities/users/{id}/{tab}` | User detail: Profile & linked identities, Authentication (factor status, access test), Sessions (terminate one/all), Groups, Access (Pumgye grants, simulator link), Activity (Hopae events and Hangang decisions) | `subjects/resolve`, `sessions/query`, `events/query`, `subjects/groups`, `explain/authentication`, `users/enable`, `users/disable`, `users/sessions-terminate`, `sessions/terminate`, `groups/members/*` |
| `#identities/sessions?user=` | Live sessions with device, bound address, assurance and activity | `sessions/query`, `sessions/terminate` |
| `#identities/groups`, `#identities/groups/{ref}` | Groups; local groups are edited with `expected_revision` and a reason, LDAP/OIDC groups are read-only with their source | `groups/search`, `groups/get`, `groups/create`, `groups/update`, `groups/delete`, `groups/members/add`, `groups/members/remove` |
| `#identities/providers` | Provider cards: health, kind, management source, re-authentication, client secret, redirect URI, last error | `status` |
| `#identities/authentication[/test]` | Service authentication profiles as forms, entity-grouped change list, CAS publish with reason and draft kept across navigation; "test access as a user" | `authentication/profiles`, `authentication/profiles/publish`, `explain/authentication` |
| `#identities/projections` | Projection plans per service with connector circuit states, plan editor | `authentication/projections`, `authentication/projections/publish`, `status` |

Every write asks for a reason. Hopae's group writes carry it in their body;
for the other writes the console sends it in the host-only
`x-hangang-change-reason` header (percent-encoded UTF-8, 1–512 characters),
which the broker records in its private operation journal (shown in the
unified audit) and never forwards.

Hopae API follow-ups the pages state in place: factor listing and reset have
no HTTP API (CLI `hopae admin factors list|reset` only); the delegated
`users/query`, `sessions/query` and `events/query` accept only `cursor` and
`limit` (no status, provider, MFA or user filter, so user sessions and events
come from a bounded scan of the newest records, labelled when partial); the
per-user detail with linked identities is not delegated; user and session
writes take no reason; `status` does not report the portal origin for
redirect URIs; the authority mode (Hopae-native or Hangang-delegated) is not
reported; there is no batch disable.

## Policies

The Policies section replaces the former embedded Pumgye page; `#pumgye` links
redirect to `#policies` (`#pumgye/policy` to `#policies/advanced`). It edits the
policy version 1 document of the independent Pumgye authority (or the `pumgye`
member of the Hangang configuration when no authority is configured).

- **Draft.** Every edit (services, permissions, roles with permissions, an
  explicit information-class list, minimum AAL and inheritance, assignments,
  network rules, resources and actions) changes a draft bound to the base
  revision. Pumgye v1 grants exactly the listed classes; classes are not a
  hierarchy, so the role editor shows one checkbox per class and no ceiling. The draft survives
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
- **Review and publish.** Shows the changes grouped by service as sentences
  (for example "Kim Analyst u_kim: analyst role revoked") with the JSON path
  secondary and the raw JSON diff on demand; subjects use their Hopae display
  names in the diff, impact table and examples. Then the
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

## Network

All Network pages call the Sumunjang console package through the host broker
(`/v1/plugins/guard/<route>`). The former Sumunjang package page is no longer
in the navigation; `#plugin-guard` links redirect to `#network`.

| Route | Page | Sumunjang routes |
| --- | --- | --- |
| `#network` | Overview: mode banner; in observe mode what enforcement would deny among tracked addresses; queue, blocks, allowlist and rule counts; network-stage denial trend and top countries from the Hangang decision log; top ASNs; recent policy changes | `policy/document`, `candidates`, `blocks`, `rules`, `explain/batch`, `audit/query` |
| `#network/threats?q=&stage=&asn=&eligible=` | Threat queue: score, stage, events, ASN, last seen; bulk approval with typed count and reason | `candidates`, `candidates/approve` |
| `#network/ip/{ip}` | IP detail: GeoIP/ASN, score and stage, matched rules, covering blocks with expiry, allowlist, explain trace (published and, while observing, if enforced), related decisions; block/unblock/allowlist with reason | `lookup`, `explain`, `blocks`, `policy/document` |
| `#network/blocks[/allowlist]?kind=` | Blocks (manual, approved, automatic) with expiry countdown; allowlist; additions validate the CIDR and preview impact | `blocks`, `networks/inspect`, `explain/batch`, `policy/document` |
| `#network/rules[/lua]?rule=` | Rules as a structured form or Lua in the host CodeMirror editor; validate, change list, what-if on tracked addresses, publish with reason | `rules`, `rules/validate`, `rules/lua`, `explain/batch` |
| `#network/policy` | Mode, automatic blocking, window, threshold, block lifetime and weights; change list, what-if, CAS publish (`expected_revision`) with reason; switching to enforce requires typing the mode | `policy/document`, `explain/batch` |
| `#network/asn` | ASNs seen in evidence and rules naming them (read-only); proposal workflow shown as planned | `candidates`, `rules` |

Sumunjang status, GeoIP databases (reload), signed updates (check) and the
Kubernetes source moved to System; raw diagnostics stay collapsed. Writes
carry the operator reason in `x-hangang-change-reason` (operation journal);
policy writes also send it in Sumunjang's `reason`, and a manual block uses
it as the block reason (128 bytes). Rule replacement has no revision
precondition in Sumunjang, so the console re-reads the published rules
right before publishing and refuses when they changed.

Sumunjang API follow-ups the pages state in place: per-address score and
signal history; per-signal counts and country on candidates; block creator
and creation time; an `expected_revision` on `PUT /v1/rules` and
`/v1/rules/lua`; the Lua source is not retained; a readable ASN catalog and
an ASN proposal API; a reason field on block, approval and rule writes;
`explain/batch` and impact estimates cover tracked addresses only.

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
