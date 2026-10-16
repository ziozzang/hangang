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
| Policies | `#policies/services/{id}` | Recent decisions for the Pumgye service |
| Audit | `#audit` | Unified administrative audit from console accounts, console package operations and Pumgye publications; failed sources are labelled; account changes show a structured before/after diff. Console-account audit retention, policy and export moved to `#account-audit`; earlier `#audit-trail` links redirect |
| System | `#system` | Components, packages, decision events, exporter and privacy profile; raw JSON only behind *View raw diagnostics* |

Identities, Policies, Network and Devices & Workloads otherwise show an entity
opener and links to the current component pages. When decision events are off,
every decision view states *Decision events disabled* instead of showing an
empty list. Actions that need later phases (simulator, reveal) are shown
disabled with the reason.

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
