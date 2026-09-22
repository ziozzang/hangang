# Documentation conventions

[Documentation](README.md) · [한국어 안내](README.ko.md)

English is the reference language for Hangang documentation. Korean documents are full translations of their English sources, not summaries.
Preserve every section, explanation, table, example, prerequisite, failure case,
and limitation. Each translation links to its English source. Update the English
contract first and update its existing Korean translation in the same change.

## Organization

- `README.md`: product overview, comparison, and a working local quick start.
- `README.ko.md`: Korean introduction and quick start, with the same commands.
- `docs/README.md`: complete English guide index, organized by user task.
- `docs/README.ko.md`: Korean navigation to the reference guides.
- `docs/ko/`: full Korean translations using the source guide's filename.
- `docs/openapi.json`: machine-readable management API and configuration schema.
- `examples/`: runnable examples and their usage instructions.
- `deploy/`: portable templates; credentials and operator state remain local.

Keep existing reference filenames stable. Link to the guide that owns a contract
instead of repeating its full explanation in several guides. For example, route
matching belongs in `MATCHING.md`, account sessions in `ADMIN_USERS.md`, and
publication semantics in `CONFIG_PUBLICATION.md`. A cross-reference may introduce the
concept, but must link to the detailed contract. Translations must not replace
source explanations with links.

## Page structure

Use one descriptive, sentence-case H1, followed by navigation to the documentation
index and, when available, the other language. Begin with the capability and its
scope. Add sections appropriate to the topic in this order:

1. Prerequisites and configuration.
2. Behavior, including reload, failure, and connection lifetime.
3. Management API, console, and observability.
4. Limitations and compatibility.
5. Examples, verification, and related guides.

Short references do not need empty sections to satisfy this outline. Use H2 for
major sections and H3 only inside an H2. Keep paragraphs focused on one topic.
Use tables for comparable options and fenced blocks with a language for commands,
JSON, YAML, and code. Commands start from the repository root unless stated
otherwise. Identify a configuration fragment when it is not a runnable file.

## Language and terminology

Use the [terminology guide](GLOSSARY.md) consistently. Keep API paths, JSON keys,
metric names, CLI flags, and code identifiers unchanged in every language. Use
“management API” and “management console” in prose; retain `admin` in actual
identifiers. Distinguish the configured backend from the outbound connection
policy and the configuration revision from a runtime generation.

English reference pages contain English prose. Language-switch labels and the bilingual terminology table are exceptions. Korean translations use polite, direct language and retain the original scope
and detail. Translate prose and headings; preserve executable examples, API
paths, JSON keys, metric names, flags, and values. Adjust relative Markdown links
for the translated file's directory. Do not interleave a Korean translation
inside an English reference. A local guarantee must never become a fleet-wide
guarantee. Where a Korean translation does not yet exist, link to the English
guide explicitly rather than presenting a short summary as its translation.

## Claims and examples

Describe current behavior, not implementation milestones or future promises.
State limitations as current boundaries rather than unfinished task lists.
Explain why a feature helps the operator, then link to its contract. Comparisons
must name the product scope, link to official sources, and record the review
date. Do not infer that another product lacks a feature merely because a source
does not mention it. Performance rankings require comparable measurements.

Use loopback addresses and reserved example domains. Include required setup,
expected results, and shutdown steps in runnable tutorials. Never copy production
configuration, private topology, credentials, or experiment receipts into public
documentation. Follow the [public repository policy](DEVELOPMENT.md#public-repository-policy).

## Validation

Stage the intended documentation changes, then run:

```sh
make check-docs
git diff --cached --check
```

The documentation checker reads the Git index so ignored local files cannot hide
broken published links. It checks local link targets, reference-page navigation,
language placement, heading structure, and translated section/table/code-block
parity. Structural parity does not replace a semantic translation review. It does not validate external website
availability or replace testing commands against a running gateway. Review both
languages when changing examples, defaults, or failure behavior.
