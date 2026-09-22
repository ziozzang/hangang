# Development

[Documentation](README.md) · [한국어 안내](README.ko.md)

Use Rust 1.96 or newer, a C compiler for bundled native dependencies, Python 3,
and Node.js/npm for console development. Build with the committed lockfiles.

```sh
cargo build --locked
cargo test --locked --all-targets
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cd web
npm ci
npx playwright install chromium
npm test
```

Python integration fixtures use temporary state and owned loopback services.
Run `make test` after building; Docker, PostgreSQL, Redis, ACME and Kubernetes
fixtures need their documented optional dependencies. `make test-web` includes
an actual embedded-server browser check. Schema tests need Python's `jsonschema`
package. `make static` builds the Linux static binary used by the Dockerfile.

To change the Lua editor bundle, run `npm run build:lua-editor` inside `web/`
and commit the generated assets with the source change. The rest of the console
is served from checked-in assets embedded by the Rust build.

## Documentation

Follow the [documentation conventions](DOCUMENTATION.md) and [terminology](GLOSSARY.md).
English is the reference language; Korean summaries live under `docs/ko/`.
Stage changes and run `make check-docs` before publishing.

## Public repository policy

Keep implementation, reproducible automated tests, synthetic examples and current
user/developer guides in Git. Keep experiments, research notes, local benchmark
results, deployment receipts, operating configuration, credentials, certificate
keys and runtime databases outside published history. `.gitignore` covers local
copies, and the publication checker rejects forbidden paths even when forcibly
staged.

```sh
git diff --cached --stat
python3 tools/check_publish.py
python3 -m unittest discover -s tests -p test_publish_policy.py
```

The checker inspects the Git index, not only working-tree files. It prints paths
and finding categories without printing matched secrets. To compare against
literal values from a private environment file, use
`python3 tools/check_publish.py --secrets-file /path/to/private.env`.
It never sources that file. Pattern checks do not replace human review.

Enable the supplied pre-commit checks with `git config core.hooksPath .githooks`
if the clone has no existing hook policy. The hook also runs Gitleaks when
installed. Preserve existing security hooks when integrating these checks.

Use independent branches/worktrees for parallel changes. Keep generated outputs
and local operational files out of commits. Never publish an old unfiltered
branch after a repository history cleanup; start from the current public branch.
