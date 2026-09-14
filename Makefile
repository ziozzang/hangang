.PHONY: build test check probes static
build:
	cargo build --locked
check:
	cargo fmt --check
	cargo clippy --all-targets --locked -- -D warnings
test:
	cargo test --locked
	cargo build --locked
	python3 tests/smoke.py
	python3 tests/docker_smoke.py
	python3 tests/sql_smoke.py
	python3 tests/acme_runtime.py
	python3 examples/transforms/run.py
	python3 examples/cache/run.py
	python3 examples/sni/run.py
	python3 examples/upstream/run.py
	python3 tests/restart_smoke.py
	python3 tests/upgrade_smoke.py
probes:
	cargo test --manifest-path experiments/rust-lua/Cargo.toml --locked
	cd experiments/go-lua && go test -race ./...
static:
	RUSTFLAGS='-C target-feature=+crt-static' cargo build --locked --release --target x86_64-unknown-linux-gnu

.PHONY: coverage
coverage:
	cargo llvm-cov clean --workspace
	cargo llvm-cov --all-targets --no-report -- --test-threads=1
	LLVM_PROFILE_FILE='$(CURDIR)/target/llvm-cov-target/hangang-smoke-%p-%m.profraw' HANGANG_BINARY=target/llvm-cov-target/debug/hangang python3 tests/smoke.py
	LLVM_PROFILE_FILE='$(CURDIR)/target/llvm-cov-target/hangang-extra-%p-%m.profraw' HANGANG_BINARY=target/llvm-cov-target/debug/hangang python3 tests/docker_smoke.py
	LLVM_PROFILE_FILE='$(CURDIR)/target/llvm-cov-target/hangang-extra-%p-%m.profraw' HANGANG_BINARY=target/llvm-cov-target/debug/hangang python3 tests/sql_smoke.py
	LLVM_PROFILE_FILE='$(CURDIR)/target/llvm-cov-target/hangang-extra-%p-%m.profraw' HANGANG_BINARY=target/llvm-cov-target/debug/hangang python3 tests/restart_smoke.py
	LLVM_PROFILE_FILE='$(CURDIR)/target/llvm-cov-target/hangang-extra-%p-%m.profraw' HANGANG_BINARY=target/llvm-cov-target/debug/hangang python3 tests/upgrade_smoke.py
	LLVM_PROFILE_FILE='$(CURDIR)/target/llvm-cov-target/hangang-extra-%p-%m.profraw' HANGANG_BINARY=target/llvm-cov-target/debug/hangang python3 tests/acme_runtime.py
	LLVM_PROFILE_FILE='$(CURDIR)/target/llvm-cov-target/hangang-transform-%p-%m.profraw' HANGANG_BINARY=target/llvm-cov-target/debug/hangang python3 examples/transforms/run.py
	LLVM_PROFILE_FILE='$(CURDIR)/target/llvm-cov-target/hangang-cache-%p-%m.profraw' HANGANG_BINARY=target/llvm-cov-target/debug/hangang python3 examples/cache/run.py
	LLVM_PROFILE_FILE='$(CURDIR)/target/llvm-cov-target/hangang-sni-%p-%m.profraw' HANGANG_BINARY=target/llvm-cov-target/debug/hangang python3 examples/sni/run.py
	LLVM_PROFILE_FILE='$(CURDIR)/target/llvm-cov-target/hangang-upstream-%p-%m.profraw' HANGANG_BINARY=target/llvm-cov-target/debug/hangang python3 examples/upstream/run.py
	cargo llvm-cov report --summary-only --ignore-filename-regex '/tests/'

.PHONY: test-postgres test-web
test-postgres:
	python3 tests/pg_fixture.py
test-web:
	cd web && npm test
	python3 tests/web_smoke.py

.PHONY: test-soak test-static-container test-static-admin-relay-container coverage-postgres
test-soak:
	python3 tests/soak.py
test-static-container:
	python3 tests/static_container.py
test-static-admin-relay-container:
	python3 tests/admin_gateway_static_container.py
coverage-postgres:
	HANGANG_PG_COVERAGE=1 python3 tests/pg_fixture.py
	cargo llvm-cov report --summary-only --ignore-filename-regex '/tests/'

.PHONY: test-redis test-kubernetes test-acme
test-redis:
	python3 tests/redis_fixture.py
test-kubernetes:
	python3 tests/kubernetes_cluster.py
test-acme:
	HANGANG_PEBBLE_TEST=1 cargo test --test acme -- --include-ignored --test-threads=1

.PHONY: coverage-redis coverage-acme
coverage-redis:
	HANGANG_REDIS_COVERAGE=1 HANGANG_BINARY=$(CURDIR)/target/llvm-cov-target/debug/hangang LLVM_PROFILE_FILE='$(CURDIR)/target/llvm-cov-target/hangang-extra-%p-%m.profraw' python3 tests/redis_fixture.py
	cargo llvm-cov report --summary-only --ignore-filename-regex '/tests/'
coverage-acme:
	HANGANG_PEBBLE_TEST=1 cargo llvm-cov --no-report --test acme -- --include-ignored --test-threads=1
	cargo llvm-cov report --summary-only --ignore-filename-regex '/tests/'

.PHONY: test-transforms
test-transforms:
	cargo test --locked --test transform_body --test transform_http --test policy_process --test admin_api
	python3 examples/transforms/run.py

.PHONY: test-cache
test-cache:
	cargo test --locked --lib cache
	cargo test --locked --test cache_http --test admin_api
	cargo build --locked
	python3 examples/cache/run.py

.PHONY: test-sni
test-sni:
	cargo test --locked --test certificates --test config_tls --test sni_config --test sni_passthrough --test tcp
	cargo build --locked
	python3 examples/sni/run.py

.PHONY: test-upstream
test-upstream:
	cargo test --locked --lib upstream::tests
	cargo test --locked --test upstream_http --test upstream_dns --test tcp_outbound
	cargo build --locked
	python3 examples/upstream/run.py

.PHONY: test-fleet
test-fleet:
	cargo build --locked --bin hangang
	python3 examples/fleet-observer/run.py
	python3 tests/fleet_observer_tls.py
	HANGANG_FLEET_BROWSER=1 python3 tests/fleet_collector_https.py
	python3 tests/fleet_collector_transport.py
	python3 tests/fleet_inventory_reload.py
