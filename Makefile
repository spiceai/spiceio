.PHONY: build release check fmt fmt-check clippy doc lint test test-unit test-live test-extended test-writeback test-sccache-clean test-clean-unit ci clean all \
	loadgen bench-sccache bench-sccache-build bench-sccache-all

# Default: format + full CI-local gate (lint + unit + live when SMB creds set).
# Prefer `make ci` explicitly when validating a PR — see CLAUDE.md.
all: fmt ci

build:
	cargo build --locked --all-targets --all-features

release:
	cargo build --release --locked

check:
	cargo check --locked --all-targets --all-features

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all --check

clippy:
	cargo clippy --locked --all-targets --all-features -- -D warnings -D clippy::all -D clippy::cargo -A clippy::cargo-common-metadata

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --no-deps --document-private-items

# Fast static gate only — NOT sufficient to claim CI will pass.
lint: fmt-check check clippy doc

# Unit tests only (no SMB).
test-unit: test-clean-unit
	# --features loadgen so spiceio-loadgen's own tests run: they cover the
	# per-operation status classifier that decides whether the load burst can
	# see a failed write, and would silently not compile without it.
	cargo test --locked --features loadgen

test-clean-unit:
	python3 scripts/test-sccache-clean-unit.py

# Destructive retention test against an already-running instance. Requires
# SCCACHE_BUCKET; SCCACHE_ENDPOINT and SCCACHE_S3_KEY_PREFIX select the cache.
test-sccache-clean:
	./scripts/test-sccache-clean.py

# CI sccache integration (requires SPICEIO_SMB_USER/PASS). This is the gate
# that custom curl benches do NOT replace.
test: build
	./scripts/test-sccache.sh

# All live SMB suites CI runs (sccache + extended + write-back + stress).
test-live: build
	./scripts/ci-local.sh --live-only

test-extended: build test
	./scripts/test-sccache-spiceai.sh

# Write-back acknowledgement + machine-wide disk spill, on their own.
test-writeback: build
	./scripts/test-writeback.sh

# Full parity with .github/workflows/ci.yml. Use this before declaring a PR
# green when NAS credentials are available. Fails if live suites are skipped
# while CI_REQUIRE_LIVE=1 (default when SMB creds are set).
ci:
	./scripts/ci-local.sh

# ── sccache performance ─────────────────────────────────────────────────────
#
# Benchmarks, not gates: they measure, they do not pass or fail, and they are
# never run by `make ci`. Both need SPICEIO_SMB_USER/PASS and write timestamped
# results under benches/results/.

# The load generator lives behind a feature so `make release` stays lean.
loadgen:
	cargo build --release --locked --features loadgen --bin spiceio-loadgen

# Synthetic sccache-shaped load: concurrency sweep, latency percentiles, and
# per-request server-side attribution from the access log.
bench-sccache: release loadgen
	./scripts/bench-sccache.sh

# Real cargo builds through sccache, comparing spiceio against a local-disk
# cache (the floor) and an uncached build (the ceiling).
bench-sccache-build: release
	./scripts/bench-sccache-build.sh

bench-sccache-all: bench-sccache bench-sccache-build

clean:
	cargo clean
