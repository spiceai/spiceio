.PHONY: build release check fmt fmt-check clippy doc lint test test-unit test-live test-extended ci clean all

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
test-unit:
	cargo test --locked

# CI sccache integration (requires SPICEIO_SMB_USER/PASS). This is the gate
# that custom curl benches do NOT replace.
test: build
	./scripts/test-sccache.sh

# All live SMB suites CI runs (sccache + extended + stress).
test-live: build
	./scripts/ci-local.sh --live-only

test-extended: build test
	./scripts/test-sccache-spiceai.sh

# Full parity with .github/workflows/ci.yml. Use this before declaring a PR
# green when NAS credentials are available. Fails if live suites are skipped
# while CI_REQUIRE_LIVE=1 (default when SMB creds are set).
ci:
	./scripts/ci-local.sh

clean:
	cargo clean
