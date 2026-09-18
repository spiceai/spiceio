.PHONY: build release check fmt fmt-check clippy doc lint test test-unit test-live test-extended test-writeback test-sccache-clean test-clean-unit ci clean all \
	install uninstall loadgen bench-sccache bench-sccache-build bench-sccache-all

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
	python3 scripts/test-sccache-nas.py self-test

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

# ── local install ───────────────────────────────────────────────────────────
#
# Puts the optimized build where a long-running local instance picks it up
# (the launchd agent runs `~/.local/bin/spiceio`). Override BINDIR or PREFIX
# to install elsewhere.

PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin
LAUNCHD_LABEL ?= ai.spice.spiceio
# A loaded launchd agent keeps executing the binary it started, so an install
# that does not restart it changes nothing for its clients. RESTART_AGENT=0
# stages the new binary and leaves the running one alone.
RESTART_AGENT ?= 1

# The dSYM is installed alongside the binary the way the release tarball ships
# it: release builds are stripped, so without it a crash report from the
# installed binary is raw addresses with nothing to resolve them against.
# install(1) replaces the target through a temp file and a rename, so
# overwriting a *running* binary is safe — the live process keeps the old
# inode until it restarts. The dSYM is a bundle, so it gets the same treatment
# by hand: copy beside the old one, then swap, so a failed copy (out of space)
# leaves the previous one intact rather than nothing at all. `cp -RL` because
# cargo leaves target/release/spiceio.dSYM as a *symlink* into deps/ — copying
# it verbatim installs a dangling link that symbolizes nothing.
install: release
	install -d "$(BINDIR)"
	install -m 0755 target/release/spiceio "$(BINDIR)/spiceio"
	rm -rf "$(BINDIR)/spiceio.dSYM.new"
	cp -RL target/release/spiceio.dSYM "$(BINDIR)/spiceio.dSYM.new"
	rm -rf "$(BINDIR)/spiceio.dSYM"
	mv "$(BINDIR)/spiceio.dSYM.new" "$(BINDIR)/spiceio.dSYM"
	@echo "installed $$("$(BINDIR)/spiceio" --version) -> $(BINDIR)/spiceio"
	@case ":$$PATH:" in \
	  *":$(BINDIR):"*) ;; \
	  *) echo "note: $(BINDIR) is not on PATH" ;; \
	esac
	@if launchctl print "gui/$$(id -u)/$(LAUNCHD_LABEL)" >/dev/null 2>&1; then \
	  if [ "$(RESTART_AGENT)" != "0" ]; then \
	    echo "restarting $(LAUNCHD_LABEL) (SIGTERM: in-flight requests and the write-back backlog drain first)"; \
	    launchctl kickstart -k "gui/$$(id -u)/$(LAUNCHD_LABEL)"; \
	  else \
	    echo "note: $(LAUNCHD_LABEL) still runs the previous binary; restart it with"; \
	    echo "      launchctl kickstart -k gui/$$(id -u)/$(LAUNCHD_LABEL)"; \
	  fi; \
	fi

# Removes what `install` wrote. Leaves the launchd agent, its config and its
# log alone — those are not ours to remove, and a bootout would be a surprise
# from an uninstall of the binary.
uninstall:
	rm -f "$(BINDIR)/spiceio"
	rm -rf "$(BINDIR)/spiceio.dSYM"

clean:
	cargo clean
