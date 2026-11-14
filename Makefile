.PHONY: build release check fmt fmt-check clippy doc lint test test-unit test-live test-extended test-writeback test-sccache-clean test-clean-unit test-setup-action ci clean all \
	install uninstall loadgen bench-sccache bench-sccache-build bench-sccache-all

# Default: format + full CI-local gate (lint + unit + live when SMB creds set).
# Prefer `make ci` explicitly when validating a PR — see AGENTS.md.
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
test-unit: test-clean-unit test-setup-action test-agent-install
	# --features loadgen so spiceio-loadgen and spiceio-sccache-nas tests run:
	# loadgen's status classifier, and the NAS durability checker's path /
	# listing / digest tests (no SMB). They would silently not compile without it.
	cargo test --locked --features loadgen

# `make install`'s launchd half and the sccache-spiceio wrapper, against a
# stubbed launchctl: plist edits, key creation, reload-vs-kickstart, and the
# post-restart auth check. Touches no real agent.
.PHONY: test-agent-install
test-agent-install:
	cargo build --locked --bin spiceio
	bash scripts/test-agent-install.sh target/debug/spiceio

# Setup-action download helper (no gh / curl-to-GitHub). Includes the
# two-server check that Authorization is not forwarded on a host change.
test-setup-action:
	bash .github/actions/setup/test-download-release.sh

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

# All live SMB suites CI runs (sccache + extended + conditional + write-back +
# stress + auth).
test-live: build
	./scripts/ci-local.sh --live-only

test-extended: build test
	./scripts/test-sccache-spiceai.sh

# Write-back acknowledgement + machine-wide disk spill, on their own.
test-writeback: build
	./scripts/test-writeback.sh

# SigV4 enforce/log/off against real signers, and aws-chunked decoding.
.PHONY: test-auth
test-auth: build
	./scripts/test-auth.sh

.PHONY: test-conditional
test-conditional: build
	python3 scripts/test-conditional.py

# Full parity with .github/workflows/ci.yml. Use this before declaring a PR
# green when NAS credentials are available. Fails if live suites are skipped
# while CI_REQUIRE_LIVE=1 (default when SMB creds are set).
ci:
	./scripts/ci-local.sh

# ── sccache performance ─────────────────────────────────────────
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

# ── local install ───────────────────────────────────────────
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
# The agent requires SigV4. install sets the agent's SPICEIO_S3_AUTH to
# AGENT_AUTH: enforce, log (verify and log, but serve anyway; for moving
# clients over) or off. AGENT_AUTH=keep leaves its auth settings alone. An
# agent that names no credentials file gets S3_CREDENTIALS_FILE, created with
# a fresh key if it does not exist. A file that exists is never rewritten.
AGENT_AUTH ?= enforce
S3_CREDENTIALS_FILE ?= $(HOME)/.config/spiceio/credentials

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
#
# sccache-spiceio is sccache with the agent's key, for RUSTC_WRAPPER (see the
# script). scripts/agent-install.sh does the launchd half: it sets the
# agent's SigV4 settings in its plist, restarts it (a reload if the plist
# changed, since kickstart keeps the old environment), then reports where it
# listens and checks that an unsigned request is refused and a request
# signed through sccache-spiceio is served. It never chooses a listen
# address; it warns when the agent's SPICEIO_BIND is reachable beyond this host.
install: release
	install -d "$(BINDIR)"
	install -m 0755 target/release/spiceio "$(BINDIR)/spiceio"
	install -m 0755 scripts/sccache-spiceio "$(BINDIR)/sccache-spiceio"
	rm -rf "$(BINDIR)/spiceio.dSYM.new"
	cp -RL target/release/spiceio.dSYM "$(BINDIR)/spiceio.dSYM.new"
	rm -rf "$(BINDIR)/spiceio.dSYM"
	mv "$(BINDIR)/spiceio.dSYM.new" "$(BINDIR)/spiceio.dSYM"
	@echo "installed $$("$(BINDIR)/spiceio" --version) -> $(BINDIR)/spiceio (+ sccache-spiceio)"
	@case ":$$PATH:" in \
	  *":$(BINDIR):"*) ;; \
	  *) echo "note: $(BINDIR) is not on PATH" ;; \
	esac
	@BINDIR="$(BINDIR)" LAUNCHD_LABEL="$(LAUNCHD_LABEL)" RESTART_AGENT="$(RESTART_AGENT)" \
	  AGENT_AUTH="$(AGENT_AUTH)" S3_CREDENTIALS_FILE="$(S3_CREDENTIALS_FILE)" \
	  ./scripts/agent-install.sh

# Removes what `install` wrote. Leaves the launchd agent, its config, its log
# and the credentials file alone. Those are configuration, not ours to remove:
# a bootout would be a surprise from uninstalling the binary, and deleting
# the key would lock out every client that signs with it.
uninstall:
	rm -f "$(BINDIR)/spiceio" "$(BINDIR)/sccache-spiceio"
	rm -rf "$(BINDIR)/spiceio.dSYM"

clean:
	cargo clean
