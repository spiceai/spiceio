#!/usr/bin/env bash
# ── CI-local gate ────────────────────────────────────────────────────────────
#
# Run the *same* checks GitHub Actions runs in `.github/workflows/ci.yml`, on
# this machine. This exists so agents and humans cannot declare a PR "green"
# after only `make lint` or a custom curl bench — those leave a gap that CI
# then fails (see the sccache write-error flake that unit/stress benches miss).
#
# Usage:
#   source /tmp/spiceio-bench-env.sh   # or export SPICEIO_SMB_* yourself
#   ./scripts/ci-local.sh
#
# Env:
#   CI_REQUIRE_LIVE=1   Fail if SMB credentials are missing (default: 1 when
#                       SPICEIO_SMB_USER is set, else 0 so pure lint PRs work).
#   SPICEIO_SMB_*       Same as CI / the live test scripts.
#   SPICEIO_SMB_CONNECTIONS  Forced to 8 for live steps to match CI job env
#                       unless already set.
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

LIVE_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --live-only) LIVE_ONLY=1 ;;
        -h|--help)
            echo "Usage: $0 [--live-only]"
            echo "  (default)  lint + unit + build + live SMB suites"
            echo "  --live-only  only the three CI live scripts (assumes binary built)"
            exit 0
            ;;
        *)
            echo "unknown arg: $arg (try --help)" >&2
            exit 2
            ;;
    esac
done

have_smb=0
if [[ -n "${SPICEIO_SMB_USER:-}" && -n "${SPICEIO_SMB_PASS:-}" ]]; then
    have_smb=1
fi

# Default: require live tests whenever credentials are present; otherwise allow
# lint-only (e.g. docs-only work without NAS access).
if [[ -z "${CI_REQUIRE_LIVE:-}" ]]; then
    if [[ "$have_smb" -eq 1 ]]; then
        CI_REQUIRE_LIVE=1
    else
        CI_REQUIRE_LIVE=0
    fi
fi

step() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo " ci-local: $*"
    echo "═══════════════════════════════════════════════════════════════"
}

run_live_suites() {
    # Match CI job-level pool pin so local and CI see the same concurrency.
    export SPICEIO_SMB_CONNECTIONS="${SPICEIO_SMB_CONNECTIONS:-8}"
    # CI defaults when repo vars are unset.
    export SPICEIO_REGION="${SPICEIO_REGION:-us-west-1}"

    step "sccache integration (scripts/test-sccache.sh)"
    (
        export SPICEIO_BUCKET="${SPICEIO_BUCKET:-spiceio}"
        export SPICEIO_BIND="${SPICEIO_BIND:-127.0.0.1:18333}"
        ./scripts/test-sccache.sh
    )

    step "extended S3 ops (scripts/test-extended.sh)"
    (
        export SPICEIO_BUCKET=extended
        export SPICEIO_BIND=127.0.0.1:18336
        export AWS_DEFAULT_REGION="${SPICEIO_REGION}"
        ./scripts/test-extended.sh
    )

    step "concurrent stress (scripts/stress-concurrent.sh)"
    (
        export SPICEIO_BUCKET=stress
        export SPICEIO_BIND=127.0.0.1:18335
        export AWS_DEFAULT_REGION="${SPICEIO_REGION}"
        ./scripts/stress-concurrent.sh
    )
}

if [[ "$LIVE_ONLY" -eq 0 ]]; then
    # ── 1. Lint (fmt + check + clippy + rustdoc) — same flags as CI ───────
    step "lint (make lint)"
    make lint

    # ── 2. Unit tests ─────────────────────────────────────────────────────
    step "unit tests (cargo test --locked --features loadgen)"
    # --features loadgen also runs spiceio-loadgen's status-classifier tests.
    cargo test --locked --features loadgen

    # ── 3. Debug binaries (live scripts expect ./target/debug/spiceio, and
    #      test-sccache.sh's load burst expects ./target/debug/spiceio-loadgen)
    step "build debug binaries"
    cargo build --locked --features loadgen --bins
fi

# ── Live SMB suites (exactly what CI runs when HAS_SMB_PASS) ──────────────
if [[ "$have_smb" -eq 1 ]]; then
    run_live_suites
elif [[ "$CI_REQUIRE_LIVE" == "1" || "$LIVE_ONLY" -eq 1 ]]; then
    echo ""
    echo "ci-local: FAIL — live suites required but SPICEIO_SMB_USER/PASS are not set."
    echo "  Export credentials (or source /tmp/spiceio-bench-env.sh) and re-run."
    echo "  Live suites (test-sccache / test-extended / stress-concurrent) are what"
    echo "  CI runs; skipping them is how sccache write-error failures ship."
    exit 1
else
    echo ""
    echo "ci-local: SKIP live SMB suites (SPICEIO_SMB_USER/PASS not set)."
    echo "  Set CI_REQUIRE_LIVE=1 to force failure without credentials."
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " ci-local: ALL CHECKS PASSED (parity with .github/workflows/ci.yml)"
echo "═══════════════════════════════════════════════════════════════"
