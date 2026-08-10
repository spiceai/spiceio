# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is spiceio

spiceio is an S3-compatible API proxy that translates S3 HTTP requests into SMB 3.1.x file operations. It speaks the SMB wire protocol directly over TCP (no mount, no libsmbclient) and uses macOS CommonCrypto via FFI for all cryptographic primitives (NTLMv2 auth, SHA-256, HMAC). Targets macOS 26+ only.

## Design principles

- **Reliability and resilience** — handle errors gracefully, recover from transient failures, never corrupt data. Correctness comes first.
- **High performance** — minimize allocations, avoid unnecessary copies, use efficient I/O patterns. The proxy should not be the bottleneck.
- **macOS 26+ only** — leverage core OS APIs (CommonCrypto, Security.framework, system libraries) wherever possible instead of pulling in external crates. Keep the dependency tree minimal.
- **SMB 3.1.x** — implement the SMB 3.1.x dialect family. Stay current with protocol capabilities.

## Build & Run

```bash
make                           # fmt + full CI-local gate (see make ci)
make ci                        # **required before PR green** — parity with .github/workflows/ci.yml
make release                   # optimized release build
make lint                      # static only: fmt-check + check + clippy + rustdoc (NOT full CI)
make test-unit                 # cargo test --locked (no SMB)
make test                      # sccache integration only (requires SPICEIO_SMB_USER/PASS)
make test-live                 # sccache + extended + write-back + stress (CI live steps)
make test-writeback            # write-back ack + machine-wide spill, on their own
make fmt                       # auto-format
make clean                     # cargo clean

make bench-sccache             # synthetic sccache-shaped load, concurrency sweep
make bench-sccache-build       # real cargo builds: spiceio vs local-disk vs no cache
make bench-sccache-all         # both
```

### Measuring sccache performance

The two bench targets answer different questions and are **measurements, not
gates** — `make ci` never runs them.

- `make bench-sccache` drives `spiceio-loadgen` (a dependency-free HTTP/1.1
  client built behind the `loadgen` feature) over **persistent keep-alive
  connections**, which is how sccache actually talks to the proxy. It sweeps
  concurrency, reports p50/p90/p99/p99.9 and TTFB per operation class, and runs
  a second pass with the GET body cache disabled so proxy-cache hits and real
  NAS reads are not conflated. Do not go back to per-request `curl` fan-out: it
  pays a TCP handshake per request and cannot offer enough load to find the knee.
- `make bench-sccache-build` runs real `cargo build`s three ways — no cache,
  sccache on local disk, sccache through spiceio — and reads sccache's own JSON
  stats (`--stats-format json`) for per-hit and per-write latency. The local-disk
  arm is the floor; a warm-build number without it is not interpretable.

Both write timestamped output to `benches/results/` (gitignored). Committed
reference runs live in `benches/baselines/`.

**A single before/after pair does not decide anything here.** The NAS is shared,
and a plain baseline-then-change comparison moved several metrics in *both*
directions by more than the effect being measured — the same change read as
+333% on one phase and −37% on another. Alternate the arms (A,B,A,B,…) so drift
spreads across both instead of landing on whichever ran second, take at least
three reps, and compare medians *with the per-rep spread printed* — a median
difference smaller than the spread is not a result. The `mixed` phase (70% GET
hit / 20% miss / 10% PUT) is the one that tracks a real sccache client; `put`
alone measures memory bandwidth once write-back acknowledges from memory. Note
that the standard sweep's ~300 MiB working set never reaches the write-back
ceiling, so any change to backlog/backpressure behaviour needs
`BENCH_OBJECTS`/`BENCH_OPS_PER_WORKER` raised past it to be exercised at all.

`SPICEIO_ACCESS_LOG=<path>` turns on a per-request TSV log
(`t_ms method status req_bytes resp_bytes head_us total_us path`). `head_us` is
time to the response head (for GetObject: SMB open + first read); `total_us`
also covers streaming the body, so the gap between them is streaming cost.
Comparing it against client-side latency attributes time to spiceio versus the
client and the network. Off by default and free when off.

### PR / agent verification gate (do not skip)

**`make lint` alone is not enough** to claim CI will pass. CI also runs unit tests
and four live SMB suites (`test-sccache.sh`, `test-extended.sh`,
`test-writeback.sh`, `stress-concurrent.sh`) against the shared NAS.

Before declaring a PR green when NAS credentials are available:

```bash
source /tmp/spiceio-bench-env.sh   # or export SPICEIO_SMB_USER/PASS/SERVER/SHARE
make ci                           # or: ./scripts/ci-local.sh
```

Rules:

- Custom curl benches / 10× stress **do not replace** `scripts/test-sccache.sh`.
  That script asserts sccache **cache hits > 0 and write errors == 0** — the
  exact failure mode unit tests and HTTP-only benches miss.
- `scripts/test-writeback.sh` is the only check that an *asynchronously
  acknowledged* write reaches the NAS. It cannot be replaced by asserting
  against the instance that took the write — that instance's own cache answers
  either way — so it restarts and reads back through a second instance with
  write-back and the spill both off.
- If `SPICEIO_SMB_USER`/`PASS` are set, `make ci` **requires** the live suites
  (`CI_REQUIRE_LIVE=1` by default). Do not unset credentials to skip them.
- Without credentials, `make ci` still runs lint + unit tests and prints SKIP
  for live suites (set `CI_REQUIRE_LIVE=1` to force a hard fail).

The binary requires these environment variables:
- `SPICEIO_SMB_SERVER` (required) — SMB server hostname or IP
- `SPICEIO_SMB_USER` (required) — SMB username
- `SPICEIO_SMB_PASS` (required) — SMB password
- `SPICEIO_SMB_SHARE` (required) — SMB share name
- `SPICEIO_BIND` — listen address (default `0.0.0.0:8333`)
- `SPICEIO_SMB_PORT` — SMB port (default `445`)
- `SPICEIO_SMB_DOMAIN` — SMB domain (default empty)
- `SPICEIO_BUCKET` — virtual S3 bucket name (defaults to `SPICEIO_SMB_SHARE`)
- `SPICEIO_REGION` — AWS region to advertise (default `us-east-1`)
- `SPICEIO_SMB_CONNECTIONS` — number of SMB TCP connections in the pool (default: **2 × CPU count, clamped to 8–32**). A latency knob, not a throughput one — see `default_pool_size`
- `SPICEIO_SMB_MAX_IO` — max standalone read/write I/O size in bytes (default `262144`; raise for servers that handle larger I/O)
- `SPICEIO_MULTIPART_TTL_SECS` — age at which an abandoned multipart upload is reaped (default `86400`)
- `SPICEIO_CLEANUP_GRACE_SECS` — startup cleanup leaves WAL temps / upload dirs newer than this alone (default `900`), so instances sharing one share don't delete each other's in-flight state; `0` restores a blanket sweep
- `SPICEIO_LOG_FILE` — append logs to this file in addition to stderr (optional; non-blocking, never stalls the proxy)
- `SPICEIO_ACCESS_LOG` — per-request TSV metrics log for benchmarking (optional; off by default, one atomic load per request when off)
- `SPICEIO_OBJECT_CACHE_BYTES` — max total GET body cache size (default `8589934592` = **8 GiB**, i.e. up to 8 GiB resident). **The most effective tuning knob**: the body cache is the only path that answers a GET without backend I/O, and eviction is O(log n) so a large cache costs no CPU. Budget is logged at startup, hit rate at shutdown; lower it on hosts that cannot spare the memory
- `SPICEIO_OBJECT_CACHE_MAX_OBJECT` — max size of a single cached object (default: 1/64 of the budget, so it scales with it — 128 MiB at the 8 GiB default). The cap is about how many *other* objects one admission evicts: a fixed 32 MiB cap against a 256 MiB budget measured a hit-rate drop from 93% to 60%
- `SPICEIO_OBJECT_CACHE_ENTRIES` — max cache entries (default `131072`, sized so *bytes* stay the binding constraint rather than the entry count)
- `SPICEIO_SPILL_DIR` — machine-wide disk tier behind the memory cache (default `/var/tmp/spiceio-cache`; `off` or empty disables). Shared by every spiceio instance on the host, so a second instance benefits from the first one's reads and the cache is not bounded by one process's memory. Created 0700 — sharing is between processes of the same user, because a world-writable cache lets any local user plant an entry that a correct digest makes indistinguishable from a real one; an existing directory keeps its permissions, so a group-shared one is opt-in. Budget is clamped so at least 10 GiB stays free and to half the space above that, recomputed every sweep
- `SPICEIO_SPILL_BYTES` — disk budget for the whole spill directory, across all instances (default `68719476736` = **64 GiB**)
- `SPICEIO_WRITE_BACK` — acknowledge PutObject from memory and write to the NAS in the background (**on by default**; `0`/`false`/`off` disables). **Trades durability for latency**: a crash between the 200 and the background write loses that object (recoverable once it reaches the spill, which is where the flusher puts it first). Measured 2.6–6.7× end to end on a put-then-read sweep. Right for a cache backend, wrong for a system of record
- `SPICEIO_WRITE_BACK_BYTES` — ceiling on un-flushed bytes before PutObject writes through synchronously (default `1073741824` = 1 GiB). This is the backpressure a backlogged NAS applies to clients
- `SPICEIO_IMMUTABLE_OBJECTS` — when `1`/`true`, serve a cached body by key with **no backend round trip at all** (content-addressed stores like sccache, where the key is a hash of the bytes). Default off (etag-revalidated, which still costs one SMB open per hit). Trades noticing a backend-side delete for the round trip — harmless for a cache, wrong for a mutable namespace

## Architecture

The codebase has five modules:

- **`s3`** — HTTP layer. Parses incoming S3 API requests and produces XML responses. `router.rs` is the central dispatch (path-style bucket routing). Covers GetObject, PutObject, CopyObject, DeleteObject, HeadObject, ListObjectsV1/V2, multipart uploads (including UploadPartCopy, the form `aws s3 cp`/`sync` use for objects above the ~8 MiB multipart threshold), and stub endpoints for ACL/tagging/versioning. `xml.rs` is a hand-rolled XML builder. `multipart.rs` manages upload state in-memory, with parts stored as temp files under `.spiceio-uploads/` on the SMB share. `body.rs` implements `SpiceioBody`, a zero-copy streaming response body (channel-backed for large reads, inline for XML/errors).

  Caching lives here too. `object_cache.rs` is the in-memory tier (L1) and the entry point to both; `spill.rs` is the second tier (L2) — a directory on local disk shared by every instance on the machine, addressed by `sha256(backend-identity \0 key)`, published by atomic rename, carrying a body digest so a torn or power-loss-damaged entry reads as a miss rather than a wrong answer. Its eviction is LRU against a machine-wide budget, serialized between processes by a non-blocking `flock`, and it doubles as the write-back journal: a not-yet-flushed body is named `.d` (dirty) rather than `.o`, which keeps the sweeper from evicting it and lets a restart — or a peer instance — find and replay writes stranded by a crash. `writeback.rs` is the queue behind `SPICEIO_WRITE_BACK`: bodies acknowledged to the client but not yet on the NAS, flushed by a small pool of workers (journal → NAS → adopt the backend's etag in both tiers). Every operation that could observe the gap consults it — GET/HEAD serve from the cache without revalidating, DELETE cancels or waits out a flush, LIST overlays pending keys, copy paths flush the source first — and per-key ordering is total: a key is queued at most once, and a write arriving mid-flush re-queues on completion.

- **`smb`** — Wire protocol client. `protocol.rs` defines SMB 3.1.x packet structures (little-endian). `client.rs` manages a TCP connection, negotiate/session-setup handshake, and exposes operations (tree connect, create, read, write, close, query directory, pipelined read). `pool.rs` manages N authenticated connections for concurrent request fan-out. `auth.rs` implements NTLMv2 challenge-response. `ops.rs` provides the high-level `ShareSession` abstraction the S3 layer consumes (list, read, write, delete, stat, copy).

- **`crypto`** — FFI bindings to macOS CommonCrypto (`Security.framework`/`libcommonCrypto`). Exposes MD4, MD5, SHA-256 (one-shot and streaming), SHA-512, HMAC-MD5, HMAC-SHA256, and AES-128-CMAC — between them they cover NTLMv2 auth, SMB 3.1.x preauth integrity, and signing. No Rust crypto crates: reach for `crypto::ffi` before adding a dependency, the primitive is probably already there.

- **`http`** — HTTP front-end tuning for the S3 listener (connection builder, header-read timeout, accept backoff, shutdown grace). Kept out of the accept loop so `tests/http_frontend.rs` exercises the same configuration the server runs with. HTTP/1.1 only — every S3 client speaks HTTP/1.1 to a plain-HTTP endpoint, and the protocol-sniffing `auto` server both pulls in the whole HTTP/2 stack and defers the header timeout past the connect-and-say-nothing case it exists for.

- **`crash`** — Crash reporting. A panic hook (location + backtrace, works with `panic = "abort"`) and an async-signal-safe fatal-signal handler (SIGSEGV/SIGBUS/SIGILL/SIGFPE/SIGTRAP/SIGABRT: fault address, registers, frame-pointer backtrace). Reports are written synchronously to stderr and `SPICEIO_LOG_FILE`, bypassing the async logger. Release builds stay stripped; `target/release/spiceio.dSYM` (from `split-debuginfo = "packed"`) symbolizes the raw addresses offline via `atos -l <image base>`. Tested end-to-end via the hidden `--crash-test <panic|segv|abort>` flag (`tests/crash_report.rs`).

**Request flow:** HTTP request → `s3::router::handle_request` → S3 operation → `smb::ops::ShareSession` method → `smb::client::SmbClient` wire operations → TCP to SMB server.

## Key design decisions

- Zero external crypto dependencies — all crypto goes through `crypto::ffi` to CommonCrypto.
- No `async-trait` — the SMB client uses `tokio::sync::Mutex` around the TCP stream with manual `async` methods.
- Connection pool — N TCP connections (default: 2 × CPU count, clamped 8–32) to the same SMB server. Concurrent S3 requests fan out across connections instead of serializing on a single mutex. File handles are pinned to the connection that opened them. Two per core rather than one because a connection owns its stream for a whole round trip, so pool size bounds head-of-line blocking rather than CPU work: measured on the mixed phase, 16 → 32 connections cut p90 by 52% at concurrency 32 and 36% at 64, and tightened the run-to-run spread, for one extra second of startup.
- Least-loaded dispatch — each connection tracks its queue depth via `StreamGuard`, the only way to reach the stream (so the accounting cannot be skipped) and `SmbPool::pick` sends new work to the shallowest healthy connection, rotating on ties. A connection owns its stream for a whole round trip, so blind round-robin could put a one-round-trip HEAD behind a multi-megabyte pipelined batch.
- Two-tier object cache — L1 in process memory, L2 on local disk shared machine-wide. L2 exists because the backend saturates at a fixed rate while local NVMe does not, and because a second instance should not re-fetch what the first already pulled down. A disk hit is promoted into memory; both tiers are written on the way out.
- Write-back is bounded and yields to readers — acknowledging a PUT before the NAS write is a durability trade, so it is capped by un-flushed bytes (past which PutObject writes through synchronously), drained at shutdown, and journalled to the spill so a crash is recoverable rather than silent. Flushers take the same admission slot live requests do, and stand down while **clients** are using the backend. The signal is client demand, not spare admission permits: admission is sized to keep every connection pipelined (`pool × 8` = 128 at the default pool of 16), while the NAS saturates at a measured concurrency of ~8, so a reserve expressed as a fraction of permits only engaged past ~96 concurrent requests — an order of magnitude too late. Measured with that old reserve, 32% of GETs in a put-then-get sweep took over 1 ms (median 48 ms among them) in seconds when *no client PUT was running at all*; they were queued behind the proxy's own drain. Yielding on demand instead measured +66%/+130% throughput and −35%/−52% p90 on the mixed sccache-shaped phase at concurrency 8/32. *Every* flusher yields — exempting one to keep the drain moving was measured on the sustained case it was meant for (a working set past the write-back ceiling, so the backlog genuinely reaches the urgent threshold) and came out slightly worse on every metric (−7% throughput, +10% p90, +8% p99), because the urgent override already stops the backlog growing untouched. The client yield is lifted once the backlog passes half the ceiling (PutObject is about to write through synchronously anyway) or the drain begins (there is no client left to defer to). A caller blocked in `flush_key` — CopyObject and UploadPartCopy, which need the source *on the NAS* — lifts it too, and must: it holds an admission slot while waiting, so counting it as client traffic deadlocked it against the flusher it was waiting on (two concurrent copies of an unclaimed pending source stalled both into a 503). **Journalling is deliberately not part of what yields.** Standing down defers the NAS write; the disk spill is local and costs the backend nothing, so a yielding flusher keeps writing memory-only bodies to the journal. Bolting the journal to the front of the NAS write meant deferring the write also deferred it becoming crash-recoverable, leaving acknowledged objects in memory alone until the backlog went urgent.
- Object body cache is the throughput lever — the backend saturates at a fixed rate (measured ~100 MiB/s; see `benches/baselines/`), and the cache is the only mechanism that beats it. Eviction is a `pop_first` on a use-generation index, not a scan, so the cache can be sized to a real working set. Writes populate it (write-through): a cache client reads back what it just wrote, and the bytes are already in hand. `SPICEIO_IMMUTABLE_OBJECTS` serves hits with no round trip at all.
- Zero-copy response bodies — each SMB response is read into one allocation and handed to decoders as `Bytes` views (`send_recv`, `parse_compound_response`, `decode_read_response_bytes`), so no read payload is memcpy'd out of its buffer.
- Proactive keepalive — the healer probes connections idle for 45s with SMB2 ECHO, and SMB sockets enable TCP keepalive, so a session dropped while idle is poisoned and reconnected before a client request lands on it.
- Verified before publish — `WalWriter::commit` stats the temp file *before* the rename and refuses to publish if it is shorter than the bytes written, so a failed check leaves any existing object untouched. `assemble_parts` checks each part against its acknowledged size while streaming, and `collect_body` enforces Content-Length for every buffered body path. Nothing corrupt reaches the client's key, so no compensating delete (which would race a concurrent writer) is needed.
- Server-side copy — CopyObject, UploadPartCopy and multipart assembly issue `FSCTL_SRV_COPYCHUNK_WRITE` (after `FSCTL_SRV_REQUEST_RESUME_KEY`), so the NAS copies the bytes internally and they never cross the proxy. Probed once per process; a server that answers "not supported" falls back to streaming for the rest of the run.
- Multi-instance safety — startup cleanup only sweeps WAL temps / upload dirs older than `SPICEIO_CLEANUP_GRACE_SECS`, judged on the *server's* clock (measured by writing a probe file, so clock skew can't age a live file out) — several instances can serve one share. The reaper refreshes each live upload's marker file so a slow client's upload never looks abandoned.
- Directory listings ask for up to 1 MiB of entries per QUERY_DIRECTORY (credit-charged accordingly) instead of a fixed 64 KiB, cutting round trips on wide prefixes.
- Pipelined reads — streaming GetObject sends a batch of read requests (up to `READ_PIPELINE_DEPTH` = 64, bounded by the adaptive in-flight budget) before collecting responses, hiding per-request round-trip latency.
- HTTP front end — `TCP_NODELAY` on accepted sockets (S3 responses are small and latency-sensitive), a 120s header-read timeout that also reclaims idle/half-dead connections, a backoff on `accept()` errors so descriptor exhaustion can't spin the loop, and a graceful shutdown that drains in-flight requests (30s cap) before exit.
- The four stop signals drain — SIGTERM, SIGINT, SIGHUP and SIGQUIT take the graceful path, and a second one stops immediately. Not *every* terminating signal: SIGUSR1/SIGALRM and friends still kill without draining, and SIGKILL cannot be caught. Catching these four is a write-back requirement, not tidiness. Measured against v0.7.0, which caught only SIGTERM/SIGINT: an uncaught SIGHUP against a 240 MiB backlog lost **225 of 240 acknowledged writes**, and SIGQUIT did not stop the process at all within 30s (an operator would reach for SIGKILL and lose the same writes). What an *uncatchable* stop loses is bounded separately, by journalling acknowledged bodies to the spill continuously rather than only at the head of their own flush — see the write-back bullet. `scripts/test-writeback.sh` §8 asserts the signal behaviour per signal.
- SMB2 credit accounting — each connection tracks its credit balance (grants banked from every response's `CreditResponse`, charges consumed in lockstep with MessageId allocation). Pipelined batches clamp to the balance and oversized single I/O splits, so in-flight charge never exceeds the server-granted sequence window.
- Configurable I/O cap — standalone read/write ops default to 256 KB (the measured streaming sweet spot); raisable via `SPICEIO_SMB_MAX_IO`, always clamped to the server's negotiated max. Compound operations always cap at 64 KB.
- GetObject streams SMB read chunks directly to the HTTP response via `SpiceioBody::channel` — no full-file buffering.
- PutObject streams HTTP request body chunks directly to SMB write calls — no full-body collection.
- Body is collected into `Bytes` only for operations that require the full payload (multi-delete, multipart complete, upload-part for ETag hashing).
- S3 path-style addressing only (no virtual-hosted-style).
- Multipart upload parts are stored as temporary SMB files, not in memory.
