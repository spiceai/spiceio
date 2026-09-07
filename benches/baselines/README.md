# sccache performance baseline

Reference runs for `make bench-sccache` and `make bench-sccache-build`. Compare
a change against these numbers before claiming it helped.

The [2026-09-07 correctness and retention comparison](20260907-correctness-retention/README.md)
adds all functional suites and 1,272 measurements from three alternating
before/after repetitions. It records zero request errors after the fixes and
a 32.6% sustained mixed-throughput regression at concurrency 32.

| | |
| --- | --- |
| current baseline | **2026-08-09**, v0.7.0 + write-back scheduling fixes |
| superseded | 2026-08-04/05, v0.5.10 (`dc53e1f`) — kept below for the defect writeup |
| host | macOS 26 (Darwin 25.6.0), Mac15,8, 16 cores, **10GbE** uplink |
| NAS | `smb://<nas>/<share>` (shared — expect run-to-run noise) |
| sccache | 0.17.0 |

Raw artifacts: `20260809-build-spiceai/` and `20260809-writeback-pool/` are the
current ones. `20260804-synthetic/`, `20260804-build/`, `20260804-pool-sweep.log`,
`20260804-build-spiceai/` and `20260805-build-spiceai-postfix/` are the
superseded runs, kept because §5 and §6 reference their evidence.

### What is not committed

**No logs, and no host or share identifiers.** This repository is public. The
proxy log (`SPICEIO_LOG_FILE`) and the per-request access log
(`SPICEIO_ACCESS_LOG`) both carry the backend's address, the share name and
local filesystem paths; the access log is also ~0.5–0.75 MB per run. Neither is
needed to read a baseline, so committed artifacts are limited to reports,
result tables and `sccache --show-stats` output, with the backend written as
`smb://<nas>/<share>`. Everything is still written to `benches/results/`
(gitignored) on every run, so the detail is there locally when a run needs
diagnosing.

`.gitignore` enforces the log half of this; the identifiers are on whoever adds
a run to scrub.

> Some pre-2026-08-09 baselines still contain proxy logs with those details.
> They predate this rule and are already in the public history, so removing them
> now would need a history rewrite rather than a deletion commit.

## How to compare against these

**A single before/after pair does not decide anything on this rig.** The NAS is
shared, and a plain baseline-then-change comparison has moved metrics in *both*
directions by more than the effect under test — one change read as +333% on one
phase and −37% on another in the same run. Alternate the arms (A,B,A,B,…), take
at least three reps, and compare medians **with the per-rep spread printed**; a
median difference smaller than the spread is not a result. The `mixed` phase
(70% GET hit / 20% miss / 10% PUT) is the one that tracks a real sccache client.
`put` alone measures memory bandwidth, since write-back acknowledges from memory.

Note that the standard synthetic sweep's ~300 MiB working set never reaches the
write-back ceiling, so any change to backlog or backpressure behaviour needs
`BENCH_OBJECTS`/`BENCH_OPS_PER_WORKER` raised past it to be exercised at all.

## Headline

1. **The data path saturates at ~100 MiB/s and reaches it at concurrency 8.**
   Beyond that, added concurrency buys zero throughput and adds latency
   proportionally. The in-memory GET cache is the only thing that beats the
   ceiling. (§1, still current.)
2. **A real warm build is now 1.16–1.26× local disk, and a cold build is at
   parity.** Was 1.40× warm / 1.16× cold. Per *write*, spiceio is now faster
   than local disk — write-back acknowledges from memory. (§4.)
3. **The proxy's own write drain was the main source of read tail latency.**
   32% of GETs in a put-then-get sweep took over 1 ms (median 48 ms among them)
   in seconds when no client PUT was running at all: they were queued behind
   write-back flushing. Fixing what the flushers yield to measured +66%/+130%
   throughput and −35%/−52% p90 on the mixed phase. (§6.)
4. **The connection pool is a latency knob, and 12–16 was too small.** The
   default is now 2 × CPU clamped 8–32. At 32 the mixed phase's p90 fell 52% at
   concurrency 32 and 36% at 64 versus 16, and the run-to-run spread tightened
   markedly. (§3.)
5. **spiceio dropped 3.3% of large writes under burst load** — found 2026-08-04,
   fixed. Kept in §5 because the mechanism and the gate that missed it are worth
   remembering.

## 1. Throughput ceiling (synthetic, concurrency sweep)

From the 2026-08-04 run at pool 12; the ceiling is a property of the NAS and has
not moved. `nocache` disables spiceio's GET body cache, so every read reaches
the NAS.

| conc | PUT MiB/s | GET MiB/s (nocache) | GET MiB/s (cached) | PUT p50 | GET p50 (nocache) |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 44.1 | 50.6 | 151.4 | 3.7ms | 2.4ms |
| 8 | 93.7 | 101.0 | 312.5 | 23.0ms | 9.5ms |
| 32 | 95.7 | 100.8 | 276.0 | 87.7ms | 83.6ms |
| 64 | 103.3 | 102.2 | 308.7 | 173.1ms | 239.0ms |
| 128 | 101.5 | 100.5 | 321.1 | 485.7ms | 563.4ms |
| 256 | 102.4 | 97.2 | 327.6 | 1238.8ms | 1311.7ms |

Reads and writes hit the *same* ~100 MiB/s wall, and both are already there at
concurrency 8. From 8 → 256 concurrency, PUT throughput moves 94 → 102 MiB/s
(+9%) while p50 latency grows 54× (23ms → 1239ms). That is a fixed-capacity
server absorbing all extra offered load as queue depth.

Metadata operations are unaffected and scale normally — HEAD sustains
7,000–13,500 ops/s with p50 under 36ms even at concurrency 256. **Nothing about
the metadata path needs work.**

## 2. Where the time goes (server-side access log)

`SPICEIO_ACCESS_LOG` records how long spiceio held each request; the load
generator records what the client saw. At concurrency 128, `cached`:

| | client p50 | server p50 | server head p50 |
| --- | ---: | ---: | ---: |
| PUT | 485.7ms | 457.4ms | 457.4ms |
| GET | 120.8ms | 135.0ms | 133.3ms |
| HEAD | 17.6ms | 13.8ms | 13.8ms |

Two conclusions:

1. **Client-observed latency is essentially all spiceio + SMB.** HTTP framing
   and the client account for single-digit milliseconds. There is nothing to win
   in the HTTP front end.
2. **For GET, `head_us` ≈ `total_us`** (133ms of a 135ms request) — the cost is
   the SMB open plus first read, *not* streaming the body out. Bulk transfer is
   comparatively free; per-request setup is what costs.

In the current write-back configuration the same log reads very differently:
GET p50 is **0.01 ms** (a cache hit does no backend I/O at all) and the whole
distribution is bimodal, so read *percentiles* — not means — are what to watch.

## 3. Pool size is a latency knob

The ceiling is not the connection pool. Concurrency fixed at 32, `nocache`, pool
size swept (2026-08-04):

| SMB connections | PUT MiB/s | GET MiB/s | PUT p50 | GET p50 |
| ---: | ---: | ---: | ---: | ---: |
| 4 | 79.0 | 89.8 | 154.5ms | 123.4ms |
| 12 | 97.0 | 100.6 | 97.4ms | 82.6ms |
| 24 | 93.6 | 94.8 | 64.0ms | 47.9ms |
| 48 | 105.2 | 97.7 | 67.0ms | 28.1ms |

4 → 48 connections is a 12× increase for **no throughput gain** past 12, so the
~100 MiB/s ceiling is on the NAS side, not in spiceio's pooling. But latency
keeps improving all the way out (GET p50 123ms → 28ms), and **that is what the
pool is for.**

The 2026-08-04 run concluded "the default pool of 12 is already the right size",
reading only the throughput column. That was wrong, and it was also measuring a
pool the product did not ship: `default_pool_size` was CPU-count clamped 4–16,
so this 16-core host actually ran 16 while every recorded bench pinned 12. Both
bench scripts now leave `SPICEIO_SMB_CONNECTIONS` unset so they measure whatever
the binary defaults to.

Re-measured 16 versus 32 on the mixed phase, 3 interleaved reps
(`20260809-writeback-pool/`), against the v0.7.0 baseline as arm A:

| conc | metric | v0.7.0 pool 16 | fixed pool 16 | fixed pool 32 |
| ---: | --- | ---: | ---: | ---: |
| 8 | p90 | 3.82ms | 2.35ms (−38%) | **1.60ms (−58%)** |
| 32 | p90 | 8.91ms | 10.28ms (+15%) | **4.30ms (−52%)** |
| 64 | p90 | 10.48ms | 17.31ms (+65%) | **6.70ms (−36%)** |

Per-rep p90 spread is the important part — the medians alone hide it:

| conc | v0.7.0 pool 16 | fixed pool 16 | fixed pool 32 |
| ---: | --- | --- | --- |
| 32 | 9.5, 8.9, 8.5 | 3.7, 10.3, 13.6 | **4.3, 3.8, 4.9** |
| 64 | 8.4, 13.7, 10.5 | 19.7, 15.5, 17.3 | **6.7, 7.4, 6.1** |

Pool 32 is both faster and far steadier. It also removes a real regression: the
flusher fix *alone* at pool 16 is worse than baseline at concurrency 64 (p90 reps
19.7/15.5/17.3 against 8.4/13.7/10.5, non-overlapping), and the wider pool is
what absorbs it. Cost is one extra second of startup — 0.68/0.69 s to
authenticate 16 connections versus 1.33/1.67 s for 32 — and more concurrent SMB
sessions on the server, which is why it is still capped.

**Not verified:** aggregate session load with several spiceio instances against
one NAS. Two instances on this host would open 64 sessions at startup. If a
deployment runs more than one, check the server's session limits before
accepting the default.

## 4. Real builds

spiceai `-p spice`, 1163 compile units, `-j16`, two reps
(`20260809-build-spiceai/`). `local` is sccache on local disk — the floor a
network backend is measured against; `nocache` is the compile-everything ceiling.

| arm | phase | rep 1 | rep 2 | vs local |
| --- | --- | ---: | ---: | ---: |
| no cache | full | 127.3s | — | — |
| local disk | cold | 151.9s | 159.5s | — |
| local disk | warm | **19.7s** | **20.9s** | floor |
| spiceio | cold | 155.4s | 160.0s | **1.00–1.02×** |
| spiceio | warm | **24.9s** | **24.2s** | **1.16–1.26×** |

Per operation, from sccache's own JSON stats:

| | local disk | spiceio |
| --- | ---: | ---: |
| cache write avg | 1.46 / 1.53 ms | **1.13 / 1.24 ms** |
| cache read hit avg | 1.55 / 1.21 ms | 25.16 / 25.39 ms |
| read / write errors, timeouts | 0 | 0 |

Three things worth carrying forward:

1. **The cold build is at parity with local disk** (1.00–1.02×, was 1.16×), and
   spiceio's per-*write* cost is *below* local disk's. Write-back acknowledges
   from memory, so storing to a NAS-backed cache beats storing to a local file.
2. **The warm gap is 1.16–1.26×** (+3.3–5.2s on a ~20s build), down from 1.40×
   (+9.8s). What remains is per-hit latency: 25 ms against 1.5 ms is a 16×
   per-op gap that only shows up as 1.2× in wall clock because `-j16` hides it
   behind compilation. A less parallel build would feel more of it.
3. **Versus no cache the cache saves 80%** (127.3s → 24.9s).

### Immutable objects did not change wall clock

`SPICEIO_IMMUTABLE_OBJECTS=1` serves a hit with no backend round trip at all,
and the per-hit number moves exactly as designed — **25.16 ms → 2.06 ms, 12×**.
The warm build did not follow: 26.7s, no better than the 24.9s without it. At
`-j16` the ~1.7s of aggregate latency this removes is already hidden behind
compilation and sits under the run-to-run spread. Its cold arm read 189.0s
against 155–160s elsewhere, which is machine state on a third consecutive heavy
build rather than the setting.

So: the setting's synthetic read-throughput win is real, and it is still the
right default for a content-addressed store — but **do not expect it to show up
in build wall clock at high `-j`**. Claim it for per-request latency and for
backend load, not for build time.

### Small builds cannot measure the backend

This repo, `--all-targets --all-features`, 68 units, -j16 (2026-08-04):

| arm | cold | warm | per-hit | per-write | write errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| no cache | 9.1s | — | — | — | — |
| local disk | 13.5s | 4.0s | 0.58ms | 1.20ms | 0 |
| spiceio | 9.5s | 4.0s | 28.02ms | 29.24ms | 0 |

Per operation spiceio cost ~48× local disk on a read, yet warm wall clock was
identical at 4.0s: at 68 units and -j16 there is enough parallelism to hide 1.9s
of aggregate backend latency behind cargo's own overhead. **Use the spiceai run
above, not this one, to judge a backend change.**

## 5. Defect found and fixed: spiceio dropped large writes under burst load

*Historical, 2026-08-04/05. Every wall-clock figure in this section is from that
run and is superseded by §4 — it is kept because the mechanism, and the reason
the gate missed it, are the parts worth remembering.*

The large run turned up something the wall clock alone would not have:

- **40 of 1203 PutObject requests (3.3%) were answered `404`** during the cold
  build, all inside one ~10s window at the peak PUT rate (~32 PUT/s).
- They fail *fast* — 1.8ms mean versus 20.6ms for successful PUTs — so spiceio
  is rejecting them before doing the work, not timing out.
- Bucketed by size the rate looked like a gradient (0.7% under 256 KiB, 6.9% at
  256 KiB–1 MiB, 10.1% at ≥1 MiB). It is not — see *Mechanism* below; size is a
  proxy for which code path the request takes.

Consequence: sccache counted 40 cache write errors and those artifacts never
entered the cache. The warm build then took **41 misses instead of 1** and
recompiled them. Every one of the 40 keys is re-uploaded successfully 171–177s
later — that is the *next* build storing it, not a retry within the failing one.

This is silent cache-hit-rate loss. The build still succeeds, so nothing except
a write-error check catches it — and the existing gate only asserts
`write_errors == 0` on the *warm* build of a 28-unit crate, which never
generates the burst that triggers it.

Evidence: `20260804-build-spiceai/failed-puts.tsv` (the 40 failing requests) and
`summary.txt` (the per-path split). The full per-request logs are ~740 KB each
and are not committed — regenerate with `SPICEIO_ACCESS_LOG` set, which the
bench scripts do automatically.
The proxy's own `spiceio.log` records the SMB-level cause; it is written to
`benches/results/` on every run but **not committed** — see *What is not
committed* above.

### Mechanism

Not a size gradient — a **code-path split**. `handle_put_object` takes the
streaming WAL path above the 64 KiB compound threshold, and `open_wal_write`
runs *before* the request body is read. Split at that threshold, the same run
reads:

| path | PUTs | 404s | rate |
| --- | ---: | ---: | ---: |
| ≤64 KiB (compound) | 618 | 0 | **0.0%** |
| >64 KiB (WAL stream) | 585 | 40 | **6.8%** |

`should_retry` excluded `io::ErrorKind::NotFound`, so any missing-path error
during setup became an immediate `404 NoSuchKey` with no retry — which is also
why the failures are *fast* (1.8ms vs 20.6ms for a successful PUT): they fail
before a single body byte moves.

The instrumentation added with the fix then caught the condition live and named
the path:

```
[spiceio] write setup hit a missing path (attempt 1), dropping cached dirs
and retrying: not found: .spiceio-wal\01785891110839789000-0532
```

It is the **WAL temp**, not the destination. Every streaming PUT creates its
temp under one shared `.spiceio-wal` directory, which `ensured_dirs` caches
after the first request and never re-creates. So when that directory becomes
unresolvable for a moment, *every* concurrent streaming PUT fails at once and
keeps failing — which is exactly the observed shape: 40 failures inside one ~10s
window, with destination parents that were mostly distinct and therefore never
the common factor. (What makes `.spiceio-wal` briefly unresolvable — a peer
instance's startup sweep of an emptied WAL directory, or NAS-side path
resolution under load — is still open; the recovery does not depend on which.)

### Fix

1. `NotFound` during write setup now evicts the `ensured_dirs` cache entries for
   the destination and retries. The two steps only work together: retrying
   without evicting re-runs the identical skip. Applied to **every** write
   destination path — `open_wal_write`, `put_object`, `write_temp`,
   `copy_range_to_temp`, and the WAL commit rename (which additionally
   re-creates the destination parents, since rename creates nothing).
2. `io_to_s3_write_error` maps `NotFound` on a write to a retryable 503. A PUT
   creates the key, so "NoSuchKey" can never be a truthful answer. Applied to
   PutObject, CopyObject, UploadPart, UploadPartCopy and CompleteMultipartUpload
   destinations; source lookups keep their honest 404.
3. `ensure_dirs` no longer caches unverified directories when a compound chain
   comes back short — while still surfacing the real NTSTATUS first, so a
   `OBJECT_PATH_NOT_FOUND` stays `NotFound` (and reaches the recovery above)
   and an `ACCESS_DENIED` stays a 403.

### Post-fix

| arm | cold | warm | per-hit | per-write | write errors | warm misses |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| before | 194.3s | 34.2s | 22.90ms | 20.30ms | **40** | **41** |
| after | 163.2s | **24.4s** | 26.50ms | 22.11ms | **0** | **0** |

Warm build 34.2s → 24.4s, matching the local-disk arm *of that run* (24.4s):
**the whole 1.40× penalty was this bug**, not backend latency. Both arms are
faster today — see §4, where local disk measures 19.7–20.9s — so do not compare
these figures against the current ones. Two post-fix runs, zero
non-200 PUTs in 1162 and 1163 attempts.

A third run then produced the direct evidence: the recovery **fired once and
absorbed it** — `recovered: 1, unrecovered: 0, 503 fallbacks: 0`, and 0 of 1162
PUTs answered anything but 200. The condition still occurs; the client no longer
sees it.

Post-fix warm builds across three runs: 24.4s, 24.4s, 23.5s, every one with zero
write errors and zero warm-build misses. (The `local` arm in the third run
measured 41.8s against 24.4s previously — local-disk run-to-run variance on this
box is high, so the cross-arm comparison above uses the earlier, quieter runs.)

### The gate that missed it

Worth recording, because the first version of the load burst could not have
caught this. `spiceio-loadgen` counted any completed HTTP response as a
successful op — only transport failures became errors — and the gate allowlisted
404 globally. A proxy answering *every* PUT with 404 would have posted perfect
throughput and zero errors.

Now each reply is classified against the status its **operation** expects: a PUT
or a cache-hit read answered 404 is a failure, 404 is a success only for a miss
probe, and 5xx never passes. A negative control (PUTs against a nonexistent
bucket) reports `ops=0, err=16, PUT status 404×16`; the same run previously
reported `ops=16, err=0`. With that in place the burst budget is **0**.

## 6. The proxy's own write drain was starving client reads

Found 2026-08-09 while looking for headroom in cached write-back mode, and the
largest single win in this refresh.

### Symptom

In a put-then-get sweep the GET distribution is bimodal: p50 **0.01 ms** (a
cache hit does no backend I/O) but p99 **224–638 ms**. Splitting the access log
at 1 ms:

| | share | median | p99 |
| --- | ---: | ---: | ---: |
| GETs answered from cache | 67.5% | ~0.01ms | — |
| GETs that reached the backend | 32.5% | 48ms | 800ms |

Bucketing the slow ones by wall-clock second placed them in seconds where **no
client PUT was running at all** — the second after a 512-object PUT burst, and
the ten seconds after that. They were queued behind write-back flushing: the
proxy's own deferred writes, competing with client reads for the same NAS.

### Mechanism

The flushers did yield, but against the wrong signal. They stood down when spare
*admission permits* fell below a quarter of the budget — and admission is sized
to keep every connection pipelined (`pool × 8`, so 128 permits at the default
pool of 16), while the NAS saturates at a measured concurrency of about 8. The
reserve therefore did not engage until ~96 client requests were in flight, an
order of magnitude past the point where reads had already started queueing. At
any realistic sccache concurrency it never engaged at all.

### Fix

Yield to *client demand* — a gauge of foreground requests actually holding an
SMB slot — rather than to spare permits. Measured at pool 12, 3 interleaved reps,
mixed phase:

| conc | throughput | p90 | p99 |
| ---: | ---: | ---: | ---: |
| 8 | **+66%** | −35% | −28% |
| 32 | **+130%** | −52% | −32% |

`put` alone is unchanged (±2%), as expected: nothing about it touches the
backend on the critical path. See §3 for the same change re-measured at the real
default pool, where concurrency 64 needs the wider pool to come out ahead.

### Three things that did *not* work, recorded so they are not retried

- **Keeping one flusher always-on** so the drain never fully stalls. Measured on
  the sustained case it was meant for — a working set past the write-back
  ceiling, so the backlog genuinely reaches the urgent threshold — and came out
  slightly *worse* on every metric (−7% throughput, +10% p90, +8% p99). The
  urgent-backlog override already stops the backlog growing untouched.
- **Micro-optimising the cache hit path** (lock contention, per-hit allocations).
  Server-side p50 for a hit is 0.00–0.01 ms and for a write-back PUT 0.03 ms; the
  proxy is not on the critical path at all in this mode. There is nothing to win
  there until something else changes.
- **Raising the clamp ceiling alone** to widen the pool. `default_pool_size` was
  `available_parallelism().clamp(4, 16)`, so on a 16-core host the CPU count
  binds first and raising the ceiling changes nothing. The formula had to change.

### Two hazards the fix introduced, both fixed

Recorded because both were found by adversarial review rather than by any
benchmark, and neither would have shown up as a slow number:

1. **A copy waiting on the drain suppressed the drain.** CopyObject and
   UploadPartCopy await `flush_key` while holding an admission slot, so they
   counted as the client traffic the flushers defer to. Two concurrent copies of
   a not-yet-claimed pending source were enough to stall the flusher they were
   both blocked on. Reproduced: **503, 503 after 30.0s** (exactly
   `PENDING_FLUSH_TIMEOUT`) versus **200, 200 in 2.1s** with the fix, which is
   to let a waiter *raise* the drain's priority. Covered by
   `scripts/test-writeback.sh` §9.
2. **Yielding also deferred durability.** A body used to reach the disk journal
   only as the first step of its own flush, so deferring the flush deferred the
   write becoming crash-recoverable — under continuous client traffic,
   acknowledged objects could sit in memory alone until the backlog hit the
   urgent threshold. Journalling is local disk and costs the NAS nothing, so it
   now continues while the flusher stands down from the *backend*.

### Related: uncatchable-signal loss

Not a performance number, but measured in the same session and worth keeping.
v0.7.0 handled SIGTERM and SIGINT only. Against a 240 MiB backlog:

| signal | v0.7.0 | now |
| --- | --- | --- |
| SIGHUP | exit 129, **225 of 240 acknowledged writes lost** | 240/240 on the NAS, exit 0 |
| SIGQUIT | still running after 30s | exit 0 |

## Reproducing

```bash
source /tmp/spiceio-bench-env.sh          # or export SPICEIO_SMB_USER/PASS/SERVER/SHARE

# Synthetic sweep. Leave BENCH_SMB_CONNECTIONS unset so it measures the pool
# spiceio actually ships with; set it only to sweep the pool deliberately.
BENCH_CONCURRENCY="1 8 32 64 128 256" BENCH_OBJECTS=512 BENCH_OPS_PER_WORKER=16 \
  BENCH_LABEL=baseline ./scripts/bench-sccache.sh

# The large build (§4) — this is the one that finds things.
BUILD_TARGET="$HOME/dev/spiceai" BUILD_PACKAGE=spice \
  BUILD_ARMS="nocache local spiceio" BUILD_JOBS=16 ./scripts/bench-sccache-build.sh

# Backlog/backpressure behaviour needs a working set past the write-back
# ceiling; the standard sweep's ~300 MiB never reaches it.
BENCH_PASSES=writeback BENCH_PHASES="put,mixed" BENCH_CONCURRENCY=32 \
  BENCH_OBJECTS=2048 BENCH_OPS_PER_WORKER=512 ./scripts/bench-sccache.sh

# Pool sweep (§3).
for pool in 8 16 32; do
  BENCH_PASSES=writeback BENCH_PHASES="put,mixed" BENCH_CONCURRENCY="8 32 64" \
    BENCH_SMB_CONNECTIONS=$pool ./scripts/bench-sccache.sh
done
```

## Where to look next

Ranked by the evidence above, not by guesswork.

0. ~~Fix the dropped writes (§5).~~ **Done.**
1. ~~Stop the write drain queueing in front of client reads (§6).~~ **Done** —
   the largest win in this refresh.
2. ~~Size the pool for latency rather than throughput (§3).~~ **Done.**
3. **Per-hit latency is what is left.** 25 ms against local disk's 1.5 ms is the
   whole remaining warm-build gap (§4). `SPICEIO_IMMUTABLE_OBJECTS` already
   takes it to 2.06 ms without changing wall clock at `-j16`, so the win is not
   in shaving the hit further — it is in workloads with less parallelism to hide
   it. Measure at `-j4` before investing here.
4. **Confirm the NAS-side limit.** Measure the same share from a second client,
   or from the macOS SMB client directly. If ~100 MiB/s is the NAS's own limit,
   bulk-throughput work in spiceio cannot pay off.
5. **Verify multi-instance session load** before trusting the pool default on a
   host that runs more than one spiceio (§3).
