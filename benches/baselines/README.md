# sccache performance baseline — 2026-08-04, spiceio v0.5.10

Reference run for `make bench-sccache` and `make bench-sccache-build`. Compare a
change against these numbers before claiming it helped.

| | |
| --- | --- |
| spiceio | v0.5.10 (`dc53e1f`) |
| host | macOS 26 (Darwin 25.6.0), Mac15,8, 16 cores, **10GbE** uplink |
| NAS | `smb://192.168.3.148/ai_platform_dev` (shared — expect some run-to-run noise) |
| SMB pool | 12 connections unless stated |
| working set | 512 objects, weighted 4 KiB–16 MiB (mean ≈ 589 KiB) |
| sccache | 0.17.0 |

Raw artifacts: `20260804-synthetic/` (per-point JSON + server-side summaries),
`20260804-build/`, `20260804-pool-sweep.log`, and the two spiceai build runs
`20260804-build-spiceai/` (pre-fix) and `20260805-build-spiceai-postfix/`.

## Headline

1. **The data path saturates at ~100 MiB/s and reaches it at concurrency 8.**
   Beyond that, added concurrency buys zero throughput and adds latency
   proportionally. spiceio's in-memory GET cache is the only thing that beats
   the ceiling — it triples read throughput for objects it can hold.
2. **A real warm build was 1.40× slower through spiceio than on local disk**
   (34.2s vs 24.4s for spiceai's 1163 units at -j16). That gap was entirely
   finding 3 — it is **24.4s, matching local disk, once fixed**.
3. **spiceio dropped 3.3% of large writes under burst load** (§5), costing
   cache-hit rate on the *next* build. **Fixed** — see §5 for the mechanism,
   the fix, and the post-fix numbers.

## 1. Throughput ceiling (synthetic, concurrency sweep)

`nocache` disables spiceio's GET body cache, so every read reaches the NAS.

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

## 3. The ceiling is not spiceio's connection pool

Concurrency fixed at 32, `nocache`, pool size swept:

| SMB connections | PUT MiB/s | GET MiB/s | PUT p50 | GET p50 |
| ---: | ---: | ---: | ---: | ---: |
| 4 | 79.0 | 89.8 | 154.5ms | 123.4ms |
| 12 | 97.0 | 100.6 | 97.4ms | 82.6ms |
| 24 | 93.6 | 94.8 | 64.0ms | 47.9ms |
| 48 | 105.2 | 97.7 | 67.0ms | 28.1ms |

4 → 48 connections is a 12× increase in pool size for **no throughput gain**
past 12. Latency does improve (GET p50 123ms → 28ms) because requests start
service sooner, but the aggregate rate is pinned. The local link is 10GbE, so
~100 MiB/s (≈840 Mbit/s) is not our NIC either — the constraint is on the NAS
side (its uplink, its disks, or its SMB server), not in spiceio's pooling.

**The default pool of 12 is already the right size.** Raising it trades memory
and NAS sessions for lower queueing latency only.

## 4. Real builds

### Small: this repo, `--all-targets --all-features`, 68 units, -j16

| arm | cold | warm | per-hit | per-write | write errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| no cache | 9.1s | — | — | — | — |
| local disk | 13.5s | 4.0s | 0.58ms | 1.20ms | 0 |
| spiceio | 9.5s | 4.0s | 28.02ms | 29.24ms | 0 |

Per operation spiceio costs ~48× local disk on a read and ~24× on a write, yet
warm wall clock is identical at 4.0s: at 68 units and -j16 there is enough
parallelism to hide 1.9s of aggregate backend latency behind cargo's own
overhead. **A build this small cannot tell you anything about the backend** —
which is why the run below exists.

### Large: spiceai `-p spice`, 1163 units, -j16

| arm | cold | warm | per-hit | per-write | write errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| local disk | 167.9s | 24.4s | 0.62ms | 1.22ms | 0 |
| spiceio | 194.3s | 34.2s | 22.90ms | 20.30ms | **40** |

**Warm build: 34.2s vs 24.4s — spiceio is 1.40× slower, +9.8s on a 24s build.**
Cold: 194.3s vs 167.9s (1.16×). These are the *pre-fix* figures; §5 explains
where the 9.8s went and what it is now.

## 5. Defect found and fixed: spiceio dropped large writes under burst load

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
A `spiceio.log` is now preserved alongside future runs so the SMB-level cause
can be attributed; this run predates that change.

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

Warm build 34.2s → 24.4s, which is exactly the local-disk figure from §4: **the
whole 1.40× penalty was this bug**, not backend latency. Two post-fix runs, zero
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

## Reproducing

```bash
source /tmp/spiceio-bench-env.sh          # or export SPICEIO_SMB_USER/PASS/SERVER/SHARE

BENCH_CONCURRENCY="1 8 32 64 128 256" BENCH_OBJECTS=512 BENCH_OPS_PER_WORKER=16 \
  BENCH_SMB_CONNECTIONS=12 BENCH_LABEL=baseline ./scripts/bench-sccache.sh

BUILD_ARMS="nocache local spiceio" BUILD_JOBS=16 \
  BUILD_CARGO_EXTRA="--all-targets --all-features" ./scripts/bench-sccache-build.sh

# The large build (§4, §5) — this is the one that finds things
BUILD_TARGET="$HOME/dev/spiceai" BUILD_PACKAGE=spice \
  BUILD_ARMS="local spiceio" BUILD_JOBS=16 ./scripts/bench-sccache-build.sh

# Pool sweep (section 3)
for pool in 4 12 24 48; do
  BENCH_PASSES=nocache BENCH_CONCURRENCY=32 BENCH_OBJECTS=192 \
    BENCH_OPS_PER_WORKER=12 BENCH_SMB_CONNECTIONS=$pool BENCH_PHASES="put,get" \
    ./scripts/bench-sccache.sh
done
```

## Where to look next

Ranked by the evidence above, not by guesswork:

0. ~~Fix the dropped writes (§5).~~ **Done** — and it was worth more than any
   throughput work here: it alone closed the entire warm-build gap to local disk.
1. **Avoid the transfer.** The body cache is the only measure that beat the
   ceiling (3.2× on reads). Its limits — 256 MiB total, 4 MiB per object — are
   what capped it here; the 16 MiB objects in the mix never qualified. Sizing
   these to the working set, and `SPICEIO_IMMUTABLE_OBJECTS` for
   content-addressed keys like sccache's, is the highest-leverage knob.
2. **Cut per-request setup, not bulk transfer.** `head_us ≈ total_us` on GET
   says the open-and-first-read round trips are the cost. Compounding or
   eliminating round trips on the open path helps; making the streaming path
   faster does not.
3. **Confirm the NAS-side limit before optimizing further.** Measure the same
   share from a second client, or from the macOS SMB client directly. If ~100
   MiB/s is the NAS's own limit, throughput work in spiceio cannot pay off and
   the remaining wins are all in (1) and (2).
