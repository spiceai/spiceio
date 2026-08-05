# Read-path optimization — 2026-08-05

Same bench shape as `../README.md` (512 objects, weighted 4 KiB–16 MiB,
concurrency sweep, 12 SMB connections) so the numbers are directly comparable.

## Result

GET, p50 latency and throughput:

| conc | baseline | default (etag) | immutable |
| ---: | ---: | ---: | ---: |
| 1 | 0.95ms / 151 MiB/s | 0.62ms / 765 | **0.06ms / 3947** |
| 8 | 4.40ms / 313 | 0.95ms / 3832 | **0.49ms / 6263** |
| 32 | 12.61ms / 276 | 3.89ms / 4150 | **2.83ms / 5462** |
| 64 | 35.06ms / 309 | 7.88ms / 4222 | **3.95ms / 6474** |
| 128 | 120.82ms / 321 | 21.08ms / 2207 | **7.58ms / 7466** |
| 256 | 363.29ms / 328 | 37.34ms / 3987 | **17.04ms / 7578** |

**At concurrency 256: 23× throughput (328 → 7578 MiB/s), 21× p50, 17× p99.**
The default (etag) mode gains 12× without any configuration change.

Real sccache build (spiceai `-p spice`, 1163 units, -j16):

| | before | after | local disk |
| --- | ---: | ---: | ---: |
| warm build | 24.4s | **21.3s** | 21.7s |
| per cache hit | 26.5ms | **1.52ms** | 0.50ms |
| cold build | 163–230s | 154.5s | 148.8s |

The warm build now matches a local-disk cache — the backend is out of the
critical path entirely.

## PUT is unchanged, and that is expected

~100 MiB/s across the sweep, before and after. Writes must reach the backend,
and the backend's rate is the external ceiling established in `../README.md` §1
and §3. Nothing in this change targets it, and nothing in it regressed.

## What produced the win

1. **Immutable hits take no round trip.** A hit used to cost a HEAD (immutable)
   or an open *and* a close (etag) — 0.56ms and a pool slot, to revalidate a key
   that by construction cannot change. See `object_cache::get_by_key`.
2. **Writes populate the cache.** A cache client reads back what it just wrote,
   and the bytes are already in hand, so a PUT now fills the cache instead of
   invalidating it. This is why the *warm* build got faster: the cold build
   populated it.
3. **Etag revalidation is one round trip, not two.** The hit path stats instead
   of opening, so it no longer has a handle to close.
4. **Eviction is O(log n).** It was a scan of every entry for the minimum
   use-generation, under the cache lock, per insert — which capped how large the
   cache could usefully be. That cap was the thing worth removing, because the
   cache is the only mechanism that beats the backend's rate.
5. **The budget is sized for a real working set** (8 GiB default) and the
   per-object cap derives from it (1/64), so one large object cannot evict a
   large share of the cache.

## What was measured and rejected

- **Larger SMB I/O.** The server advertises 8 MiB; we cap at 256 KiB. Sweeping
  256 KiB → 8 MiB changed nothing and slightly *hurt* (larger chunks shrink the
  pipeline batch under the 4 MiB in-flight budget). `io-size-sweep.log`.
- **Prefetching.** sccache issues **zero HEADs** in a full build — 0 of ~4,700
  requests — so there is no HEAD→GET signal to speculate on, keys are content
  hashes with no locality to extrapolate, and the backend is bandwidth-saturated
  so a speculative fetch would displace a real one. Write-through is the version
  of this that pays, because it is certainty rather than prediction.
- **A fixed 32 MiB per-object cap.** Measured a hit-rate drop from 93% to 60% at
  the then-256 MiB budget: each 16 MiB artifact displaced ~28 average ones, and
  the small objects it evicted were the overwhelming majority of requests. Hence
  the derived cap.

## Caveats

- The cache is **process-local and lost on restart**. The first build after a
  restart pays full backend cost. A local-disk tier would fix that, and is the
  obvious next step — its value is capacity and persistence, not latency
  (memory hits already cost 1.52ms against local disk's 0.50ms, and the residual
  is HTTP plus proxy overhead, which a disk tier would not remove).
- The 8 GiB default is **up to 8 GiB resident**. Budget is logged at startup and
  hit rate at shutdown.
- `SPICEIO_IMMUTABLE_OBJECTS` now serves hits with no backend call at all, where
  it previously revalidated with a HEAD. Correct for content-addressed stores;
  wrong for a mutable namespace.
