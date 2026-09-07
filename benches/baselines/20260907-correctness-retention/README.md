# Correctness and retention validation — 2026-09-07

The fixed revision passed every functional suite and completed 1,059,840 measured live requests with **zero request errors**. The baseline produced **nine PUT 500s and three unexpected GET-hit 404s**. There is a material performance cost at high concurrency: sustained mixed throughput at 32 workers fell **32.6%**, and p99 latency increased **98.0%** in this run. This tradeoff needs review before merging.

The complete comparison contains **1,272 measurements across 212 cases**, with three alternating before/after repetitions. All planned cases ran, including native SMB; there are no skipped cases, duplicate repetitions, or unaccounted requests. See [all comparisons](comparison.md), [every repetition](measurements.tsv), and [environment, binary identities, coverage, and queue statistics](environment.json).

## Revisions and method

- Before: `2ad4a874ff4813f8190117bc645af0dbb90b708c`.
- After application: `b6d2eec0d8dae6774f74bd0d7a5b0323e5c3b557`.
- Host: Mac15,8, 16 logical CPUs, 128 GiB RAM, macOS 26.6.2, Rust 1.98.0, sccache 0.17.0; AC power and sleep prevention. Runs were sequential against the same live NAS from 19:01 to 21:40 UTC.
- Every family ran A1, B1, A2, B2, A3, B3. Values below are the median and observed minimum–maximum. A difference smaller than the larger arm's spread is inconclusive. Exceeding this threshold is not a statistical significance claim.
- Both release binaries and application sources/manifests were verified unchanged after measurement. Harness adjustments isolated ports, files, spills, and cache prefixes; fixed the external CLI fixture and lockfile; and used existing native credentials with an environment-password fallback. File-descriptor limits were 8,192 on both revisions. Benchmarks used the shipped 32-connection pool; CI used eight.
- The host and NAS are shared. Large unrelated CPU-load spikes overlapped baseline microbenchmark repetition 2 and synthetic repetition 3. Observed one-minute load reached 237 and 156, respectively. All measurements are retained. The sustained family ran after those spikes.

The measured application predates a final script-only cleanup fix: native mounts now use a `diskutil unmount` fallback when normal `umount` reports the mount busy. That post-measurement fallback was exercised successfully in the last two transfer pairs. No application code or timed workload changed for it.

## Functional results

| Check | Before | After |
| --- | --- | --- |
| Rust tests, all features and targets | 340 passed; none ignored | 370 passed; none ignored |
| Criterion smoke cases | 54 passed | 54 passed |
| Cleanup Python tests | Helper absent in baseline | 6 passed |
| Full `make ci` | Existing Clippy failures on Rust 1.98 | Passed |
| Four live NAS suites | Passed separately after Clippy stopped CI | Passed in CI |
| Rustdoc and doctests | Passed separately; zero doctests | Passed in CI; zero doctests |
| Live Spice.ai CLI cold/warm builds | 1,164 warm hits; 100% hit rate; zero cache errors | Same |
| Live ten-day retention | Fresh sentinel retained; no older residual objects | Same |

The four live suites are `test-sccache.sh`, `test-extended.sh`, `test-writeback.sh`, and `stress-concurrent.sh`. They include cache-hit/error assertions, write-back persistence across process restarts, and concurrent request checks. The external CLI fixture was pinned to Spice.ai commit `8aecb8657ecb52c55cf1c5e6fb434f2c68faacb2`, using Rust 1.96.1 for both revisions.

The new retention helper/test was reused against both proxy binaries. Each isolated prefix contained one fresh sentinel and no expired objects, so these two runs deleted zero old objects. Each cleanup used a fixed ten-day modification-time cutoff and an independent follow-up listing. The earlier task's global live cleanup was separate: 1,830,554 old objects were removed through a rebuilt proxy, followed by 6,647 through the original installed endpoint, with fresh-sentinel and cutoff checks passing.

## Performance and correctness

| Family | Cases | Measurements | Result |
| --- | ---: | ---: | --- |
| Criterion: crypto, SMB protocol, S3 | 54 | 324 | All completed; 50/54 median changes within repetition spread |
| Standard synthetic load | 120 | 720 | Before: 12 request errors; after: zero |
| Real cargo builds | 5 | 30 | All completed; zero cache errors/timeouts; 28/28 warm hits |
| Live S3 transfers | 19 | 114 | All transfers completed |
| Native SMB transfers | 4 | 24 | All transfers completed; first-pair cleanup recovered as described below |
| Sustained write-back | 10 | 60 | Zero request errors on both revisions; queue limit exercised in all six runs |

Standard synthetic runs used 512 objects, 24 operations per worker with a minimum of 512 per phase, six concurrency levels (1, 8, 32, 64, 128, 256), four cache modes, and five phases. Sustained runs used 4,096 objects, 512 operations per worker, concurrency 8/32, and the same five phases. Each revision received 752,640 standard plus 307,200 sustained measured requests. Failed baseline cases retain their metrics and error counts, but are excluded from successful-throughput comparisons.

The mixed workload is 70% GET hit, 20% GET miss, and 10% PUT. All modes used etag validation. `cached` uses synchronous writes with memory/disk caching; `nocache` disables the memory cache while leaving disk spill configured. `writeback` enables both caches and asynchronous writes; `nospill` disables the disk tier.

| Representative mixed case | Before median [min–max] | After median [min–max] | Change |
| --- | ---: | ---: | ---: |
| Standard write-back, c8, mixed ops/s | 618.49 [583.72–618.54] | 709.60 [658.08–985.24] | +14.7% (within spread) |
| Standard write-back, c32, mixed ops/s | 790.21 [780.13–826.89] | 811.32 [805.21–914.26] | +2.7% (within spread) |
| Sustained write-back, c8, mixed ops/s | 2,819.27 [2,629.19–3,067.35] | 3,597.47 [3,326.95–3,648.98] | +27.6% |
| Sustained write-back, c32, mixed ops/s | 4,227.70 [4,122.39–4,989.10] | 2,848.47 [2,745.95–2,905.55] | -32.6% |
| Sustained write-back, c32, mixed p90 ms | 10.36 [9.89–14.62] | 17.20 [16.81–18.85] | +66.1% |
| Sustained write-back, c32, mixed p99 ms | 85.86 [80.44–93.84] | 169.99 [163.89–187.67] | +98.0% |
| Synchronous cached, c32, mixed p90 ms | 26.41 [14.82–31.20] | 51.34 [49.98–52.83] | +94.4% |

The synchronous cached latency increase is consistent with the additional WAL publication work and coordination needed for safe overwrites. Default write-back standard throughput changes at concurrency 8/32 were within spread. The sustained results have a clear concurrency-dependent tradeoff: higher throughput at eight workers, lower throughput and worse tails at 32. The full comparison includes every other phase and concurrency level.

Warm cargo builds through spiceio had a median of **2.5 seconds** before [2.5–2.5] and after [2.5–2.6], versus **2.1 seconds** [2.1–2.2] on local disk for both revisions and **5.6 seconds** uncached. Both proxy binaries compiled the same before-revision source workload, with fresh target directories and 16 jobs. The separate larger Spice.ai CLI integration also passed on both versions.

Eight parallel 500 MiB uploads measured median **106.3 → 106.8 MiB/s**, and matching downloads **107.0 → 108.0 MiB/s**; both changes were within spread. Native `cp` measurements include OS caching/buffering and do not isolate raw link speed or durable-write latency.

Actual queue-full fallbacks confirm the sustained workload exceeded the configured 1 GiB write-back ceiling:

| Repetition | Before synchronous fallbacks | After synchronous fallbacks | Flush retries before / after |
| --- | ---: | ---: | ---: |
| 1 | 3,564 | 3,965 | 0 / 0 |
| 2 | 3,768 | 4,144 | 0 / 0 |
| 3 | 3,790 | 4,053 | 0 / 0 |

## Exceptions, cleanup, and artifacts

The baseline's Clippy failure was preserved, and its remaining tests were run separately. The first native transfer pair returned exit 1 only after all measurements, because normal `umount` reported a busy mount. `diskutil unmount` recovered both private mounts, the empty directories were removed, and both recovery checks passed. Both subsequent transfer pairs exited zero with the fallback. Original exit codes and recovery rows remain in [comparison.md](comparison.md).

An earlier validation attempt exposed the overwrite race and was superseded by this complete comparison of the final application revision. A descriptor-limited attempt and its failures remain archived locally. None of those earlier timings are substituted into this matrix.

After timing, all 26 explicitly identified benchmark/build/CLI cache prefixes were checked: the benchmark/build prefixes were already empty, and 4,648 remaining CLI cache objects were removed. Follow-up listings found zero remaining objects. Private native mounts were released; the temporary cleanup proxy was stopped. The installed service on port 8333 remained running and was not upgraded or restarted.

Raw logs, request traces, original and recovery exit records, harness patches, invalid attempts, and analysis scripts remain in `target/validation-2026-09-07-final/` and `target/validation-2026-09-07/`. The compact files here contain every final measurement and its error counts. `NA` in the TSV marks a metric that does not apply to that benchmark family. Credentials and full request logs are not included.
