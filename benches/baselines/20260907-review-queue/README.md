# PR review follow-up: atomic writes and 1 GiB versus 2 GiB queues

Keep the default queue at **1 GiB**. The atomic small-write optimization improves the published PR without enlarging the queue. A 2 GiB queue acknowledges PUT bursts faster and reduces synchronous fallbacks, but worsens mixed-workload throughput and p99 latency in this comparison.

At 32 workers, the optimized 1 GiB configuration improves sustained mixed throughput **42.9%** over the published PR (2,741 → 3,918 ops/s) and reduces p99 **57.6%** (208.7 → 88.5 ms). It remains **10.3% below trunk's throughput** (4,368 ops/s); that residual difference exceeds the repetition spread. Its p90/p99 differences versus trunk are within spread. Synchronous cached p90 improves **28.2%** versus the published PR (55.5 → 39.9 ms), but remains above trunk's 17.3 ms. The tables below retain the ranges behind these conclusions.

Increasing the optimized queue from 1 to 2 GiB reduces mixed throughput **73.9% at 8 workers** and **17.4% at 32**, while increasing p99 **272.7%** and **80.9%**, respectively. All four differences exceed repetition spread. At 32 workers, p90 improves 28.6% despite the worse p99 and throughput.

The two valid review findings were addressed: copy sources now acquire the publication read lock through every source open, including streaming reconnects; small atomic writes batch temp creation, WRITE, and metadata verification before the existing verified rename. This reduces the normal small-write path from five SMB round trips to three, after parent directories exist. The temp handle remains open across publication and bounded rename retries. Unsupported metadata queries use the existing path stat.

Six new Rust regressions cover copy-open ordering, lock release after opening, fast-path publication, unsupported query fallback, short writes/incorrect stored sizes, and malformed metadata ranges. The `size_of` import comment was invalid: it has been in the Rust prelude since 1.80, and this Rust 2024 crate compiles as written.

## Performance

Each cell is a median [minimum–maximum] over three rotating repetitions. A median difference smaller than the larger repetition spread is inconclusive; exceeding it is not a statistical significance claim. All comparisons use the same live NAS, fixed load generator, pool of 32 connections, and etag revalidation. The shared host and NAS can still introduce noise.

| Sustained mixed workload | Published PR, 1 GiB | Optimized, 1 GiB | Optimized, 2 GiB |
| --- | ---: | ---: | ---: |
| 8 workers, ops/s | 2,746.09 [2,432.94–2,946.64] | 3,304.10 [3,128.31–3,645.50] | 862.76 [818.35–1,067.20] |
| 8 workers, p90 ms | 5.26 [3.88–7.37] | 3.38 [3.16–4.58] | 14.61 [11.97–15.32] |
| 8 workers, p99 ms | 37.83 [36.54–38.53] | 36.82 [35.94–37.31] | 137.23 [109.58–179.93] |
| 32 workers, ops/s | 2,741.07 [2,728.74–2,911.63] | 3,918.24 [3,870.72–4,039.91] | 3,237.48 [3,171.83–3,522.82] |
| 32 workers, p90 ms | 17.65 [14.82–18.04] | 13.65 [12.89–15.19] | 9.75 [9.65–9.82] |
| 32 workers, p99 ms | 208.65 [181.69–208.88] | 88.51 [71.07–104.92] | 160.12 [137.76–185.14] |

The original trunk is also measured in every repetition; see [all mixed comparisons](comparison.md) and [all five phases and every repetition](measurements.tsv). The synchronous-cached comparison still shows a latency cost versus trunk’s in-place writes, so this report does not claim that every performance regression is eliminated.

## Queue tradeoff

| PUT acknowledgement throughput | Optimized, 1 GiB | Optimized, 2 GiB |
| --- | ---: | ---: |
| 8 workers, ops/s | 323.91 [319.27–325.14] | 1,337.05 [1,312.85–1,391.77] |
| 32 workers, ops/s | 327.31 [326.86–327.46] | 1,377.67 [1,363.23–1,384.47] |

PUT acknowledgement is not durable NAS throughput. The mixed phase follows the PUT/read/HEAD phases and inherits their remaining backlog; the larger queue changes that backlog. These are finite workload sequences, not an indefinitely running mixed stream. All six optimized sustained runs reached their configured queue ceiling, verified by nonzero synchronous fallback counters.

The sustained key space is 4,096 objects / 2,451,865,600 bytes (2.28 GiB), above both queue limits. A larger cap permits another GiB of pending bodies and raises the urgent-flush threshold from 512 MiB to 1 GiB. Process RSS also includes the object cache and temporary buffers, so it is not the size of the queue itself. The measured peak RSS, fallback counts, and flush retries for each run appear in [the comparison](comparison.md#queue-pressure-and-process-memory).

Across the two concurrency levels in each process, the 1 GiB configuration recorded a median **3,970 [3,839–4,047]** synchronous fallbacks, versus **761 [747–802]** at 2 GiB. Median sampled peak RSS rose from **3,230 [3,128–3,236] MiB** to **3,551 [3,342–3,586] MiB**. Every sustained run had zero flush retries.

The default remains 1 GiB. The measured 2 GiB option is available with `SPICEIO_WRITE_BACK_BYTES=2147483648`; the installed service was not reconfigured or restarted.

## Validation and reproducibility

- All 1,286,400 measured requests across 21 runs / 210 measurements completed with zero request errors.
- `make ci` passed: 376 Rust tests, 6 Python tests, lint, and all four live NAS suites. `cargo test --locked --all-features --all-targets` also passed, including 54 Criterion smoke cases. The release binaries were built before timing and their SHA-256 identities verified throughout.
- The isolated live ten-day retention test passed: the fresh sentinel survived, no expired objects remained, and zero old objects were present to delete. This follow-up did not repeat the earlier global cleanup.
- All 21 experiment prefixes were independently verified empty after timing; 0 residual objects were removed. Temporary proxies were stopped.
- The earlier [full before/after matrix](../20260907-correctness-retention/README.md) remains the record for Criterion timings, real builds, large transfers, native SMB, the full concurrency ladder, and the Spice.ai CLI integration. This follow-up reruns full local CI and the targeted synchronous/sustained comparisons; it does not relabel the older timings as measurements of the new revision.
- The first report-parser attempt rejected a duplicate concurrency argument after a successful benchmark. The parser was corrected and the original raw sample retained; no measured workload was changed or rerun to replace it. An initial Clippy finding in a new test was fixed before the successful CI gate.

Binary identities, run order, request accounting, and memory/load samples summarized per run are in [environment.json](environment.json). Raw local artifacts remain in `target/review-2026-09-07/`; credentials and NAS identifiers are excluded from these committed files.
