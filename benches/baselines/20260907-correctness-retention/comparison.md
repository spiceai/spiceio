# Before/after test and benchmark comparison

Before: `2ad4a874ff4813f8190117bc645af0dbb90b708c`; after: `b6d2eec0d8dae6774f74bd0d7a5b0323e5c3b557`.

Three alternating before/after repetitions per benchmark family. Values below are the median and observed minimum–maximum across repetitions. A change within that spread is inconclusive; this is not a statistical significance claim. Failed requests must be considered alongside throughput and latency.

Both application revisions use the same host, live NAS, toolchains, workload settings, and isolated test ports. Application sources remain unchanged. The saved harness patches isolate temporary files, cache prefixes, and ports, and require the existing lockfile for the Spice.ai integration build. The real-build benchmark uses the same before-revision source workload for both proxy binaries.

Host: Mac15,8, 16 logical CPUs, 128 GiB RAM, macOS 26.6.2; Rust 1.98.0 and sccache 0.17.0. The live Spice.ai CLI integration fixture is pinned to `8aecb8657ecb52c55cf1c5e6fb434f2c68faacb2` and Rust 1.96.1. The machine and NAS are shared: process overlap is recorded in `environment.json` and `contention.jsonl`.

Two bursts of unrelated host activity affected parts of the baseline measurements: approximately 19:38–19:43 UTC during its second microbenchmark repetition and 20:50–20:56 UTC during its third synthetic repetition. Observed one-minute load reached 237 and 156 on this 16-CPU host. All samples are retained; these measurements do not isolate code effects from host contention.

Benchmark mode names below are the existing script names. All use etag validation (immutable mode off). `nocache` leaves the disk tier enabled, so its reads are not an isolated measurement of NAS throughput. The optional native mount uses buffered `cp` and OS caches; it is not a durable-write or raw-link ceiling.

| Mode | Write-back | Memory cache | Disk tier |
| --- | --- | --- | --- |
| cached | off | on | on |
| nocache | off | off | on |
| writeback | on | on | on |
| nospill | on | on | off |

## Tests and run completion

| Run | Exit | Seconds | Log |
| --- | ---: | ---: | --- |
| before-ci | 2 | 5.076 | before-ci.log |
| before-all-target-tests | 0 | 3.389 | before-all-target-tests.log |
| before-live-fallback | 0 | 202.424 | before-live-fallback.log |
| before-rustdoc-fallback | 0 | 0.505 | before-rustdoc-fallback.log |
| before-doctest-fallback | 0 | 0.183 | before-doctest-fallback.log |
| before-spiceai-integration | 0 | 194.421 | before-spiceai-integration.log |
| before-retention | 0 | 0.689 | before-retention.log |
| after-ci | 0 | 128.972 | after-ci.log |
| after-all-target-tests | 0 | 2.632 | after-all-target-tests.log |
| after-live-fallback | 0 | — | after-ci |
| after-rustdoc-fallback | 0 | — | after-ci |
| after-doctest-fallback | 0 | — | after-ci |
| after-spiceai-integration | 0 | 226.118 | after-spiceai-integration.log |
| after-retention | 0 | 0.682 | after-retention.log |
| criterion-r1-before | 0 | 514.328 | criterion-r1-before.log |
| criterion-r1-after | 0 | 513.205 | criterion-r1-after.log |
| criterion-r2-before | 0 | 740.199 | criterion-r2-before.log |
| criterion-r2-after | 0 | 508.611 | criterion-r2-after.log |
| criterion-r3-before | 0 | 512.259 | criterion-r3-before.log |
| criterion-r3-after | 0 | 516.344 | criterion-r3-after.log |
| synthetic-r1-before | 0 | 526.703 | synthetic-r1-before.log |
| synthetic-r1-after | 0 | 545.421 | synthetic-r1-after.log |
| synthetic-r2-before | 0 | 528.762 | synthetic-r2-before.log |
| synthetic-r2-after | 0 | 542.934 | synthetic-r2-after.log |
| synthetic-r3-before | 0 | 702.676 | synthetic-r3-before.log |
| synthetic-r3-after | 0 | 544.334 | synthetic-r3-after.log |
| build-r1-before | 0 | 27.929 | build-r1-before.log |
| build-r1-after | 0 | 27.186 | build-r1-after.log |
| build-r2-before | 0 | 27.399 | build-r2-before.log |
| build-r2-after | 0 | 27.223 | build-r2-after.log |
| build-r3-before | 0 | 27.239 | build-r3-before.log |
| build-r3-after | 0 | 27.306 | build-r3-after.log |
| live-throughput-r1-before | 1 | 209.988 | live-throughput-r1-before.log |
| live-throughput-r1-after | 1 | 194.138 | live-throughput-r1-after.log |
| live-throughput-r2-before | 0 | 195.391 | live-throughput-r2-before.log |
| live-throughput-r2-after | 0 | 190.436 | live-throughput-r2-after.log |
| live-throughput-r3-before | 0 | 194.894 | live-throughput-r3-before.log |
| live-throughput-r3-after | 0 | 195.947 | live-throughput-r3-after.log |
| sustained-writeback-r1-before | 0 | 125.438 | sustained-writeback-r1-before.log |
| sustained-writeback-r1-after | 0 | 127.877 | sustained-writeback-r1-after.log |
| sustained-writeback-r2-before | 0 | 130.947 | sustained-writeback-r2-before.log |
| sustained-writeback-r2-after | 0 | 131.245 | sustained-writeback-r2-after.log |
| sustained-writeback-r3-before | 0 | 131.648 | sustained-writeback-r3-before.log |
| sustained-writeback-r3-after | 0 | 130.774 | sustained-writeback-r3-after.log |
| live-throughput-r1-before-cleanup-recovery (supplemental) | 0 | 0.0 | live-throughput-r1-before-cleanup-recovery.log |
| live-throughput-r1-after-cleanup-recovery (supplemental) | 0 | 1.18 | live-throughput-r1-after-cleanup-recovery.log |

## Synthetic load

Throughput in operations/second; p90 latency in milliseconds.

| Case | Before ops/s | After ops/s | Throughput change | Before p90 | After p90 | Errors before / after |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| sustained-writeback/writeback/c32/get | 1.11e+04 [6.82e+03–1.19e+04] (n=3) | 5.32e+03 [5.24e+03–6.48e+03] (n=3) | -52.1% | 6.36 [6.25–6.74] (n=3) | 8.6 [7.77–9.26] (n=3) | [0, 0, 0] / [0, 0, 0] |
| sustained-writeback/writeback/c32/head-hit | 1.22e+04 [1.21e+04–1.33e+04] (n=3) | 1.02e+04 [9.74e+03–1.06e+04] (n=3) | -16.4% | 6.92 [6.64–7] (n=3) | 7.76 [7.74–8.25] (n=3) | [0, 0, 0] / [0, 0, 0] |
| sustained-writeback/writeback/c32/head-miss | 6.36e+03 [5.9e+03–6.37e+03] (n=3) | 6.31e+03 [5.44e+03–6.63e+03] (n=3) | -0.9% (within spread) | 7.57 [6.51–7.61] (n=3) | 7.57 [6.94–8.1] (n=3) | [0, 0, 0] / [0, 0, 0] |
| sustained-writeback/writeback/c32/mixed | 4.23e+03 [4.12e+03–4.99e+03] (n=3) | 2.85e+03 [2.75e+03–2.91e+03] (n=3) | -32.6% | 10.4 [9.89–14.6] (n=3) | 17.2 [16.8–18.8] (n=3) | [0, 0, 0] / [0, 0, 0] |
| sustained-writeback/writeback/c32/put | 312 [311–323] (n=3) | 320 [319–328] (n=3) | +2.4% (within spread) | 353 [284–355] (n=3) | 314 [276–324] (n=3) | [0, 0, 0] / [0, 0, 0] |
| sustained-writeback/writeback/c8/get | 5.42e+03 [4.71e+03–6.49e+03] (n=3) | 1.42e+03 [1.35e+03–1.58e+03] (n=3) | -73.7% | 2.43 [2.28–2.67] (n=3) | 9.22 [5.21–9.7] (n=3) | [0, 0, 0] / [0, 0, 0] |
| sustained-writeback/writeback/c8/head-hit | 9.32e+03 [7.42e+03–1.08e+04] (n=3) | 1.08e+04 [1.07e+04–1.11e+04] (n=3) | +15.4% (within spread) | 1.92 [1.64–1.97] (n=3) | 1.68 [1.62–1.7] (n=3) | [0, 0, 0] / [0, 0, 0] |
| sustained-writeback/writeback/c8/head-miss | 9.66e+03 [9.2e+03–1.08e+04] (n=3) | 1.06e+04 [1.01e+04–1.11e+04] (n=3) | +9.5% (within spread) | 1.17 [1.15–1.26] (n=3) | 1.16 [1.1–1.27] (n=3) | [0, 0, 0] / [0, 0, 0] |
| sustained-writeback/writeback/c8/mixed | 2.82e+03 [2.63e+03–3.07e+03] (n=3) | 3.6e+03 [3.33e+03–3.65e+03] (n=3) | +27.6% | 4.33 [3.47–4.75] (n=3) | 3.19 [3.09–3.69] (n=3) | [0, 0, 0] / [0, 0, 0] |
| sustained-writeback/writeback/c8/put | 309 [307–331] (n=3) | 307 [303–324] (n=3) | -0.7% (within spread) | 86.9 [82.6–93.8] (n=3) | 109 [108–112] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/cached/c1/get | 1.22e+03 [825–1.46e+03] (n=3) | 1.4e+03 [1.37e+03–1.41e+03] (n=3) | +14.9% (within spread) | 1.07 [0.869–1.74] (n=3) | 0.886 [0.836–0.952] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/cached/c1/head-hit | 1.31e+03 [1.23e+03–1.42e+03] (n=3) | 1.19e+03 [1.11e+03–1.31e+03] (n=3) | -9.3% (within spread) | 0.812 [0.751–0.866] (n=3) | 0.924 [0.843–1.06] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/cached/c1/head-miss | 1.9e+03 [1.63e+03–2.39e+03] (n=3) | 1.69e+03 [1.18e+03–1.88e+03] (n=3) | -11.2% (within spread) | 0.588 [0.463–0.621] (n=3) | 0.636 [0.6–1.17] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/cached/c1/mixed | 467 [453–514] (n=3) | 440 [367–451] (n=3) | -5.7% (within spread) | 2.14 [2.03–2.63] (n=3) | 4.31 [4.13–4.93] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/cached/c1/put | 72.2 [70.1–73] (n=3) | 64.7 [61.9–66.1] (n=3) | -10.4% | 23.1 [22.8–24.1] (n=3) | 23.6 [22.6–24.7] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/cached/c128/get | 6.15e+03 [5.98e+03–6.18e+03] (n=3) | 6.03e+03 [6.01e+03–6.31e+03] (n=3) | request errors in case; do not compare | 28.1 [27.6–31.2] (n=3) | 28.8 [28–29] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/cached/c128/head-hit | 6.12e+03 [5.52e+03–6.21e+03] (n=3) | 6.21e+03 [5.99e+03–6.24e+03] (n=3) | request errors in case; do not compare | 29.3 [27.7–32.7] (n=3) | 28.9 [27.1–29.7] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/cached/c128/head-miss | 6.76e+03 [6.7e+03–6.84e+03] (n=3) | 6.73e+03 [6.39e+03–7.01e+03] (n=3) | request errors in case; do not compare | 22.6 [22.5–23] (n=3) | 23.2 [23–23.7] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/cached/c128/mixed | 1.3e+03 [1.18e+03–1.36e+03] (n=3) | 1.06e+03 [1.06e+03–1.08e+03] (n=3) | request errors in case; do not compare | 194 [188–212] (n=3) | 280 [276–288] (n=3) | [0, 0, 1] / [0, 0, 0] |
| synthetic/cached/c128/put | 182 [170–184] (n=3) | 179 [176–179] (n=3) | request errors in case; do not compare | 1.64e+03 [1.63e+03–1.69e+03] (n=3) | 1.1e+03 [1.05e+03–1.15e+03] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/cached/c256/get | 5.77e+03 [4.8e+03–6.01e+03] (n=3) | 5.69e+03 [5.13e+03–5.94e+03] (n=3) | request errors in case; do not compare | 64.7 [59.3–72.1] (n=3) | 58.1 [53.6–69.7] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/cached/c256/head-hit | 6e+03 [5.86e+03–6.12e+03] (n=3) | 5.92e+03 [5.8e+03–6.02e+03] (n=3) | request errors in case; do not compare | 55.4 [55–57.4] (n=3) | 56.9 [52.2–63.2] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/cached/c256/head-miss | 6.22e+03 [6.14e+03–6.84e+03] (n=3) | 5.93e+03 [5.89e+03–6.77e+03] (n=3) | request errors in case; do not compare | 51.7 [51.5–55.5] (n=3) | 50.8 [42.2–58.1] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/cached/c256/mixed | 1.11e+03 [1.07e+03–1.13e+03] (n=3) | 989 [978–1.03e+03] (n=3) | request errors in case; do not compare | 590 [551–625] (n=3) | 621 [615–654] (n=3) | [1, 0, 0] / [0, 0, 0] |
| synthetic/cached/c256/put | 181 [174–182] (n=3) | 178 [176–178] (n=3) | request errors in case; do not compare | 3.27e+03 [3.18e+03–3.34e+03] (n=3) | 1.9e+03 [1.9e+03–1.95e+03] (n=3) | [0, 1, 1] / [0, 0, 0] |
| synthetic/cached/c32/get | 6.43e+03 [5.75e+03–6.69e+03] (n=3) | 6.65e+03 [6.51e+03–6.73e+03] (n=3) | +3.3% (within spread) | 8.51 [8.09–8.89] (n=3) | 7.89 [7.38–7.95] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/cached/c32/head-hit | 6.21e+03 [4.2e+03–6.34e+03] (n=3) | 6.33e+03 [2.8e+03–6.34e+03] (n=3) | +2.0% (within spread) | 8.58 [8.2–14.3] (n=3) | 8.48 [8.24–25.6] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/cached/c32/head-miss | 8.7e+03 [7.2e+03–9.72e+03] (n=3) | 7.31e+03 [6.76e+03–9.01e+03] (n=3) | -15.9% (within spread) | 5.43 [5.19–6.54] (n=3) | 6.11 [5.37–6.38] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/cached/c32/mixed | 1.1e+03 [1.06e+03–1.19e+03] (n=3) | 1.03e+03 [988–1.04e+03] (n=3) | -6.2% (within spread) | 26.4 [14.8–31.2] (n=3) | 51.3 [50–52.8] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/cached/c32/put | 188 [179–189] (n=3) | 183 [181–185] (n=3) | -2.8% (within spread) | 321 [319–397] (n=3) | 259 [247–260] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/cached/c64/get | 6.31e+03 [5.37e+03–6.48e+03] (n=3) | 6.28e+03 [6.03e+03–6.51e+03] (n=3) | request errors in case; do not compare | 16.8 [14.1–17.8] (n=3) | 14.1 [13.8–14.3] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/cached/c64/head-hit | 6.14e+03 [4.7e+03–6.42e+03] (n=3) | 6.35e+03 [4.39e+03–6.45e+03] (n=3) | request errors in case; do not compare | 16 [15–21.2] (n=3) | 14.3 [13.7–31.9] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/cached/c64/head-miss | 7.35e+03 [7.16e+03–7.46e+03] (n=3) | 8.16e+03 [6.76e+03–8.68e+03] (n=3) | request errors in case; do not compare | 11.5 [11.3–11.9] (n=3) | 11.5 [11.1–11.6] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/cached/c64/mixed | 1.38e+03 [1.26e+03–1.4e+03] (n=3) | 1.11e+03 [1.01e+03–1.13e+03] (n=3) | request errors in case; do not compare | 61.6 [44.6–82.6] (n=3) | 136 [127–136] (n=3) | [0, 1, 0] / [0, 0, 0] |
| synthetic/cached/c64/put | 177 [175–181] (n=3) | 180 [178–181] (n=3) | request errors in case; do not compare | 922 [811–928] (n=3) | 542 [531–621] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/cached/c8/get | 5.2e+03 [5.2e+03–5.57e+03] (n=3) | 5.86e+03 [5.49e+03–6.02e+03] (n=3) | +12.7% | 2.68 [2.39–2.97] (n=3) | 2.37 [2.09–2.68] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/cached/c8/head-hit | 6.13e+03 [4.06e+03–6.15e+03] (n=3) | 6.11e+03 [5.74e+03–6.23e+03] (n=3) | -0.3% (within spread) | 2.53 [2.44–3.89] (n=3) | 2.41 [2.32–2.41] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/cached/c8/head-miss | 1.04e+04 [9.29e+03–1.11e+04] (n=3) | 1.11e+04 [8.74e+03–1.13e+04] (n=3) | +7.1% (within spread) | 1.18 [1.06–1.19] (n=3) | 0.951 [0.94–1.12] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/cached/c8/mixed | 1.2e+03 [1.19e+03–1.2e+03] (n=3) | 1.06e+03 [1.05e+03–1.19e+03] (n=3) | -11.7% | 18.3 [17.1–18.6] (n=3) | 18.9 [18.4–19.5] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/cached/c8/put | 161 [153–161] (n=3) | 145 [141–146] (n=3) | -10.1% | 113 [106–128] (n=3) | 101 [97.4–104] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nocache/c1/get | 89.3 [88.8–89.6] (n=3) | 86.6 [84.5–87.3] (n=3) | -3.1% (within spread) | 19.5 [19.2–19.6] (n=3) | 18.9 [18.9–19.7] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nocache/c1/head-hit | 1.11e+03 [1.11e+03–1.45e+03] (n=3) | 1.38e+03 [1.37e+03–1.39e+03] (n=3) | +23.8% (within spread) | 0.975 [0.753–1.1] (n=3) | 0.783 [0.782–0.793] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nocache/c1/head-miss | 2.05e+03 [1.23e+03–2.21e+03] (n=3) | 1.87e+03 [1.84e+03–1.9e+03] (n=3) | -8.7% (within spread) | 0.554 [0.529–1.09] (n=3) | 0.584 [0.565–0.601] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nocache/c1/mixed | 105 [105–110] (n=3) | 101 [97.9–103] (n=3) | -3.9% (within spread) | 19.3 [18.9–20.5] (n=3) | 19.1 [18.9–19.4] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nocache/c1/put | 71.8 [69.1–73.4] (n=3) | 66.4 [64.4–68] (n=3) | -7.6% | 23.7 [22.5–23.9] (n=3) | 22.5 [22.1–23.3] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nocache/c128/get | 180 [180–182] (n=3) | 175 [174–175] (n=3) | request errors in case; do not compare | 1.65e+03 [1.61e+03–1.67e+03] (n=3) | 1.64e+03 [1.61e+03–1.7e+03] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nocache/c128/head-hit | 5.47e+03 [5.42e+03–6.22e+03] (n=3) | 6.05e+03 [5.48e+03–6.39e+03] (n=3) | request errors in case; do not compare | 32.7 [28.8–35.9] (n=3) | 29.3 [26.9–39.1] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nocache/c128/head-miss | 6.43e+03 [5.06e+03–6.7e+03] (n=3) | 7.02e+03 [5.99e+03–7.1e+03] (n=3) | request errors in case; do not compare | 24.1 [22.5–43.1] (n=3) | 22 [21.8–30.9] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nocache/c128/mixed | 245 [243–248] (n=3) | 235 [234–238] (n=3) | request errors in case; do not compare | 1.25e+03 [1.25e+03–1.31e+03] (n=3) | 1.3e+03 [1.25e+03–1.31e+03] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nocache/c128/put | 182 [175–183] (n=3) | 177 [176–177] (n=3) | request errors in case; do not compare | 1.62e+03 [1.61e+03–1.64e+03] (n=3) | 1.15e+03 [1.1e+03–1.15e+03] (n=3) | [1, 0, 0] / [0, 0, 0] |
| synthetic/nocache/c256/get | 180 [121–181] (n=3) | 175 [174–176] (n=3) | request errors in case; do not compare | 3.01e+03 [2.99e+03–4.69e+03] (n=3) | 2.85e+03 [2.83e+03–2.88e+03] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nocache/c256/head-hit | 6.07e+03 [5.79e+03–6.13e+03] (n=3) | 5.92e+03 [5.88e+03–6.25e+03] (n=3) | request errors in case; do not compare | 54.4 [50.2–54.5] (n=3) | 55.6 [52.3–56.2] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nocache/c256/head-miss | 5.99e+03 [5.29e+03–6.67e+03] (n=3) | 6.51e+03 [4.28e+03–6.72e+03] (n=3) | request errors in case; do not compare | 55.2 [49.5–72] (n=3) | 45.8 [42.2–122] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nocache/c256/mixed | 243 [242–244] (n=3) | 234 [234–235] (n=3) | request errors in case; do not compare | 2.33e+03 [2.32e+03–2.34e+03] (n=3) | 2.33e+03 [2.31e+03–2.33e+03] (n=3) | [2, 0, 1] / [0, 0, 0] |
| synthetic/nocache/c256/put | 182 [97.7–182] (n=3) | 178 [176–178] (n=3) | request errors in case; do not compare | 3.32e+03 [3.27e+03–7.27e+03] (n=3) | 1.92e+03 [1.89e+03–1.96e+03] (n=3) | [1, 1, 1] / [0, 0, 0] |
| synthetic/nocache/c32/get | 187 [187–188] (n=3) | 182 [178–183] (n=3) | -2.9% | 339 [336–358] (n=3) | 334 [334–338] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nocache/c32/head-hit | 6.25e+03 [5.87e+03–6.46e+03] (n=3) | 6.38e+03 [5.98e+03–6.59e+03] (n=3) | +2.1% (within spread) | 8.39 [8.2–9.11] (n=3) | 8.23 [7.85–9.78] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nocache/c32/head-miss | 7.32e+03 [4.44e+03–9.94e+03] (n=3) | 6.65e+03 [6.59e+03–8.66e+03] (n=3) | -9.2% (within spread) | 6.05 [5.16–16.9] (n=3) | 6.53 [5.75–6.7] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nocache/c32/mixed | 263 [245–265] (n=3) | 242 [238–252] (n=3) | -8.0% | 265 [257–292] (n=3) | 280 [271–289] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nocache/c32/put | 186 [181–190] (n=3) | 179 [178–185] (n=3) | -3.5% (within spread) | 333 [316–411] (n=3) | 242 [240–255] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nocache/c64/get | 180 [178–181] (n=3) | 174 [174–174] (n=3) | -3.7% | 956 [949–966] (n=3) | 995 [981–1.05e+03] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nocache/c64/head-hit | 6.27e+03 [6.22e+03–6.47e+03] (n=3) | 6.23e+03 [6.09e+03–6.63e+03] (n=3) | -0.7% (within spread) | 14.6 [13.5–15.3] (n=3) | 15.3 [13.8–15.4] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nocache/c64/head-miss | 7.83e+03 [6.45e+03–9.73e+03] (n=3) | 6.49e+03 [6.37e+03–6.79e+03] (n=3) | -17.2% (within spread) | 11.3 [10.8–13.4] (n=3) | 13.5 [12.1–13.7] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nocache/c64/mixed | 248 [242–248] (n=3) | 235 [230–236] (n=3) | -5.0% | 665 [627–729] (n=3) | 713 [686–741] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nocache/c64/put | 182 [174–183] (n=3) | 173 [173–180] (n=3) | -4.6% (within spread) | 917 [840–921] (n=3) | 625 [569–677] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nocache/c8/get | 178 [173–180] (n=3) | 173 [171–175] (n=3) | -3.1% (within spread) | 87.3 [84.4–89.7] (n=3) | 83.4 [79.3–89.1] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nocache/c8/head-hit | 5.83e+03 [4.25e+03–5.84e+03] (n=3) | 6.48e+03 [5.24e+03–6.62e+03] (n=3) | +11.0% (within spread) | 2.51 [2.27–3.85] (n=3) | 2.14 [2.1–2.65] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nocache/c8/head-miss | 1.05e+04 [9.98e+03–1.11e+04] (n=3) | 1.14e+04 [4.37e+03–1.16e+04] (n=3) | +8.7% (within spread) | 0.99 [0.953–1.17] (n=3) | 0.949 [0.941–4.19] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nocache/c8/mixed | 236 [233–236] (n=3) | 229 [214–232] (n=3) | -2.8% (within spread) | 76.1 [72.5–78.1] (n=3) | 71 [70.8–75.1] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nocache/c8/put | 153 [145–162] (n=3) | 143 [132–147] (n=3) | -6.1% (within spread) | 118 [115–122] (n=3) | 102 [97.1–106] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c1/get | 986 [862–1.44e+03] (n=3) | 1.45e+03 [1.44e+03–1.53e+03] (n=3) | +46.6% (within spread) | 1.42 [0.84–1.55] (n=3) | 0.792 [0.724–0.838] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c1/head-hit | 1.24e+03 [1.05e+03–1.26e+03] (n=3) | 1.4e+03 [1.26e+03–1.58e+03] (n=3) | +12.8% (within spread) | 0.876 [0.849–1.4] (n=3) | 0.784 [0.698–0.847] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c1/head-miss | 1.89e+03 [1.73e+03–2.06e+03] (n=3) | 1.82e+03 [1.22e+03–1.95e+03] (n=3) | -3.9% (within spread) | 0.571 [0.563–0.666] (n=3) | 0.626 [0.568–0.813] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c1/mixed | 564 [526–689] (n=3) | 576 [538–651] (n=3) | +2.1% (within spread) | 3.13 [2.92–3.49] (n=3) | 3.29 [2.73–3.35] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c1/put | 5.77e+03 [5.34e+03–6.08e+03] (n=3) | 5.99e+03 [5.8e+03–7.02e+03] (n=3) | +3.8% (within spread) | 0.294 [0.291–0.323] (n=3) | 0.299 [0.258–0.322] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c128/get | 6.92e+03 [6.68e+03–9.19e+03] (n=3) | 8.42e+03 [2.43e+03–9.03e+03] (n=3) | +21.7% (within spread) | 26.5 [22–26.6] (n=3) | 20.3 [17.5–21.4] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c128/head-hit | 1.34e+04 [9.26e+03–1.42e+04] (n=3) | 1.79e+04 [1.16e+04–2.22e+04] (n=3) | +33.6% (within spread) | 28.9 [22.4–31.4] (n=3) | 20.9 [17.6–31.7] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c128/head-miss | 5.31e+03 [4.65e+03–6.01e+03] (n=3) | 6.06e+03 [5.56e+03–6.63e+03] (n=3) | +14.1% (within spread) | 38.2 [34.7–48.8] (n=3) | 28.1 [23.8–32] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c128/mixed | 839 [540–854] (n=3) | 1.31e+03 [1.24e+03–2.33e+03] (n=3) | +56.2% (within spread) | 59.4 [46.4–98.3] (n=3) | 95.2 [92.1–118] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c128/put | 1.19e+04 [1.19e+04–1.22e+04] (n=3) | 1.2e+04 [1.19e+04–1.21e+04] (n=3) | +0.5% (within spread) | 11.4 [11.3–11.5] (n=3) | 11.3 [11–11.5] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c256/get | 1.07e+04 [7.31e+03–1.08e+04] (n=3) | 9.74e+03 [4.79e+03–1.27e+04] (n=3) | -9.3% (within spread) | 63.7 [54.2–80.2] (n=3) | 38.5 [34.8–62.8] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c256/head-hit | 1.01e+04 [7.98e+03–1.88e+04] (n=3) | 1.29e+04 [1.09e+04–1.53e+04] (n=3) | +28.6% (within spread) | 50.6 [46.9–59.5] (n=3) | 50.9 [49.9–58.1] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c256/head-miss | 6.3e+03 [5.83e+03–6.67e+03] (n=3) | 6.54e+03 [5.34e+03–6.91e+03] (n=3) | +3.8% (within spread) | 53.2 [43.6–57.9] (n=3) | 50.9 [48.1–79.7] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c256/mixed | 1.38e+03 [1.17e+03–3.66e+03] (n=3) | 3.12e+03 [1.47e+03–3.25e+03] (n=3) | +126.3% (within spread) | 131 [90.2–219] (n=3) | 157 [134–204] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c256/put | 1.06e+04 [8.28e+03–1.09e+04] (n=3) | 1.01e+04 [9.61e+03–1.02e+04] (n=3) | -4.7% (within spread) | 29.8 [26.2–30.3] (n=3) | 26.6 [26.1–28.3] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c32/get | 1.35e+03 [1.34e+03–2.33e+03] (n=3) | 1.47e+03 [1.2e+03–2.85e+03] (n=3) | +9.4% (within spread) | 4.08 [3.42–6.33] (n=3) | 3.19 [3.19–8.19] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c32/head-hit | 1.78e+04 [4.06e+03–2.41e+04] (n=3) | 1.07e+04 [7.52e+03–3.35e+04] (n=3) | -40.0% (within spread) | 4.47 [3.46–8.2] (n=3) | 5.37 [2.31–8.51] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c32/head-miss | 6.46e+03 [5.17e+03–7.4e+03] (n=3) | 4.83e+03 [4.83e+03–5.58e+03] (n=3) | -25.2% (within spread) | 7.01 [6.6–8.29] (n=3) | 12.8 [7.52–15] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c32/mixed | 796 [716–956] (n=3) | 833 [783–976] (n=3) | +4.7% (within spread) | 29.8 [19.7–60.2] (n=3) | 33.3 [28.6–33.8] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c32/put | 1.53e+04 [1.52e+04–1.61e+04] (n=3) | 1.54e+04 [3.59e+03–1.63e+04] (n=3) | +0.8% (within spread) | 2.65 [2.61–2.65] (n=3) | 2.69 [2.22–2.89] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c64/get | 3.56e+03 [3e+03–3.59e+03] (n=3) | 2.23e+03 [1.71e+03–2.78e+03] (n=3) | -37.4% | 8.77 [7.85–16.7] (n=3) | 14.5 [6.79–19.7] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c64/head-hit | 1.64e+04 [1.46e+04–2.24e+04] (n=3) | 1.5e+04 [1e+04–1.61e+04] (n=3) | -8.1% (within spread) | 8.53 [7–10.5] (n=3) | 10.2 [8.72–17.9] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c64/head-miss | 6.35e+03 [5.69e+03–6.58e+03] (n=3) | 6.69e+03 [4.93e+03–7.04e+03] (n=3) | +5.4% (within spread) | 13.6 [12.6–23.9] (n=3) | 12.6 [12.5–22.1] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c64/mixed | 1.55e+03 [965–1.74e+03] (n=3) | 1.49e+03 [991–1.54e+03] (n=3) | -4.0% (within spread) | 35 [27.5–57.8] (n=3) | 52.2 [47.2–68.2] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c64/put | 1.36e+04 [1.28e+04–1.38e+04] (n=3) | 1.36e+04 [1.29e+04–1.38e+04] (n=3) | -0.1% (within spread) | 5.71 [5.67–5.74] (n=3) | 5.78 [4.8–6.81] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c8/get | 2.53e+03 [1.42e+03–2.54e+03] (n=3) | 1.44e+03 [1.34e+03–2.13e+03] (n=3) | -43.2% (within spread) | 2.18 [1.95–2.34] (n=3) | 2.21 [1.99–3.94] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c8/head-hit | 1.36e+04 [1.04e+04–1.68e+04] (n=3) | 9.4e+03 [9.22e+03–1.41e+04] (n=3) | -30.7% (within spread) | 1.27 [1.16–1.41] (n=3) | 1.56 [1.15–2.08] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c8/head-miss | 9.38e+03 [5.85e+03–9.95e+03] (n=3) | 5.53e+03 [3.41e+03–8.46e+03] (n=3) | -41.0% (within spread) | 1.38 [1.27–1.95] (n=3) | 2.18 [1.62–4.84] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c8/mixed | 650 [642–678] (n=3) | 700 [664–709] (n=3) | +7.6% | 27.4 [25.3–29.5] (n=3) | 24.4 [17–24.7] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/nospill/c8/put | 9.19e+03 [8.48e+03–1.58e+04] (n=3) | 8.82e+03 [8.78e+03–1.01e+04] (n=3) | -4.0% (within spread) | 1.74 [0.924–1.75] (n=3) | 1.8 [1.53–1.89] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c1/get | 863 [785–1.22e+03] (n=3) | 774 [485–1.06e+03] (n=3) | -10.3% (within spread) | 0.87 [0.709–1.69] (n=3) | 1.74 [1.1–2.97] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c1/head-hit | 1.14e+03 [1.11e+03–1.35e+03] (n=3) | 1.42e+03 [1.15e+03–1.44e+03] (n=3) | +24.4% (within spread) | 0.971 [0.788–1.12] (n=3) | 0.761 [0.753–1.13] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c1/head-miss | 1.76e+03 [1.65e+03–2.61e+03] (n=3) | 1.81e+03 [1.32e+03–2.01e+03] (n=3) | +2.7% (within spread) | 0.64 [0.462–0.664] (n=3) | 0.622 [0.559–0.79] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c1/mixed | 689 [581–791] (n=3) | 731 [705–752] (n=3) | +6.1% (within spread) | 2.86 [2.69–2.95] (n=3) | 2.38 [2.1–2.42] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c1/put | 6.75e+03 [5.76e+03–6.94e+03] (n=3) | 6.28e+03 [6.18e+03–6.55e+03] (n=3) | -7.0% (within spread) | 0.26 [0.256–0.308] (n=3) | 0.283 [0.282–0.304] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c128/get | 6.52e+03 [2.04e+03–8.57e+03] (n=3) | 3.47e+03 [2.55e+03–5.86e+03] (n=3) | -46.8% (within spread) | 31.7 [12.8–54.9] (n=3) | 15.2 [10.7–28.8] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c128/head-hit | 9.04e+03 [7.54e+03–1.49e+04] (n=3) | 2e+04 [1.37e+04–2.37e+04] (n=3) | +121.6% | 32.2 [28.2–41] (n=3) | 18.3 [15.1–21.7] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c128/head-miss | 6.06e+03 [5.99e+03–6.53e+03] (n=3) | 5.28e+03 [5e+03–7.17e+03] (n=3) | -12.9% (within spread) | 27.9 [27.4–30.3] (n=3) | 44.8 [21.7–46.2] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c128/mixed | 884 [772–2.4e+03] (n=3) | 1.23e+03 [1.06e+03–1.63e+03] (n=3) | +38.8% (within spread) | 114 [110–123] (n=3) | 123 [82.1–205] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c128/put | 1.19e+04 [1.15e+04–1.22e+04] (n=3) | 1.17e+04 [8.6e+03–1.18e+04] (n=3) | -1.6% (within spread) | 11.4 [11.1–13.5] (n=3) | 11.5 [11.1–11.8] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c256/get | 1.03e+04 [7.81e+03–1.18e+04] (n=3) | 5.81e+03 [2.45e+03–1.11e+04] (n=3) | -43.6% (within spread) | 45 [34.4–48.7] (n=3) | 31.3 [26.6–33.6] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c256/head-hit | 1.39e+04 [1.23e+04–1.66e+04] (n=3) | 1.99e+04 [1.75e+04–2.59e+04] (n=3) | +43.0% (within spread) | 49.6 [49.2–50.4] (n=3) | 41.8 [40.1–44.5] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c256/head-miss | 5.87e+03 [4.95e+03–6.42e+03] (n=3) | 5.77e+03 [4.62e+03–5.95e+03] (n=3) | -1.6% (within spread) | 64.4 [47.6–67.7] (n=3) | 62.7 [62.7–86.4] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c256/mixed | 1.53e+03 [1.34e+03–2.15e+03] (n=3) | 1.71e+03 [1.4e+03–5.2e+03] (n=3) | +12.0% (within spread) | 143 [120–157] (n=3) | 133 [95.1–157] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c256/put | 1.01e+04 [8.69e+03–1.07e+04] (n=3) | 1e+04 [9.69e+03–1.02e+04] (n=3) | -0.6% (within spread) | 31.9 [31.1–34.3] (n=3) | 26.3 [24.8–26.9] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c32/get | 2.03e+03 [1.58e+03–3.31e+03] (n=3) | 1.97e+03 [1.23e+03–3.76e+03] (n=3) | -2.7% (within spread) | 3.12 [3.02–5.07] (n=3) | 3.54 [3.35–4.35] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c32/head-hit | 2.26e+04 [9.84e+03–2.35e+04] (n=3) | 2.71e+04 [1.13e+04–2.86e+04] (n=3) | +19.6% (within spread) | 4.33 [3.5–4.34] (n=3) | 3.47 [2.94–14.7] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c32/head-miss | 4.92e+03 [3.36e+03–7.24e+03] (n=3) | 8.23e+03 [5.03e+03–9.33e+03] (n=3) | +67.3% (within spread) | 16.5 [7.74–23.5] (n=3) | 4.19 [3.57–15] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c32/mixed | 790 [780–827] (n=3) | 811 [805–914] (n=3) | +2.7% (within spread) | 27.8 [25.1–72.8] (n=3) | 29.5 [27.2–34] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c32/put | 1.61e+04 [1.61e+04–1.65e+04] (n=3) | 1.6e+04 [1.42e+04–1.62e+04] (n=3) | -0.8% (within spread) | 2.48 [2.25–2.65] (n=3) | 2.62 [2.57–2.67] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c64/get | 4.68e+03 [2.87e+03–7.33e+03] (n=3) | 2.8e+03 [2.67e+03–3.04e+03] (n=3) | -40.1% (within spread) | 11.8 [7.72–15.7] (n=3) | 13.2 [6.66–20.6] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c64/head-hit | 1.65e+04 [1.06e+04–2.03e+04] (n=3) | 2.19e+04 [1.63e+04–2.26e+04] (n=3) | +32.2% (within spread) | 10.5 [9.63–15.2] (n=3) | 8.79 [7.78–9.25] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c64/head-miss | 6.65e+03 [6.54e+03–7.26e+03] (n=3) | 5.1e+03 [2.78e+03–5.7e+03] (n=3) | -23.2% (within spread) | 12.4 [12–12.5] (n=3) | 24 [17–48.3] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c64/mixed | 1.28e+03 [1.17e+03–1.4e+03] (n=3) | 815 [767–1.34e+03] (n=3) | -36.5% (within spread) | 81.8 [74.8–85.9] (n=3) | 44 [28.4–53.8] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c64/put | 1.37e+04 [1.37e+04–1.38e+04] (n=3) | 1.29e+04 [6.62e+03–1.33e+04] (n=3) | -6.5% (within spread) | 5.51 [5.5–5.54] (n=3) | 5.62 [4.94–5.77] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c8/get | 1.64e+03 [973–1.74e+03] (n=3) | 1.41e+03 [1.36e+03–2.84e+03] (n=3) | -13.8% (within spread) | 1.97 [1.63–2.39] (n=3) | 3.19 [1.83–4.54] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c8/head-hit | 1.02e+04 [6.4e+03–1.31e+04] (n=3) | 1.27e+04 [6.18e+03–1.77e+04] (n=3) | +24.9% (within spread) | 1.38 [1.3–1.6] (n=3) | 1.54 [1.25–2.2] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c8/head-miss | 6.92e+03 [6.29e+03–7.1e+03] (n=3) | 4.03e+03 [3.82e+03–7.22e+03] (n=3) | -41.8% (within spread) | 1.6 [1.18–1.74] (n=3) | 2.07 [1.24–3.41] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c8/mixed | 618 [584–619] (n=3) | 710 [658–985] (n=3) | +14.7% (within spread) | 29.1 [27.7–29.2] (n=3) | 21.7 [19.2–23.7] (n=3) | [0, 0, 0] / [0, 0, 0] |
| synthetic/writeback/c8/put | 9.24e+03 [8.7e+03–1.59e+04] (n=3) | 8.79e+03 [8.77e+03–9.08e+03] (n=3) | -4.8% (within spread) | 1.9 [0.884–2.09] (n=3) | 2.04 [1.74–2.18] (n=3) | [0, 0, 0] / [0, 0, 0] |

## Real cargo builds

Wall time in seconds; local disk and uncached arms retained for comparison.

| Arm / jobs / phase | Before | After | Change | Errors before / after |
| --- | ---: | ---: | ---: | --- |
| nocache/j16/full | 5.6 [5.6–5.9] (n=3) | 5.6 [5.6–5.7] (n=3) | +0.0% (within spread) | [0.0, 0.0, 0.0] / [0.0, 0.0, 0.0] |
| local/j16/cold | 7.2 [7.2–7.2] (n=3) | 7.2 [7.1–7.2] (n=3) | +0.0% (within spread) | [0.0, 0.0, 0.0] / [0.0, 0.0, 0.0] |
| local/j16/warm | 2.1 [2.1–2.2] (n=3) | 2.1 [2.1–2.2] (n=3) | +0.0% (within spread) | [0.0, 0.0, 0.0] / [0.0, 0.0, 0.0] |
| spiceio/j16/cold | 7.3 [7.2–7.4] (n=3) | 7.2 [7.2–7.2] (n=3) | -1.4% (within spread) | [0.0, 0.0, 0.0] / [0.0, 0.0, 0.0] |
| spiceio/j16/warm | 2.5 [2.5–2.5] (n=3) | 2.5 [2.5–2.6] (n=3) | +0.0% (within spread) | [0.0, 0.0, 0.0] / [0.0, 0.0, 0.0] |

## Live file throughput

Throughput in MiB/s, including AWS CLI client overhead and proxy caches.

| Case | Before | After | Change |
| --- | ---: | ---: | ---: |
| PUT/1M | 3.6 [3.5–3.7] (n=3) | 3.7 [3.3–3.7] (n=3) | +2.8% (within spread) |
| PUT/10M | 20.4 [17.9–21] (n=3) | 20.8 [19.3–21.9] (n=3) | +2.0% (within spread) |
| PUT/50M | 57.5 [47.6–59.2] (n=3) | 53 [51.9–59.6] (n=3) | -7.8% (within spread) |
| PUT/100M | 71.4 [67.9–72.8] (n=3) | 70.2 [58.9–74.7] (n=3) | -1.7% (within spread) |
| PUT/500M | 92.7 [76.4–97.3] (n=3) | 88.3 [77.6–96.5] (n=3) | -4.7% (within spread) |
| PUT/1G | 92.8 [73.9–98.9] (n=3) | 94.6 [85.4–101] (n=3) | +1.9% (within spread) |
| GET/1M | 3.3 [2.7–3.3] (n=3) | 2.9 [2.9–3.3] (n=3) | -12.1% (within spread) |
| GET/10M | 23.8 [22.2–25.4] (n=3) | 24.6 [23.1–25.2] (n=3) | +3.4% (within spread) |
| GET/50M | 63.9 [62.8–64.8] (n=3) | 63.4 [60.3–66] (n=3) | -0.8% (within spread) |
| GET/100M | 80.9 [77.8–81.5] (n=3) | 82 [79.4–83.5] (n=3) | +1.4% (within spread) |
| GET/500M | 102 [102–103] (n=3) | 102 [99.3–103] (n=3) | -0.1% (within spread) |
| GET/1G | 106 [105–106] (n=3) | 106 [105–106] (n=3) | +0.4% (within spread) |
| PUT/100x1M | 3.8 [3.7–3.9] (n=3) | 3.9 [3.9–4] (n=3) | +2.6% (within spread) |
| PUT/20x10M | 21.5 [19.9–21.6] (n=3) | 22.1 [21.1–22.5] (n=3) | +2.8% (within spread) |
| PUT/10x50M | 57.7 [52–59.3] (n=3) | 59.8 [55.9–62.1] (n=3) | +3.6% (within spread) |
| PUT/x8 100M | 98.9 [88.7–99.4] (n=3) | 98.7 [92.2–99.7] (n=3) | -0.2% (within spread) |
| PUT/x8 500M | 106 [89.6–107] (n=3) | 107 [104–107] (n=3) | +0.5% (within spread) |
| GET/x8 100M | 104 [102–104] (n=3) | 103 [103–104] (n=3) | -0.2% (within spread) |
| GET/x8 500M | 107 [105–108] (n=3) | 108 [107–109] (n=3) | +0.9% (within spread) |
| PUT/mount 100M | 59.7 [52.7–71] (n=3) | 75.8 [63.7–76.7] (n=3) | +27.0% (within spread) |
| GET/mount 100M | 91.8 [91.7–93.4] (n=3) | 93 [92–93.8] (n=3) | +1.3% (within spread) |
| PUT/mount 500M | 63.5 [49.8–71.6] (n=3) | 73 [63.9–75.2] (n=3) | +15.0% (within spread) |
| GET/mount 500M | 92.9 [87–94.8] (n=3) | 94.3 [93–95.5] (n=3) | +1.5% (within spread) |

## Criterion microbenchmarks

Latency in nanoseconds. Each repetition uses Criterion's default sampling and measurement durations.

| Case | Before | After | Change |
| --- | ---: | ---: | ---: |
| aes128_cmac/1024 | 835 [829–835] (n=3) | 836 [830–836] (n=3) | +0.2% (within spread) |
| aes128_cmac/256 | 451 [447–472] (n=3) | 460 [457–461] (n=3) | +2.0% (within spread) |
| aes128_cmac/262144 | 1.3e+05 [1.3e+05–1.32e+05] (n=3) | 1.3e+05 [1.3e+05–1.3e+05] (n=3) | -0.2% (within spread) |
| aes128_cmac/64 | 366 [365–372] (n=3) | 371 [362–372] (n=3) | +1.4% (within spread) |
| aes128_cmac/65536 | 3.28e+04 [3.27e+04–3.38e+04] (n=3) | 3.29e+04 [3.27e+04–3.29e+04] (n=3) | +0.1% (within spread) |
| build_request_close | 104 [103–106] (n=3) | 106 [105–109] (n=3) | +2.1% (within spread) |
| decode_create_response | 0.92 [0.919–0.922] (n=3) | 0.916 [0.915–0.92] (n=3) | -0.4% (within spread) |
| decode_read_response_bytes/1024 | 3.9 [3.88–3.91] (n=3) | 3.9 [3.86–3.99] (n=3) | +0.0% (within spread) |
| decode_read_response_bytes/64 | 3.91 [3.89–3.91] (n=3) | 3.9 [3.86–3.92] (n=3) | -0.3% (within spread) |
| decode_read_response_bytes/65536 | 3.89 [3.88–3.92] (n=3) | 3.87 [3.86–3.91] (n=3) | -0.4% (within spread) |
| encode_create_request | 284 [276–296] (n=3) | 270 [270–271] (n=3) | -4.9% (within spread) |
| encode_read_request | 69.7 [66.8–75.9] (n=3) | 68 [67.4–70.6] (n=3) | -2.4% (within spread) |
| encode_set_info_rename/long_255 | 978 [978–990] (n=3) | 973 [971–980] (n=3) | -0.5% (within spread) |
| encode_set_info_rename/short_5 | 121 [120–125] (n=3) | 122 [120–124] (n=3) | +0.8% (within spread) |
| encode_set_info_rename/typical_40 | 296 [296–316] (n=3) | 301 [295–301] (n=3) | +1.8% (within spread) |
| encode_write_request/1024 | 74.5 [74–75.8] (n=3) | 74.2 [74.1–75.4] (n=3) | -0.4% (within spread) |
| encode_write_request/131072 | 1.42e+03 [1.42e+03–1.46e+03] (n=3) | 1.44e+03 [1.44e+03–1.45e+03] (n=3) | +1.3% (within spread) |
| encode_write_request/64 | 62.1 [60.3–63.7] (n=3) | 62.7 [59.4–62.7] (n=3) | +0.9% (within spread) |
| encode_write_request/65536 | 789 [786–794] (n=3) | 784 [774–790] (n=3) | -0.7% (within spread) |
| epoch_to_http_date | 18.8 [18.8–19] (n=3) | 18.8 [18.7–19] (n=3) | -0.1% (within spread) |
| epoch_to_iso8601 | 19.3 [19.2–19.4] (n=3) | 19.2 [19.1–19.4] (n=3) | -0.6% (within spread) |
| extract_element | 121 [120–121] (n=3) | 121 [118–127] (n=3) | -0.1% (within spread) |
| extract_sections_50_keys | 2.66e+03 [2.66e+03–2.67e+03] (n=3) | 2.66e+03 [2.64e+03–2.68e+03] (n=3) | -0.1% (within spread) |
| header_decode | 1.87 [1.84–1.93] (n=3) | 1.85 [1.84–1.88] (n=3) | -0.9% (within spread) |
| header_encode | 73.7 [66.8–74.6] (n=3) | 66.7 [66.3–73] (n=3) | -9.5% (within spread) |
| hex_encode_32B | 34.4 [34.3–34.8] (n=3) | 34.2 [33.9–34.2] (n=3) | -0.4% (within spread) |
| hmac_md5_64B | 596 [591–598] (n=3) | 595 [593–600] (n=3) | -0.1% (within spread) |
| hmac_sha256_64B | 319 [319–322] (n=3) | 316 [315–317] (n=3) | -1.1% |
| md4_64B | 244 [239–245] (n=3) | 237 [236–239] (n=3) | -2.7% |
| parse_compound_response/2 | 30.9 [29.6–30.9] (n=3) | 30.8 [30.8–31] (n=3) | -0.1% (within spread) |
| parse_compound_response/4 | 41.8 [39.6–42] (n=3) | 40.1 [40–40.3] (n=3) | -4.0% (within spread) |
| parse_compound_response/8 | 102 [99.8–102] (n=3) | 101 [100–102] (n=3) | -0.5% (within spread) |
| parse_directory_entries_50 | 3.44e+03 [3.43e+03–3.44e+03] (n=3) | 3.38e+03 [3.34e+03–3.38e+03] (n=3) | -1.8% |
| parse_http_date_iso8601 | 90.1 [88.7–91.2] (n=3) | 91.6 [87.9–91.9] (n=3) | +1.6% (within spread) |
| parse_http_date_rfc7231 | 112 [112–113] (n=3) | 114 [113–115] (n=3) | +1.7% (within spread) |
| parse_range | 7.88 [7.86–7.89] (n=3) | 7.92 [7.84–7.98] (n=3) | +0.5% (within spread) |
| pipelined_read_decode_zerocopy/d64_c65536 | 813 [728–832] (n=3) | 804 [729–921] (n=3) | -1.1% (within spread) |
| pipelined_read_decode_zerocopy/d64_c8192 | 514 [505–525] (n=3) | 516 [489–645] (n=3) | +0.3% (within spread) |
| pipelined_read_decode_zerocopy/d8_c65536 | 128 [128–143] (n=3) | 102 [89.4–123] (n=3) | -20.1% (within spread) |
| pipelined_write_encode/d64_c1048576 | 1.82e+06 [1.79e+06–1.85e+06] (n=3) | 1.84e+06 [1.8e+06–1.88e+06] (n=3) | +0.8% (within spread) |
| pipelined_write_encode/d64_c65536 | 1.41e+05 [1.41e+05–1.48e+05] (n=3) | 1.44e+05 [1.4e+05–1.45e+05] (n=3) | +2.2% (within spread) |
| pipelined_write_encode/d8_c65536 | 1.74e+04 [1.74e+04–1.81e+04] (n=3) | 1.71e+04 [1.7e+04–1.81e+04] (n=3) | -2.0% (within spread) |
| pipelined_write_encode_coalesced/d64_c1048576 | 8.81e+05 [8.78e+05–9.05e+05] (n=3) | 8.79e+05 [8.75e+05–9.16e+05] (n=3) | -0.2% (within spread) |
| pipelined_write_encode_coalesced/d64_c65536 | 4.87e+04 [4.82e+04–5.05e+04] (n=3) | 4.8e+04 [4.75e+04–4.95e+04] (n=3) | -1.5% (within spread) |
| pipelined_write_encode_coalesced/d8_c65536 | 6.29e+03 [6.27e+03–6.38e+03] (n=3) | 6.26e+03 [6.25e+03–6.28e+03] (n=3) | -0.5% (within spread) |
| range_resolve | 0.975 [0.97–1.07] (n=3) | 0.969 [0.962–0.996] (n=3) | -0.6% (within spread) |
| sha256/1024 | 417 [414–428] (n=3) | 416 [415–417] (n=3) | -0.3% (within spread) |
| sha256/64 | 75.7 [75–76.5] (n=3) | 78.7 [78.7–78.8] (n=3) | +4.0% |
| sha256/65536 | 2.34e+04 [2.31e+04–2.36e+04] (n=3) | 2.31e+04 [2.3e+04–2.31e+04] (n=3) | -1.4% (within spread) |
| sha512/1024 | 908 [905–927] (n=3) | 905 [901–924] (n=3) | -0.3% (within spread) |
| sha512/64 | 228 [228–229] (n=3) | 228 [228–228] (n=3) | +0.1% (within spread) |
| sha512/65536 | 3.97e+04 [3.96e+04–4.03e+04] (n=3) | 3.96e+04 [3.95e+04–3.97e+04] (n=3) | -0.2% (within spread) |
| xml_element_escape_heavy | 51 [50.7–1.71e+03] (n=3) | 50.9 [50.7–52.8] (n=3) | -0.2% (within spread) |
| xml_list_100_objects | 3.51e+04 [3.51e+04–3.53e+04] (n=3) | 3.52e+04 [3.51e+04–3.56e+04] (n=3) | +0.1% (within spread) |

Every valid per-repetition measurement and request-error count is included in [measurements.tsv](measurements.tsv). Full logs, request-level traces, invalid attempts, and harness patches are retained locally in `target/validation-2026-09-07-final/`.
