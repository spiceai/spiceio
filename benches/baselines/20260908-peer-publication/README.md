# Peer publication and multipart reaper review follow-up

Application `6573bfc` is compared with the previous PR head, `a4473f6`. The default write-back queue stays at 1 GiB.

## Changes and correctness validation

- Multipart expiry retains owned write guards through map removal. Active part/completion operations are skipped; requests that cloned a lock before expiry revalidate the upload after acquiring it.
- GET, HEAD, raw stat, streaming, and copy-source opens recheck a missing leaf name once with no fixed sleep. This absorbs a brief rename/close interval in another process, whose in-memory publication registry is independent. Missing parents, invalid paths, and permissions return immediately. This bounded retry is not distributed locking and cannot cover indefinitely stalled publication.
- A forced missing-name response fails the new recovery regression on `a4473f6` with `NotFound`. The fixed implementation passes all five open paths for name-not-found, no-such-file, and delete-pending responses. Tests also verify the retry bound and immediate permanent errors.
- `make ci` passed: 379 Rust tests, six Python cleanup tests, lint, and all four live NAS suites. All-features/all-targets tests passed, including 54 Criterion smoke cases; the release build passed.
- The write-back live suite now includes two simultaneous proxy processes with write-back, body caching, and spill disabled. Across 1,024 concurrent PUT/GET/HEAD/range/copy requests on 4 KiB and 128 KiB objects, every read returned one complete generation and no hit returned 404.
- The live ten-day retention test passed against an isolated local proxy. No expired objects were present in its private prefix; the fresh sentinel survived. All six benchmark prefixes were independently verified empty. The installed proxy on port 8333 remained running.

## Benchmark method

Six sequential runs used three paired repetitions in A/B, B/A, A/B order. Each process swept concurrency 1, 8, 32, 64, 128, and 256, with 512 objects and max(512, concurrency × 24) requests per phase. Phases were PUT, GET hit, HEAD hit, HEAD miss, GET miss, and mixed (70% GET hit / 20% GET miss / 10% PUT). Pure read phases ran twice; the last repetition supplied the reported sample. All access-log statuses, including discarded warmups, were audited.

The standard load generator places misses below a nonexistent parent. For this comparison, the harness created a marker under that parent and self-copied it to force any pending write onto the NAS before measuring. All measured miss keys remained absent, so they exercised missing **leaf names** and paid the new retry cost. The identical frozen load generator and seeded-parent harness were used for both applications.

Both arms used 32 SMB connections, etag revalidation, an isolated spill, the default 1 GiB write-back queue, and a file-descriptor limit of 8192. This small working set did not fill the queue (zero synchronous fallbacks), so these results do not replace the separate sustained queue-capacity experiment. PUT figures measure asynchronous acknowledgements, not durable NAS throughput.

The comparison contains **216 reported measurements / 451,584 reported requests**. Access logs verify **752,652 requests including warmups and seed operations, with zero status errors**. Every process reported zero flush retries.

Cells show median [minimum–maximum] across three repetitions. A delta smaller than the larger arm’s full min–max spread is marked “within spread” and is inconclusive; this is not a statistical significance test. These are finite sequential phases on a shared NAS.

## Mixed workload

| Concurrency | Before ops/s | After ops/s | Change | Before p99 ms | After p99 ms |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 741.78 [653.44–755.39] | 662.12 [654.97–674.06] | -10.7% (within spread) | 17.30 [16.09–19.44] | 19.26 [19.26–19.27] |
| 8 | 509.86 [479.04–521.92] | 564.62 [538.54–567.94] | +10.7% | 224.98 [199.87–230.65] | 158.75 [155.58–163.24] |
| 32 | 564.94 [530.95–589.93] | 500.62 [498.50–774.51] | -11.4% (within spread) | 644.28 [422.26–662.51] | 622.75 [444.04–671.05] |
| 64 | 734.56 [656.68–1,058.39] | 823.21 [701.46–1,210.28] | +12.1% (within spread) | 797.20 [792.91–1,172.52] | 726.81 [579.36–1,056.09] |
| 128 | 1,261.31 [1,119.21–2,097.05] | 1,548.93 [858.64–2,013.48] | +22.8% (within spread) | 854.77 [801.26–1,114.94] | 1,102.42 [446.40–1,146.32] |
| 256 | 1,017.60 [930.50–3,289.10] | 3,069.00 [3,010.19–3,827.32] | +201.6% (within spread) | 1,640.48 [997.53–2,107.23] | 889.75 [675.84–1,299.00] |

## HEAD missing leaf

| Concurrency | Before p50 ms | After p50 ms | Before ops/s | After ops/s |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 0.52 [0.48–0.54] | 0.93 [0.92–0.96] | 1,640.14 [1,550.60–2,010.48] | 1,031.67 [966.64–1,060.74] |
| 8 | 0.69 [0.59–0.69] | 1.49 [1.40–1.97] | 4,522.45 [4,459.46–6,190.94] | 3,432.76 [1,114.91–3,678.25] |
| 32 | 4.39 [3.12–6.89] | 11.43 [11.43–12.68] | 4,027.04 [3,974.17–6,507.32] | 2,421.87 [2,272.35–2,684.80] |
| 64 | 10.11 [6.51–10.48] | 22.78 [13.77–25.67] | 5,806.81 [5,783.93–7,813.77] | 2,798.47 [2,282.20–3,268.87] |
| 128 | 24.36 [21.80–25.14] | 48.94 [48.91–51.23] | 5,005.73 [3,302.52–5,802.90] | 2,519.00 [2,257.44–2,568.47] |
| 256 | 52.53 [50.22–60.52] | 98.34 [97.46–99.80] | 4,242.62 [3,820.77–4,751.18] | 2,640.63 [2,480.45–2,647.00] |

## GET missing leaf

| Concurrency | Before p50 ms | After p50 ms | Before ops/s | After ops/s |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 0.55 [0.55–0.58] | 1.01 [0.99–1.02] | 1,745.78 [1,631.12–1,775.24] | 912.85 [894.78–939.40] |
| 8 | 0.76 [0.71–0.79] | 1.51 [1.46–1.51] | 5,521.77 [5,484.06–6,975.89] | 3,434.16 [3,280.11–4,096.20] |
| 32 | 3.57 [3.06–5.11] | 9.54 [6.48–12.17] | 5,398.65 [4,753.43–6,532.98] | 2,615.28 [2,530.94–4,129.39] |
| 64 | 9.40 [7.08–12.60] | 25.16 [17.59–26.90] | 4,989.75 [3,743.89–6,561.80] | 2,398.33 [1,829.49–2,413.49] |
| 128 | 25.32 [15.62–26.64] | 52.94 [50.61–53.61] | 4,873.83 [4,101.26–5,669.84] | 2,335.48 [2,327.60–2,405.77] |
| 256 | 49.06 [47.78–57.05] | 106.65 [104.30–116.20] | 4,919.88 [4,116.04–5,296.10] | 2,241.04 [2,167.32–2,438.25] |

The retry adds an SMB round trip for genuine missing leaves. Pure miss throughput decreases because each missing leaf now performs two SMB opens; successful opens have no new SMB request or timer. The tables quantify the complete mixed workload rather than assuming that unchanged hit code implies unchanged observed hit timings.

All phase samples are in [measurements.tsv](measurements.tsv), with host and binary identities in [environment.json](environment.json). [comparison.md](comparison.md) includes per-metric spread comparisons and process counters. The earlier [queue-capacity experiment](../20260907-review-queue/README.md) and [full original validation matrix](../20260907-correctness-retention/README.md) retain their original source identities. Raw local logs and the seeded-parent harness are retained under `target/review-2026-09-07-r3/`.
