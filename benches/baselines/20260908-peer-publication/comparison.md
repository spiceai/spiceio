# Peer publication retry comparison

Three rotating repetitions per configuration. Cells show median [minimum–maximum].
Differences smaller than the larger repetition spread are inconclusive; this is not a statistical significance test.

## leaf-misses, mixed workload, 1 workers

| Configuration | Ops/s | p90 ms | p99 ms | Errors across all phases |
| --- | ---: | ---: | ---: | ---: |
| before | 741.78 [653.44–755.39] | 2.65 [1.97–2.84] | 17.30 [16.09–19.44] | 0 |
| after | 662.12 [654.97–674.06] | 2.01 [2.00–2.11] | 19.26 [19.26–19.27] | 0 |

| Comparison | Throughput change | p90 change | p99 change |
| --- | ---: | ---: | ---: |
| before -> after | -10.7% (within spread) | -24.3% (within spread) | +11.3% (within spread) |

## leaf-misses, mixed workload, 8 workers

| Configuration | Ops/s | p90 ms | p99 ms | Errors across all phases |
| --- | ---: | ---: | ---: | ---: |
| before | 509.86 [479.04–521.92] | 31.70 [30.31–35.66] | 224.98 [199.87–230.65] | 0 |
| after | 564.62 [538.54–567.94] | 30.44 [29.91–34.05] | 158.75 [155.58–163.24] | 0 |

| Comparison | Throughput change | p90 change | p99 change |
| --- | ---: | ---: | ---: |
| before -> after | +10.7% | -4.0% (within spread) | -29.4% |

## leaf-misses, mixed workload, 32 workers

| Configuration | Ops/s | p90 ms | p99 ms | Errors across all phases |
| --- | ---: | ---: | ---: | ---: |
| before | 564.94 [530.95–589.93] | 82.97 [50.21–109.70] | 644.28 [422.26–662.51] | 0 |
| after | 500.62 [498.50–774.51] | 93.59 [50.55–107.73] | 622.75 [444.04–671.05] | 0 |

| Comparison | Throughput change | p90 change | p99 change |
| --- | ---: | ---: | ---: |
| before -> after | -11.4% (within spread) | +12.8% (within spread) | -3.3% (within spread) |

## leaf-misses, mixed workload, 64 workers

| Configuration | Ops/s | p90 ms | p99 ms | Errors across all phases |
| --- | ---: | ---: | ---: | ---: |
| before | 734.56 [656.68–1,058.39] | 84.70 [43.67–190.19] | 797.20 [792.91–1,172.52] | 0 |
| after | 823.21 [701.46–1,210.28] | 120.38 [55.23–132.25] | 726.81 [579.36–1,056.09] | 0 |

| Comparison | Throughput change | p90 change | p99 change |
| --- | ---: | ---: | ---: |
| before -> after | +12.1% (within spread) | +42.1% (within spread) | -8.8% (within spread) |

## leaf-misses, mixed workload, 128 workers

| Configuration | Ops/s | p90 ms | p99 ms | Errors across all phases |
| --- | ---: | ---: | ---: | ---: |
| before | 1,261.31 [1,119.21–2,097.05] | 137.36 [70.44–245.86] | 854.77 [801.26–1,114.94] | 0 |
| after | 1,548.93 [858.64–2,013.48] | 111.39 [95.86–196.79] | 1,102.42 [446.40–1,146.32] | 0 |

| Comparison | Throughput change | p90 change | p99 change |
| --- | ---: | ---: | ---: |
| before -> after | +22.8% (within spread) | -18.9% (within spread) | +29.0% (within spread) |

## leaf-misses, mixed workload, 256 workers

| Configuration | Ops/s | p90 ms | p99 ms | Errors across all phases |
| --- | ---: | ---: | ---: | ---: |
| before | 1,017.60 [930.50–3,289.10] | 299.14 [135.90–309.07] | 1,640.48 [997.53–2,107.23] | 0 |
| after | 3,069.00 [3,010.19–3,827.32] | 172.58 [132.93–234.37] | 889.75 [675.84–1,299.00] | 0 |

| Comparison | Throughput change | p90 change | p99 change |
| --- | ---: | ---: | ---: |
| before -> after | +201.6% (within spread) | -42.3% (within spread) | -45.8% (within spread) |

## Queue pressure and process memory

One process covers concurrency 1, 8, 32, 64, 128, and 256 sequentially. Memory is its highest sampled RSS, not per-concurrency memory. Queue counters include warmup and cleanup.

| Run | Synchronous fallbacks | Flush retries | Peak RSS MiB | Maximum 1m host load |
| --- | ---: | ---: | ---: | ---: |
| leaf-misses-r1-before | 0 | 0 | 852 | 6.08 |
| leaf-misses-r1-after | 0 | 0 | 892 | 5.36 |
| leaf-misses-r2-after | 0 | 0 | 774 | 5.08 |
| leaf-misses-r2-before | 0 | 0 | 1,211 | 6.82 |
| leaf-misses-r3-before | 0 | 0 | 1,082 | 6.47 |
| leaf-misses-r3-after | 0 | 0 | 809 | 6.10 |
