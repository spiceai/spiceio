# PR review follow-up and queue comparison

Three rotating repetitions per configuration. Cells show median [minimum–maximum].
Differences smaller than the larger repetition spread are inconclusive; this is not a statistical significance test.

## synchronous, mixed workload, 8 workers

| Configuration | Ops/s | p90 ms | p99 ms | Errors across all phases |
| --- | ---: | ---: | ---: | ---: |
| trunk-1g | 1,190.56 [1,131.80–1,217.82] | 17.37 [13.27–19.54] | 73.06 [63.92–88.14] | 0 |
| published-1g | 1,044.71 [1,004.92–1,174.36] | 19.00 [18.92–19.35] | 90.25 [64.95–98.38] | 0 |
| optimized-1g | 1,140.75 [1,091.79–1,144.90] | 18.46 [14.20–19.04] | 76.18 [75.28–78.27] | 0 |

| Comparison | Throughput change | p90 change | p99 change |
| --- | ---: | ---: | ---: |
| published-1g -> optimized-1g | +9.2% (within spread) | -2.8% (within spread) | -15.6% (within spread) |
| trunk-1g -> optimized-1g | -4.2% (within spread) | +6.3% (within spread) | +4.3% (within spread) |

## synchronous, mixed workload, 32 workers

| Configuration | Ops/s | p90 ms | p99 ms | Errors across all phases |
| --- | ---: | ---: | ---: | ---: |
| trunk-1g | 1,146.57 [1,137.95–1,206.22] | 17.30 [14.52–22.77] | 276.03 [224.66–313.65] | 0 |
| published-1g | 911.94 [817.71–1,078.18] | 55.54 [54.86–66.03] | 245.22 [241.41–383.30] | 0 |
| optimized-1g | 1,061.70 [1,015.07–1,114.71] | 39.89 [34.67–46.11] | 233.64 [189.32–252.89] | 0 |

| Comparison | Throughput change | p90 change | p99 change |
| --- | ---: | ---: | ---: |
| published-1g -> optimized-1g | +16.4% (within spread) | -28.2% | -4.7% (within spread) |
| trunk-1g -> optimized-1g | -7.4% (within spread) | +130.5% | -15.4% (within spread) |

## sustained, mixed workload, 8 workers

| Configuration | Ops/s | p90 ms | p99 ms | Errors across all phases |
| --- | ---: | ---: | ---: | ---: |
| trunk-1g | 2,710.73 [2,684.55–2,874.40] | 4.47 [3.87–5.10] | 39.45 [35.44–40.12] | 0 |
| published-1g | 2,746.09 [2,432.94–2,946.64] | 5.26 [3.88–7.37] | 37.83 [36.54–38.53] | 0 |
| optimized-1g | 3,304.10 [3,128.31–3,645.50] | 3.38 [3.16–4.58] | 36.82 [35.94–37.31] | 0 |
| optimized-2g | 862.76 [818.35–1,067.20] | 14.61 [11.97–15.32] | 137.23 [109.58–179.93] | 0 |

| Comparison | Throughput change | p90 change | p99 change |
| --- | ---: | ---: | ---: |
| published-1g -> optimized-1g | +20.3% | -35.6% (within spread) | -2.7% (within spread) |
| trunk-1g -> optimized-1g | +21.9% | -24.4% (within spread) | -6.7% (within spread) |
| optimized-1g -> optimized-2g | -73.9% | +331.9% | +272.7% |

## sustained, mixed workload, 32 workers

| Configuration | Ops/s | p90 ms | p99 ms | Errors across all phases |
| --- | ---: | ---: | ---: | ---: |
| trunk-1g | 4,367.84 [4,352.67–4,527.38] | 10.54 [9.69–13.95] | 86.24 [75.99–92.95] | 0 |
| published-1g | 2,741.07 [2,728.74–2,911.63] | 17.65 [14.82–18.04] | 208.65 [181.69–208.88] | 0 |
| optimized-1g | 3,918.24 [3,870.72–4,039.91] | 13.65 [12.89–15.19] | 88.51 [71.07–104.92] | 0 |
| optimized-2g | 3,237.48 [3,171.83–3,522.82] | 9.75 [9.65–9.82] | 160.12 [137.76–185.14] | 0 |

| Comparison | Throughput change | p90 change | p99 change |
| --- | ---: | ---: | ---: |
| published-1g -> optimized-1g | +42.9% | -22.7% | -57.6% |
| trunk-1g -> optimized-1g | -10.3% | +29.5% (within spread) | +2.6% (within spread) |
| optimized-1g -> optimized-2g | -17.4% | -28.6% | +80.9% |

## Queue pressure and process memory

One process covers concurrency 8 and 32 sequentially. Memory is its highest sampled RSS, not per-concurrency memory. Queue counters include warmup and cleanup.

| Run | Synchronous fallbacks | Flush retries | Peak RSS MiB | Maximum 1m host load |
| --- | ---: | ---: | ---: | ---: |
| sustained-r1-trunk-1g | 3752 | 0 | 3,205 | 5.83 |
| sustained-r1-published-1g | 3902 | 0 | 3,213 | 6.28 |
| sustained-r1-optimized-1g | 4047 | 0 | 3,230 | 5.27 |
| sustained-r1-optimized-2g | 802 | 0 | 3,342 | 4.49 |
| sustained-r2-published-1g | 4179 | 0 | 3,156 | 4.73 |
| sustained-r2-optimized-1g | 3839 | 0 | 3,128 | 4.10 |
| sustained-r2-optimized-2g | 761 | 0 | 3,586 | 5.29 |
| sustained-r2-trunk-1g | 3878 | 0 | 3,291 | 5.81 |
| sustained-r3-optimized-1g | 3970 | 0 | 3,236 | 5.45 |
| sustained-r3-optimized-2g | 747 | 0 | 3,551 | 5.05 |
| sustained-r3-trunk-1g | 3691 | 0 | 3,161 | 4.15 |
| sustained-r3-published-1g | 4046 | 0 | 3,224 | 6.57 |
