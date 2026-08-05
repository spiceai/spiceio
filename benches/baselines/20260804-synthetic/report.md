# spiceio sccache bench — 20260804T224123Z

| field | value |
| --- | --- |
| label | `baseline-v0.5.10` |
| target | `smb://192.168.3.148/ai_platform_dev` |
| SMB pool | 12 |
| key space | 512 objects |
| ops per worker per phase | 16 |
| phases | `put,get,head-hit,head-miss,mixed` |
| host | `Darwin 25.6.0 Mac15,8` |

Client-observed latency from `spiceio-loadgen` over persistent
keep-alive connections. `cached` is the shipping configuration;
`nocache` disables the GET body cache so every read reaches the NAS.

## cached

| conc | phase | ops/s | MiB/s | p50 | p90 | p99 | p99.9 | err |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | put | 73.7 | 44.1 | 3.71ms | 22.00ms | 250.61ms | 317.82ms | 0 |
| 1 | get | 252.6 | 151.4 | 0.95ms | 1.69ms | 226.26ms | 233.94ms | 0 |
| 1 | head-hit | 1608.0 | 0.0 | 0.61ms | 0.65ms | 1.07ms | 2.35ms | 0 |
| 1 | head-miss | 2292.7 | 0.0 | 0.42ms | 0.47ms | 0.90ms | 5.31ms | 0 |
| 1 | mixed | 257.4 | 124.0 | 0.91ms | 1.95ms | 65.91ms | 256.37ms | 0 |
| 8 | put | 156.4 | 93.7 | 22.96ms | 118.38ms | 384.39ms | 589.45ms | 0 |
| 8 | get | 521.4 | 312.5 | 4.40ms | 12.94ms | 328.58ms | 624.80ms | 0 |
| 8 | head-hit | 4488.4 | 0.0 | 0.93ms | 3.43ms | 14.08ms | 20.41ms | 0 |
| 8 | head-miss | 11116.4 | 0.0 | 0.47ms | 1.00ms | 6.21ms | 6.71ms | 0 |
| 8 | mixed | 566.1 | 272.7 | 3.98ms | 17.51ms | 141.62ms | 630.37ms | 0 |
| 32 | put | 159.6 | 95.7 | 87.66ms | 414.97ms | 845.50ms | 1380.69ms | 0 |
| 32 | get | 460.5 | 276.0 | 12.61ms | 42.17ms | 754.41ms | 848.54ms | 0 |
| 32 | head-hit | 7480.2 | 0.0 | 4.02ms | 5.11ms | 6.59ms | 31.01ms | 0 |
| 32 | head-miss | 11283.4 | 0.0 | 2.69ms | 4.26ms | 5.94ms | 7.38ms | 0 |
| 32 | mixed | 541.0 | 260.6 | 15.53ms | 76.63ms | 432.26ms | 791.45ms | 0 |
| 64 | put | 172.3 | 103.3 | 173.09ms | 736.64ms | 1342.32ms | 1743.14ms | 0 |
| 64 | get | 515.1 | 308.7 | 35.06ms | 247.27ms | 755.94ms | 1343.57ms | 0 |
| 64 | head-hit | 6522.6 | 0.0 | 9.20ms | 12.92ms | 18.43ms | 18.87ms | 0 |
| 64 | head-miss | 13565.9 | 0.0 | 4.27ms | 5.79ms | 8.63ms | 9.99ms | 0 |
| 64 | mixed | 530.2 | 251.5 | 46.11ms | 268.35ms | 667.99ms | 1174.19ms | 0 |
| 128 | put | 169.4 | 101.5 | 485.68ms | 1329.67ms | 2002.99ms | 2526.80ms | 0 |
| 128 | get | 535.7 | 321.1 | 120.82ms | 533.72ms | 1124.24ms | 1459.66ms | 0 |
| 128 | head-hit | 6738.5 | 0.0 | 17.57ms | 23.94ms | 29.61ms | 31.57ms | 0 |
| 128 | head-miss | 13103.2 | 0.0 | 8.65ms | 12.42ms | 16.73ms | 18.14ms | 0 |
| 128 | mixed | 476.5 | 225.1 | 147.01ms | 502.42ms | 1188.29ms | 1535.83ms | 0 |
| 256 | put | 170.9 | 102.4 | 1238.79ms | 2112.63ms | 2892.85ms | 3732.24ms | 0 |
| 256 | get | 546.5 | 327.6 | 363.29ms | 821.07ms | 1338.39ms | 2200.47ms | 0 |
| 256 | head-hit | 6839.0 | 0.0 | 35.69ms | 44.04ms | 60.92ms | 68.61ms | 0 |
| 256 | head-miss | 10494.1 | 0.0 | 23.38ms | 32.77ms | 52.57ms | 56.78ms | 0 |
| 256 | mixed | 509.9 | 245.1 | 405.61ms | 750.30ms | 1380.77ms | 2035.21ms | 0 |

### cached — server-side (time spiceio held the request)

```
concurrency 1:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         1485     830.4     0.96ms     9.04ms   223.14ms   266.80ms     0.96ms     8.55ms     0
  HEAD        2048       0.0     0.50ms     0.72ms     3.81ms    19.38ms     0.50ms     3.81ms     0
  PUT          563     336.9     3.62ms    22.30ms   250.50ms   317.73ms     3.62ms   250.50ms     0

concurrency 8:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         1485     830.4     6.08ms    41.30ms   436.08ms  1026.20ms     5.93ms    32.04ms     0
  HEAD        2048       0.0     0.67ms     2.27ms     8.05ms    20.34ms     0.67ms     8.04ms     0
  PUT          563     336.9    22.57ms   116.50ms   384.32ms   589.38ms    22.57ms   384.32ms     0

concurrency 32:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         1485     830.4    21.67ms   264.62ms   839.10ms  1999.05ms    20.87ms   490.17ms     0
  HEAD        2048       0.0     3.22ms     5.23ms    10.05ms    42.32ms     3.22ms    10.05ms     0
  PUT          563     336.9    80.78ms   396.26ms   845.38ms  1380.59ms    80.77ms   845.38ms     0

concurrency 64:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         2970    1655.6    51.53ms   384.34ms  1052.85ms  2509.69ms    50.67ms   717.07ms     0
  HEAD        4096       0.0     6.12ms    11.07ms    17.26ms    35.20ms     6.12ms    17.26ms     0
  PUT         1126     671.7   163.81ms   724.60ms  1335.32ms  1785.37ms   163.81ms  1335.32ms     0

concurrency 128:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         5940    3319.0   134.96ms   602.29ms  1344.64ms  2740.18ms   133.27ms   914.96ms     0
  HEAD        8192       0.0    13.79ms    20.17ms    27.87ms    39.73ms    13.79ms    27.87ms     0
  PUT         2252    1331.1   457.43ms  1311.82ms  1963.94ms  2768.67ms   457.43ms  1963.94ms     0

concurrency 256:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET        11879    6656.6   381.94ms   843.80ms  1596.05ms  3935.06ms   378.11ms  1273.33ms     0
  HEAD       16384       0.0    27.87ms    41.00ms    46.50ms    54.21ms    27.87ms    46.50ms     0
  PUT         4505    2677.8  1195.39ms  2088.85ms  2867.65ms  5096.44ms  1195.39ms  2867.65ms     0

```

## nocache

| conc | phase | ops/s | MiB/s | p50 | p90 | p99 | p99.9 | err |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | put | 74.8 | 44.8 | 3.75ms | 21.49ms | 241.22ms | 256.28ms | 0 |
| 1 | get | 84.5 | 50.6 | 2.41ms | 19.38ms | 223.37ms | 302.88ms | 0 |
| 1 | head-hit | 1615.4 | 0.0 | 0.60ms | 0.66ms | 0.81ms | 4.13ms | 0 |
| 1 | head-miss | 2413.9 | 0.0 | 0.39ms | 0.48ms | 0.63ms | 3.16ms | 0 |
| 1 | mixed | 100.8 | 48.6 | 2.31ms | 19.05ms | 81.54ms | 228.80ms | 0 |
| 8 | put | 153.1 | 91.8 | 22.63ms | 117.45ms | 382.59ms | 561.19ms | 0 |
| 8 | get | 168.6 | 101.0 | 9.46ms | 89.21ms | 473.99ms | 952.11ms | 0 |
| 8 | head-hit | 7354.0 | 0.0 | 0.85ms | 1.71ms | 3.29ms | 5.26ms | 0 |
| 8 | head-miss | 11601.0 | 0.0 | 0.61ms | 0.97ms | 1.83ms | 2.43ms | 0 |
| 8 | mixed | 216.4 | 104.2 | 7.83ms | 81.90ms | 302.35ms | 1214.53ms | 0 |
| 32 | put | 168.4 | 100.9 | 79.51ms | 414.73ms | 850.27ms | 1284.72ms | 0 |
| 32 | get | 168.1 | 100.8 | 83.55ms | 437.95ms | 1164.01ms | 1749.76ms | 0 |
| 32 | head-hit | 7289.6 | 0.0 | 4.21ms | 5.25ms | 6.27ms | 6.59ms | 0 |
| 32 | head-miss | 3984.7 | 0.0 | 5.71ms | 18.17ms | 29.84ms | 41.90ms | 0 |
| 32 | mixed | 211.8 | 102.0 | 48.67ms | 365.76ms | 1030.61ms | 1511.12ms | 0 |
| 64 | put | 169.0 | 101.3 | 197.27ms | 803.17ms | 1262.47ms | 1733.80ms | 0 |
| 64 | get | 170.6 | 102.2 | 239.03ms | 737.38ms | 1586.19ms | 2634.82ms | 0 |
| 64 | head-hit | 7460.3 | 0.0 | 6.99ms | 12.65ms | 15.36ms | 17.64ms | 0 |
| 64 | head-miss | 10219.2 | 0.0 | 4.44ms | 9.27ms | 30.92ms | 39.38ms | 0 |
| 64 | mixed | 228.2 | 108.3 | 136.10ms | 644.23ms | 1279.46ms | 1808.25ms | 0 |
| 128 | put | 170.3 | 102.1 | 492.31ms | 1346.46ms | 2005.23ms | 2483.43ms | 0 |
| 128 | get | 167.6 | 100.5 | 563.38ms | 1476.53ms | 2759.79ms | 4152.72ms | 0 |
| 128 | head-hit | 6468.6 | 0.0 | 18.11ms | 24.71ms | 43.04ms | 44.77ms | 0 |
| 128 | head-miss | 5430.2 | 0.0 | 15.58ms | 50.72ms | 140.17ms | 145.46ms | 0 |
| 128 | mixed | 223.2 | 105.4 | 410.01ms | 1145.94ms | 2389.25ms | 3632.75ms | 0 |
| 256 | put | 168.9 | 101.2 | 1248.87ms | 2152.46ms | 2865.01ms | 3691.84ms | 0 |
| 256 | get | 162.1 | 97.2 | 1311.65ms | 2415.27ms | 3862.11ms | 5685.85ms | 0 |
| 256 | head-hit | 7048.0 | 0.0 | 34.28ms | 43.87ms | 59.07ms | 66.28ms | 0 |
| 256 | head-miss | 8471.4 | 0.0 | 19.42ms | 62.99ms | 98.61ms | 105.06ms | 0 |
| 256 | mixed | 222.3 | 106.8 | 931.99ms | 1765.61ms | 3009.37ms | 4452.97ms | 0 |

### nocache — server-side (time spiceio held the request)

```
concurrency 1:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         1485     830.4     2.29ms    19.12ms   222.38ms   302.85ms     2.28ms     9.99ms     0
  HEAD        2048       0.0     0.44ms     0.53ms     0.68ms     5.21ms     0.44ms     0.68ms     0
  PUT          563     336.9     3.69ms    21.52ms   241.16ms   256.18ms     3.69ms   241.15ms     0

concurrency 8:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         1485     830.4     9.13ms    86.37ms   473.95ms  1214.49ms     8.28ms    29.49ms     0
  HEAD        2048       0.0     0.64ms     1.38ms     3.78ms    15.24ms     0.64ms     3.78ms     0
  PUT          563     336.9    22.44ms   114.57ms   382.49ms   561.12ms    22.44ms   382.49ms     0

concurrency 32:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         1485     830.4    70.47ms   422.57ms  1163.96ms  2047.36ms    40.00ms   525.44ms     0
  HEAD        2048       0.0     3.50ms     7.09ms    23.32ms    41.82ms     3.50ms    23.32ms     0
  PUT          563     336.9    79.01ms   413.84ms   880.69ms  1477.26ms    79.01ms   880.69ms     0

concurrency 64:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         2970    1655.6   201.25ms   718.83ms  1525.07ms  2704.23ms   132.38ms   841.70ms     0
  HEAD        4096       0.0     5.74ms    12.24ms    25.80ms    45.51ms     5.74ms    25.80ms     0
  PUT         1126     671.7   197.19ms   813.56ms  1241.13ms  1756.93ms   197.19ms  1241.13ms     0

concurrency 128:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         5940    3319.0   497.12ms  1320.35ms  2649.01ms  4844.10ms   395.47ms  1483.53ms     0
  HEAD        8192       0.0    16.68ms    25.98ms    66.46ms   147.88ms    16.68ms    66.46ms     0
  PUT         2252    1331.1   495.47ms  1377.32ms  2187.69ms  3811.79ms   495.47ms  2187.69ms     0

concurrency 256:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET        11879    6656.6  1178.00ms  2189.04ms  3598.41ms  6368.52ms  1086.90ms  2389.59ms     0
  HEAD       16384       0.0    30.52ms    42.92ms    87.86ms   106.03ms    30.52ms    87.85ms     0
  PUT         4505    2677.8  1240.90ms  2161.88ms  2964.31ms  4388.05ms  1240.90ms  2964.31ms     0

```

## Raw

- Per-run JSON: `benches/results/20260804T224123Z/<pass>-c<conc>.json`
- Per-run server summary: `benches/results/20260804T224123Z/<pass>-c<conc>-server.tsv`
- Full access log (TSV `t_ms method status req_bytes resp_bytes head_us total_us path`):
  `benches/results/20260804T224123Z/access-<pass>.tsv`
