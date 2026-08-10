# spiceio sccache bench — 20260805T014123Z

| field | value |
| --- | --- |
| label | `perf-default` |
| target | `smb://<nas>/<share>` |
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
| 1 | put | 68.0 | 40.8 | 4.06ms | 24.18ms | 249.73ms | 341.26ms | 0 |
| 1 | get | 1276.1 | 764.9 | 0.62ms | 1.07ms | 3.66ms | 6.69ms | 0 |
| 1 | head-hit | 1299.7 | 0.0 | 0.67ms | 0.80ms | 3.45ms | 10.56ms | 0 |
| 1 | head-miss | 1330.1 | 0.0 | 0.50ms | 0.88ms | 5.81ms | 7.84ms | 0 |
| 1 | mixed | 457.7 | 220.5 | 0.77ms | 2.45ms | 22.61ms | 69.35ms | 0 |
| 8 | put | 152.3 | 91.3 | 23.57ms | 125.08ms | 369.03ms | 530.12ms | 0 |
| 8 | get | 6393.5 | 3832.3 | 0.95ms | 2.19ms | 4.96ms | 9.93ms | 0 |
| 8 | head-hit | 6725.1 | 0.0 | 0.95ms | 1.92ms | 4.61ms | 6.06ms | 0 |
| 8 | head-miss | 2734.8 | 0.0 | 1.23ms | 7.19ms | 21.41ms | 28.85ms | 0 |
| 8 | mixed | 1115.5 | 537.3 | 1.89ms | 19.26ms | 77.70ms | 138.62ms | 0 |
| 32 | put | 147.5 | 88.4 | 115.82ms | 504.29ms | 1240.15ms | 2020.44ms | 0 |
| 32 | get | 6923.8 | 4150.2 | 3.89ms | 6.25ms | 16.96ms | 35.81ms | 0 |
| 32 | head-hit | 7344.1 | 0.0 | 3.99ms | 6.28ms | 11.03ms | 16.30ms | 0 |
| 32 | head-miss | 11726.0 | 0.0 | 2.46ms | 4.36ms | 6.17ms | 8.43ms | 0 |
| 32 | mixed | 1337.4 | 644.2 | 8.51ms | 43.60ms | 190.25ms | 217.74ms | 0 |
| 64 | put | 171.7 | 102.9 | 184.23ms | 767.67ms | 1246.66ms | 1819.68ms | 0 |
| 64 | get | 7043.7 | 4222.1 | 7.88ms | 12.15ms | 34.16ms | 43.68ms | 0 |
| 64 | head-hit | 7147.8 | 0.0 | 8.53ms | 10.00ms | 15.73ms | 16.42ms | 0 |
| 64 | head-miss | 12172.0 | 0.0 | 4.79ms | 7.53ms | 9.64ms | 10.23ms | 0 |
| 64 | mixed | 1121.7 | 532.2 | 23.26ms | 108.86ms | 362.04ms | 525.68ms | 0 |
| 128 | put | 167.3 | 100.3 | 490.57ms | 1350.09ms | 2081.64ms | 2769.53ms | 0 |
| 128 | get | 3682.5 | 2207.3 | 21.08ms | 70.63ms | 156.05ms | 194.34ms | 0 |
| 128 | head-hit | 5473.1 | 0.0 | 21.39ms | 31.73ms | 57.75ms | 70.05ms | 0 |
| 128 | head-miss | 10848.5 | 0.0 | 10.07ms | 16.93ms | 24.72ms | 25.87ms | 0 |
| 128 | mixed | 1045.5 | 493.8 | 68.14ms | 250.26ms | 621.76ms | 1287.67ms | 0 |
| 256 | put | 156.2 | 93.7 | 1387.45ms | 2385.69ms | 3434.52ms | 4490.91ms | 0 |
| 256 | get | 6651.2 | 3986.8 | 37.34ms | 45.97ms | 62.03ms | 68.03ms | 0 |
| 256 | head-hit | 4646.2 | 0.0 | 43.97ms | 97.39ms | 221.82ms | 248.93ms | 0 |
| 256 | head-miss | 12030.9 | 0.0 | 18.61ms | 25.68ms | 119.80ms | 122.94ms | 0 |
| 256 | mixed | 956.5 | 459.8 | 201.68ms | 388.75ms | 751.09ms | 1215.99ms | 0 |

### cached — server-side (time spiceio held the request)

```
concurrency 1:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         1485     830.4     0.61ms     9.64ms    61.22ms   304.37ms     0.60ms     7.76ms     0
  HEAD        2048       0.0     0.53ms     0.67ms     4.12ms    10.45ms     0.53ms     4.12ms     0
  PUT          563     336.9     3.91ms    24.02ms   249.55ms   341.01ms     3.90ms   249.54ms     0

concurrency 8:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         1485     830.4     1.67ms    40.96ms   249.40ms  1092.48ms     1.67ms    34.63ms     0
  HEAD        2048       0.0     0.79ms     2.47ms    12.65ms    28.76ms     0.79ms    12.65ms     0
  PUT          563     336.9    23.28ms   121.66ms   368.90ms   530.02ms    23.28ms   368.90ms     0

concurrency 32:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         1485     830.4     6.49ms   194.09ms   653.91ms  1738.19ms     6.48ms   388.80ms     0
  HEAD        2048       0.0     3.03ms     5.84ms    11.24ms    23.58ms     3.03ms    11.24ms     0
  PUT          563     336.9   106.95ms   486.49ms  1240.08ms  2020.38ms   106.95ms  1240.08ms     0

concurrency 64:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         2970    1655.6    14.28ms   201.29ms   904.50ms  2505.59ms    14.28ms   666.95ms     0
  HEAD        4096       0.0     6.85ms     9.74ms    14.89ms    17.52ms     6.85ms    14.89ms     0
  PUT         1126     671.7   169.92ms   755.19ms  1228.81ms  1857.13ms   169.91ms  1228.81ms     0

concurrency 128:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         5940    3319.0    58.22ms   290.64ms  1275.82ms  3332.37ms    57.78ms   753.26ms     0
  HEAD        8192       0.0    15.75ms    26.29ms    38.42ms    66.42ms    15.75ms    38.42ms     0
  PUT         2252    1331.1   463.06ms  1327.92ms  2029.23ms  3602.72ms   463.05ms  2029.23ms     0

concurrency 256:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET        11879    6656.6    53.01ms   346.55ms  1285.21ms  3294.66ms    52.58ms  1107.68ms     0
  HEAD       16384       0.0    27.92ms    55.96ms   186.35ms   249.73ms    27.92ms   186.35ms     0
  PUT         4505    2677.8  1315.96ms  2342.74ms  3353.94ms  5398.73ms  1315.96ms  3353.94ms     0

```

## nocache

| conc | phase | ops/s | MiB/s | p50 | p90 | p99 | p99.9 | err |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | put | 68.0 | 40.7 | 3.76ms | 24.96ms | 256.83ms | 320.36ms | 0 |
| 1 | get | 85.0 | 50.9 | 2.41ms | 19.26ms | 229.99ms | 252.05ms | 0 |
| 1 | head-hit | 1063.5 | 0.0 | 0.75ms | 1.32ms | 4.47ms | 5.71ms | 0 |
| 1 | head-miss | 2147.4 | 0.0 | 0.42ms | 0.52ms | 1.54ms | 5.12ms | 0 |
| 1 | mixed | 101.3 | 48.8 | 2.30ms | 19.14ms | 84.81ms | 247.42ms | 0 |
| 8 | put | 153.8 | 92.2 | 22.41ms | 125.83ms | 372.44ms | 616.38ms | 0 |
| 8 | get | 170.9 | 102.5 | 10.13ms | 85.06ms | 488.10ms | 982.58ms | 0 |
| 8 | head-hit | 5870.4 | 0.0 | 0.91ms | 2.11ms | 5.01ms | 13.42ms | 0 |
| 8 | head-miss | 2334.4 | 0.0 | 1.13ms | 10.34ms | 30.04ms | 45.06ms | 0 |
| 8 | mixed | 221.1 | 106.5 | 8.05ms | 75.92ms | 300.26ms | 1079.99ms | 0 |
| 32 | put | 145.4 | 87.1 | 114.97ms | 480.40ms | 976.16ms | 1374.15ms | 0 |
| 32 | get | 170.1 | 102.0 | 81.58ms | 413.76ms | 1264.96ms | 1828.13ms | 0 |
| 32 | head-hit | 2376.0 | 0.0 | 6.37ms | 34.89ms | 57.41ms | 62.73ms | 0 |
| 32 | head-miss | 8176.0 | 0.0 | 3.54ms | 6.46ms | 9.93ms | 11.94ms | 0 |
| 32 | mixed | 219.6 | 105.8 | 42.79ms | 349.05ms | 775.11ms | 1314.18ms | 0 |
| 64 | put | 164.9 | 98.9 | 193.03ms | 837.50ms | 1461.92ms | 2124.22ms | 0 |
| 64 | get | 171.8 | 103.0 | 227.05ms | 737.62ms | 1736.90ms | 2614.68ms | 0 |
| 64 | head-hit | 6726.3 | 0.0 | 8.77ms | 12.79ms | 22.57ms | 29.31ms | 0 |
| 64 | head-miss | 9958.6 | 0.0 | 5.44ms | 9.65ms | 12.47ms | 13.48ms | 0 |
| 64 | mixed | 226.4 | 107.4 | 138.22ms | 615.42ms | 1370.53ms | 2335.99ms | 0 |
| 128 | put | 167.6 | 100.5 | 484.07ms | 1391.85ms | 2239.14ms | 2875.64ms | 0 |
| 128 | get | 172.9 | 103.6 | 524.49ms | 1493.30ms | 2774.04ms | 3809.37ms | 0 |
| 128 | head-hit | 6604.1 | 0.0 | 17.93ms | 24.63ms | 31.32ms | 33.21ms | 0 |
| 128 | head-miss | 10674.6 | 0.0 | 9.47ms | 14.82ms | 45.42ms | 48.70ms | 0 |
| 128 | mixed | 228.3 | 107.8 | 374.90ms | 1125.01ms | 2346.05ms | 3902.29ms | 0 |
| 256 | put | 166.9 | 100.0 | 1268.35ms | 2214.95ms | 3051.99ms | 4125.69ms | 0 |
| 256 | get | 176.1 | 105.5 | 1230.46ms | 2189.99ms | 3585.31ms | 5216.47ms | 0 |
| 256 | head-hit | 6968.3 | 0.0 | 35.17ms | 43.13ms | 62.36ms | 69.20ms | 0 |
| 256 | head-miss | 10473.5 | 0.0 | 21.66ms | 31.04ms | 74.49ms | 82.43ms | 0 |
| 256 | mixed | 225.4 | 108.4 | 931.98ms | 1730.89ms | 2840.35ms | 3961.86ms | 0 |

### nocache — server-side (time spiceio held the request)

```
concurrency 1:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         1485     830.4     2.27ms    19.16ms   226.29ms   300.67ms     2.27ms     7.54ms     0
  HEAD        2048       0.0     0.50ms     0.92ms     4.60ms    14.80ms     0.50ms     4.60ms     0
  PUT          563     336.9     3.65ms    24.99ms   256.73ms   320.21ms     3.65ms   256.72ms     0

concurrency 8:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         1485     830.4     9.16ms    81.99ms   488.07ms  1108.81ms     8.24ms    48.38ms     0
  HEAD        2048       0.0     0.74ms     2.40ms    17.55ms    44.94ms     0.74ms    17.55ms     0
  PUT          563     336.9    22.23ms   123.80ms   372.38ms   616.26ms    22.23ms   372.37ms     0

concurrency 32:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         1485     830.4    70.79ms   386.30ms  1141.50ms  1828.10ms    39.98ms   544.49ms     0
  HEAD        2048       0.0     4.17ms    15.42ms    47.62ms    62.60ms     4.17ms    47.62ms     0
  PUT          563     336.9   117.03ms   483.29ms   976.12ms  1374.06ms   117.02ms   976.12ms     0

concurrency 64:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         2970    1655.6   191.90ms   708.85ms  1643.66ms  3544.56ms   128.96ms   971.05ms     0
  HEAD        4096       0.0     6.53ms    12.73ms    22.50ms    32.02ms     6.53ms    22.50ms     0
  PUT         1126     671.7   200.55ms   839.48ms  1485.75ms  2473.44ms   200.55ms  1485.75ms     0

concurrency 128:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         5940    3319.0   484.28ms  1359.17ms  2597.92ms  4845.76ms   375.03ms  1491.43ms     0
  HEAD        8192       0.0    14.62ms    25.99ms    44.19ms    87.28ms    14.62ms    44.19ms     0
  PUT         2252    1331.1   489.66ms  1407.36ms  2279.97ms  3779.72ms   489.66ms  2279.97ms     0

concurrency 256:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET        11879    6656.6  1131.41ms  2065.09ms  3393.13ms  6481.14ms  1035.78ms  2281.76ms     0
  HEAD       16384       0.0    30.44ms    40.84ms    47.36ms    57.19ms    30.44ms    47.36ms     0
  PUT         4505    2677.8  1255.36ms  2222.00ms  3088.42ms  5033.45ms  1255.36ms  3088.42ms     0

```

## Raw

- Per-run JSON: `benches/results/20260805T014123Z/<pass>-c<conc>.json`
- Per-run server summary: `benches/results/20260805T014123Z/<pass>-c<conc>-server.tsv`
- Full access log (TSV `t_ms method status req_bytes resp_bytes head_us total_us path`):
  `benches/results/20260805T014123Z/access-<pass>.tsv`
