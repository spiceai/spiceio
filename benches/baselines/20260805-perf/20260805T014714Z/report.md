# spiceio sccache bench — 20260805T014714Z

| field | value |
| --- | --- |
| label | `perf-immutable` |
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
| 1 | put | 72.6 | 43.5 | 3.88ms | 22.31ms | 243.01ms | 265.50ms | 0 |
| 1 | get | 6585.2 | 3947.2 | 0.06ms | 0.21ms | 1.75ms | 5.95ms | 0 |
| 1 | head-hit | 1411.0 | 0.0 | 0.68ms | 0.78ms | 1.25ms | 3.74ms | 0 |
| 1 | head-miss | 1994.8 | 0.0 | 0.48ms | 0.56ms | 0.85ms | 2.62ms | 0 |
| 1 | mixed | 588.8 | 283.6 | 0.21ms | 2.12ms | 21.80ms | 84.84ms | 0 |
| 8 | put | 150.6 | 90.3 | 22.90ms | 120.79ms | 407.52ms | 536.40ms | 0 |
| 8 | get | 10449.4 | 6263.5 | 0.49ms | 1.55ms | 3.21ms | 10.14ms | 0 |
| 8 | head-hit | 6260.4 | 0.0 | 0.96ms | 2.40ms | 4.01ms | 6.35ms | 0 |
| 8 | head-miss | 13028.2 | 0.0 | 0.54ms | 0.79ms | 1.59ms | 3.19ms | 0 |
| 8 | mixed | 1379.8 | 664.6 | 0.28ms | 13.70ms | 93.84ms | 205.83ms | 0 |
| 32 | put | 169.8 | 101.8 | 82.91ms | 410.29ms | 841.93ms | 1150.18ms | 0 |
| 32 | get | 9111.8 | 5461.7 | 2.83ms | 5.89ms | 18.65ms | 33.30ms | 0 |
| 32 | head-hit | 2728.1 | 0.0 | 7.08ms | 25.52ms | 47.34ms | 51.44ms | 0 |
| 32 | head-miss | 14723.7 | 0.0 | 1.87ms | 2.84ms | 8.31ms | 19.72ms | 0 |
| 32 | mixed | 1454.9 | 700.8 | 1.86ms | 40.58ms | 279.60ms | 318.12ms | 0 |
| 64 | put | 161.5 | 96.8 | 199.63ms | 801.00ms | 1537.04ms | 2104.14ms | 0 |
| 64 | get | 10800.3 | 6473.8 | 3.95ms | 9.69ms | 26.70ms | 38.39ms | 0 |
| 64 | head-hit | 6067.0 | 0.0 | 10.48ms | 14.05ms | 18.43ms | 20.37ms | 0 |
| 64 | head-miss | 3666.7 | 0.0 | 11.77ms | 37.61ms | 57.96ms | 78.02ms | 0 |
| 64 | mixed | 1461.0 | 693.1 | 2.27ms | 83.15ms | 415.04ms | 453.86ms | 0 |
| 128 | put | 167.7 | 100.5 | 488.22ms | 1403.01ms | 2215.72ms | 2840.85ms | 0 |
| 128 | get | 12455.2 | 7465.8 | 7.58ms | 14.98ms | 41.56ms | 64.09ms | 0 |
| 128 | head-hit | 6038.2 | 0.0 | 18.87ms | 28.96ms | 39.92ms | 49.22ms | 0 |
| 128 | head-miss | 8824.0 | 0.0 | 13.63ms | 21.86ms | 27.25ms | 32.59ms | 0 |
| 128 | mixed | 1642.0 | 775.5 | 18.54ms | 152.57ms | 679.86ms | 1104.71ms | 0 |
| 256 | put | 168.2 | 100.8 | 1251.63ms | 2190.23ms | 3013.55ms | 3616.41ms | 0 |
| 256 | get | 12642.3 | 7577.9 | 17.04ms | 30.51ms | 76.58ms | 126.36ms | 0 |
| 256 | head-hit | 6817.2 | 0.0 | 35.04ms | 44.94ms | 128.20ms | 133.73ms | 0 |
| 256 | head-miss | 11915.5 | 0.0 | 18.79ms | 34.21ms | 51.51ms | 53.75ms | 0 |
| 256 | mixed | 1728.8 | 831.0 | 81.76ms | 250.77ms | 724.80ms | 1034.72ms | 0 |

### cached — server-side (time spiceio held the request)

```
concurrency 1:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         1485     830.4     0.00ms     0.01ms     0.55ms     0.76ms     0.00ms     0.55ms     0
  HEAD        2048       0.0     0.51ms     0.93ms     1.73ms    12.03ms     0.51ms     1.72ms     0
  PUT          563     336.9     3.79ms    22.19ms   242.91ms   265.33ms     3.79ms   242.91ms     0

concurrency 8:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         1485     830.4     0.00ms     0.01ms    19.38ms    32.58ms     0.00ms    19.38ms     0
  HEAD        2048       0.0     0.61ms     1.47ms     3.73ms     7.00ms     0.61ms     3.73ms     0
  PUT          563     336.9    22.73ms   119.48ms   407.32ms   536.31ms    22.73ms   407.32ms     0

concurrency 32:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         1485     830.4     0.01ms     0.03ms    56.22ms   132.92ms     0.01ms    56.21ms     0
  HEAD        2048       0.0     2.85ms     9.66ms    37.16ms    51.32ms     2.85ms    37.16ms     0
  PUT          563     336.9    81.90ms   389.00ms   841.85ms  1150.06ms    81.90ms   841.85ms     0

concurrency 64:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         2970    1655.6     0.01ms     0.01ms    92.64ms   225.45ms     0.00ms    92.64ms     0
  HEAD        4096       0.0     8.68ms    18.25ms    48.48ms    81.64ms     8.68ms    48.48ms     0
  PUT         1126     671.7   186.76ms   781.13ms  1536.53ms  2872.26ms   186.76ms  1536.53ms     0

concurrency 128:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         5940    3319.0     0.01ms    28.16ms   175.33ms   590.88ms     0.01ms   175.33ms     0
  HEAD        8192       0.0    16.02ms    24.85ms    34.53ms    44.67ms    16.02ms    34.53ms     0
  PUT         2252    1331.1   467.08ms  1387.10ms  2185.68ms  2906.63ms   467.08ms  2185.67ms     0

concurrency 256:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET        11879    6656.6     0.01ms   110.16ms   285.81ms   592.84ms     0.01ms   285.81ms     0
  HEAD       16384       0.0    21.56ms    43.01ms    63.73ms    82.85ms    21.56ms    63.73ms     0
  PUT         4505    2677.8  1208.12ms  2162.57ms  2979.64ms  4122.33ms  1208.12ms  2979.64ms     0

```

## Raw

- Per-run JSON: `benches/results/20260805T014714Z/<pass>-c<conc>.json`
- Per-run server summary: `benches/results/20260805T014714Z/<pass>-c<conc>-server.tsv`
- Full access log (TSV `t_ms method status req_bytes resp_bytes head_us total_us path`):
  `benches/results/20260805T014714Z/access-<pass>.tsv`
