# spiceio sccache bench — 20260809T221638Z

| field | value |
| --- | --- |
| label | `B-rep2` |
| target | `smb://<nas>/<share>` |
| SMB pool | 16 |
| key space | 512 objects |
| ops per worker per phase | 24 |
| phases | `put,mixed` |
| host | `Darwin 25.6.0 Mac15,8` |

Client-observed latency from `spiceio-loadgen` over persistent
keep-alive connections. `cached` is the shipping configuration;
`nocache` disables the GET body cache so every read reaches the NAS.

## writeback

| conc | phase | ops/s | MiB/s | p50 | p90 | p99 | p99.9 | err |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 8 | put | 15788.5 | 9463.8 | 0.32ms | 0.87ms | 3.63ms | 6.07ms | 0 |
| 8 | mixed | 4040.9 | 1946.3 | 0.25ms | 2.94ms | 49.25ms | 83.40ms | 0 |
| 32 | put | 18686.4 | 10757.8 | 1.40ms | 2.39ms | 7.16ms | 10.66ms | 0 |
| 32 | mixed | 3908.8 | 1812.4 | 0.43ms | 10.28ms | 92.78ms | 190.69ms | 0 |
| 64 | put | 16018.6 | 9601.7 | 3.35ms | 4.97ms | 16.46ms | 25.52ms | 0 |
| 64 | mixed | 6998.6 | 3377.2 | 0.64ms | 15.54ms | 96.09ms | 180.07ms | 0 |

### writeback — server-side (time spiceio held the request)

```
concurrency 8:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET          461     216.6     0.01ms     3.01ms    49.57ms    83.14ms     0.01ms    25.12ms     0
  PUT          563     336.9     0.03ms     0.41ms     3.34ms     5.77ms     0.02ms     3.34ms     0

concurrency 32:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET          692     306.0     0.01ms    12.21ms   104.26ms   190.36ms     0.01ms    60.13ms     0
  PUT          844     492.2     0.03ms     0.66ms     5.17ms     9.23ms     0.03ms     5.17ms     0

concurrency 64:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         1383     657.6     0.01ms    17.75ms   101.39ms   200.05ms     0.01ms    84.38ms     0
  PUT         1689    1004.3     0.03ms     2.08ms    13.15ms    23.75ms     0.03ms    13.14ms     0

```

## Raw

- Per-run JSON: `benches/results/pool/20260809T221638Z/<pass>-c<conc>.json`
- Per-run server summary: `benches/results/pool/20260809T221638Z/<pass>-c<conc>-server.tsv`
- Full access log (TSV `t_ms method status req_bytes resp_bytes head_us total_us path`):
  `benches/results/pool/20260809T221638Z/access-<pass>.tsv`
