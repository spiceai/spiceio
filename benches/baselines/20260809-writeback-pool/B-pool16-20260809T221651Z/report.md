# spiceio sccache bench — 20260809T221651Z

| field | value |
| --- | --- |
| label | `B-rep3` |
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
| 8 | put | 9982.9 | 5983.8 | 0.49ms | 1.64ms | 4.07ms | 11.64ms | 0 |
| 8 | mixed | 5098.9 | 2455.9 | 0.17ms | 2.35ms | 46.72ms | 73.18ms | 0 |
| 32 | put | 17859.2 | 10281.5 | 1.54ms | 2.32ms | 7.45ms | 12.62ms | 0 |
| 32 | mixed | 4573.9 | 2120.8 | 0.53ms | 13.60ms | 49.90ms | 163.66ms | 0 |
| 64 | put | 15851.3 | 9501.5 | 3.47ms | 4.73ms | 16.14ms | 23.45ms | 0 |
| 64 | mixed | 9222.4 | 4450.3 | 0.28ms | 17.31ms | 93.53ms | 128.95ms | 0 |

### writeback — server-side (time spiceio held the request)

```
concurrency 8:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET          461     216.6     0.01ms     2.38ms    49.16ms    72.62ms     0.01ms    19.94ms     0
  PUT          563     336.9     0.03ms     0.29ms     3.47ms    10.55ms     0.03ms     3.47ms     0

concurrency 32:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET          692     306.0     0.01ms    14.65ms    73.42ms   163.47ms     0.01ms    47.88ms     0
  PUT          844     492.2     0.03ms     0.93ms     5.88ms    11.53ms     0.03ms     5.88ms     0

concurrency 64:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         1383     657.6     0.01ms    18.09ms    95.49ms   157.50ms     0.01ms    75.57ms     0
  PUT         1689    1004.3     0.03ms     1.43ms    12.79ms    26.60ms     0.03ms    12.79ms     0

```

## Raw

- Per-run JSON: `benches/results/pool/20260809T221651Z/<pass>-c<conc>.json`
- Per-run server summary: `benches/results/pool/20260809T221651Z/<pass>-c<conc>-server.tsv`
- Full access log (TSV `t_ms method status req_bytes resp_bytes head_us total_us path`):
  `benches/results/pool/20260809T221651Z/access-<pass>.tsv`
