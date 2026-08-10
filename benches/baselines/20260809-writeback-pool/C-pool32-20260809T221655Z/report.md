# spiceio sccache bench — 20260809T221655Z

| field | value |
| --- | --- |
| label | `C-rep3` |
| target | `smb://<nas>/<share>` |
| SMB pool | 32 |
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
| 8 | put | 9515.5 | 5703.7 | 0.56ms | 1.77ms | 4.58ms | 11.66ms | 0 |
| 8 | mixed | 5181.4 | 2495.7 | 0.23ms | 1.60ms | 41.69ms | 74.94ms | 0 |
| 32 | put | 18123.2 | 10433.5 | 1.48ms | 2.25ms | 7.54ms | 11.65ms | 0 |
| 32 | mixed | 3411.2 | 1581.7 | 0.28ms | 4.89ms | 131.46ms | 210.22ms | 0 |
| 64 | put | 15889.2 | 9524.1 | 3.47ms | 4.82ms | 16.53ms | 25.07ms | 0 |
| 64 | mixed | 7411.9 | 3576.6 | 1.09ms | 6.08ms | 62.54ms | 175.96ms | 0 |

### writeback — server-side (time spiceio held the request)

```
concurrency 8:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET          461     216.6     0.01ms     1.35ms    45.69ms    74.54ms     0.01ms    14.96ms     0
  PUT          563     336.9     0.03ms     0.28ms     4.19ms    10.68ms     0.03ms     4.19ms     0

concurrency 32:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET          692     306.0     0.01ms     5.48ms   135.32ms   209.94ms     0.01ms    34.72ms     0
  PUT          844     492.2     0.04ms     0.83ms     5.95ms    10.54ms     0.04ms     5.95ms     0

concurrency 64:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         1383     657.6     0.01ms     6.11ms    65.85ms   192.14ms     0.01ms    41.51ms     0
  PUT         1689    1004.3     0.03ms     2.09ms    13.67ms    26.65ms     0.03ms    13.67ms     0

```

## Raw

- Per-run JSON: `benches/results/pool/20260809T221655Z/<pass>-c<conc>.json`
- Per-run server summary: `benches/results/pool/20260809T221655Z/<pass>-c<conc>-server.tsv`
- Full access log (TSV `t_ms method status req_bytes resp_bytes head_us total_us path`):
  `benches/results/pool/20260809T221655Z/access-<pass>.tsv`
