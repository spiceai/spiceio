# spiceio sccache bench — 20260809T221629Z

| field | value |
| --- | --- |
| label | `C-rep1` |
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
| 8 | put | 9433.4 | 5654.5 | 0.56ms | 1.52ms | 4.05ms | 10.46ms | 0 |
| 8 | mixed | 2923.0 | 1407.9 | 0.12ms | 4.85ms | 53.37ms | 86.60ms | 0 |
| 32 | put | 19078.7 | 10983.6 | 1.44ms | 2.25ms | 6.37ms | 10.61ms | 0 |
| 32 | mixed | 5603.5 | 2598.2 | 0.49ms | 4.30ms | 27.32ms | 134.57ms | 0 |
| 64 | put | 16220.5 | 9722.8 | 3.44ms | 4.63ms | 15.29ms | 26.01ms | 0 |
| 64 | mixed | 8935.0 | 4311.6 | 1.20ms | 6.70ms | 78.43ms | 160.16ms | 0 |

### writeback — server-side (time spiceio held the request)

```
concurrency 8:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET          461     216.6     0.00ms     7.44ms    55.81ms    86.30ms     0.00ms    22.76ms     0
  PUT          563     336.9     0.03ms     0.31ms     3.54ms     9.41ms     0.03ms     3.54ms     0

concurrency 32:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET          692     306.0     0.01ms     4.28ms    28.43ms   134.28ms     0.01ms    21.25ms     0
  PUT          844     492.2     0.03ms     1.06ms     4.94ms     9.63ms     0.03ms     4.94ms     0

concurrency 64:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         1383     657.6     0.01ms     6.29ms    82.54ms   164.91ms     0.01ms    26.00ms     0
  PUT         1689    1004.3     0.04ms     2.34ms    11.44ms    23.56ms     0.04ms    11.44ms     0

```

## Raw

- Per-run JSON: `benches/results/pool/20260809T221629Z/<pass>-c<conc>.json`
- Per-run server summary: `benches/results/pool/20260809T221629Z/<pass>-c<conc>-server.tsv`
- Full access log (TSV `t_ms method status req_bytes resp_bytes head_us total_us path`):
  `benches/results/pool/20260809T221629Z/access-<pass>.tsv`
