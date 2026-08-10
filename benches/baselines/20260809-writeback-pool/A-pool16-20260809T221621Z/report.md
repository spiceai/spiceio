# spiceio sccache bench — 20260809T221621Z

| field | value |
| --- | --- |
| label | `A-rep1` |
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
| 8 | put | 9967.9 | 5974.9 | 0.54ms | 1.57ms | 4.76ms | 10.51ms | 0 |
| 8 | mixed | 3431.5 | 1652.8 | 0.11ms | 3.23ms | 60.16ms | 125.56ms | 0 |
| 32 | put | 17699.2 | 10189.4 | 1.56ms | 2.15ms | 7.02ms | 11.25ms | 0 |
| 32 | mixed | 5142.1 | 2384.2 | 0.29ms | 9.52ms | 101.78ms | 144.14ms | 0 |
| 64 | put | 16356.5 | 9804.3 | 3.32ms | 4.43ms | 15.80ms | 25.20ms | 0 |
| 64 | mixed | 9529.7 | 4598.5 | 0.68ms | 8.45ms | 49.06ms | 146.64ms | 0 |

### writeback — server-side (time spiceio held the request)

```
concurrency 8:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET          461     216.6     0.00ms     3.29ms    61.41ms   125.42ms     0.00ms    16.69ms     0
  PUT          563     336.9     0.03ms     0.31ms     3.89ms     9.22ms     0.03ms     3.89ms     0

concurrency 32:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET          692     306.0     0.01ms    10.10ms   109.93ms   143.46ms     0.01ms    89.41ms     0
  PUT          844     492.2     0.04ms     0.89ms     5.62ms    10.46ms     0.04ms     5.61ms     0

concurrency 64:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         1383     657.6     0.01ms    10.04ms    50.16ms   152.79ms     0.01ms    48.43ms     0
  PUT         1689    1004.3     0.04ms     1.78ms    11.95ms    23.02ms     0.04ms    11.95ms     0

```

## Raw

- Per-run JSON: `benches/results/pool/20260809T221621Z/<pass>-c<conc>.json`
- Per-run server summary: `benches/results/pool/20260809T221621Z/<pass>-c<conc>-server.tsv`
- Full access log (TSV `t_ms method status req_bytes resp_bytes head_us total_us path`):
  `benches/results/pool/20260809T221621Z/access-<pass>.tsv`
