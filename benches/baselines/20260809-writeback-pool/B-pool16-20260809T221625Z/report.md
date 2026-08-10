# spiceio sccache bench — 20260809T221625Z

| field | value |
| --- | --- |
| label | `B-rep1` |
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
| 8 | put | 9080.9 | 5443.2 | 0.63ms | 1.71ms | 3.72ms | 10.42ms | 0 |
| 8 | mixed | 5495.2 | 2646.8 | 0.17ms | 2.07ms | 36.60ms | 72.24ms | 0 |
| 32 | put | 19377.3 | 11155.5 | 1.39ms | 2.19ms | 6.43ms | 12.61ms | 0 |
| 32 | mixed | 6526.1 | 3025.9 | 0.50ms | 3.74ms | 39.37ms | 114.05ms | 0 |
| 64 | put | 15571.0 | 9333.4 | 3.56ms | 4.85ms | 16.06ms | 28.06ms | 0 |
| 64 | mixed | 4733.4 | 2284.1 | 1.12ms | 19.65ms | 114.94ms | 207.88ms | 0 |

### writeback — server-side (time spiceio held the request)

```
concurrency 8:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET          461     216.6     0.01ms     2.08ms    52.21ms    71.82ms     0.01ms    16.78ms     0
  PUT          563     336.9     0.03ms     0.29ms     3.59ms     9.75ms     0.03ms     3.59ms     0

concurrency 32:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET          692     306.0     0.01ms     3.52ms    43.01ms   113.64ms     0.01ms    31.86ms     0
  PUT          844     492.2     0.04ms     0.80ms     5.03ms    11.28ms     0.04ms     5.03ms     0

concurrency 64:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         1383     657.6     0.01ms    21.25ms   121.91ms   319.33ms     0.01ms    89.02ms     0
  PUT         1689    1004.3     0.03ms     1.99ms    12.26ms    25.92ms     0.03ms    12.26ms     0

```

## Raw

- Per-run JSON: `benches/results/pool/20260809T221625Z/<pass>-c<conc>.json`
- Per-run server summary: `benches/results/pool/20260809T221625Z/<pass>-c<conc>-server.tsv`
- Full access log (TSV `t_ms method status req_bytes resp_bytes head_us total_us path`):
  `benches/results/pool/20260809T221625Z/access-<pass>.tsv`
