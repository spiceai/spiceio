# spiceio sccache bench — 20260809T221647Z

| field | value |
| --- | --- |
| label | `A-rep3` |
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
| 8 | put | 10038.7 | 6017.3 | 0.50ms | 1.60ms | 4.21ms | 10.78ms | 0 |
| 8 | mixed | 3706.2 | 1785.1 | 0.13ms | 3.82ms | 59.34ms | 102.81ms | 0 |
| 32 | put | 18979.3 | 10926.4 | 1.48ms | 2.25ms | 7.12ms | 10.69ms | 0 |
| 32 | mixed | 3220.8 | 1493.4 | 0.26ms | 8.48ms | 97.88ms | 228.46ms | 0 |
| 64 | put | 16314.7 | 9779.2 | 3.42ms | 4.32ms | 14.62ms | 26.93ms | 0 |
| 64 | mixed | 12217.4 | 5895.5 | 1.14ms | 10.48ms | 57.72ms | 100.32ms | 0 |

### writeback — server-side (time spiceio held the request)

```
concurrency 8:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET          461     216.6     0.00ms     4.20ms    59.45ms   102.47ms     0.00ms    16.06ms     0
  PUT          563     336.9     0.03ms     0.31ms     3.58ms     9.88ms     0.03ms     3.58ms     0

concurrency 32:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET          692     306.0     0.01ms     9.96ms   108.12ms   228.31ms     0.01ms    80.54ms     0
  PUT          844     492.2     0.04ms     0.81ms     5.25ms     9.79ms     0.04ms     5.25ms     0

concurrency 64:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         1383     657.6     0.01ms    10.97ms    68.08ms    99.66ms     0.01ms    54.72ms     0
  PUT         1689    1004.3     0.03ms     1.65ms    11.46ms    24.25ms     0.03ms    11.46ms     0

```

## Raw

- Per-run JSON: `benches/results/pool/20260809T221647Z/<pass>-c<conc>.json`
- Per-run server summary: `benches/results/pool/20260809T221647Z/<pass>-c<conc>-server.tsv`
- Full access log (TSV `t_ms method status req_bytes resp_bytes head_us total_us path`):
  `benches/results/pool/20260809T221647Z/access-<pass>.tsv`
