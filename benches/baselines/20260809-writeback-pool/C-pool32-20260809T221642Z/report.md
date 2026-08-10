# spiceio sccache bench — 20260809T221642Z

| field | value |
| --- | --- |
| label | `C-rep2` |
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
| 8 | put | 10215.8 | 6123.5 | 0.48ms | 1.68ms | 4.55ms | 10.38ms | 0 |
| 8 | mixed | 5928.2 | 2855.3 | 0.15ms | 1.53ms | 39.20ms | 68.09ms | 0 |
| 32 | put | 18605.5 | 10711.1 | 1.47ms | 2.25ms | 7.10ms | 11.54ms | 0 |
| 32 | mixed | 3581.0 | 1660.4 | 0.38ms | 3.81ms | 72.90ms | 195.33ms | 0 |
| 64 | put | 16314.5 | 9779.1 | 3.35ms | 4.67ms | 16.80ms | 24.33ms | 0 |
| 64 | mixed | 5412.8 | 2611.9 | 1.29ms | 7.44ms | 37.80ms | 167.28ms | 0 |

### writeback — server-side (time spiceio held the request)

```
concurrency 8:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET          461     216.6     0.01ms     1.31ms    41.84ms    67.76ms     0.00ms     9.36ms     0
  PUT          563     336.9     0.03ms     0.29ms     3.86ms     9.71ms     0.03ms     3.86ms     0

concurrency 32:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET          692     306.0     0.01ms     3.92ms    87.27ms   195.13ms     0.01ms    22.36ms     0
  PUT          844     492.2     0.03ms     0.90ms     5.49ms    10.73ms     0.03ms     5.49ms     0

concurrency 64:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         1383     657.6     0.01ms     7.54ms    43.94ms   273.18ms     0.01ms    26.76ms     0
  PUT         1689    1004.3     0.03ms     2.16ms    12.39ms    24.64ms     0.03ms    12.39ms     0

```

## Raw

- Per-run JSON: `benches/results/pool/20260809T221642Z/<pass>-c<conc>.json`
- Per-run server summary: `benches/results/pool/20260809T221642Z/<pass>-c<conc>-server.tsv`
- Full access log (TSV `t_ms method status req_bytes resp_bytes head_us total_us path`):
  `benches/results/pool/20260809T221642Z/access-<pass>.tsv`
