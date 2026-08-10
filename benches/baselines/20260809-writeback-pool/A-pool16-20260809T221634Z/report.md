# spiceio sccache bench — 20260809T221634Z

| field | value |
| --- | --- |
| label | `A-rep2` |
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
| 8 | put | 9662.4 | 5791.8 | 0.55ms | 1.59ms | 4.68ms | 9.96ms | 0 |
| 8 | mixed | 2829.9 | 1363.1 | 0.11ms | 3.84ms | 63.05ms | 136.38ms | 0 |
| 32 | put | 17979.7 | 10350.9 | 1.44ms | 2.47ms | 6.05ms | 12.25ms | 0 |
| 32 | mixed | 2614.3 | 1212.2 | 0.33ms | 8.91ms | 112.10ms | 233.07ms | 0 |
| 64 | put | 15916.6 | 9540.6 | 3.45ms | 5.22ms | 16.53ms | 25.16ms | 0 |
| 64 | mixed | 7198.5 | 3473.6 | 1.29ms | 13.69ms | 97.14ms | 196.34ms | 0 |

### writeback — server-side (time spiceio held the request)

```
concurrency 8:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET          461     216.6     0.00ms     4.01ms    79.87ms   136.14ms     0.00ms    19.98ms     0
  PUT          563     336.9     0.03ms     0.31ms     4.09ms     8.85ms     0.03ms     4.09ms     0

concurrency 32:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET          692     306.0     0.01ms     9.51ms   126.71ms   233.03ms     0.01ms    90.84ms     0
  PUT          844     492.2     0.03ms     0.99ms     4.67ms    10.63ms     0.03ms     4.67ms     0

concurrency 64:
  method     count       MiB        p50        p90        p99        max   head_p50   head_p99   5xx
  GET         1383     657.6     0.01ms    15.12ms   105.07ms   209.04ms     0.01ms    96.90ms     0
  PUT         1689    1004.3     0.04ms     2.03ms    13.17ms    23.65ms     0.03ms    13.17ms     0

```

## Raw

- Per-run JSON: `benches/results/pool/20260809T221634Z/<pass>-c<conc>.json`
- Per-run server summary: `benches/results/pool/20260809T221634Z/<pass>-c<conc>-server.tsv`
- Full access log (TSV `t_ms method status req_bytes resp_bytes head_us total_us path`):
  `benches/results/pool/20260809T221634Z/access-<pass>.tsv`
