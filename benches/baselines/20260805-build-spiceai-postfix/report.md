# spiceio real-build sccache bench — build-20260805T004520Z

| field | value |
| --- | --- |
| label | `post-review-fixes` |
| build | `/Users/lukim/dev/spiceai` (-p spice) |

`local` is sccache on local disk — the floor a network backend is measured
against. `nocache` is the compile-everything ceiling.

| arm | jobs | phase | wall | hits | misses | hit avg | write avg | errors |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| local | 16 | cold | 160.6s | 0 | 1163 | 0.00ms | 1.15ms | 0 |
| local | 16 | warm | 41.8s | 1162 | 1 | 1.49ms | 6.20ms | 0 |
| spiceio | 16 | cold | 230.0s | 2 | 1161 | 1.89ms | 20.99ms | 0 |
| spiceio | 16 | warm | 23.5s | 1163 | 0 | 27.86ms | 0.00ms | 0 |

## spiceio versus local disk

| jobs | phase | local | spiceio | overhead | per-op gap |
| ---: | --- | ---: | ---: | ---: | --- |
| 16 | cold | 160.6s | 230.0s | 1.43x | +19.84ms per cache write |
| 16 | warm | 41.8s | 23.5s | 0.56x | +26.37ms per cache hit |

## Raw

- `build-results.tsv` — every measurement, tab separated
- `stats-<arm>-j<jobs>-warm.txt` — full `sccache --show-stats` per arm
- `access-build.tsv` — spiceio server-side per-request log for the spiceio arm
