# spiceio real-build sccache bench — build-20260804T231645Z

| field | value |
| --- | --- |
| label | `baseline-v0.5.10-spiceai` |
| build | `/Users/lukim/dev/spiceai` (-p spice) |

`local` is sccache on local disk — the floor a network backend is measured
against. `nocache` is the compile-everything ceiling.

| arm | jobs | phase | wall | hits | misses | hit avg | write avg | errors |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| local | 16 | cold | 167.9s | 0 | 1163 | 0.00ms | 1.22ms | 0 |
| local | 16 | warm | 24.4s | 1162 | 1 | 0.62ms | 2.32ms | 0 |
| spiceio | 16 | cold | 194.3s | 2 | 1161 | 2.64ms | 20.30ms | 40 |
| spiceio | 16 | warm | 34.2s | 1122 | 41 | 22.90ms | 58.50ms | 0 |

## spiceio versus local disk

| jobs | phase | local | spiceio | overhead | per-op gap |
| ---: | --- | ---: | ---: | ---: | --- |
| 16 | cold | 167.9s | 194.3s | 1.16x | +19.08ms per cache write |
| 16 | warm | 24.4s | 34.2s | 1.40x | +22.28ms per cache hit |

## Raw

- `build-results.tsv` — every measurement, tab separated
- `stats-<arm>-j<jobs>-warm.txt` — full `sccache --show-stats` per arm
- `access-build.tsv` — spiceio server-side per-request log for the spiceio arm
