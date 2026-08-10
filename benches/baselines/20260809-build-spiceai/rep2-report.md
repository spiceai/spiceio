# spiceio real-build sccache bench — build-20260809T233331Z

| field | value |
| --- | --- |
| label | `post-review-fixes-rep2` |
| build | `~/dev/spiceai` (-p spice) |

`local` is sccache on local disk — the floor a network backend is measured
against. `nocache` is the compile-everything ceiling.

| arm | jobs | phase | wall | hits | misses | hit avg | write avg | errors |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| local | 16 | cold | 159.5s | 0 | 1163 | 0.00ms | 1.53ms | 0 |
| local | 16 | warm | 20.9s | 1163 | 0 | 1.21ms | 0.00ms | 0 |
| spiceio | 16 | cold | 160.0s | 3 | 1160 | 1.44ms | 1.24ms | 0 |
| spiceio | 16 | warm | 24.2s | 1163 | 0 | 25.39ms | 0.00ms | 0 |

## spiceio versus local disk

| jobs | phase | local | spiceio | overhead | per-op gap |
| ---: | --- | ---: | ---: | ---: | --- |
| 16 | cold | 159.5s | 160.0s | 1.00x | +-0.29ms per cache write |
| 16 | warm | 20.9s | 24.2s | 1.16x | +24.18ms per cache hit |

## Raw

- `build-results.tsv` — every measurement, tab separated
- `stats-<arm>-j<jobs>-warm.txt` — full `sccache --show-stats` per arm
- `access-build.tsv` — spiceio server-side per-request log for the spiceio arm
