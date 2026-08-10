# spiceio real-build sccache bench — build-20260809T231959Z

| field | value |
| --- | --- |
| label | `post-review-fixes-pool32` |
| build | `~/dev/spiceai` (-p spice) |

`local` is sccache on local disk — the floor a network backend is measured
against. `nocache` is the compile-everything ceiling.

| arm | jobs | phase | wall | hits | misses | hit avg | write avg | errors |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| nocache | 16 | full | 127.3s | 0 | 0 | 0.00ms | 0.00ms | 0 |
| local | 16 | cold | 151.9s | 0 | 1163 | 0.00ms | 1.46ms | 0 |
| local | 16 | warm | 19.7s | 1163 | 0 | 1.55ms | 0.00ms | 0 |
| spiceio | 16 | cold | 155.4s | 0 | 1163 | 0.00ms | 1.13ms | 0 |
| spiceio | 16 | warm | 24.9s | 1163 | 0 | 25.16ms | 0.00ms | 0 |

## spiceio versus local disk

| jobs | phase | local | spiceio | overhead | per-op gap |
| ---: | --- | ---: | ---: | ---: | --- |
| 16 | cold | 151.9s | 155.4s | 1.02x | +-0.33ms per cache write |
| 16 | warm | 19.7s | 24.9s | 1.26x | +23.61ms per cache hit |

## Cache value

| jobs | no cache | spiceio warm | saved |
| ---: | ---: | ---: | ---: |
| 16 | 127.3s | 24.9s | 80% |

## Raw

- `build-results.tsv` — every measurement, tab separated
- `stats-<arm>-j<jobs>-warm.txt` — full `sccache --show-stats` per arm
- `access-build.tsv` — spiceio server-side per-request log for the spiceio arm
