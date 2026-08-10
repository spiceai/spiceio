# spiceio real-build sccache bench — build-20260809T232901Z

| field | value |
| --- | --- |
| label | `post-review-fixes-immutable` |
| build | `~/dev/spiceai` (-p spice) |

`local` is sccache on local disk — the floor a network backend is measured
against. `nocache` is the compile-everything ceiling.

| arm | jobs | phase | wall | hits | misses | hit avg | write avg | errors |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| spiceio | 16 | cold | 189.0s | 0 | 1163 | 0.00ms | 1.29ms | 0 |
| spiceio | 16 | warm | 26.7s | 1163 | 0 | 2.06ms | 0.00ms | 0 |

## spiceio versus local disk

| jobs | phase | local | spiceio | overhead | per-op gap |
| ---: | --- | ---: | ---: | ---: | --- |

## Raw

- `build-results.tsv` — every measurement, tab separated
- `stats-<arm>-j<jobs>-warm.txt` — full `sccache --show-stats` per arm
- `access-build.tsv` — spiceio server-side per-request log for the spiceio arm
