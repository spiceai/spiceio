# spiceio real-build sccache bench — build-20260804T230803Z

| field | value |
| --- | --- |
| label | `baseline-v0.5.10` |
| build | `~/dev/spiceio/.claude/worktrees/prancy-tickling-dijkstra` |

`local` is sccache on local disk — the floor a network backend is measured
against. `nocache` is the compile-everything ceiling.

| arm | jobs | phase | wall | hits | misses | hit avg | write avg | errors |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| nocache | 16 | full | 9.1s | 0 | 0 | 0.00ms | 0.00ms | 0 |
| local | 16 | cold | 13.5s | 0 | 68 | 0.00ms | 1.20ms | 0 |
| local | 16 | warm | 4.0s | 68 | 0 | 0.58ms | 0.00ms | 0 |
| spiceio | 16 | cold | 9.5s | 0 | 68 | 0.00ms | 29.24ms | 0 |
| spiceio | 16 | warm | 4.0s | 68 | 0 | 28.02ms | 0.00ms | 0 |

## spiceio versus local disk

| jobs | phase | local | spiceio | overhead | per-op gap |
| ---: | --- | ---: | ---: | ---: | --- |
| 16 | cold | 13.5s | 9.5s | 0.70x | +28.04ms per cache write |
| 16 | warm | 4.0s | 4.0s | 1.00x | +27.44ms per cache hit |

## Cache value

| jobs | no cache | spiceio warm | saved |
| ---: | ---: | ---: | ---: |
| 16 | 9.1s | 4.0s | 56% |

## Raw

- `build-results.tsv` — every measurement, tab separated
- `stats-<arm>-j<jobs>-warm.txt` — full `sccache --show-stats` per arm
- `access-build.tsv` — spiceio server-side per-request log for the spiceio arm
