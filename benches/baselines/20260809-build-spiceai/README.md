# Real-build sccache benchmark — 2026-08-09

spiceai `-p spice`, 1163 compile units, `-j16`. Files are prefixed by run:

| prefix | arms | why |
| --- | --- | --- |
| `rep1-` | nocache, local, spiceio | the headline comparison |
| `rep2-` | local, spiceio | repeat, because one pair does not decide anything here |
| `immutable-` | spiceio only | `SPICEIO_IMMUTABLE_OBJECTS=1`, the sccache production setting |

`local` is sccache on local disk — the floor a network backend is measured
against. `nocache` is the compile-everything ceiling. Numbers and the reading of
them are in `../README.md` §4; the short version is that the cold build is at
parity with local disk, the warm build is 1.16–1.26×, and per *write* spiceio is
faster than local disk because write-back acknowledges from memory.

`immutable-` is kept because it is a **negative result worth not repeating**: it
cuts per-hit cost 25.16 ms → 2.06 ms (12×) and does not move warm wall clock at
`-j16`, where that latency is already hidden behind compilation.

Per run: `report.md`, `build-results.tsv` (every measurement), and
`stats-<arm>-j16-warm.txt` (full `sccache --show-stats`).

**No logs are committed.** This is a public repository, and both the proxy log
and the per-request access log carry the backend's address, the share name and
local filesystem paths, none of which a baseline needs. Both are written to
`benches/results/` on every run (gitignored) — `SPICEIO_LOG_FILE` and
`SPICEIO_ACCESS_LOG`, which the bench script sets automatically — so the
SMB-level cause of a failed cache write is still there to read locally.

Reproduce:

```bash
source /tmp/spiceio-bench-env.sh
BUILD_TARGET="$HOME/dev/spiceai" BUILD_PACKAGE=spice \
  BUILD_ARMS="nocache local spiceio" BUILD_JOBS=16 ./scripts/bench-sccache-build.sh
```
