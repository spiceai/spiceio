# Write-back flusher policy × pool size — 2026-08-09

Three arms, interleaved A,B,C,A,B,C,… over three reps so NAS drift spreads
across all of them rather than landing on whichever ran last. Directory names
are `<arm>-pool<n>-<run timestamp>`.

| arm | binary | pool | what it isolates |
| --- | --- | ---: | --- |
| A | v0.7.0 | 16 | baseline — flushers yield on spare admission permits |
| B | this branch | 16 | the flusher fix alone, at the old default |
| C | this branch | 32 | the fix plus the new default pool |

Phases `put,mixed` at concurrency 8/32/64. `mixed` (70% GET hit / 20% miss /
10% PUT) is the one that tracks a real sccache client; `put` alone measures
memory bandwidth, because write-back acknowledges from memory.

Per run: `report.md`, plus `writeback-c<conc>.json` (client-side latency) and
`writeback-c<conc>-server.tsv` (time spiceio held each request). The ~545 KB
per-run access logs are not committed — regenerate with `SPICEIO_ACCESS_LOG`,
which the bench script sets automatically.

Read the medians **with the per-rep spread**; see `../README.md` §3, where the
spread is what shows C to be steadier and not merely faster. Recompute with:

```bash
python3 - <<'PY'
import json, glob, pathlib, statistics as st
runs = {}
for d in glob.glob("*/"):
    p = pathlib.Path(d)
    if not (p / "report.md").exists():
        continue
    arm = p.name.split("-")[0]
    for f in p.glob("writeback-c*.json"):
        conc = int(f.stem.split("-c")[1])
        for ph in json.loads(f.read_text())["phases"]:
            runs.setdefault((arm, conc, ph["phase"]), []).append(ph)
for k in sorted(runs):
    v = runs[k]
    print(k, "ops/s", round(st.median(x["ops_per_sec"] for x in v)),
          "p90", [round(x["latency_us"]["p90"] / 1000, 1) for x in v])
PY
```
