# spiceio

**S3-compatible API proxy that turns any SMB share into an S3 endpoint** -- no mounting, no `libsmbclient`, no FUSE. Translates S3 HTTP requests directly into SMB 3.1.x wire-protocol operations over TCP.

## Why spiceio

Most tools that bridge SMB and S3 (MinIO, s3proxy, VersityGW) require mounting the share to the local filesystem first. spiceio skips that entirely -- it speaks the SMB wire protocol directly over TCP (port 445), so there's no mount, no kernel driver, and no FUSE layer in the way.

This makes it the simplest path from "I have an SMB share" to "any S3 client can use it":

```
S3 client  --->  spiceio (HTTP :8333)  --->  SMB server (TCP :445)
              S3 API translation            SMB 3.1.x wire protocol
```

### Key highlights

- **Zero-mount design** -- speaks SMB 3.1.x natively over TCP, never touches the local filesystem
- **Full S3 compatibility** for common operations: Get/Put/Copy/Delete/Head Object, ListObjects (v1 & v2), ListBuckets, multipart uploads, range + conditional requests
- **SMB2 compounding** -- batches Create+Read+Close or Create+Write+Close into single round trips for small file performance
- **Credit-window flow control** -- tracks the server's SMB2 credit grants per connection and sizes pipelined batches to the granted window, so sustained bursts never violate the protocol's sequence window
- **Streaming I/O** -- GetObject and PutObject stream directly between HTTP and SMB without buffering entire files
- **Load-aware connection pool** -- requests are dispatched to the least-busy SMB connection, so a one-round-trip HEAD never queues behind a multi-megabyte pipelined batch
- **Proactive keepalive** -- idle connections are probed with SMB2 ECHO (and TCP keepalive), so a session the server dropped while idle is reconnected before a client request ever lands on it
- **Server-side copy** -- CopyObject, UploadPartCopy and multipart assembly use SMB's `FSCTL_SRV_COPYCHUNK`, so the file server copies the bytes itself and they never cross the proxy (falls back to streaming if the server lacks it)
- **Verified before publish** -- every streamed write (PutObject, CopyObject, multipart assembly) is size-checked *before* it replaces the destination, so a failed check leaves the existing object untouched
- **Non-blocking logging** -- timestamped stdout/stderr with optional file tee via `SPICEIO_LOG_FILE`; dedicated writer thread, never stalls the proxy
- **Crash reporting built in** -- panics and fatal signals (SIGSEGV/SIGBUS/...) always leave a diagnosable report on stderr and in the log file: version, uptime, panic location, registers, fault address, and a backtrace with the info needed to symbolize stripped release builds offline
- **Optional SigV4 authentication** -- require every request to be signed with a configured access key (header or presigned URL, signed payloads and signed aws-chunked uploads included), or run in a log-only mode while clients are moved onto keys. Off by default; see [Authentication](#authentication)
- **Simple config** -- everything via environment variables, single binary, `--version` flag
- **Zero external crypto** -- NTLMv2 auth and AES-CMAC signing via macOS CommonCrypto FFI

### Use cases

- **sccache remote cache** -- point sccache at spiceio to store build cache on a NAS without cloud storage
- **CI artifact storage** -- use `aws s3 cp` to push/pull build artifacts from any SMB share
- **NAS integration** -- give S3-native tools access to existing file shares

## Quick start

Requires macOS 26+ and Rust (edition 2024).

```bash
make release
```

```bash
export SPICEIO_SMB_SERVER=nas.local
export SPICEIO_SMB_USER=admin
export SPICEIO_SMB_PASS=secret
export SPICEIO_SMB_SHARE=files
./target/release/spiceio
```

Now any S3 client works:

```bash
aws s3 ls s3://files/ --endpoint-url http://localhost:8333
aws s3 cp myfile.txt s3://files/remote.txt --endpoint-url http://localhost:8333
```

Without access keys configured, spiceio does not authenticate requests: anyone
who can reach the port can read, write and delete the whole share with the SMB
account's rights. Bind to loopback, or configure keys to require signed
requests ([Authentication](#authentication)).

### sccache example

Start spiceio with immutable-object caching on — sccache keys are content
hashes, so a cached body can be served without revalidating it. This is worth
**23x read throughput** and is the single most effective setting for this
workload (see [`benches/baselines/`](benches/baselines/)):

```bash
export SPICEIO_IMMUTABLE_OBJECTS=1
./target/release/spiceio
```

Then point sccache at it:

```bash
export SCCACHE_BUCKET=files
export SCCACHE_ENDPOINT=http://localhost:8333
export SCCACHE_REGION=us-east-1
export SCCACHE_S3_USE_SSL=false
export SCCACHE_S3_KEY_PREFIX=sccache
# Any values work while spiceio's auth is off; with it on, use a configured key
# (or RUSTC_WRAPPER=sccache-spiceio, see "The local launchd agent" below).
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export RUSTC_WRAPPER=sccache
export CARGO_INCREMENTAL=0

cargo build   # artifacts cached on your NAS via spiceio
```

The body cache defaults to 8 GiB of resident memory; lower
`SPICEIO_OBJECT_CACHE_BYTES` on hosts that cannot spare it. spiceio logs the
budget at startup and the achieved hit rate at shutdown.

Behind it sits a **machine-wide disk spill** (`/var/tmp/spiceio-cache`, 64 GiB,
on by default), so a working set larger than memory still avoids the NAS — and
every spiceio instance on the host shares one pool of cached bytes. Set
`SPICEIO_SPILL_DIR=off` to disable it.

Writes are also acknowledged from memory by default: PutObject returns as soon
as the body is cached, and the NAS write happens in the background. The client
never waits on it, because every read of that key is served from the cache
until the write lands — measured **2.6–6.7× faster end to end** on a
put-then-read sweep.

**This trades durability for latency.** A `kill -9` between the
acknowledgement and the background write loses that object. Right for a cache
(the entry is rebuilt), wrong for a system of record — turn it off with
`SPICEIO_WRITE_BACK=0` if this endpoint is anyone's source of truth. A
graceful stop (SIGTERM, SIGINT, SIGHUP or SIGQUIT) drains first, and anything
already written to the disk spill is replayed on the next start. Reads, listings, deletes and
copies all stay consistent with what was acknowledged; see
[Write-back](#write-back) below.

## Configuration

All configuration is via environment variables:

| Variable                      | Required | Default             | Description               |
| ----------------------------- | -------- | ------------------- | ------------------------- |
| `SPICEIO_SMB_SERVER`          | yes      |                     | SMB server hostname or IP |
| `SPICEIO_SMB_USER`            | yes      |                     | SMB username              |
| `SPICEIO_SMB_PASS`            | yes      |                     | SMB password              |
| `SPICEIO_SMB_SHARE`           | yes      |                     | SMB share name            |
| `SPICEIO_BIND`                | no       | `127.0.0.1:8333`    | Listen address. Loopback only by default: the S3 endpoint is unauthenticated, so set this (`0.0.0.0:8333`, `*:8333`, or a specific interface) to accept other hosts |
| `SPICEIO_SMB_PORT`            | no       | `445`               | SMB port                  |
| `SPICEIO_SMB_DOMAIN`          | no       | *(empty)*           | SMB domain                |
| `SPICEIO_BUCKET`              | no       | `SPICEIO_SMB_SHARE` | Virtual S3 bucket name    |
| `SPICEIO_REGION`              | no       | `us-east-1`         | AWS region to advertise   |
| `SPICEIO_SMB_CONNECTIONS`     | no       | 2× CPU count (8–32) | SMB connections in the pool |
| `SPICEIO_SMB_MAX_IO`          | no       | `262144`            | Max standalone read/write I/O size, bytes |
| `SPICEIO_MULTIPART_TTL_SECS`  | no       | `86400`             | Age at which an abandoned multipart upload is reaped |
| `SPICEIO_CLEANUP_GRACE_SECS`  | no       | `900`               | Startup cleanup leaves temp files/uploads newer than this alone, so instances sharing a share don't delete each other's in-flight state. `0` sweeps everything |
| `SPICEIO_LOG_FILE`            | no       | *(none)*            | Append logs to file (non-blocking) |
| `SPICEIO_ACCESS_LOG`          | no       | *(none)*            | Per-request TSV metrics log for benchmarking: `t_ms method status req_bytes resp_bytes head_us total_us path` |
| `SPICEIO_INSTANCE_ID`         | no       | random UUID v4      | Identity of this process. Logged at startup and sent as `service.instance.id` on every OTEL metric. Pin it to keep a stable series across restarts |
| `SPICEIO_MACHINE`             | no       | kernel hostname     | `machine` dimension on every OTEL metric. Override when the hostname is not the name you want in dashboards |
| `SPICEIO_OTEL_ENDPOINT`       | no       | *(none)*            | Push performance metrics over OTLP/gRPC to a Spice Cloud app. Accepts `org/app` (e.g. `spicehq/spiceio`), `https://spice.ai/org/app`, or a raw gRPC URL (`https://host:443`, `http://127.0.0.1:50051`) |
| `SPICEIO_OTEL_API_KEY`        | no       | *(none)*            | Spice Cloud app API key (`x-api-key` metadata). Required for Cloud ingest |
| `SPICEIO_OTEL_REGION`         | no       | `us-east-1`         | Cloud region used when `SPICEIO_OTEL_ENDPOINT` is an org/app pair; selects `{region}-prod-aws-flight.spiceai.io` |
| `SPICEIO_OTEL_INTERVAL_SECS`  | no       | `15`                | How often metrics are pushed. Failed pushes are retried with the interval re-accumulated rather than dropped |
| `SPICEIO_OBJECT_CACHE_BYTES`  | no       | `8589934592` (8 GiB) | Max total GET body cache size — up to this much resident memory. The most effective tuning knob |
| `SPICEIO_OBJECT_CACHE_MAX_OBJECT` | no   | budget / 64 (128 MiB) | Max size of a single cached object; scales with the budget so one object cannot evict a large share of the cache |
| `SPICEIO_OBJECT_CACHE_ENTRIES`| no       | `131072`            | Max body-cache entries (sized so bytes bind first) |
| `SPICEIO_IMMUTABLE_OBJECTS`   | no       | off                 | When `1`/`true`, serve cached bodies by key with **no backend round trip**. For content-addressed stores (sccache) where the key is a hash of the content. Gives up noticing a backend-side delete. Also turns on the existence index (fast 404s) unless `SPICEIO_EXISTENCE_INDEX` overrides |
| `SPICEIO_EXISTENCE_INDEX`     | no       | follows immutable   | Lazy per-directory name set: one SMB list of a parent, then missing leaves 404 with no open. Default on when immutable objects are on. `0`/`false`/`off` disables; `1`/`true` enables even if immutable is off. Wrong for a mutable namespace that must notice a peer's PUT |
| `SPICEIO_EXISTENCE_INDEX_TTL_SECS` | no | `0` (until PUT/DELETE) | Completeness TTL for a listed directory. `0` never expires; a peer PUT of a new hash 404s until then (acceptable for sccache) |
| `SPICEIO_SPILL_DIR`           | no       | `/var/tmp/spiceio-cache` | Disk tier behind the memory cache, shared by every instance on the host. Created 0700, so sharing is between processes of the same user; point this at a group-shared directory for cross-user sharing. `off` (or empty) disables it |
| `SPICEIO_SPILL_BYTES`         | no       | `68719476736` (64 GiB) | Disk budget for the whole spill directory, across all instances. Clamped so at least 10 GiB stays free, and to half the space above that |
| `SPICEIO_WRITE_BACK`          | no       | **on**              | Acknowledge PutObject from memory and write to the NAS in the background. `0`/`false`/`off` disables. **Trades durability for latency** — see [Write-back](#write-back) |
| `SPICEIO_WRITE_BACK_BYTES`    | no       | `1073741824` (1 GiB) | Ceiling on un-flushed bytes; past it PutObject writes through synchronously, applying backpressure |
| `SPICEIO_STRICT_PREFIXES`     | no       | disabled            | Comma-separated key prefixes with synchronous, server-coordinated writes and atomic write preconditions. `*` selects the whole bucket. Overrides write-back, immutable cache shortcuts, and the existence index for matching keys. Configure identically on every instance; see [Conditional writes](#conditional-writes) |
| `SPICEIO_S3_ACCESS_KEY_ID`    | no       | *(none)*            | Access key id clients sign with. Set together with `SPICEIO_S3_SECRET_ACCESS_KEY`; see [Authentication](#authentication) |
| `SPICEIO_S3_SECRET_ACCESS_KEY`| no       | *(none)*            | Its secret (at least 16 characters) |
| `SPICEIO_S3_CREDENTIALS_FILE` | no       | *(none)*            | File of `ACCESS_KEY_ID SECRET` lines, for several keys or a rotation. Must not be group/other accessible (`chmod 600`) |
| `SPICEIO_S3_AUTH`             | no       | `enforce` if a key is configured, else `off` | `off` (no authentication), `log` (verify and log failures, serve anyway), `enforce` (reject unsigned and badly signed requests) |

## Authentication

spiceio can require that every request be signed with AWS Signature Version 4
by an access key you configure. Clients sign exactly as they would for S3, with
the key as their AWS credentials. The keys authenticate clients *to spiceio*;
spiceio still connects to the NAS with its own SMB account, so no client ever
holds the SMB password.

```bash
export SPICEIO_S3_ACCESS_KEY_ID=ci-cache
export SPICEIO_S3_SECRET_ACCESS_KEY="$(openssl rand -base64 30)"
./target/release/spiceio   # S3 auth: enforce (SigV4; access keys: ci-cache)
```

```bash
# Any S3 client, with that key as its AWS credentials:
export AWS_ACCESS_KEY_ID=ci-cache
export AWS_SECRET_ACCESS_KEY=...   # the same secret
aws s3 ls s3://files/ --endpoint-url http://localhost:8333
```

Three modes, set with `SPICEIO_S3_AUTH`:

- **`off`** — no authentication. The default when no key is configured, so
  existing deployments behave exactly as before.
- **`enforce`** — every request except a CORS preflight must carry a valid
  signature from a configured key. This is the default once any key is
  configured: a key that is configured but not required would be a trap.
  Checked before anything else answers, including cache hits that never touch
  the NAS.
- **`log`** — verify exactly as `enforce` does, but serve the request anyway
  and log what would have been rejected. Use it to move clients onto keys
  without an outage, then switch to `enforce` once the log is quiet.

What is verified:

- `Authorization` header signatures and presigned URLs (`aws s3 presign`),
  with a 15-minute clock-skew window and presigned expiry up to 7 days.
- Signed payloads: a body that does not hash to its signed
  `x-amz-content-sha256` is rejected (`XAmzContentSHA256Mismatch`) before it
  is stored or acknowledged, write-back included, and before operations that
  ignore their body (DELETE, CopyObject, multipart initiate/abort) act. A
  presigned URL's digest can be in its query or in a signed
  `x-amz-content-sha256` header; if both are present, they must agree.
- Signed aws-chunked uploads (minio-go/mc), chunk by chunk, including signed
  trailers. Unsigned aws-chunked uploads (`aws s3 cp` in aws-cli v2) are
  accepted when the request headers are signed, as S3 does. A body pinned by
  a whole-body digest is never decoded as aws-chunked: unsigned headers
  (`Content-Encoding`, for one) cannot switch it to framing the digest does
  not cover.
- Every `x-amz-*` header must be signed, so a header such as
  `x-amz-copy-source` cannot be added to a signed request in transit. In a
  presigned request this includes `x-amz-content-sha256` and `x-amz-date`,
  which its signature covers only when they are listed.
- The request is read exactly as it was signed. The path is split into
  bucket and key after decoding, and query parameter names are decoded, the
  way the signature decodes them: `/bucket%2Fkey` is `/bucket/key`. A signed
  request that repeats a query parameter or a signed header is refused
  (`InvalidArgument`), because a signature does not cover their order. So is
  raw whitespace in `x-amz-copy-source`, because header values sign with
  whitespace runs collapsed; percent-encode it, as S3 clients do. One that
  lacks a header it signed is refused too (`AccessDenied`), because an absent
  header signs like an empty one. Any of these could otherwise be rewritten
  in transit into a different request, such as dropping a signed empty
  `If-Match` or copying a different object.

Session tokens are refused rather than ignored: only long-term keys are
supported. A rejected request returns the standard S3 error code; for
`SignatureDoesNotMatch` the response includes the canonical request and string
to sign that spiceio computed, which is the quickest way to find where a
client's signing differs. Failures are logged at most once a second, with a
count of what was suppressed.

To rotate a key without downtime, list old and new together in a credentials
file, move clients over, then remove the old line and restart:

```bash
cat > ~/.config/spiceio/keys <<'KEYS'
# ACCESS_KEY_ID  SECRET_ACCESS_KEY
ci-cache-2025    old-secret...
ci-cache-2026    new-secret...
KEYS
chmod 600 ~/.config/spiceio/keys
export SPICEIO_S3_CREDENTIALS_FILE=~/.config/spiceio/keys
```

Over plain HTTP, SigV4 keeps the secret off the wire and stops a request from
being altered, but a captured request can be replayed within the 15-minute
window and the data itself is not encrypted. Keep spiceio on a trusted network
or loopback.

### The local launchd agent (`make install`)

`make install` sets up SigV4 for a launchd agent (`ai.spice.spiceio`) running
the installed binary, and checks that it works:

1. If the agent's plist names no credentials file, the agent gets
   `~/.config/spiceio/credentials` (mode 0600, in a 0700 directory). If that
   file does not exist, install creates it with a fresh key. A credentials
   file that already exists is never rewritten. An agent that already names
   one keeps it, because other clients may sign with its keys.
2. install sets `SPICEIO_S3_CREDENTIALS_FILE` and `SPICEIO_S3_AUTH` in the
   plist's `EnvironmentVariables`. The edit is made on a copy and renamed into
   place, and the plist keeps its mode, its format and its symlink. First,
   `spiceio --check-auth` validates the result exactly as startup would, so a
   bad key file stops the install, not the agent.
3. install restarts the agent. If the plist's environment differs from what
   launchd loaded, it does a full reload instead, because `kickstart` would
   keep the old environment.
4. install checks the result. An unsigned request must be refused, and a
   request signed through `sccache-spiceio` must be served. Otherwise the
   install fails.

```bash
make install                    # SPICEIO_S3_AUTH=enforce
make install AGENT_AUTH=log     # verify and log, but still serve unsigned requests
make install AGENT_AUTH=keep    # leave the agent's auth settings alone
make install RESTART_AGENT=0    # stage the binary and the plist edit; a later install reloads it
```

sccache has to sign too, and once the agent enforces, an sccache that does not
sign **fails the build**, because its server cannot start against a store that
refuses it. Use the `sccache-spiceio` wrapper, installed beside the binary. It
passes the agent's key to sccache alone, so your shell's `AWS_PROFILE` still
applies to real AWS:

```bash
export RUSTC_WRAPPER="$HOME/.local/bin/sccache-spiceio"   # instead of sccache
# remove SCCACHE_S3_NO_CREDENTIALS; the wrapper unsets it, and AWS_SESSION_TOKEN
sccache --stop-server   # once: a running sccache server keeps the settings it started with
```

The wrapper signs with the *last* key in the file (or in
`SPICEIO_CLIENT_CREDENTIALS_FILE`). To rotate:

1. Append a new key.
2. Run `make install` so the agent accepts both keys.
3. Run `sccache --stop-server` so sccache starts signing with the new key.
4. Delete the old line and run `make install` again.

## OTEL metrics (Spice Cloud)

spiceio **pushes** performance metrics over OTLP/gRPC to a Spice Cloud app — it
does not expose a scrape endpoint. The Cloud app's Flight port is the
`MetricsService` ingest Spice already runs; metric names must match dataset
names in that app.

Each process has an **instance id** (UUID v4, or `SPICEIO_INSTANCE_ID`) and
labels every data point with **`machine`** (hostname, or `SPICEIO_MACHINE`)
and `service.instance.id`, so two proxies or two hosts are distinguishable in
the same app.

```bash
export SPICEIO_OTEL_ENDPOINT=spicehq/spiceio          # or https://spice.ai/spicehq/spiceio
export SPICEIO_OTEL_API_KEY=<app api key>
export SPICEIO_OTEL_REGION=us-west-2                  # this app's region
# optional: SPICEIO_INSTANCE_ID=nas-1
# optional: SPICEIO_MACHINE=build-host-3
```

Pushed metrics (delta sums/histograms over the interval, gauges as snapshots):

| Metric | Type | Dimensions |
| ------ | ---- | ---------- |
| `spiceio_http_requests` | Sum | `method`, `status`, `machine`, `service.instance.id` |
| `spiceio_http_request_bytes` / `spiceio_http_response_bytes` | Sum | `method`, `status`, `machine`, `service.instance.id` |
| `spiceio_http_duration_us` / `spiceio_http_head_duration_us` | Histogram | `method`, `status`, `machine`, `service.instance.id` |
| `spiceio_cache_hits` / `_misses` / `_hit_bytes` / `_bytes` / `_entries` | Gauge | `machine`, `service.instance.id` |
| `spiceio_spill_*`, `spiceio_writeback_*`, `spiceio_smb_inflight`, `spiceio_uptime_seconds` | Gauge | `machine`, `service.instance.id` |
| `spiceio_existence_absents` / `spiceio_existence_lists` | Gauge | `machine`, `service.instance.id` |

A failed push is retried with the interval re-accumulated; a down Cloud app
never stalls the proxy.

## Caching

Three tiers answer a GET, in order:

| Tier | Where | Size | Shared |
| ---- | ----- | ---- | ------ |
| L1   | process memory | 8 GiB (`SPICEIO_OBJECT_CACHE_BYTES`) | no |
| L2   | local disk (`SPICEIO_SPILL_DIR`) | 64 GiB (`SPICEIO_SPILL_BYTES`) | every instance on the machine |
| —    | the NAS over SMB | — | — |

A **directory existence index** (on with `SPICEIO_IMMUTABLE_OBJECTS`) sits
beside the body cache: one SMB list of a parent directory, then missing leaves
404 with no open. That is the sccache cold-build path (GET 404, then compile).
A negative cache of past 404s cannot help — each compile unit is a unique hash
seen once.

L2 exists because the backend saturates at a fixed rate (~100 MiB/s measured)
while local NVMe does not, and because a second spiceio instance should not
have to re-fetch what the first one already pulled down. Entries are addressed
by `sha256(backend-identity \0 key)` and carry a digest of the body, so a
half-written or power-loss-damaged entry reads as a miss rather than as a wrong
answer, and two instances fronting different shares never see each other's
objects. Eviction is LRU against the shared budget, serialized between
instances by an advisory lock; whichever instance holds it sweeps, the rest
skip that round. The directory is created 0700 — a world-writable cache would
let any local user plant an entry, and a planted entry with a correct digest is
served as a hit. Point `SPICEIO_SPILL_DIR` at a directory you have set up with
group permissions if instances run as different users.

Entries are also written on the way *out*: a PutObject populates both tiers, so
a cache client that reads back what it just wrote is served from memory.

### Write-back

PutObject returns once the body is in the cache. A pool of background flushers
then journals it to the disk spill, writes it to the NAS, and adopts the
backend's real etag and mtime in both tiers. On by default; `SPICEIO_WRITE_BACK=0`
turns it off and restores a synchronous backend write per PUT.

What is guaranteed:

- **Reads see it.** GET, range GET, and HEAD read the pending generation directly,
  even if its memory-cache entry was evicted.
- **Replacements preserve acknowledged data.** PUT, COPY, multipart completion,
  and DELETE pause a pending predecessor until the backend operation succeeds.
  Failed or cancelled replacements leave it queued for recovery and flushing.
  Synchronous writes, including small objects, use a WAL temp and atomic rename;
  this costs extra SMB round trips compared with overwriting a small file in place.
- **Listings include it.** ListObjects overlays this instance's pending keys.
- **Copies work.** CopyObject and UploadPartCopy flush the source first, since
  the NAS performs the copy itself and has to be able to open the source.
- **Backpressure is real.** Past `SPICEIO_WRITE_BACK_BYTES` of un-flushed data,
  PutObject writes through synchronously and clients feel the slow backend.
- **Reads keep priority.** Flushers take the same admission slot live requests
  do, and stand down while clients are using the backend — so the proxy's own
  write drain does not become a read-latency spike. They resume once the backlog
  passes half of `SPICEIO_WRITE_BACK_BYTES`, where PutObject is about to write
  through synchronously anyway. Under sustained read load the queue fills and
  PutObject reverts to synchronous.
- **Shutdown drains.** **SIGTERM, SIGINT, SIGHUP and SIGQUIT** — the four ways a
  process is normally asked to stop — flush acknowledged writes (30s cap) before
  exit; signal a second time to stop immediately instead of waiting it out.
  These four specifically, not "every terminating signal": SIGUSR1, SIGALRM and
  friends still terminate without draining, and SIGKILL cannot be caught at all.
  Catching them matters because an uncaught stop takes the queue with it —
  measured against v0.7.0, which handled only SIGTERM/SIGINT, a `kill -HUP`
  against a 240 MiB backlog lost 225 of 240 acknowledged writes.
- **A hard kill loses only the newest writes.** Acknowledged bodies are written
  to the disk journal continuously — including while the flushers are standing
  down for client reads, since that is local disk and costs the NAS nothing — so
  what a SIGKILL or a power cut loses is the objects acknowledged in the moments
  before it, not the whole queue. Whatever reached the journal is replayed by the
  next start or by a peer instance. Journalling is *not* synchronous with the
  200; if you need it to be, use `SPICEIO_WRITE_BACK=0`.

What is not:

- **A crash between the 200 and the background write loses that object.** Once
  it reaches the disk spill it is recoverable — dirty entries are never
  evicted, and are replayed on the next start or by a peer instance that finds
  them — but the window before that is real. This is the setting's whole
  trade: right for the cache workloads spiceio fronts, and the reason
  `SPICEIO_WRITE_BACK=0` exists for anything that is a system of record.
- **Peer instances and other S3 clients do not see the object until it
  flushes**, except through the shared spill on the same machine.

GET producers retain their admission permit until streaming ends. Cache-fill
buffers share an additional budget equal to `SPICEIO_OBJECT_CACHE_BYTES`, so
concurrent streams cannot each allocate an unrestricted fill buffer. Recovery
scans dirty-entry metadata first, skips owned writes, and loads one body at a
time before applying queue backpressure.

Paginated listings reuse sorted snapshots, bounded to 64 MiB and 64 snapshots.
Snapshots expire after five idle minutes. A new first-page request walks the
backend afresh; an expired, evicted, or oversized snapshot is rebuilt and
pagination resumes after the continuation's last key. Pending writes are included
even when their prefix directory has not reached the NAS yet.

### Cleaning the remote sccache store

sccache 0.17 has no `clean` subcommand. The repository's `scripts/sccache`
helper provides it for a spiceio endpoint, using S3 listing and batch deletion:

```sh
export SCCACHE_ENDPOINT=http://127.0.0.1:8333
export SCCACHE_BUCKET=ai_platform_dev
export SCCACHE_S3_KEY_PREFIX=sccache
./scripts/sccache clean --older-than-days 10 --dry-run
make test-sccache-clean
```

`make test-sccache-clean` runs the helper against the configured live instance
and **deletes objects strictly older than ten days** under that cache directory
prefix. It verifies that a fresh test object survives and that no objects older
than the cleanup's fixed cutoff remain, then removes the test object. Age uses
S3 `LastModified`, not last access. Empty prefixes are rejected. The helper
walks individual directories and limits concurrent delete batches to four
(`--concurrency` accepts 1–16). It requires Python 3 and does not restart the
sccache server. The regular live sccache suite runs this check within its own
test prefix; `make test-clean-unit` exercises age boundaries, pagination,
prefix isolation, dry runs, and partial deletion errors without a NAS.

## Supported S3 operations

- **Objects**: GetObject (range + conditional), PutObject (conditional-write), CopyObject, DeleteObject, HeadObject
- **Listing**: ListObjectsV1, ListObjectsV2, ListBuckets
- **Multipart**: CreateMultipartUpload, UploadPart, UploadPartCopy, CompleteMultipartUpload, AbortMultipartUpload, ListParts, ListMultipartUploads (UploadPartCopy is what `aws s3 cp`/`sync` use to copy objects above the ~8 MiB multipart threshold)
- **Bucket**: HeadBucket, GetBucketLocation, CreateBucket, DeleteBucket
- **Stubs**: ACL, tagging, versioning, encryption, lifecycle, CORS (returns valid empty responses)

Path-style addressing only (no virtual-hosted-style), over HTTP/1.1.

Uploads sent with `Content-Encoding: aws-chunked` (aws-cli v2's `aws s3 cp`,
minio-go/mc, and other SDKs that stream with a trailing checksum) are decoded
before they are stored, in every authentication mode. The trailing checksum is
parsed but not verified.

ListObjects without a `delimiter` walks subdirectories recursively (full S3
semantics — `aws s3 ls --recursive` and `aws s3 sync` see every key); with
`delimiter=/` it lists one level and reports subdirectories as common
prefixes. spiceio's internal bookkeeping directories (`.spiceio-wal/`,
`.spiceio-uploads/`, `.spiceio-locks/`) are hidden from listings.

## Conditional writes

Enable a strict namespace before using write preconditions:

```bash
# Coordinate metadata updates while keeping the normal sccache fast path.
export SPICEIO_STRICT_PREFIXES='metadata/,locks/'
# Or use '*' for every key in the bucket.
```

For matching keys, `PutObject`, `CompleteMultipartUpload`, and destination
`CopyObject` support `If-None-Match: *` (create only if absent) and
`If-Match: "<etag>"` (replace only the version read). Conditions are evaluated
at publication, after the entire body or copy has been staged and verified.
Competing creates have exactly one winner; competing updates against an ETag
cannot both replace that version. A failed condition returns `412
PreconditionFailed`; a missing `If-Match` destination returns `404 NoSuchKey`.
An uncertain rename can return `409 ConditionalRequestConflict`: read the
current state before retrying. Invalid or duplicate validators fail with 400.
Write conditions outside the configured prefixes also fail with 400
`InvalidRequest`; they are never silently ignored or treated as a best-effort
existence check. Conditional GET/HEAD remain available everywhere.

All mutations in a strict prefix, **including unconditional PUT, COPY,
multipart completion, and DELETE**, coordinate through exclusive SMB opens
on per-key files in `.spiceio-locks/`. Publication stays on the connection
holding that lock; a lost connection cannot reconnect and resume an unfenced
commit. Strict writes flush the data and version reservation to the NAS and
publish before acknowledging, even when write-back is enabled. Reads revalidate
against the NAS even in immutable mode; the body cache can still serve a body
whose ETag matches. Ordinary keys retain memory acknowledgment and the existing
backend request sequence. No extra dependencies are required.

ETags remain opaque size/timestamp validators. Strict writes reserve increasing
timestamps in checksummed, durable per-key records, including across deletion,
so equal-size writes cannot reuse an ETag on a coarse clock. A server that
rounds timestamps may require advancing `LastModified` to the next second;
rapid updates on such a server can put it ahead of wall-clock time. A server
that cannot preserve the requested timestamp fails the write. A damaged
version record fails closed. Do not remove `.spiceio-locks/`, including records
for deleted objects, or write directly into strict prefixes through SMB.

**Deployment:** drain and stop all instances before enabling or changing strict
prefixes, then start every writer with the same configuration and this version
of spiceio. Existing dirty spill entries must be drained first; startup refuses
strict mode if it finds any in its spill namespace. Older instances and direct
SMB writers do not participate in this protocol. Durability depends on the NAS
honoring SMB FLUSH and its underlying storage guarantees.

`make test-conditional` runs the two-instance NAS races, copy/multipart checks,
and an immediate-process-death durability check. It is also part of `make ci`
when NAS credentials are present. Stateful SMB wire tests run without a NAS.

## Crash reports & graceful shutdown

If spiceio panics or hits a fatal signal it writes a crash report to stderr
and (when `SPICEIO_LOG_FILE` is set) appends it to the log file before dying —
version, pid, uptime, thread, panic message + source location, fault address
and registers for signals, and a backtrace.

Release binaries are stripped, so reports include the image load address and
ASLR slide; `make release` also emits `target/release/spiceio.dSYM` (and the
release tarball bundles it), so raw addresses symbolize offline with:

```bash
atos -o target/release/spiceio.dSYM \
     -l <image base from the report> <addresses...>
```

`SIGTERM` and `SIGINT` (Ctrl-C) both shut down gracefully: the listener stops
accepting, in-flight requests are given up to 30 seconds to finish (so a
transfer in progress is not cut off and a half-written object is never left
behind), then the log file is flushed before exit. Startup/config errors
(missing env vars, unreachable SMB server) exit cleanly with a one-line reason
— only genuine bugs produce crash reports.

## Architecture

Five modules:

- **`s3`** -- HTTP layer. Parses S3 requests, produces XML responses. Router dispatches to the appropriate handler. Small files (<64KB) use compound fast paths; large files stream.
- **`smb`** -- Wire protocol client. Manages TCP connection, negotiate/session-setup handshake, and file operations. Supports SMB2 compounding for batching multiple operations in a single round trip.
- **`crypto`** -- FFI bindings to macOS CommonCrypto. MD4, SHA-256, SHA-512, HMAC-MD5, HMAC-SHA256, AES-128-CMAC. No Rust crypto crates.
- **`http`** -- HTTP front-end tuning for the listener: HTTP/1.1 connection builder, header-read timeout, accept backoff, and shutdown grace. Factored out of the accept loop so the integration tests exercise the same settings the server runs with.
- **`crash`** -- Crash reporting. Panic hook plus async-signal-safe fatal-signal handler; reports go to stderr and the log file synchronously, bypassing the async logger.

```
HTTP request
  -> s3::router::handle_request
    -> smb::ops::ShareSession method
      -> smb::client::SmbClient wire operations
        -> TCP to SMB server
```

## Development

```bash
make                   # fmt + full CI-local gate
make ci                # parity with GitHub Actions (lint + unit + live SMB suites)
make release           # optimized release build
make install           # install the release build (+ dSYM, sccache-spiceio) into ~/.local/bin; set up SigV4 for the launchd agent, restart it, check its auth
make lint              # static only — not sufficient to claim CI will pass
make test-unit         # cargo test (no SMB)
make test              # sccache integration (requires SPICEIO_SMB_USER/PASS)
make test-live         # every live SMB suite CI runs
make test-auth         # S3 auth modes + aws-chunked, against real clients
make test-extended     # also builds spiceai repo through sccache/spiceio
make clean             # cargo clean
```

Live tests require `SPICEIO_SMB_USER` and `SPICEIO_SMB_PASS` and access to an SMB
server. **Run `make ci` with those credentials before merging** — custom HTTP
benches are not a substitute for `scripts/test-sccache.sh` (which asserts
sccache cache hits and zero read/write errors the same way CI does).

### sccache performance

```bash
make bench-sccache        # synthetic sccache-shaped load, concurrency sweep
make bench-sccache-build  # real cargo builds: spiceio vs local disk vs no cache
```

Measurements, not gates — `make ci` never runs them. `bench-sccache` drives
`spiceio-loadgen` over persistent keep-alive connections (how sccache actually
talks to the proxy), pins `SPICEIO_IMMUTABLE_OBJECTS=1` (sccache production;
existence index on), sweeps concurrency, and reports p99/p99.9 and TTFB
per operation class, alongside server-side per-request timings from
`SPICEIO_ACCESS_LOG`. `bench-sccache-build` runs real `cargo build`s three ways
and reads sccache's own per-hit and per-write latency, with a local-disk cache
as the floor to measure the network backend against. Results land in
`benches/results/`; committed reference runs are in `benches/baselines/`.

## How it compares

| Tool | Needs local mount? | SMB access method | Cross-platform? | Best for |
|---|---|---|---|---|
| **spiceio** | No | Direct SMB 3.1.x wire | macOS 26+ only | Cleanest wire-level proxy, zero dependencies |
| **rclone** | No | rclone's SMB backend | Yes | Cross-platform, battle-tested |
| MinIO + mount | Yes | CIFS/FUSE mount | Yes | Production-grade S3 features |
| s3proxy / VersityGW | Yes | CIFS/FUSE mount | Yes | Lightweight or high-perf FS backends |

## License

Apache 2.0
