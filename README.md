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
| `SPICEIO_BIND`                | no       | `0.0.0.0:8333`      | Listen address            |
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
| `SPICEIO_OBJECT_CACHE_BYTES`  | no       | `8589934592` (8 GiB) | Max total GET body cache size — up to this much resident memory. The most effective tuning knob |
| `SPICEIO_OBJECT_CACHE_MAX_OBJECT` | no   | budget / 64 (128 MiB) | Max size of a single cached object; scales with the budget so one object cannot evict a large share of the cache |
| `SPICEIO_OBJECT_CACHE_ENTRIES`| no       | `131072`            | Max body-cache entries (sized so bytes bind first) |
| `SPICEIO_IMMUTABLE_OBJECTS`   | no       | off                 | When `1`/`true`, serve cached bodies by key with **no backend round trip**. For content-addressed stores (sccache) where the key is a hash of the content. Gives up noticing a backend-side delete |
| `SPICEIO_SPILL_DIR`           | no       | `/var/tmp/spiceio-cache` | Disk tier behind the memory cache, shared by every instance on the host. Created 0700, so sharing is between processes of the same user; point this at a group-shared directory for cross-user sharing. `off` (or empty) disables it |
| `SPICEIO_SPILL_BYTES`         | no       | `68719476736` (64 GiB) | Disk budget for the whole spill directory, across all instances. Clamped so at least 10 GiB stays free, and to half the space above that |
| `SPICEIO_WRITE_BACK`          | no       | **on**              | Acknowledge PutObject from memory and write to the NAS in the background. `0`/`false`/`off` disables. **Trades durability for latency** — see [Write-back](#write-back) |
| `SPICEIO_WRITE_BACK_BYTES`    | no       | `1073741824` (1 GiB) | Ceiling on un-flushed bytes; past it PutObject writes through synchronously, applying backpressure |

## Caching

Three tiers answer a GET, in order:

| Tier | Where | Size | Shared |
| ---- | ----- | ---- | ------ |
| L1   | process memory | 8 GiB (`SPICEIO_OBJECT_CACHE_BYTES`) | no |
| L2   | local disk (`SPICEIO_SPILL_DIR`) | 64 GiB (`SPICEIO_SPILL_BYTES`) | every instance on the machine |
| —    | the NAS over SMB | — | — |

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

- **Reads see it.** GET and HEAD on a key with a pending write are served from
  the cache without revalidating — a stat would report the previous version.
- **Deletes order correctly.** DELETE cancels a queued write and waits out one
  in flight, so a flush cannot resurrect a deleted object.
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

## Supported S3 operations

- **Objects**: GetObject (range + conditional), PutObject (conditional-write), CopyObject, DeleteObject, HeadObject
- **Listing**: ListObjectsV1, ListObjectsV2, ListBuckets
- **Multipart**: CreateMultipartUpload, UploadPart, UploadPartCopy, CompleteMultipartUpload, AbortMultipartUpload, ListParts, ListMultipartUploads (UploadPartCopy is what `aws s3 cp`/`sync` use to copy objects above the ~8 MiB multipart threshold)
- **Bucket**: HeadBucket, GetBucketLocation, CreateBucket, DeleteBucket
- **Stubs**: ACL, tagging, versioning, encryption, lifecycle, CORS (returns valid empty responses)

Path-style addressing only (no virtual-hosted-style), over HTTP/1.1.

ListObjects without a `delimiter` walks subdirectories recursively (full S3
semantics — `aws s3 ls --recursive` and `aws s3 sync` see every key); with
`delimiter=/` it lists one level and reports subdirectories as common
prefixes. spiceio's internal bookkeeping directories (`.spiceio-wal/`,
`.spiceio-uploads/`) are hidden from listings.

## Crash reports & graceful shutdown

If spiceio panics or hits a fatal signal it writes a crash report to stderr
and (when `SPICEIO_LOG_FILE` is set) appends it to the log file before dying —
version, pid, uptime, thread, panic message + source location, fault address
and registers for signals, and a backtrace.

Release binaries are stripped, so reports include the image load address and
ASLR slide; `make release` also emits `target/release/spiceio.dSYM` (and the
release tarball bundles it), so raw addresses symbolize offline with:

```bash
atos -o target/release/spiceio.dSYM/Contents/Resources/DWARF/spiceio \
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
make lint              # static only — not sufficient to claim CI will pass
make test-unit         # cargo test (no SMB)
make test              # sccache integration (requires SPICEIO_SMB_USER/PASS)
make test-live         # sccache + extended + concurrent stress (CI live steps)
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
talks to the proxy), sweeps concurrency, and reports p50/p90/p99/p99.9 and TTFB
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
