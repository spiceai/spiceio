# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is spiceio

spiceio is an S3-compatible API proxy that translates S3 HTTP requests into SMB 3.1.x file operations. It speaks the SMB wire protocol directly over TCP (no mount, no libsmbclient) and uses macOS CommonCrypto via FFI for all cryptographic primitives (NTLMv2 auth, SHA-256, HMAC). Targets macOS 26+ only.

## Design principles

- **Reliability and resilience** — handle errors gracefully, recover from transient failures, never corrupt data. Correctness comes first.
- **High performance** — minimize allocations, avoid unnecessary copies, use efficient I/O patterns. The proxy should not be the bottleneck.
- **macOS 26+ only** — leverage core OS APIs (CommonCrypto, Security.framework, system libraries) wherever possible instead of pulling in external crates. Keep the dependency tree minimal.
- **SMB 3.1.x** — implement the SMB 3.1.x dialect family. Stay current with protocol capabilities.

## Build & Run

```bash
make                           # fmt + lint + test + build (default target)
make release                   # optimized release build
make lint                      # fmt-check + check + strict clippy + rustdoc warnings
make test                      # sccache integration test (requires SPICEIO_SMB_USER/PASS)
make fmt                       # auto-format
make clean                     # cargo clean
```

The binary requires these environment variables:
- `SPICEIO_SMB_SERVER` (required) — SMB server hostname or IP
- `SPICEIO_SMB_USER` (required) — SMB username
- `SPICEIO_SMB_PASS` (required) — SMB password
- `SPICEIO_SMB_SHARE` (required) — SMB share name
- `SPICEIO_BIND` — listen address (default `0.0.0.0:8333`)
- `SPICEIO_SMB_PORT` — SMB port (default `445`)
- `SPICEIO_SMB_DOMAIN` — SMB domain (default empty)
- `SPICEIO_BUCKET` — virtual S3 bucket name (defaults to `SPICEIO_SMB_SHARE`)
- `SPICEIO_REGION` — AWS region to advertise (default `us-east-1`)
- `SPICEIO_SMB_CONNECTIONS` — number of SMB TCP connections in the pool (default: CPU count, clamped to 4–12)
- `SPICEIO_SMB_MAX_IO` — max standalone read/write I/O size in bytes (default `262144`; raise for servers that handle larger I/O)
- `SPICEIO_MULTIPART_TTL_SECS` — age at which an abandoned multipart upload is reaped (default `86400`)
- `SPICEIO_CLEANUP_GRACE_SECS` — startup cleanup leaves WAL temps / upload dirs newer than this alone (default `900`), so instances sharing one share don't delete each other's in-flight state; `0` restores a blanket sweep
- `SPICEIO_LOG_FILE` — append logs to this file in addition to stderr (optional; non-blocking, never stalls the proxy)

## Architecture

The codebase has five modules:

- **`s3`** — HTTP layer. Parses incoming S3 API requests and produces XML responses. `router.rs` is the central dispatch (path-style bucket routing). Covers GetObject, PutObject, CopyObject, DeleteObject, HeadObject, ListObjectsV1/V2, multipart uploads (including UploadPartCopy, the form `aws s3 cp`/`sync` use for objects above the ~8 MiB multipart threshold), and stub endpoints for ACL/tagging/versioning. `xml.rs` is a hand-rolled XML builder. `multipart.rs` manages upload state in-memory, with parts stored as temp files under `.spiceio-uploads/` on the SMB share. `body.rs` implements `SpiceioBody`, a zero-copy streaming response body (channel-backed for large reads, inline for XML/errors).

- **`smb`** — Wire protocol client. `protocol.rs` defines SMB 3.1.x packet structures (little-endian). `client.rs` manages a TCP connection, negotiate/session-setup handshake, and exposes operations (tree connect, create, read, write, close, query directory, pipelined read). `pool.rs` manages N authenticated connections for concurrent request fan-out. `auth.rs` implements NTLMv2 challenge-response. `ops.rs` provides the high-level `ShareSession` abstraction the S3 layer consumes (list, read, write, delete, stat, copy).

- **`crypto`** — FFI bindings to macOS CommonCrypto (`Security.framework`/`libcommonCrypto`). Exposes MD4, MD5, SHA-256 (one-shot and streaming), SHA-512, HMAC-MD5, HMAC-SHA256, and AES-128-CMAC — between them they cover NTLMv2 auth, SMB 3.1.x preauth integrity, and signing. No Rust crypto crates: reach for `crypto::ffi` before adding a dependency, the primitive is probably already there.

- **`http`** — HTTP front-end tuning for the S3 listener (connection builder, header-read timeout, accept backoff, shutdown grace). Kept out of the accept loop so `tests/http_frontend.rs` exercises the same configuration the server runs with. HTTP/1.1 only — every S3 client speaks HTTP/1.1 to a plain-HTTP endpoint, and the protocol-sniffing `auto` server both pulls in the whole HTTP/2 stack and defers the header timeout past the connect-and-say-nothing case it exists for.

- **`crash`** — Crash reporting. A panic hook (location + backtrace, works with `panic = "abort"`) and an async-signal-safe fatal-signal handler (SIGSEGV/SIGBUS/SIGILL/SIGFPE/SIGTRAP/SIGABRT: fault address, registers, frame-pointer backtrace). Reports are written synchronously to stderr and `SPICEIO_LOG_FILE`, bypassing the async logger. Release builds stay stripped; `target/release/spiceio.dSYM` (from `split-debuginfo = "packed"`) symbolizes the raw addresses offline via `atos -l <image base>`. Tested end-to-end via the hidden `--crash-test <panic|segv|abort>` flag (`tests/crash_report.rs`).

**Request flow:** HTTP request → `s3::router::handle_request` → S3 operation → `smb::ops::ShareSession` method → `smb::client::SmbClient` wire operations → TCP to SMB server.

## Key design decisions

- Zero external crypto dependencies — all crypto goes through `crypto::ffi` to CommonCrypto.
- No `async-trait` — the SMB client uses `tokio::sync::Mutex` around the TCP stream with manual `async` methods.
- Connection pool — N TCP connections (default: CPU count, clamped 4–12) to the same SMB server. Concurrent S3 requests fan out across connections instead of serializing on a single mutex. File handles are pinned to the connection that opened them.
- Least-loaded dispatch — each connection tracks its queue depth via `StreamGuard`, the only way to reach the stream (so the accounting cannot be skipped) and `SmbPool::pick` sends new work to the shallowest healthy connection, rotating on ties. A connection owns its stream for a whole round trip, so blind round-robin could put a one-round-trip HEAD behind a multi-megabyte pipelined batch.
- Zero-copy response bodies — each SMB response is read into one allocation and handed to decoders as `Bytes` views (`send_recv`, `parse_compound_response`, `decode_read_response_bytes`), so no read payload is memcpy'd out of its buffer.
- Proactive keepalive — the healer probes connections idle for 45s with SMB2 ECHO, and SMB sockets enable TCP keepalive, so a session dropped while idle is poisoned and reconnected before a client request lands on it.
- Verified before publish — `WalWriter::commit` stats the temp file *before* the rename and refuses to publish if it is shorter than the bytes written, so a failed check leaves any existing object untouched. `assemble_parts` checks each part against its acknowledged size while streaming, and `collect_body` enforces Content-Length for every buffered body path. Nothing corrupt reaches the client's key, so no compensating delete (which would race a concurrent writer) is needed.
- Server-side copy — CopyObject, UploadPartCopy and multipart assembly issue `FSCTL_SRV_COPYCHUNK_WRITE` (after `FSCTL_SRV_REQUEST_RESUME_KEY`), so the NAS copies the bytes internally and they never cross the proxy. Probed once per process; a server that answers "not supported" falls back to streaming for the rest of the run.
- Multi-instance safety — startup cleanup only sweeps WAL temps / upload dirs older than `SPICEIO_CLEANUP_GRACE_SECS`, judged on the *server's* clock (measured by writing a probe file, so clock skew can't age a live file out) — several instances can serve one share. The reaper refreshes each live upload's marker file so a slow client's upload never looks abandoned.
- Directory listings ask for up to 1 MiB of entries per QUERY_DIRECTORY (credit-charged accordingly) instead of a fixed 64 KiB, cutting round trips on wide prefixes.
- Pipelined reads — streaming GetObject sends a batch of read requests (up to `READ_PIPELINE_DEPTH` = 64, bounded by the adaptive in-flight budget) before collecting responses, hiding per-request round-trip latency.
- HTTP front end — `TCP_NODELAY` on accepted sockets (S3 responses are small and latency-sensitive), a 120s header-read timeout that also reclaims idle/half-dead connections, a backoff on `accept()` errors so descriptor exhaustion can't spin the loop, and a graceful shutdown that drains in-flight requests (30s cap) before exit.
- SMB2 credit accounting — each connection tracks its credit balance (grants banked from every response's `CreditResponse`, charges consumed in lockstep with MessageId allocation). Pipelined batches clamp to the balance and oversized single I/O splits, so in-flight charge never exceeds the server-granted sequence window.
- Configurable I/O cap — standalone read/write ops default to 256 KB (the measured streaming sweet spot); raisable via `SPICEIO_SMB_MAX_IO`, always clamped to the server's negotiated max. Compound operations always cap at 64 KB.
- GetObject streams SMB read chunks directly to the HTTP response via `SpiceioBody::channel` — no full-file buffering.
- PutObject streams HTTP request body chunks directly to SMB write calls — no full-body collection.
- Body is collected into `Bytes` only for operations that require the full payload (multi-delete, multipart complete, upload-part for ETag hashing).
- S3 path-style addressing only (no virtual-hosted-style).
- Multipart upload parts are stored as temporary SMB files, not in memory.
