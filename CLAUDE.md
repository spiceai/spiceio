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

## Architecture

The codebase has three modules:

- **`s3`** — HTTP layer. Parses incoming S3 API requests and produces XML responses. `router.rs` is the central dispatch (path-style bucket routing). Covers GetObject, PutObject, CopyObject, DeleteObject, HeadObject, ListObjectsV1/V2, multipart uploads, and stub endpoints for ACL/tagging/versioning. `xml.rs` is a hand-rolled XML builder. `multipart.rs` manages upload state in-memory, with parts stored as temp files under `.spiceio-uploads/` on the SMB share. `body.rs` implements `SpiceioBody`, a zero-copy streaming response body (channel-backed for large reads, inline for XML/errors).

- **`smb`** — Wire protocol client. `protocol.rs` defines SMB 3.1.x packet structures (little-endian). `client.rs` manages the TCP connection, negotiate/session-setup handshake, and exposes operations (tree connect, create, read, write, close, query directory). `auth.rs` implements NTLMv2 challenge-response. `ops.rs` provides the high-level `ShareSession` abstraction the S3 layer consumes (list, read, write, delete, stat, copy).

- **`crypto`** — FFI bindings to macOS CommonCrypto (`Security.framework`/`libcommonCrypto`). Exposes MD4, SHA-256, and HMAC-MD5. No Rust crypto crates.

**Request flow:** HTTP request → `s3::router::handle_request` → S3 operation → `smb::ops::ShareSession` method → `smb::client::SmbClient` wire operations → TCP to SMB server.

## Key design decisions

- Zero external crypto dependencies — all crypto goes through `crypto::ffi` to CommonCrypto.
- No `async-trait` — the SMB client uses `tokio::sync::Mutex` around the TCP stream with manual `async` methods.
- GetObject streams SMB read chunks directly to the HTTP response via `SpiceioBody::channel` — no full-file buffering.
- PutObject streams HTTP request body chunks directly to SMB write calls — no full-body collection.
- Body is collected into `Bytes` only for operations that require the full payload (multi-delete, multipart complete, upload-part for ETag hashing).
- S3 path-style addressing only (no virtual-hosted-style).
- Multipart upload parts are stored as temporary SMB files, not in memory.
