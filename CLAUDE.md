# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is spio

spio is an S3-compatible API proxy that translates S3 HTTP requests into SMB 3.1.x file operations. It speaks the SMB wire protocol directly over TCP (no mount, no libsmbclient) and uses macOS CommonCrypto via FFI for all cryptographic primitives (NTLMv2 auth, SHA-256, HMAC). Targets macOS 26+ only.

## Design principles

- **Reliability and resilience** — handle errors gracefully, recover from transient failures, never corrupt data. Correctness comes first.
- **High performance** — minimize allocations, avoid unnecessary copies, use efficient I/O patterns. The proxy should not be the bottleneck.
- **macOS 26+ only** — leverage core OS APIs (CommonCrypto, Security.framework, system libraries) wherever possible instead of pulling in external crates. Keep the dependency tree minimal.
- **SMB 3.1.x** — implement the SMB 3.1.x dialect family. Stay current with protocol capabilities.

## Build & Run

```bash
cargo build                    # debug build
cargo build --release          # optimized release build
cargo check                    # type-check without building
```

No test suite exists yet. No linter or formatter is configured beyond `cargo check`.

The binary requires these environment variables:
- `SPIO_SMB_SERVER` (required) — SMB server hostname or IP
- `SPIO_SMB_USER` (required) — SMB username
- `SPIO_SMB_PASS` (required) — SMB password
- `SPIO_SMB_SHARE` (required) — SMB share name
- `SPIO_BIND` — listen address (default `0.0.0.0:8333`)
- `SPIO_SMB_PORT` — SMB port (default `445`)
- `SPIO_SMB_DOMAIN` — SMB domain (default empty)
- `SPIO_BUCKET` — virtual S3 bucket name (defaults to `SPIO_SMB_SHARE`)
- `SPIO_REGION` — AWS region to advertise (default `us-east-1`)

## Architecture

The codebase has three modules:

- **`s3`** — HTTP layer. Parses incoming S3 API requests and produces XML responses. `router.rs` is the central dispatch (path-style bucket routing). Covers GetObject, PutObject, CopyObject, DeleteObject, HeadObject, ListObjectsV1/V2, multipart uploads, and stub endpoints for ACL/tagging/versioning. Auth is SigV4 (header + presigned URL) in `auth.rs`. `xml.rs` is a hand-rolled XML builder. `multipart.rs` manages upload state in-memory, with parts stored as temp files under `.spio-uploads/` on the SMB share.

- **`smb`** — Wire protocol client. `protocol.rs` defines SMB 3.1.x packet structures (little-endian). `client.rs` manages the TCP connection, negotiate/session-setup handshake, and exposes operations (tree connect, create, read, write, close, query directory, query info). `auth.rs` implements NTLMv2 challenge-response. `ops.rs` provides the high-level `ShareSession` abstraction the S3 layer consumes (list, read, write, delete, stat, copy).

- **`crypto`** — FFI bindings to macOS CommonCrypto (`Security.framework`/`libcommonCrypto`). Exposes MD4, SHA-256, HMAC-MD5, HMAC-SHA256. No Rust crypto crates.

**Request flow:** HTTP request → `s3::router::handle_request` → S3 operation → `smb::ops::ShareSession` method → `smb::client::SmbClient` wire operations → TCP to SMB server.

## Key design decisions

- Zero external crypto dependencies — all crypto goes through `crypto::ffi` to CommonCrypto.
- No `async-trait` — the SMB client uses `tokio::sync::Mutex` around the TCP stream with manual `async` methods.
- Body is fully collected into `Bytes` before routing (no streaming).
- S3 path-style addressing only (no virtual-hosted-style).
- Multipart upload parts are stored as temporary SMB files, not in memory.
