# spiceio

**S3-compatible API proxy that turns any SMB share into an S3 endpoint** -- no mounting, no `libsmbclient`, no FUSE. Translates S3 HTTP requests directly into SMB 3.1.x wire-protocol operations over TCP (port 445).

## Why spiceio

Most tools that bridge SMB and S3 (MinIO, s3proxy, VersityGW) require mounting the share to the local filesystem first. spiceio skips that entirely -- it speaks the SMB wire protocol directly over TCP, so there's no mount, no kernel driver, and no FUSE layer in the way. It's the most "pure" SMB-to-S3 gateway available: a single binary that translates on the wire and never touches the local filesystem.

```
S3 client  --->  spiceio (HTTP :8333)  --->  SMB server (TCP :445)
              S3 API translation            SMB 3.1.x wire protocol
```

### Key highlights

- **Zero-mount design** -- speaks SMB 3.1.x natively over TCP, never touches the local filesystem
- **Full S3 compatibility** for the most common operations:
  - Get/Put/Copy/Delete/Head Object
  - ListObjects (v1 & v2), ListBuckets
  - Multipart uploads (create, upload-part, complete, abort, list-parts, list-uploads)
  - Range + conditional requests (If-Match, If-None-Match, If-Modified-Since)
  - HeadBucket, GetBucketLocation, and stubs for ACL/tagging/versioning
- **SMB2 compounding** -- batches Create+Read+Close or Create+Write+Close into single round trips for small file performance
- **Streaming I/O** -- GetObject and PutObject stream directly between HTTP and SMB without buffering entire files
- **Simple config** -- everything via environment variables, single lightweight Rust binary
- **Zero external crypto** -- NTLMv2 auth and AES-CMAC signing via macOS CommonCrypto FFI (no Rust crypto crates)

### Use cases

- **sccache/ccache remote cache** -- point sccache at spiceio to store compilation cache on a NAS without cloud storage costs
- **CI artifact storage** -- use `aws s3 cp` to push/pull build artifacts from any SMB share
- **NAS integration** -- give any S3-native tool (Terraform, DVC, Restic, etc.) access to existing file shares

## Quick start

macOS 26+ only.

```bash
# Build from source (requires Rust edition 2024)
make release

# Or grab a release binary
curl -L -o spiceio https://github.com/spiceai/spiceio/releases/latest/download/spiceio-macos-arm64
chmod +x spiceio
```

```bash
export SPICEIO_SMB_SERVER=your-nas.local
export SPICEIO_SMB_USER=youruser
export SPICEIO_SMB_PASS=yourpass
export SPICEIO_SMB_SHARE=yourshare

./spiceio   # listens on 0.0.0.0:8333 by default
```

Now any S3 client works instantly:

```bash
aws s3 ls s3://yourshare/ --endpoint-url http://localhost:8333
aws s3 cp myfile.txt s3://yourshare/remote.txt --endpoint-url http://localhost:8333
```

The virtual S3 bucket name defaults to the share name. Change it with `SPICEIO_BUCKET` if you want a different name.

### sccache example

```bash
# With spiceio running against your NAS:
export SCCACHE_BUCKET=yourshare
export SCCACHE_ENDPOINT=http://localhost:8333
export SCCACHE_REGION=us-east-1
export SCCACHE_S3_USE_SSL=false
export SCCACHE_S3_KEY_PREFIX=sccache
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export RUSTC_WRAPPER=sccache
export CARGO_INCREMENTAL=0

cargo build   # compilation artifacts cached on your NAS via spiceio
```

## Configuration

All configuration is via environment variables:

| Variable             | Required | Default             | Description               |
| -------------------- | -------- | ------------------- | ------------------------- |
| `SPICEIO_SMB_SERVER` | yes      |                     | SMB server hostname or IP |
| `SPICEIO_SMB_USER`   | yes      |                     | SMB username              |
| `SPICEIO_SMB_PASS`   | yes      |                     | SMB password              |
| `SPICEIO_SMB_SHARE`  | yes      |                     | SMB share name            |
| `SPICEIO_BIND`       | no       | `0.0.0.0:8333`      | Listen address            |
| `SPICEIO_SMB_PORT`   | no       | `445`               | SMB port                  |
| `SPICEIO_SMB_DOMAIN` | no       | *(empty)*           | SMB domain                |
| `SPICEIO_BUCKET`     | no       | `SPICEIO_SMB_SHARE` | Virtual S3 bucket name    |
| `SPICEIO_REGION`     | no       | `us-east-1`         | AWS region to advertise   |

## Architecture

Three modules:

- **`s3`** -- HTTP layer. Parses S3 requests, produces XML responses. Router dispatches to the appropriate handler. Small files (<64KB) use compound fast paths; large files stream.
- **`smb`** -- Wire protocol client. Manages TCP connection, negotiate/session-setup handshake, and file operations. Supports SMB2 compounding for batching multiple operations in a single round trip.
- **`crypto`** -- FFI bindings to macOS CommonCrypto. MD4, SHA-256, SHA-512, HMAC-MD5, HMAC-SHA256, AES-128-CMAC. No Rust crypto crates.

```
HTTP request
  -> s3::router::handle_request
    -> smb::ops::ShareSession method
      -> smb::client::SmbClient wire operations
        -> TCP to SMB server
```

## Development

```bash
make                   # fmt + lint + test + build
make release           # optimized release build
make lint              # fmt-check + check + strict clippy + rustdoc warnings
make test              # S3 API tests + sccache integration test
make test-extended     # above + builds spiceai repo through sccache/spiceio
make clean             # cargo clean
```

Tests require `SPICEIO_SMB_USER` and `SPICEIO_SMB_PASS` environment variables and access to an SMB server.

## How it compares

| Tool | Needs local mount? | SMB access method | Cross-platform? | Best for |
|---|---|---|---|---|
| **spiceio** | No | Direct SMB 3.1.x wire | macOS 26+ only | Cleanest wire-level proxy, zero external dependencies |
| **rclone** | No | rclone's SMB backend | Yes | Cross-platform, battle-tested (best if not on macOS 26+) |
| MinIO + mount | Yes | CIFS/FUSE mount | Yes | Production-grade S3 features at scale |
| s3proxy / VersityGW | Yes | CIFS/FUSE mount | Yes | Lightweight or high-perf filesystem backends |

## License

Apache 2.0
