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
- **Streaming I/O** -- GetObject and PutObject stream directly between HTTP and SMB without buffering entire files
- **Simple config** -- everything via environment variables, single binary
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

## Supported S3 operations

- **Objects**: GetObject (range + conditional), PutObject (conditional-write), CopyObject, DeleteObject, HeadObject
- **Listing**: ListObjectsV1, ListObjectsV2, ListBuckets
- **Multipart**: CreateMultipartUpload, UploadPart, CompleteMultipartUpload, AbortMultipartUpload, ListParts, ListMultipartUploads
- **Bucket**: HeadBucket, GetBucketLocation, CreateBucket, DeleteBucket
- **Stubs**: ACL, tagging, versioning, encryption, lifecycle, CORS (returns valid empty responses)

Path-style addressing only (no virtual-hosted-style).

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
| **spiceio** | No | Direct SMB 3.1.x wire | macOS 26+ only | Cleanest wire-level proxy, zero dependencies |
| **rclone** | No | rclone's SMB backend | Yes | Cross-platform, battle-tested |
| MinIO + mount | Yes | CIFS/FUSE mount | Yes | Production-grade S3 features |
| s3proxy / VersityGW | Yes | CIFS/FUSE mount | Yes | Lightweight or high-perf FS backends |

## License

Apache 2.0
