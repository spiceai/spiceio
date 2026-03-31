# spiceio

S3-compatible API proxy to SMB file shares. Translates S3 HTTP requests into SMB 3.1.x wire protocol operations over TCP.

- Speaks SMB directly — no mount, no libsmbclient
- NTLMv2 authentication via macOS CommonCrypto (no external crypto crates)
- macOS 26+ only

## Supported S3 operations

GetObject (range + conditional), PutObject, CopyObject, DeleteObject, HeadObject, ListObjectsV1/V2, ListBuckets, multipart uploads (create/upload-part/complete/abort/list-parts/list-uploads), HeadBucket, GetBucketLocation, and stubs for ACL, tagging, and versioning.

## Build

Requires Rust (edition 2024) and macOS 26+.

```bash
make                # fmt + lint + test + build
make release        # optimized release build
make test           # run tests
make lint           # fmt-check + check + strict clippy + rustdoc warnings
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

## Usage

```bash
export SPICEIO_SMB_SERVER=nas.local
export SPICEIO_SMB_USER=admin
export SPICEIO_SMB_PASS=secret
export SPICEIO_SMB_SHARE=files
./target/release/spiceio
```

Then use any S3 client pointed at `http://localhost:8333`:

```bash
aws s3 ls s3://files/ --endpoint-url http://localhost:8333
aws s3 cp local.txt s3://files/remote.txt --endpoint-url http://localhost:8333
```

## License

Apache 2.0
