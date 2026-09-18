#!/usr/bin/env python3
"""Prove sccache objects reached the NAS after spiceio shutdown.

The live sccache suite can pass on cache hits served from spiceio's memory
(or the machine-wide spill) even when write-back never landed the body on
the share. This helper closes that gap in two phases:

  snapshot  GET every object under the test's sccache prefix through the
            still-running instance and record key / size / sha256. Those
            GETs may be answered from the object cache — that is the
            acknowledged generation the client was promised.

  verify    After a graceful drain, confirm the same digest on the share.
            Default path is GET through a cache-less spiceio instance
            (CI has no smbfs mount). Pass ``--mount`` only when
            ``SPICEIO_SMB_MOUNT`` is set locally.

sccache stores each compiler result at a SHA-256-keyed path
(`normalize_key`: ``a/b/c/<64-hex>``). Snapshot refuses a prefix that
does not contain at least one such object, so a misconfigured prefix
cannot silently verify the wrong tree.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path
import runpy

HELPER = Path(__file__).with_name("sccache")
API = runpy.run_path(str(HELPER))

# sccache S3 keys are `normalize_key(sha256)` → a/b/c/<64 lowercase hex>.
SHA_LEAF = re.compile(r"^[0-9a-f]{64}$")
# CacheWrite stores a zip; a non-zip body is not an sccache object.
SCCACHE_ZIP_MAGIC = b"PK\x03\x04"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def mount_path(mount: Path, key: str) -> Path:
    if key.startswith("/") or "\\" in key or any(part in (".", "..") for part in key.split("/")):
        raise ValueError(f"refusing to resolve key {key!r} under the mount")
    return mount.joinpath(*key.split("/"))


def is_sha_keyed(key: str) -> bool:
    return bool(SHA_LEAF.fullmatch(key.rsplit("/", 1)[-1]))


def load_manifest(path: Path) -> dict:
    doc = json.loads(path.read_text())
    objects = doc.get("objects")
    if not isinstance(objects, list) or not objects:
        raise RuntimeError(f"{path} has no objects to verify")
    for obj in objects:
        for field in ("key", "size", "sha256"):
            if field not in obj:
                raise RuntimeError(f"{path} object missing {field}")
        if not SHA_LEAF.fullmatch(obj["sha256"]):
            raise RuntimeError(f"{path} has a malformed sha256 for {obj['key']}")
    return doc


def snapshot(endpoint: str, bucket: str, prefix: str, out: Path) -> int:
    prefix = API["cache_prefix"](prefix)
    client = API["S3"](endpoint, bucket)
    objects = []
    try:
        for page in client.pages(prefix):
            for obj in page:
                key = obj["key"]
                # sccache also drops a `.sccache_check` probe under the prefix;
                # only the SHA-256-keyed compiler results are the durability
                # contract this check is for.
                if not is_sha_keyed(key):
                    continue
                body = client.request("GET", key)
                if not body.startswith(SCCACHE_ZIP_MAGIC):
                    raise RuntimeError(
                        f"{key} is not an sccache zip (magic={body[:4]!r}); "
                        "refusing to treat it as a compiler-cache object"
                    )
                digest = sha256_bytes(body)
                if len(body) != obj["size"]:
                    raise RuntimeError(
                        f"{key}: listing size {obj['size']} != GET body {len(body)}"
                    )
                objects.append({"key": key, "size": len(body), "sha256": digest})
    finally:
        client.close()

    sha_keyed = [obj for obj in objects if is_sha_keyed(obj["key"])]
    if not sha_keyed:
        raise RuntimeError(
            f"no SHA-256-keyed sccache objects under {prefix!r} "
            f"({len(objects)} object(s) listed)"
        )

    out.write_text(json.dumps(
        {"prefix": prefix, "objects": objects},
        indent=2,
        sort_keys=True,
    ) + "\n")
    total = sum(obj["size"] for obj in objects)
    print(
        f"[metrics] nas_snapshot objects={len(objects)} sha_keyed={len(sha_keyed)} "
        f"bytes={total} prefix={prefix}",
        flush=True,
    )
    return 0


def _refresh_ancestors(path: Path, mount: Path) -> None:
    """Force smbfs to readdir each parent so a peer's SMB create is visible."""
    current = path.parent
    try:
        current.relative_to(mount)
    except ValueError:
        return
    while True:
        try:
            os.listdir(current)
        except OSError:
            # Parent may not exist yet; listdir is a best-effort smbfs cache
            # refresh and a missing directory is the miss path, not a failure.
            pass
        if current == mount:
            break
        current = current.parent


def verify_mount(manifest: dict, mount: Path, timeout: float) -> None:
    if not mount.is_dir():
        raise RuntimeError(f"mount {mount} is not a directory")
    paths = [(obj, mount_path(mount, obj["key"])) for obj in manifest["objects"]]
    deadline = time.monotonic() + timeout
    missing: list[tuple[dict, Path]] = []
    while True:
        missing = [(obj, path) for obj, path in paths if not path.is_file()]
        if not missing:
            break
        for _, path in missing:
            _refresh_ancestors(path, mount)
        if time.monotonic() >= deadline:
            sample = ", ".join(obj["key"] for obj, _ in missing[:8])
            raise RuntimeError(
                f"{len(missing)} of {len(paths)} sccache object(s) missing on {mount} "
                f"after {timeout:.0f}s (smbfs directory cache can lag a "
                f"wire-protocol write): {sample}"
            )
        time.sleep(0.5)

    errors: list[str] = []
    for obj, path in paths:
        digest, size = sha256_file(path)
        if size != obj["size"]:
            errors.append(f"{obj['key']}: size {size} != acknowledged {obj['size']}")
        elif digest != obj["sha256"]:
            errors.append(
                f"{obj['key']}: sha256 {digest} != acknowledged {obj['sha256']}"
            )
    if errors:
        raise RuntimeError(
            f"{len(errors)} of {len(paths)} sccache object(s) did not match on "
            f"{mount}: " + "; ".join(errors[:8])
        )


def verify_http(manifest: dict, endpoint: str, bucket: str) -> None:
    client = API["S3"](endpoint, bucket)
    errors: list[str] = []
    try:
        for obj in manifest["objects"]:
            try:
                body = client.request("GET", obj["key"])
            except RuntimeError as exc:
                errors.append(f"{obj['key']}: {exc}")
                continue
            digest = sha256_bytes(body)
            if len(body) != obj["size"]:
                errors.append(
                    f"{obj['key']}: size {len(body)} != acknowledged {obj['size']}"
                )
            elif digest != obj["sha256"]:
                errors.append(
                    f"{obj['key']}: sha256 {digest} != acknowledged {obj['sha256']}"
                )
    finally:
        client.close()
    if errors:
        raise RuntimeError(
            f"{len(errors)} of {len(manifest['objects'])} sccache object(s) "
            f"did not match through {endpoint}: " + "; ".join(errors[:8])
        )


def self_test() -> int:
    leaf = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    assert is_sha_keyed(f"a/b/c/{leaf}")
    assert not is_sha_keyed("a/b/c/not-a-hash")
    assert not is_sha_keyed("prefix/.sccache_check")
    assert not is_sha_keyed("a/b/c/" + "A" * 64)
    mount = Path("/Volumes/share")
    assert mount_path(mount, f"pre/a/b/c/{leaf}") == mount / "pre" / "a" / "b" / "c" / leaf
    for bad in ("/etc/passwd", "../escape", "a/../b", "a\\b"):
        try:
            mount_path(mount, bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"mount_path accepted {bad!r}")
    assert sha256_bytes(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    print("PASS: nas helper unit tests", flush=True)
    return 0


def verify(manifest_path: Path, mount: str | None, endpoint: str | None,
           bucket: str | None, timeout: float) -> int:
    doc = load_manifest(manifest_path)
    sha_keyed = sum(1 for obj in doc["objects"] if is_sha_keyed(obj["key"]))
    total = sum(obj["size"] for obj in doc["objects"])
    if mount:
        verify_mount(doc, Path(mount), timeout)
        via = f"mount={mount}"
    elif endpoint and bucket:
        verify_http(doc, endpoint, bucket)
        via = f"http={endpoint}"
    else:
        raise RuntimeError("verify requires --mount or --endpoint and --bucket")
    print(
        f"[metrics] nas_verify objects={len(doc['objects'])} sha_keyed={sha_keyed} "
        f"bytes={total} via={via}",
        flush=True,
    )
    print(
        f"PASS: {len(doc['objects'])} sccache object(s) ({sha_keyed} SHA-256-keyed) "
        f"matched on the NAS after shutdown",
        flush=True,
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    snap = commands.add_parser(
        "snapshot",
        help="record key/size/sha256 for every sccache object under a prefix",
    )
    snap.add_argument("--endpoint", required=True)
    snap.add_argument("--bucket", required=True)
    snap.add_argument("--prefix", required=True)
    snap.add_argument("--out", required=True, type=Path)

    ver = commands.add_parser(
        "verify",
        help="check a snapshot against a local mount or a cache-less spiceio",
    )
    ver.add_argument("--manifest", required=True, type=Path)
    ver.add_argument("--mount", default="")
    ver.add_argument("--endpoint", default="")
    ver.add_argument("--bucket", default="")
    ver.add_argument("--timeout", type=float, default=15.0)
    commands.add_parser("self-test", help="path and digest unit checks")

    args = parser.parse_args()
    try:
        if args.command == "snapshot":
            return snapshot(args.endpoint, args.bucket, args.prefix, args.out)
        if args.command == "self-test":
            return self_test()
        return verify(
            args.manifest,
            args.mount or None,
            args.endpoint or None,
            args.bucket or None,
            args.timeout,
        )
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"FAIL: sccache NAS check: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
