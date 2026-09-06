#!/usr/bin/env python3
"""Live, destructive retention test. Only the configured sccache prefix is cleaned."""

import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import uuid

helper = Path(__file__).with_name("sccache")
api = runpy.run_path(str(helper))


def main():
    endpoint = os.environ.get("SCCACHE_ENDPOINT", "http://127.0.0.1:8333")
    bucket = os.environ.get("SCCACHE_BUCKET")
    prefix = api["cache_prefix"](os.environ.get("SCCACHE_S3_KEY_PREFIX", "sccache"))
    client = api["S3"](endpoint, bucket)
    key = prefix + ".spiceio-retention-test-" + uuid.uuid4().hex
    content = os.urandom(64)
    created = False
    try:
        # The helper's age filter must retain this fresh object while it removes
        # real cache objects older than ten days. Never clear the entire bucket.
        client.request("PUT", key, body=content)
        created = True
        command = [str(helper), "clean", "--endpoint", endpoint, "--bucket", bucket,
                   "--prefix", prefix, "--older-than-days", "10"]
        result = subprocess.run(command, check=True, text=True, stdout=subprocess.PIPE)
        summary = json.loads(result.stdout)
        print(json.dumps(summary, sort_keys=True), flush=True)
        if client.request("GET", key) != content:
            raise RuntimeError("cleanup removed or changed the fresh sentinel")
        # Verify the exact fixed cutoff used by the cleanup, rather than moving
        # the threshold while a long listing is in progress.
        cutoff = api["timestamp"](summary["cutoff"])
        remaining = 0
        examples = []
        for page in client.pages(prefix):
            for obj in page:
                if obj["modified"] < cutoff:
                    remaining += 1
                    if len(examples) < 5:
                        examples.append({"key": obj["key"], "modified": obj["modified"].isoformat()})
        if remaining:
            raise RuntimeError(f"{remaining} object(s) older than {summary['cutoff']} remain: "
                               f"{json.dumps(examples, sort_keys=True)}")
        print(f"PASS: {summary['deleted']} old objects deleted; fresh sentinel preserved; "
              f"no objects remain older than {summary['cutoff']}")
    finally:
        if created:
            client.delete([key])
        client.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"FAIL: live sccache retention test: {error}", file=sys.stderr)
        sys.exit(1)
