#!/usr/bin/env python3
"""Exercise retention, pagination and S3 error handling over a loopback HTTP peer."""

import datetime as dt
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import runpy
import subprocess
import threading
import unittest
import urllib.parse
import xml.etree.ElementTree as ET

HELPER = Path(__file__).with_name("sccache")
API = runpy.run_path(str(HELPER))
NS = API["NS"]


class RetentionTest(unittest.TestCase):
    def setUp(self):
        self.now = dt.datetime.now(dt.timezone.utc)
        self.objects = {"cache/a": self.now - dt.timedelta(days=11),
                        "cache/b": self.now - dt.timedelta(days=1),
                        "cache/nested/c": self.now - dt.timedelta(days=30),
                        "cache/nested/d": self.now,
                        "cache-other/old": self.now - dt.timedelta(days=50)}
        self.deleted = []
        self.fail_delete = False
        self.fail_once = False
        self.retried = set()
        self.lock = threading.Lock()
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def respond(self, root):
                body = ET.tostring(root)
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                prefix = query["prefix"][0]
                fixture.assertEqual(query["delimiter"], ["/"])
                marker = query.get("continuation-token", [""])[0]
                with fixture.lock:
                    records = dict(fixture.objects)
                entries = set()
                for key in records:
                    if key.startswith(prefix):
                        tail = key[len(prefix):]
                        entries.add(prefix + tail.split("/", 1)[0] + "/" if "/" in tail else key)
                entries = sorted(key for key in entries if key > marker)
                page = entries[:1]  # Force pagination even with only a few objects.
                root = ET.Element(f"{{{NS}}}ListBucketResult")
                ET.SubElement(root, f"{{{NS}}}IsTruncated").text = "true" if len(entries) > 1 else "false"
                if len(entries) > 1:
                    ET.SubElement(root, f"{{{NS}}}NextContinuationToken").text = page[-1]
                for key in page:
                    if key.endswith("/"):
                        ET.SubElement(ET.SubElement(root, f"{{{NS}}}CommonPrefixes"), f"{{{NS}}}Prefix").text = key
                    else:
                        obj = ET.SubElement(root, f"{{{NS}}}Contents")
                        ET.SubElement(obj, f"{{{NS}}}Key").text = key
                        ET.SubElement(obj, f"{{{NS}}}LastModified").text = records[key].isoformat()
                        ET.SubElement(obj, f"{{{NS}}}Size").text = "7"
                self.respond(root)

            def do_POST(self):
                root = ET.fromstring(self.rfile.read(int(self.headers["Content-Length"])))
                response = ET.Element(f"{{{NS}}}DeleteResult")
                for obj in root.findall(f"{{{NS}}}Object"):
                    key = obj.findtext(f"{{{NS}}}Key")
                    with fixture.lock:
                        transient = fixture.fail_once and key not in fixture.retried
                        if transient:
                            fixture.retried.add(key)
                    failed = fixture.fail_delete or transient
                    entry = ET.SubElement(response, f"{{{NS}}}Error" if failed else f"{{{NS}}}Deleted")
                    ET.SubElement(entry, f"{{{NS}}}Key").text = key
                    if failed:
                        ET.SubElement(entry, f"{{{NS}}}Code").text = "InternalError" if transient else "AccessDenied"
                    else:
                        with fixture.lock:
                            fixture.objects.pop(key, None)
                            fixture.deleted.append(key)
                self.respond(response)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def command(self, *args):
        return subprocess.run([str(HELPER), "clean", "--endpoint", self.endpoint,
                               "--bucket", "test", "--prefix", "cache", "--older-than-days", "10", *args],
                              capture_output=True, text=True, timeout=10)

    def test_clean_traverses_pages_while_deleting_and_keeps_recent_and_other_prefixes(self):
        result = self.command()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["deleted"], 2)
        self.assertEqual(sorted(self.deleted), ["cache/a", "cache/nested/c"])
        self.assertEqual(set(self.objects), {"cache/b", "cache/nested/d", "cache-other/old"})

    def test_exact_ten_day_boundary_is_retained(self):
        self.objects["cache/boundary"] = self.now - dt.timedelta(days=10)
        client = API["S3"](self.endpoint, "test")
        try:
            API["clean"](client, "cache", 10, now=self.now)
        finally:
            client.close()
        self.assertIn("cache/boundary", self.objects)

    def test_dry_run_does_not_delete(self):
        result = self.command("--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["eligible"], 2)
        self.assertEqual(self.deleted, [])

    def test_per_object_delete_error_fails_the_command(self):
        self.fail_delete = True
        result = self.command()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("AccessDenied", result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(self.deleted, [])

    def test_retries_transient_errors_without_double_counting_deletions(self):
        self.fail_once = True
        result = self.command()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["deleted"], 2)
        self.assertEqual(sorted(self.deleted), ["cache/a", "cache/nested/c"])
        self.assertEqual(self.retried, set(self.deleted))

    def test_rejects_empty_or_traversing_prefix(self):
        for prefix in ("", "/", "../", "cache/../", "cache//sub"):
            with self.assertRaises(ValueError):
                API["cache_prefix"](prefix)


if __name__ == "__main__":
    unittest.main()
