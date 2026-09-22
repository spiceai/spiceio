#!/usr/bin/env python3
"""Two-server checks for github_fetch.StripAuthOnHostChange.

Stock urllib.request keeps Authorization across a host change. The GitHub
release-asset API 302s to release-assets.githubusercontent.com, so that
default is the leak. These servers are the local stand-in for that hop.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import github_fetch  # noqa: E402


TOKEN = "secret-workflow-token"
AUTH = f"Bearer {TOKEN}"


class _Record:
    def __init__(self) -> None:
        self.authorization: str | None = None


def _handler(record: _Record, on_get):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            record.authorization = self.headers.get("Authorization")
            on_get(self)

        def log_message(self, *_args) -> None:
            return

    return Handler


def _serve(handler) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


def _stop(httpd: ThreadingHTTPServer) -> None:
    httpd.shutdown()
    httpd.server_close()


def _pair(src_on_get, dst_on_get):
    src_rec = _Record()
    dst_rec = _Record()
    dst = _serve(_handler(dst_rec, dst_on_get))

    def redirect(handler: BaseHTTPRequestHandler) -> None:
        src_on_get(handler, f"http://127.0.0.1:{dst.server_port}/asset")

    src = _serve(_handler(src_rec, redirect))
    return src, dst, src_rec, dst_rec


def _ok(handler: BaseHTTPRequestHandler) -> None:
    handler.send_response(200)
    handler.end_headers()
    handler.wfile.write(b"ok")


class StockUrllibLeakTests(unittest.TestCase):
    def test_urlopen_forwards_authorization_to_other_host(self) -> None:
        def src_on_get(handler: BaseHTTPRequestHandler, location: str) -> None:
            handler.send_response(302)
            handler.send_header("Location", location)
            handler.end_headers()

        src, dst, src_rec, dst_rec = _pair(src_on_get, lambda h: _ok(h))
        self.addCleanup(_stop, src)
        self.addCleanup(_stop, dst)

        req = urllib.request.Request(f"http://127.0.0.1:{src.server_port}/api")
        req.add_header("Authorization", AUTH)
        req.add_header("User-Agent", "spiceio-setup")
        with urllib.request.urlopen(req) as resp:
            body = resp.read()

        self.assertEqual(body, b"ok")
        self.assertEqual(src_rec.authorization, AUTH)
        # Evidence that the default opener is unsafe for the asset API hop.
        self.assertEqual(dst_rec.authorization, AUTH)


class StripAuthTests(unittest.TestCase):
    def test_cross_host_redirect_drops_authorization(self) -> None:
        def src_on_get(handler: BaseHTTPRequestHandler, location: str) -> None:
            handler.send_response(302)
            handler.send_header("Location", location)
            handler.end_headers()

        src, dst, src_rec, dst_rec = _pair(src_on_get, lambda h: _ok(h))
        self.addCleanup(_stop, src)
        self.addCleanup(_stop, dst)

        body = github_fetch.fetch(
            f"http://127.0.0.1:{src.server_port}/api",
            "application/octet-stream",
            TOKEN,
        )
        self.assertEqual(body, b"ok")
        self.assertEqual(src_rec.authorization, AUTH)
        self.assertIsNone(dst_rec.authorization)

    def test_same_host_redirect_keeps_authorization(self) -> None:
        rec = _Record()
        seen_paths: list[str] = []

        def on_get(handler: BaseHTTPRequestHandler) -> None:
            rec.authorization = handler.headers.get("Authorization")
            seen_paths.append(handler.path)
            if handler.path == "/from":
                handler.send_response(302)
                handler.send_header("Location", "/to")
                handler.end_headers()
                return
            _ok(handler)

        httpd = _serve(_handler(rec, on_get))
        self.addCleanup(_stop, httpd)

        body = github_fetch.fetch(
            f"http://127.0.0.1:{httpd.server_port}/from",
            "application/vnd.github+json",
            TOKEN,
        )
        self.assertEqual(body, b"ok")
        self.assertEqual(seen_paths, ["/from", "/to"])
        self.assertEqual(rec.authorization, AUTH)


class DownloadAssetTests(unittest.TestCase):
    def test_asset_hop_does_not_forward_token(self) -> None:
        dst_rec = _Record()
        dst = _serve(_handler(dst_rec, lambda h: _ok(h)))
        self.addCleanup(_stop, dst)

        api_rec = _Record()

        def api_on_get(handler: BaseHTTPRequestHandler) -> None:
            api_rec.authorization = handler.headers.get("Authorization")
            if handler.path.endswith("/releases/tags/v0.11.0"):
                payload = {
                    "assets": [
                        {
                            "name": "spiceio-macOS-ARM64.tar.gz",
                            "url": f"http://127.0.0.1:{handler.server.server_port}/releases/assets/1",
                        }
                    ]
                }
                body = json.dumps(payload).encode()
                handler.send_response(200)
                handler.send_header("Content-Type", "application/json")
                handler.end_headers()
                handler.wfile.write(body)
                return
            if handler.path.endswith("/releases/assets/1"):
                handler.send_response(302)
                handler.send_header(
                    "Location", f"http://127.0.0.1:{dst.server_port}/asset"
                )
                handler.end_headers()
                return
            handler.send_response(404)
            handler.end_headers()

        api = _serve(_handler(api_rec, api_on_get))
        self.addCleanup(_stop, api)

        dest = tempfile.mkdtemp()
        github_fetch.download_asset(
            "spiceai/spiceio",
            "v0.11.0",
            dest,
            "spiceio-macOS-ARM64.tar.gz",
            TOKEN,
            api_base=f"http://127.0.0.1:{api.server_port}",
        )
        with open(os.path.join(dest, "spiceio-macOS-ARM64.tar.gz"), "rb") as fh:
            self.assertEqual(fh.read(), b"ok")
        self.assertEqual(api_rec.authorization, AUTH)
        self.assertIsNone(dst_rec.authorization)


if __name__ == "__main__":
    unittest.main(verbosity=2)
