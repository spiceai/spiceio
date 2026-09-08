#!/usr/bin/env python3
"""Exercise reads and copies while a separate spiceio process replaces a key.

The caller starts both proxies with write-back, body cache, and spill disabled.
Only the supplied private prefix is created or deleted.
"""

import concurrent.futures
import http.client
import sys
import threading
import urllib.parse


def main():
    writer_url, reader_url, bucket, prefix = sys.argv[1:]

    def connection(url):
        parsed = urllib.parse.urlsplit(url)
        assert parsed.scheme == "http"
        return http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=30)

    def request(conn, method, key, body=None, headers=None, expected=200):
        path = urllib.parse.quote(f"/{bucket}/{key}", safe="/")
        conn.request(method, path, body, headers or {})
        response = conn.getresponse()
        data = response.read()
        assert response.status == expected, (method, key, response.status)
        return data, dict(response.getheaders())

    total = 0
    for size in (4096, 131072):
        key = f"{prefix}/{size}"
        dest = f"{key}-copy"
        versions = (b"A" * size, b"B" * size)
        barrier = threading.Barrier(5, timeout=30)
        setup = connection(writer_url)

        def worker(role):
            conn = connection(writer_url if role == "put" else reader_url)
            count = 0
            try:
                barrier.wait()
                for i in range(64 if role == "put" else 32 if role == "copy" else 128):
                    if role == "put":
                        request(conn, "PUT", key, versions[i % 2])
                    elif role == "head":
                        _, headers = request(conn, "HEAD", key)
                        headers = {k.lower(): v for k, v in headers.items()}
                        assert int(headers["content-length"]) == size
                    elif role == "range":
                        body, _ = request(
                            conn, "GET", key,
                            headers={"Range": "bytes=1024-2047"}, expected=206,
                        )
                        assert body in (b"A" * 1024, b"B" * 1024)
                    elif role == "copy":
                        body, _ = request(
                            conn, "PUT", dest, b"",
                            {"x-amz-copy-source": f"/{bucket}/{key}"},
                        )
                        assert b"<CopyObjectResult" in body and b"<Error>" not in body
                        body, _ = request(conn, "GET", dest)
                        assert body in versions
                        count += 1
                    else:
                        body, _ = request(conn, "GET", key)
                        assert body in versions, "read returned a partial or mixed generation"
                    count += 1
            finally:
                conn.close()
            return count

        try:
            request(setup, "PUT", key, versions[0])
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(worker, role)
                           for role in ("put", "get", "head", "range", "copy")]
                total += sum(future.result() for future in futures)
        finally:
            try:
                for path in (dest, key):
                    request(setup, "DELETE", path, expected=204)
            finally:
                setup.close()
        print(f"  peer publication: {size} byte generations verified", flush=True)
    print(f"  peer publication: {total} concurrent requests, no false misses or torn bodies")


if __name__ == "__main__":
    main()
