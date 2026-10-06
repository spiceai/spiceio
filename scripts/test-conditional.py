#!/usr/bin/env python3
"""Live conditional-write gate: independent proxies, one NAS, no SDK dependencies."""
import concurrent.futures
import http.client
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import uuid
import xml.etree.ElementTree as ET


def main():
    for name in ("SPICEIO_SMB_USER", "SPICEIO_SMB_PASS"):
        if not os.environ.get(name):
            raise SystemExit(f"{name} is required")
    prefix = f"conditional-{uuid.uuid4().hex}/"
    processes, logs, ports, keys = [], [], [], set()
    bucket = "conditional"
    env = os.environ.copy()
    env.update(
        SPICEIO_SMB_SERVER=env.get("SPICEIO_SMB_SERVER", "192.168.3.148"),
        SPICEIO_SMB_SHARE=env.get("SPICEIO_SMB_SHARE", "ai_platform_dev"),
        SPICEIO_BUCKET=bucket,
        SPICEIO_STRICT_PREFIXES=prefix,
        SPICEIO_WRITE_BACK="1",
        SPICEIO_IMMUTABLE_OBJECTS="1",
        SPICEIO_EXISTENCE_INDEX="1",
        SPICEIO_OBJECT_CACHE_BYTES="16777216",
        SPICEIO_SPILL_DIR="off",
        SPICEIO_SMB_CONNECTIONS="4",
    )

    def request(instance, method, key="", body=None, headers=None, query=""):
        path = f"/{bucket}/{key}" if key else "/"
        connection = http.client.HTTPConnection("127.0.0.1", ports[instance], timeout=60)
        try:
            connection.request(method, path + query, body, headers or {})
            response = connection.getresponse()
            return response.status, {k.lower(): v for k, v in response.getheaders()}, response.read()
        finally:
            connection.close()

    def key(name):
        value = prefix + name
        keys.add(value)
        return value

    def expect(response, status):
        assert response[0] == status, (response[0], status, response[2][:1000])
        return response

    def race(target, headers):
        barrier = threading.Barrier(16)

        def put(i):
            body = f"writer-{i:02d}".encode()
            barrier.wait()
            return body, request(i % 2, "PUT", target, body, headers)

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
            results = list(executor.map(put, range(16)))
        winners = [(body, result) for body, result in results if result[0] == 200]
        assert len(winners) == 1, [(body, result[0]) for body, result in results]
        assert sum(result[0] == 412 for _, result in results) == 15, results
        assert expect(request(1, "GET", target), 200)[2] == winners[0][0]
        return winners[0][1][1]["etag"]

    with tempfile.TemporaryDirectory(prefix="spiceio-conditional-") as directory:
        try:
            for i in range(2):
                with socket.socket() as listener:
                    listener.bind(("127.0.0.1", 0))
                    ports.append(listener.getsockname()[1])
                log = open(Path(directory) / f"proxy-{i}.log", "w+")
                logs.append(log)
                processes.append(subprocess.Popen(
                    ["./target/debug/spiceio"],
                    env={**env, "SPICEIO_BIND": f"127.0.0.1:{ports[i]}"},
                    stdout=log, stderr=subprocess.STDOUT,
                ))
                for _ in range(120):
                    assert processes[i].poll() is None, "proxy exited during startup"
                    try:
                        if request(i, "GET")[0] == 200:
                            break
                    except OSError:
                        pass
                    time.sleep(0.5)
                else:
                    raise AssertionError("proxy never became ready")

            for repetition in range(3):
                target = key(f"race-{repetition}")
                original = race(target, {"If-None-Match": "*"})
                changed = race(target, {"If-Match": original})
                assert changed != original
                expect(request(0, "PUT", target, b"stale", {"If-Match": original}), 412)
                expect(request(0, "DELETE", target), 204)
                recreated = expect(request(1, "PUT", target, b"recreated", {"If-None-Match": "*"}), 200)
                assert recreated[1]["etag"] != changed
                expect(request(0, "PUT", target, b"stale", {"If-Match": changed}), 412)
            print("PASS: two-instance create/CAS races have exactly one winner; DELETE does not reuse ETags")

            missing = key("missing")
            expect(request(0, "PUT", missing, b"no", {"If-Match": '"missing"'}), 404)
            source, dest = key("copy-source"), key("copy-dest")
            expect(request(0, "PUT", source, b"copy bytes"), 200)
            copy = {"x-amz-copy-source": f"/{bucket}/{source}", "If-None-Match": "*"}
            expect(request(1, "PUT", dest, b"", copy), 200)
            expect(request(0, "PUT", dest, b"", copy), 412)
            current = expect(request(0, "HEAD", dest), 200)[1]["etag"]
            expect(request(1, "PUT", dest, b"", {"x-amz-copy-source": f"/{bucket}/{source}", "If-Match": current}), 200)
            expect(request(0, "PUT", dest, b"", {"x-amz-copy-source": f"/{bucket}/{source}", "If-Match": current}), 412)
            print("PASS: destination copy conditions")

            multipart = key("multipart")
            initiated = expect(request(0, "POST", multipart, b"", query="?uploads"), 200)
            upload = ET.fromstring(initiated[2]).findtext(".//{*}UploadId")
            assert upload
            part = expect(request(0, "PUT", multipart, b"multipart bytes", query=f"?partNumber=1&uploadId={upload}"), 200)
            completion = f"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{part[1]['etag']}</ETag></Part></CompleteMultipartUpload>".encode()
            predecessor = expect(request(1, "PUT", multipart, b"predecessor"), 200)[1]["etag"]
            expect(request(0, "POST", multipart, completion, {"If-None-Match": "*"}, f"?uploadId={upload}"), 412)
            expect(request(0, "POST", multipart, completion, {"If-Match": predecessor}, f"?uploadId={upload}"), 200)
            assert expect(request(1, "GET", multipart), 200)[2] == b"multipart bytes"
            print("PASS: multipart completion checks destination and preserves upload after 412")

            crash = key("crash")
            body = b"committed before success" * 8192
            expect(request(0, "PUT", crash, body, {"If-None-Match": "*"}), 200)
            processes[0].kill()
            processes[0].wait(timeout=10)
            assert expect(request(1, "GET", crash), 200)[2] == body
            expect(request(1, "PUT", crash, b"duplicate", {"If-None-Match": "*"}), 412)
            print("PASS: conditional success survives immediate process death, read through peer with immutable cache enabled")
        except BaseException:
            for log in logs:
                log.flush()
                log.seek(0)
                print(log.read()[-16000:])
            raise
        finally:
            if len(processes) == 2 and processes[1].poll() is None:
                for target in keys:
                    try:
                        request(1, "DELETE", target)
                    except OSError:
                        pass
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=40)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
            for log in logs:
                log.close()


if __name__ == "__main__":
    main()
