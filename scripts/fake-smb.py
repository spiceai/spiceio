"""A fake SMB server for tests: it refuses every login, or accepts any.

    python3 -I scripts/fake-smb.py [--status 0xC000006D | --accept] [--port N] [--log FILE]

It listens on 127.0.0.1, on port N or a free one, and prints `port N` on its
first line of output. Each connection gets just enough of a handshake for spiceio's
client to reach the authenticating leg: an SMB 3.1.1 negotiate response, then
an NTLM challenge for the first session setup. The second session setup, the
one that carries the NTLMv2 response, is answered with --status (default
STATUS_LOGON_FAILURE) and logged as one line, `auth`, to --log, so a test can
count how many logins spiceio attempted. A real server counts each of those
toward an account lockout.

With --accept it answers that second session setup with STATUS_SUCCESS and a
tree connect with a disk share, all unsigned: it knows no password, so it
cannot sign. A client that accepts this session has not checked that the
server knows the session key.

It speaks no other command: anything else is answered with
STATUS_ACCESS_DENIED.
"""

import argparse
import socket
import struct
import sys
import threading

NEGOTIATE, SESSION_SETUP, TREE_CONNECT = 0, 1, 3
MORE_PROCESSING_REQUIRED = 0xC0000016
ACCESS_DENIED = 0xC0000022
SESSION_ID = 0x0000_1234_5678_9ABC

args = argparse.ArgumentParser()
args.add_argument("--status", default="0xC000006D")
args.add_argument("--accept", action="store_true")
args.add_argument("--port", type=int, default=0)
args.add_argument("--log", default=None)
opts = args.parse_args()
reject = 0 if opts.accept else int(opts.status, 16)
lock = threading.Lock()


def log(line):
    if opts.log:
        with lock, open(opts.log, "a") as f:
            f.write(line + "\n")


def header(command, status, message_id, session_id):
    return (
        b"\xfeSMB"
        + struct.pack("<HHIHHIIQIIQ", 64, 1, status, command, 64, 1, 0, message_id, 0, 0, session_id)
        + b"\0" * 16
    )


def negotiate_body():
    return struct.pack(
        "<HHHH16sIIIIQQHHI",
        65,  # StructureSize
        1,  # SecurityMode: signing enabled
        0x0311,  # DialectRevision
        0,  # NegotiateContextCount
        b"\x5a" * 16,  # ServerGuid
        0,  # Capabilities
        1 << 20,  # MaxTransactSize
        1 << 20,  # MaxReadSize
        1 << 20,  # MaxWriteSize
        0,  # SystemTime
        0,  # ServerStartTime
        128,  # SecurityBufferOffset
        0,  # SecurityBufferLength
        0,  # NegotiateContextOffset
    )


def challenge():
    target_info = struct.pack("<HH", 0, 0)  # MsvAvEOL
    fixed = (
        b"NTLMSSP\0"
        + struct.pack("<I", 2)  # CHALLENGE_MESSAGE
        + struct.pack("<HHI", 0, 0, 56)  # TargetNameFields
        + struct.pack("<I", 0xE2898215)  # NegotiateFlags
        + b"\x11" * 8  # ServerChallenge
        + b"\0" * 8  # Reserved
        + struct.pack("<HHI", len(target_info), len(target_info), 56)  # TargetInfoFields
        + b"\x0a\x00\x63\x45\x00\x00\x00\x0f"  # Version
    )
    return fixed + target_info


def session_setup_body(blob):
    return struct.pack("<HHHH", 9, 0, 64 + 8, len(blob)) + blob


def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def serve(conn):
    with conn:
        while True:
            frame = recv_exact(conn, 4)
            if frame is None:
                return
            msg = recv_exact(conn, int.from_bytes(frame[1:4], "big"))
            if msg is None or msg[:4] != b"\xfeSMB":
                return
            command, = struct.unpack_from("<H", msg, 12)
            message_id, = struct.unpack_from("<Q", msg, 24)
            session_id, = struct.unpack_from("<Q", msg, 40)
            if command == NEGOTIATE:
                reply = header(NEGOTIATE, 0, message_id, 0) + negotiate_body()
            elif command == SESSION_SETUP and session_id == 0:
                reply = header(SESSION_SETUP, MORE_PROCESSING_REQUIRED, message_id, SESSION_ID)
                reply += session_setup_body(challenge())
            elif command == SESSION_SETUP:
                log("auth")
                reply = header(SESSION_SETUP, reject, message_id, session_id)
                if reject:
                    reply += struct.pack("<HBBI", 9, 0, 0, 0) + b"\0"  # error response
                else:
                    reply += session_setup_body(b"")
            elif command == TREE_CONNECT and opts.accept:
                log("tree")
                reply = header(TREE_CONNECT, 0, message_id, session_id)
                reply = reply[:36] + struct.pack("<I", 7) + reply[40:]  # TreeId
                reply += struct.pack("<HBBIII", 16, 1, 0, 0, 0, 0x001F01FF)
            else:
                reply = header(command, ACCESS_DENIED, message_id, session_id)
                reply += struct.pack("<HBBI", 9, 0, 0, 0) + b"\0"
            conn.sendall(b"\0" + len(reply).to_bytes(3, "big") + reply)


listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", opts.port))
listener.listen(64)
print("port", listener.getsockname()[1], flush=True)
try:
    while True:
        conn, _ = listener.accept()
        threading.Thread(target=serve, args=(conn,), daemon=True).start()
except KeyboardInterrupt:
    sys.exit(0)
