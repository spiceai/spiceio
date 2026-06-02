//! SMB2 client — manages TCP connections and speaks the protocol.

use bytes::Buf;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use bytes::{BufMut, BytesMut};

/// Timeout for a single SMB response read. Prevents indefinite mutex hold when
/// the SMB server is slow or unresponsive under heavy load.
const SMB_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout for a socket write. There is no OS-level write timeout, so a server
/// that stops draining its receive window under heavy concurrent write load
/// would otherwise block `write_all` forever (hanging the request). On timeout
/// we poison the connection — the pool healer reconnects it.
const SMB_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout for the initial TCP handshake to the SMB server. Without this,
/// a server that drops SYNs leaves the OS waiting ~75-90s, which stalls
/// pool initialization past any sensible CI window.
const SMB_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

use super::auth;
use super::protocol::*;

/// Configuration for connecting to an SMB server.
#[derive(Debug, Clone)]
pub struct SmbConfig {
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub domain: String,
    pub workstation: String,
    /// Cap for standalone read/write I/O (0 = use DEFAULT_MAX_IO).
    pub max_io_size: u32,
}

impl SmbConfig {
    pub fn share_path(&self, share: &str) -> String {
        format!("\\\\{}\\{}", self.server, share)
    }
}

/// Default I/O cap for standalone (non-compound) read/write operations.
///
/// 256 KB is the measured sweet spot for streaming throughput: on a 10G link a
/// single-stream PutObject rises from ~31 MiB/s at 64 KB to ~744 MiB/s at
/// 256 KB. The WAL writer bounds its in-flight burst with the adaptive flush
/// budget (`write_inflight`), which backs off on resets, so this cap sets the
/// per-write size rather than how much is buffered at once. 256 KB stays well
/// within what essentially every SMB server handles, and small files keep using
/// the 64 KB compound cap (so per-op latency is unchanged). Override via
/// `SPICEIO_SMB_MAX_IO`; the effective size is always clamped to the server's
/// negotiated maximum.
const DEFAULT_MAX_IO: u32 = 262144;

/// An authenticated SMB2 session.
pub struct SmbClient {
    stream: Mutex<TcpStream>,
    message_id: AtomicU64,
    session_id: u64,
    config: SmbConfig,
    /// Effective max read size for standalone (non-compound) reads.
    pub max_read_size: u32,
    /// Effective max write size for standalone (non-compound) writes.
    pub max_write_size: u32,
    /// Capped max for compound operations (64KB — some NAS servers reject
    /// larger payloads inside compound requests).
    pub compound_max_read_size: u32,
    pub compound_max_write_size: u32,
    /// 16-byte client GUID
    client_guid: [u8; 16],
    /// SMB 3.1.1 signing key (derived after auth)
    signing_key: Option<[u8; 16]>,
    /// Set on read timeout — connection framing is desynchronized.
    poisoned: AtomicBool,
}

impl SmbClient {
    /// Connect to the SMB server and authenticate.
    pub async fn connect(config: SmbConfig) -> io::Result<Arc<Self>> {
        let addr = format!("{}:{}", config.server, config.port);
        let stream =
            match tokio::time::timeout(SMB_CONNECT_TIMEOUT, TcpStream::connect(&addr)).await {
                Ok(Ok(s)) => {
                    crate::slog!("[spiceio] smb tcp connected: {addr}");
                    s
                }
                Ok(Err(e)) => {
                    crate::serr!("[spiceio] smb tcp connect failed: {addr}: {e}");
                    return Err(e);
                }
                Err(_) => {
                    let msg = format!(
                        "smb tcp connect timed out after {}s: {addr}",
                        SMB_CONNECT_TIMEOUT.as_secs()
                    );
                    crate::serr!("[spiceio] {msg}");
                    return Err(io::Error::new(io::ErrorKind::TimedOut, msg));
                }
            };
        stream.set_nodelay(true)?;

        // Enlarge socket buffers to 1 MB for large read/write throughput.
        {
            use std::os::fd::AsRawFd;

            unsafe extern "C" {
                fn setsockopt(
                    socket: i32,
                    level: i32,
                    option_name: i32,
                    option_value: *const u8,
                    option_len: u32,
                ) -> i32;
            }

            const SOL_SOCKET: i32 = 0xffff;
            const SO_SNDBUF: i32 = 0x1001;
            const SO_RCVBUF: i32 = 0x1002;

            let fd = stream.as_raw_fd();
            let buf_size: i32 = 4 * 1024 * 1024;
            let ptr = std::ptr::from_ref(&buf_size).cast();
            let len = size_of::<i32>() as u32;
            unsafe {
                setsockopt(fd, SOL_SOCKET, SO_SNDBUF, ptr, len);
                setsockopt(fd, SOL_SOCKET, SO_RCVBUF, ptr, len);
            }
        }

        let mut client_guid = [0u8; 16];
        unsafe extern "C" {
            fn arc4random_buf(buf: *mut u8, nbytes: usize);
        }
        unsafe {
            arc4random_buf(client_guid.as_mut_ptr(), 16);
        }

        // Use a temporary non-Arc client for the handshake, then wrap in Arc.
        let mut client = Self {
            stream: Mutex::new(stream),
            message_id: AtomicU64::new(0),
            session_id: 0,
            config,
            max_read_size: 65536,
            max_write_size: 65536,
            compound_max_read_size: 65536,
            compound_max_write_size: 65536,
            client_guid,
            signing_key: None,
            poisoned: AtomicBool::new(false),
        };

        client.negotiate_and_auth().await?;
        Ok(Arc::new(client))
    }

    /// Whether this connection has been poisoned by a timeout.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Relaxed)
    }

    fn next_message_id(&self) -> u64 {
        self.message_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Read exactly `buf.len()` bytes from the stream with a timeout.
    ///
    /// On timeout the stream framing is desynchronized, so we poison the
    /// connection (all future operations fail fast) and drop the underlying
    /// socket to fully close both halves.
    async fn read_exact_timeout(&self, stream: &mut TcpStream, buf: &mut [u8]) -> io::Result<()> {
        if self.poisoned.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "SMB connection poisoned by an earlier transport error",
            ));
        }
        match tokio::time::timeout(SMB_READ_TIMEOUT, stream.read_exact(buf)).await {
            Ok(result) => result.map(|_| ()),
            Err(_) => {
                self.poisoned.store(true, Ordering::Relaxed);
                // Drop the socket to fully close both halves.
                let _ = stream.shutdown().await;
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "SMB server read timed out; connection poisoned",
                ))
            }
        }
    }

    /// Write all of `buf` to the stream with a timeout. A server that stops
    /// draining its receive window under heavy concurrent write load would
    /// otherwise block `write_all` indefinitely (there is no OS write timeout),
    /// hanging the request. On timeout we poison the connection and drop the
    /// socket, mirroring the read path; the pool healer reconnects it.
    async fn write_all_timeout(&self, stream: &mut TcpStream, buf: &[u8]) -> io::Result<()> {
        if self.poisoned.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "SMB connection poisoned by an earlier transport error",
            ));
        }
        match tokio::time::timeout(SMB_WRITE_TIMEOUT, stream.write_all(buf)).await {
            Ok(result) => result,
            Err(_) => {
                self.poisoned.store(true, Ordering::Relaxed);
                let _ = stream.shutdown().await;
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "SMB server write timed out; connection poisoned",
                ))
            }
        }
    }

    /// Mark the connection poisoned and best-effort shut the socket down. A
    /// failed transport/framing/pipelined/compound op can leave unread responses
    /// queued in the stream; closing the socket lets the server release the
    /// session promptly and ensures the leftover bytes can never be misread as a
    /// later reply (the poisoned flag already blocks reuse until the pool heals).
    async fn poison(&self) {
        self.poisoned.store(true, Ordering::Relaxed);
        let _ = self.stream.lock().await.shutdown().await;
    }

    /// Send a packet and receive a response, also returning the raw SMB2 response bytes
    /// (without NetBIOS header) for preauth hash computation.
    async fn send_recv_raw(&self, packet: &[u8]) -> io::Result<(Header, Vec<u8>, Vec<u8>)> {
        let (header, body, raw) = self.send_recv_inner(packet).await?;
        Ok((header, body, raw))
    }

    async fn send_recv(&self, packet: &[u8]) -> io::Result<(Header, Vec<u8>)> {
        let (header, body, _raw) = self.send_recv_inner(packet).await?;
        Ok((header, body))
    }

    async fn send_recv_inner(&self, packet: &[u8]) -> io::Result<(Header, Vec<u8>, Vec<u8>)> {
        // Poison on any transport/framing error so the connection is never
        // reused with a desynchronized stream (a partial/leftover frame would
        // otherwise be misread as the next operation's reply).
        let r = self.send_recv_io(packet).await;
        if r.is_err() {
            self.poison().await;
        }
        r
    }

    async fn send_recv_io(&self, packet: &[u8]) -> io::Result<(Header, Vec<u8>, Vec<u8>)> {
        let mut stream = self.stream.lock().await;

        // Sign the packet if we have a signing key. We need a writable buffer
        // to sign in-place; `BytesMut::from(&[u8])` is one alloc + one copy
        // (same cost as the previous `to_vec`, but expressed as a typed buffer
        // that mirrors what the pipelined paths do).
        if let Some(ref key) = self.signing_key {
            let mut signed = BytesMut::from(packet);
            sign_packet(&mut signed, key);
            self.write_all_timeout(&mut stream, &signed).await?;
        } else {
            self.write_all_timeout(&mut stream, packet).await?;
        }
        stream.flush().await?;

        // Read responses, looping past STATUS_PENDING interim responses
        loop {
            let mut len_buf = [0u8; 4];
            self.read_exact_timeout(&mut stream, &mut len_buf).await?;
            let msg_len = u32::from_be_bytes(len_buf) as usize;

            if !(SMB2_HEADER_SIZE..=16 * 1024 * 1024).contains(&msg_len) {
                crate::serr!("[spiceio] smb invalid message length: {msg_len}");
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid SMB2 message length: {msg_len}"),
                ));
            }

            let mut msg = vec![0u8; msg_len];
            self.read_exact_timeout(&mut stream, &mut msg).await?;

            let header = Header::decode(&msg).ok_or_else(|| {
                crate::serr!("[spiceio] smb invalid header");
                io::Error::new(io::ErrorKind::InvalidData, "invalid SMB2 header")
            })?;

            // STATUS_PENDING (0x00000103): server is still processing, wait for real response
            if header.status == 0x0000_0103 {
                continue;
            }

            let body = msg[SMB2_HEADER_SIZE..].to_vec();
            return Ok((header, body, msg));
        }
    }

    /// Perform negotiate + session setup (NTLM auth) with signing key derivation.
    async fn negotiate_and_auth(&mut self) -> io::Result<()> {
        // Preauth integrity hash — tracks all handshake messages for key derivation
        let mut preauth_hash = [0u8; 64];

        // ── Step 1: Negotiate ──
        let msg_id = self.next_message_id();
        let hdr = Header::new(Command::Negotiate, msg_id);
        let packet = build_request(&hdr, |buf| {
            encode_negotiate_request(buf, &self.client_guid);
        });

        // Hash the negotiate request (SMB2 message, skip 4-byte NetBIOS header)
        update_preauth_hash(&mut preauth_hash, &packet[4..]);

        let (resp_hdr, resp_body, resp_raw) = self.send_recv_raw(&packet).await?;
        if NtStatus::from_u32(resp_hdr.status).is_error() {
            return Err(handshake_error(
                "negotiate",
                resp_hdr.status,
                io::ErrorKind::ConnectionRefused,
            ));
        }

        // Hash the negotiate response
        update_preauth_hash(&mut preauth_hash, &resp_raw);

        let neg_resp = decode_negotiate_response(&resp_body).ok_or_else(|| {
            crate::serr!("[spiceio] smb invalid negotiate response");
            io::Error::new(io::ErrorKind::InvalidData, "invalid negotiate response")
        })?;
        let io_cap = if self.config.max_io_size > 0 {
            self.config.max_io_size
        } else {
            DEFAULT_MAX_IO
        };
        crate::slog!(
            "[spiceio] negotiated SMB 0x{:04X}, server_max={}K io_cap={}K",
            neg_resp.dialect_revision,
            neg_resp.max_read_size / 1024,
            io_cap / 1024,
        );

        // ── Step 2: Session Setup (NTLM Negotiate) ──
        let ntlm_negotiate = auth::build_negotiate_message();
        let spnego_negotiate = auth::wrap_spnego_negotiate(&ntlm_negotiate);

        let msg_id = self.next_message_id();
        let mut hdr = Header::new(Command::SessionSetup, msg_id);
        let packet = build_request(&hdr, |buf| {
            encode_session_setup_request(buf, &spnego_negotiate);
        });

        // Hash session setup request 1
        update_preauth_hash(&mut preauth_hash, &packet[4..]);

        let (resp_hdr, resp_body, resp_raw) = self.send_recv_raw(&packet).await?;

        // The first session-setup leg should return MORE_PROCESSING_REQUIRED
        // carrying the NTLM challenge. The session is allocated on this leg, so a
        // server at capacity refuses *here* — classify any other error status
        // (commonly server capacity) as a typed, retryable error instead of
        // failing to parse a challenge out of an error body (which surfaced as a
        // hard InvalidData 500 and stopped the pool from shrinking).
        let status1 = NtStatus::from_u32(resp_hdr.status);
        if status1.is_error() && status1 != NtStatus::MoreProcessingRequired {
            return Err(handshake_error(
                "session setup",
                resp_hdr.status,
                io::ErrorKind::PermissionDenied,
            ));
        }

        // Hash session setup response 1
        update_preauth_hash(&mut preauth_hash, &resp_raw);

        let sess_resp = decode_session_setup_response(&resp_hdr, &resp_body).ok_or_else(|| {
            crate::serr!("[spiceio] smb invalid session setup response");
            io::Error::new(io::ErrorKind::InvalidData, "invalid session setup response")
        })?;

        // Parse NTLM challenge from SPNEGO wrapper
        let challenge_data = auth::unwrap_spnego(&sess_resp.security_buffer);
        let challenge = auth::parse_challenge_message(challenge_data).ok_or_else(|| {
            crate::serr!("[spiceio] smb invalid NTLM challenge");
            io::Error::new(io::ErrorKind::InvalidData, "invalid NTLM challenge")
        })?;

        // ── Step 3: Session Setup (NTLM Auth) ──
        let (ntlm_auth, session_base_key) = auth::build_authenticate_message(
            &challenge,
            &self.config.username,
            &self.config.password,
            &self.config.domain,
            &self.config.workstation,
        );
        let spnego_auth = auth::wrap_spnego_auth(&ntlm_auth);

        let msg_id = self.next_message_id();
        hdr = Header::new(Command::SessionSetup, msg_id);
        hdr.session_id = sess_resp.session_id;
        let packet = build_request(&hdr, |buf| {
            encode_session_setup_request(buf, &spnego_auth);
        });

        // Hash session setup request 2 (this is the final hash for key derivation)
        update_preauth_hash(&mut preauth_hash, &packet[4..]);

        let (resp_hdr, ..) = self.send_recv_raw(&packet).await?;
        if NtStatus::from_u32(resp_hdr.status).is_error() {
            return Err(handshake_error(
                "session setup",
                resp_hdr.status,
                io::ErrorKind::PermissionDenied,
            ));
        }

        // Derive the signing key
        let signing_key = auth::derive_signing_key(&session_base_key, &preauth_hash);
        crate::slog!("[spiceio] authenticated, signing key derived");

        self.session_id = resp_hdr.session_id;
        let io_cap = if self.config.max_io_size > 0 {
            self.config.max_io_size
        } else {
            DEFAULT_MAX_IO
        };
        let sizes = effective_io_sizes(
            neg_resp.max_read_size,
            neg_resp.max_write_size,
            neg_resp.max_transact_size,
            io_cap,
            |name, value| {
                crate::serr!(
                    "[spiceio] smb negotiated {name}={value} — substituting io_cap={io_cap}"
                );
            },
        );
        self.max_read_size = sizes.max_read;
        self.max_write_size = sizes.max_write;
        self.compound_max_read_size = sizes.compound_max_read;
        self.compound_max_write_size = sizes.compound_max_write;
        self.signing_key = Some(signing_key);
        Ok(())
    }

    /// Connect to a share (Tree Connect).
    pub async fn tree_connect(&self, share: &str) -> io::Result<u32> {
        let path = self.config.share_path(share);
        let msg_id = self.next_message_id();
        let mut hdr = Header::new(Command::TreeConnect, msg_id);
        hdr.session_id = self.session_id;

        let packet = build_request(&hdr, |buf| {
            encode_tree_connect_request(buf, &path);
        });

        let (resp_hdr, _resp_body) = self.send_recv(&packet).await?;
        if NtStatus::from_u32(resp_hdr.status).is_error() {
            return Err(handshake_error(
                &format!("tree connect to '{share}'"),
                resp_hdr.status,
                io::ErrorKind::NotFound,
            ));
        }

        crate::slog!(
            "[spiceio] smb tree connected: \\\\{}\\{}",
            self.config.server,
            share
        );
        Ok(resp_hdr.tree_id)
    }

    /// Open a file or directory.
    pub async fn create(
        &self,
        tree_id: u32,
        path: &str,
        desired_access: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
    ) -> io::Result<CreateResponse> {
        let msg_id = self.next_message_id();
        let mut hdr = Header::new(Command::Create, msg_id);
        hdr.session_id = self.session_id;
        hdr.tree_id = tree_id;

        let packet = build_request(&hdr, |buf| {
            encode_create_request(
                buf,
                path,
                desired_access,
                share_access,
                create_disposition,
                create_options,
            );
        });

        let (resp_hdr, resp_body) = self.send_recv(&packet).await?;
        let status = NtStatus::from_u32(resp_hdr.status);
        if status.is_error() {
            return Err(smb_status_to_io_error(resp_hdr.status, path));
        }

        decode_create_response(&resp_body).ok_or_else(|| {
            crate::serr!("[spiceio] smb invalid create response: {path}");
            io::Error::new(io::ErrorKind::InvalidData, "invalid create response")
        })
    }

    /// Close a file handle.
    pub async fn close(&self, tree_id: u32, file_id: &[u8; 16]) -> io::Result<()> {
        let msg_id = self.next_message_id();
        let mut hdr = Header::new(Command::Close, msg_id);
        hdr.session_id = self.session_id;
        hdr.tree_id = tree_id;

        let packet = build_request(&hdr, |buf| {
            encode_close_request(buf, file_id);
        });

        let (resp_hdr, _) = self.send_recv(&packet).await?;
        let status = NtStatus::from_u32(resp_hdr.status);
        if status.is_error() {
            crate::serr!("[spiceio] smb close failed: 0x{:08X}", resp_hdr.status);
            return Err(io::Error::other(format!(
                "close failed: 0x{:08X}",
                resp_hdr.status
            )));
        }
        Ok(())
    }

    /// Read from an open file.
    pub async fn read(
        &self,
        tree_id: u32,
        file_id: &[u8; 16],
        offset: u64,
        length: u32,
    ) -> io::Result<bytes::Bytes> {
        // Multi-credit commands (payload > 64 KiB) consume `credit_charge`
        // sequence numbers, so advance the MessageId window by the charge.
        let msg_id = self
            .message_id
            .fetch_add(credit_charge_for(length) as u64, Ordering::Relaxed);
        let mut hdr = Header::new(Command::Read, msg_id).with_credit_charge(length);
        hdr.session_id = self.session_id;
        hdr.tree_id = tree_id;

        let packet = build_request(&hdr, |buf| {
            encode_read_request(buf, file_id, offset, length);
        });

        let (resp_hdr, resp_body) = self.send_recv(&packet).await?;
        let status = NtStatus::from_u32(resp_hdr.status);
        if status == NtStatus::EndOfFile {
            return Ok(bytes::Bytes::new());
        }
        if status.is_error() {
            crate::serr!("[spiceio] smb read failed: 0x{:08X}", resp_hdr.status);
            return Err(io::Error::other(format!(
                "read failed: 0x{:08X}",
                resp_hdr.status
            )));
        }

        decode_read_response_owned(resp_body).ok_or_else(|| {
            crate::serr!("[spiceio] smb invalid read response");
            io::Error::new(io::ErrorKind::InvalidData, "invalid read response")
        })
    }

    /// Pipelined read: send `count` read requests, then receive all responses.
    ///
    /// Holds the stream lock for the entire batch, eliminating per-request
    /// round-trip latency. Returns chunks in offset order. Stops early on EOF.
    ///
    /// Coalesces all request packets into a single contiguous buffer and signs
    /// each in-place — one allocation, one `write_all` syscall for the whole
    /// batch of request headers (only the responses carry bulk data).
    ///
    /// Responses may arrive out of order (SMB2 does not guarantee response
    /// ordering). Each response is matched to its request slot via message_id.
    pub async fn pipelined_read(
        &self,
        tree_id: u32,
        file_id: &[u8; 16],
        start_offset: u64,
        chunk_size: u32,
        count: usize,
    ) -> io::Result<Vec<bytes::Bytes>> {
        // Poison on any error: a batch leaves unread responses in the socket on
        // an early return, so the connection must not be reused.
        let r = self
            .pipelined_read_io(tree_id, file_id, start_offset, chunk_size, count)
            .await;
        if r.is_err() {
            self.poison().await;
        }
        r
    }

    async fn pipelined_read_io(
        &self,
        tree_id: u32,
        file_id: &[u8; 16],
        start_offset: u64,
        chunk_size: u32,
        count: usize,
    ) -> io::Result<Vec<bytes::Bytes>> {
        if count == 0 {
            return Ok(Vec::new());
        }
        // Defensive guard: a zero `chunk_size` would panic later on
        // `remaining.div_ceil(chunk_size as u64)` in callers, and would
        // make this function issue `count` duplicate reads at the same
        // offset. Callers are expected to have validated already, but
        // we treat this as a hard error rather than UB.
        if chunk_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pipelined_read called with chunk_size = 0",
            ));
        }

        // Multi-credit reads consume `credit_charge` sequence numbers each, so
        // the MessageId window advances by count * charge and requests are
        // spaced by `charge`. A response maps to its slot via that stride.
        let charge = credit_charge_for(chunk_size) as u64;
        let base_msg_id = self
            .message_id
            .fetch_add(count as u64 * charge, Ordering::Relaxed);

        // Each request: 4 (NetBIOS length) + SMB2_HEADER_SIZE (64) + 49
        // (read request fixed part incl. 1-byte buffer pad).
        const READ_REQUEST_FIXED: usize = 49;
        let per_packet = 4 + SMB2_HEADER_SIZE + READ_REQUEST_FIXED;
        let mut buf = BytesMut::with_capacity(per_packet * count);
        let mut packet_starts: Vec<usize> = Vec::with_capacity(count + 1);

        for i in 0..count {
            packet_starts.push(buf.len());
            let offset = start_offset + (i as u64) * (chunk_size as u64);
            let msg_id = base_msg_id + i as u64 * charge;
            let mut hdr = Header::new(Command::Read, msg_id).with_credit_charge(chunk_size);
            hdr.session_id = self.session_id;
            hdr.tree_id = tree_id;

            let packet_smb_total = SMB2_HEADER_SIZE + READ_REQUEST_FIXED;
            buf.put_u32((packet_smb_total as u32) & 0x00FF_FFFF);
            hdr.encode(&mut buf);
            encode_read_request(&mut buf, file_id, offset, chunk_size);
        }
        packet_starts.push(buf.len());

        if let Some(ref key) = self.signing_key {
            for i in 0..count {
                let start = packet_starts[i];
                let end = packet_starts[i + 1];
                sign_packet(&mut buf[start..end], key);
            }
        }

        let mut stream = self.stream.lock().await;
        self.write_all_timeout(&mut stream, &buf).await?;
        stream.flush().await?;

        // Receive responses into ordered slots (handles out-of-order delivery).
        let mut slots: Vec<Option<bytes::Bytes>> = (0..count).map(|_| None).collect();
        let mut received = 0usize;
        let mut eof_after = count; // trim to this length on EOF

        while received < count {
            let mut len_buf = [0u8; 4];
            self.read_exact_timeout(&mut stream, &mut len_buf).await?;
            let msg_len = u32::from_be_bytes(len_buf) as usize;

            if !(SMB2_HEADER_SIZE..=16 * 1024 * 1024).contains(&msg_len) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid SMB2 message length: {msg_len}"),
                ));
            }

            let mut msg = vec![0u8; msg_len];
            self.read_exact_timeout(&mut stream, &mut msg).await?;

            let header = Header::decode(&msg)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid SMB2 header"))?;

            // Skip STATUS_PENDING interim responses
            if header.status == 0x0000_0103 {
                continue;
            }

            let delta = header.message_id.wrapping_sub(base_msg_id);
            if delta % charge != 0 || (delta / charge) as usize >= count {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "unexpected message_id {} (base={}, count={}, charge={})",
                        header.message_id, base_msg_id, count, charge
                    ),
                ));
            }
            let slot = (delta / charge) as usize;

            let status = NtStatus::from_u32(header.status);
            if status == NtStatus::EndOfFile {
                // This slot and all later slots are past EOF
                eof_after = eof_after.min(slot);
                received += 1;
                continue;
            }
            if status.is_error() {
                return Err(io::Error::other(format!(
                    "pipelined read failed: 0x{:08X}",
                    header.status
                )));
            }

            // Zero-copy: hand the full `msg` Vec to the decoder, which slices
            // into it as `Bytes` without an extra body copy. For 64KB chunks
            // pipelined 64 deep this saves ~4 MiB of memcpy per batch.
            let data = decode_read_response_from_msg(msg).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid read response")
            })?;
            slots[slot] = Some(data);
            received += 1;
        }

        // Collect in order, stopping at EOF boundary
        Ok(slots
            .into_iter()
            .take(eof_after)
            .map(|s| s.unwrap_or_default())
            .collect())
    }

    /// Write to an open file.
    pub async fn write(
        &self,
        tree_id: u32,
        file_id: &[u8; 16],
        offset: u64,
        data: &[u8],
    ) -> io::Result<u32> {
        // Multi-credit commands consume `credit_charge` sequence numbers.
        let msg_id = self.message_id.fetch_add(
            credit_charge_for(data.len() as u32) as u64,
            Ordering::Relaxed,
        );
        let mut hdr = Header::new(Command::Write, msg_id).with_credit_charge(data.len() as u32);
        hdr.session_id = self.session_id;
        hdr.tree_id = tree_id;

        let packet = build_request(&hdr, |buf| {
            encode_write_request(buf, file_id, offset, data);
        });

        let (resp_hdr, resp_body) = self.send_recv(&packet).await?;
        // Check raw status: high two bits indicate severity
        // 0x00 = success, 0x40 = info, 0x80 = warning, 0xC0 = error
        if resp_hdr.status & 0xC000_0000 == 0xC000_0000 {
            crate::serr!(
                "[spiceio] smb write failed: 0x{:08X} offset={} len={}",
                resp_hdr.status,
                offset,
                data.len()
            );
            return Err(io::Error::other(format!(
                "write failed: status=0x{:08X} offset={} len={}",
                resp_hdr.status,
                offset,
                data.len()
            )));
        }

        decode_write_response(&resp_body).ok_or_else(|| {
            crate::serr!("[spiceio] smb invalid write response");
            io::Error::new(io::ErrorKind::InvalidData, "invalid write response")
        })
    }

    /// Pipelined write: send `chunks` write requests in a batch, then receive
    /// all responses. Holds the stream lock for the entire batch, eliminating
    /// per-request round-trip latency. Returns total bytes written.
    ///
    /// Coalesces all packets into a single contiguous buffer and signs each
    /// in-place — one allocation, one `write_all` syscall for the whole batch.
    /// Responses may arrive out of order; each is matched by message_id.
    pub async fn pipelined_write(
        &self,
        tree_id: u32,
        file_id: &[u8; 16],
        start_offset: u64,
        chunks: &[&[u8]],
    ) -> io::Result<u64> {
        // Poison on any error: an early return leaves unread write responses in
        // the socket, so the connection must not be reused.
        let r = self
            .pipelined_write_io(tree_id, file_id, start_offset, chunks)
            .await;
        if r.is_err() {
            self.poison().await;
        }
        r
    }

    async fn pipelined_write_io(
        &self,
        tree_id: u32,
        file_id: &[u8; 16],
        start_offset: u64,
        chunks: &[&[u8]],
    ) -> io::Result<u64> {
        if chunks.is_empty() {
            return Ok(0);
        }

        let n = chunks.len();
        // Multi-credit writes consume `credit_charge` sequence numbers each;
        // advance the window by the total charge and space each request by its
        // own charge (chunks may differ in size, e.g. a short final chunk).
        let total_charge: u64 = chunks
            .iter()
            .map(|c| credit_charge_for(c.len() as u32) as u64)
            .sum();
        let base_msg_id = self.message_id.fetch_add(total_charge, Ordering::Relaxed);

        // Each packet: 4 (NetBIOS length) + SMB2_HEADER_SIZE (64) + 48
        // (write request fixed part) + chunk data.
        const WRITE_REQUEST_FIXED: usize = 48;
        let total_bytes: usize = chunks
            .iter()
            .map(|c| 4 + SMB2_HEADER_SIZE + WRITE_REQUEST_FIXED + c.len())
            .sum();
        let mut buf = BytesMut::with_capacity(total_bytes);
        let mut packet_starts: Vec<usize> = Vec::with_capacity(n + 1);

        let mut offset = start_offset;
        let mut cum_charge = 0u64;
        for chunk in chunks.iter() {
            packet_starts.push(buf.len());
            let msg_id = base_msg_id + cum_charge;
            cum_charge += credit_charge_for(chunk.len() as u32) as u64;
            let mut hdr =
                Header::new(Command::Write, msg_id).with_credit_charge(chunk.len() as u32);
            hdr.session_id = self.session_id;
            hdr.tree_id = tree_id;

            let packet_smb_total = SMB2_HEADER_SIZE + WRITE_REQUEST_FIXED + chunk.len();
            buf.put_u32((packet_smb_total as u32) & 0x00FF_FFFF);
            hdr.encode(&mut buf);
            encode_write_request(&mut buf, file_id, offset, chunk);
            offset += chunk.len() as u64;
        }
        packet_starts.push(buf.len());

        // Sign each packet in-place. We pre-allocated exact capacity, so the
        // earlier slices are still valid (no realloc could have moved them).
        if let Some(ref key) = self.signing_key {
            for i in 0..n {
                let start = packet_starts[i];
                let end = packet_starts[i + 1];
                sign_packet(&mut buf[start..end], key);
            }
        }

        let mut stream = self.stream.lock().await;
        self.write_all_timeout(&mut stream, &buf).await?;
        stream.flush().await?;

        // Receive all responses (handles out-of-order delivery)
        let mut total_written = 0u64;
        let mut received = 0usize;
        while received < n {
            let mut len_buf = [0u8; 4];
            self.read_exact_timeout(&mut stream, &mut len_buf).await?;
            let msg_len = u32::from_be_bytes(len_buf) as usize;

            if !(SMB2_HEADER_SIZE..=16 * 1024 * 1024).contains(&msg_len) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid SMB2 message length: {msg_len}"),
                ));
            }

            let mut msg = vec![0u8; msg_len];
            self.read_exact_timeout(&mut stream, &mut msg).await?;

            let header = Header::decode(&msg)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid SMB2 header"))?;

            if header.status == 0x0000_0103 {
                continue;
            }

            if header.status & 0xC000_0000 == 0xC000_0000 {
                return Err(io::Error::other(format!(
                    "pipelined write failed: 0x{:08X}",
                    header.status
                )));
            }

            let body = &msg[SMB2_HEADER_SIZE..];
            let written = decode_write_response(body).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid write response")
            })?;
            total_written += written as u64;
            received += 1;
        }

        Ok(total_written)
    }

    /// Rename a file using SET_INFO with FileRenameInformation.
    pub async fn rename(
        &self,
        tree_id: u32,
        file_id: &[u8; 16],
        new_path: &str,
        replace_if_exists: bool,
    ) -> io::Result<()> {
        let msg_id = self.next_message_id();
        let mut hdr = Header::new(Command::SetInfo, msg_id);
        hdr.session_id = self.session_id;
        hdr.tree_id = tree_id;

        let packet = build_request(&hdr, |buf| {
            encode_set_info_rename(buf, file_id, new_path, replace_if_exists);
        });

        let (resp_hdr, _) = self.send_recv(&packet).await?;
        if resp_hdr.status & 0xC000_0000 == 0xC000_0000 {
            crate::serr!(
                "[spiceio] smb rename failed: 0x{:08X} -> {}",
                resp_hdr.status,
                new_path
            );
            return Err(io::Error::other(format!(
                "rename failed: status=0x{:08X} -> {}",
                resp_hdr.status, new_path
            )));
        }
        Ok(())
    }

    /// List directory contents.
    pub async fn query_directory(
        &self,
        tree_id: u32,
        file_id: &[u8; 16],
        pattern: &str,
    ) -> io::Result<Vec<DirectoryEntry>> {
        let mut all_entries = Vec::new();
        let mut first = true;

        loop {
            let msg_id = self.next_message_id();
            let mut hdr = Header::new(Command::QueryDirectory, msg_id);
            hdr.session_id = self.session_id;
            hdr.tree_id = tree_id;

            let restart = first;
            first = false;

            let packet = build_request(&hdr, |buf| {
                encode_query_directory_request(
                    buf,
                    file_id,
                    pattern,
                    FILE_ID_BOTH_DIRECTORY_INFORMATION,
                    restart,
                );
            });

            let (resp_hdr, resp_body) = self.send_recv(&packet).await?;
            let status = NtStatus::from_u32(resp_hdr.status);

            if status == NtStatus::NoMoreFiles {
                break;
            }
            if status.is_error() {
                crate::serr!(
                    "[spiceio] smb query directory failed: 0x{:08X}",
                    resp_hdr.status
                );
                return Err(io::Error::other(format!(
                    "query directory failed: 0x{:08X}",
                    resp_hdr.status
                )));
            }

            // Parse the output buffer from the response body
            if resp_body.len() >= 9 {
                let buf_offset = (&resp_body[2..4] as &[u8]).get_u16_le() as usize;
                let buf_length = (&resp_body[4..8] as &[u8]).get_u32_le() as usize;
                let start = buf_offset.saturating_sub(SMB2_HEADER_SIZE);
                let end = (start + buf_length).min(resp_body.len());
                if start < end {
                    let entries = parse_directory_entries(&resp_body[start..end]);
                    all_entries.extend(entries);
                }
            }
        }

        Ok(all_entries)
    }

    // ── Compound operations (multiple SMB ops in one round trip) ────────

    /// Send a compound request and parse the compound response.
    ///
    /// Caller sets `SMB2_FLAGS_RELATED` on related-chain requests.
    /// This method handles `NextCommand` offsets, signing, and framing.
    async fn send_compound(
        &self,
        requests: Vec<(Header, BytesMut)>,
    ) -> io::Result<Vec<(Header, Vec<u8>)>> {
        // Poison on any transport/framing error so a desynchronized compound
        // stream is never reused.
        let r = self.send_compound_io(requests).await;
        if r.is_err() {
            self.poison().await;
        }
        r
    }

    async fn send_compound_io(
        &self,
        requests: Vec<(Header, BytesMut)>,
    ) -> io::Result<Vec<(Header, Vec<u8>)>> {
        let n = requests.len();

        // Padded message sizes (8-byte aligned except last).
        let sizes: Vec<usize> = requests
            .iter()
            .enumerate()
            .map(|(i, (_, body))| {
                let raw = SMB2_HEADER_SIZE + body.len();
                if i < n - 1 {
                    raw + (8 - raw % 8) % 8
                } else {
                    raw
                }
            })
            .collect();

        let total: usize = sizes.iter().sum();
        let mut buf = BytesMut::with_capacity(4 + total);
        buf.put_u32((total as u32) & 0x00FF_FFFF); // NetBIOS length (big-endian, masked to 24 bits)

        for (i, (mut header, body)) in requests.into_iter().enumerate() {
            let body_len = body.len();
            header.next_command = if i < n - 1 { sizes[i] as u32 } else { 0 };

            let msg_start = buf.len();
            header.encode(&mut buf);
            buf.put_slice(&body);

            // Pad to 8-byte alignment
            let pad = sizes[i] - SMB2_HEADER_SIZE - body_len;
            if pad > 0 {
                buf.extend_from_slice(&[0u8; 7][..pad]);
            }

            // Sign this message
            if let Some(ref key) = self.signing_key {
                sign_message(&mut buf[msg_start..msg_start + sizes[i]], key);
            }
        }

        // Send and receive under the stream lock
        let mut stream = self.stream.lock().await;
        self.write_all_timeout(&mut stream, &buf).await?;
        stream.flush().await?;

        // Read response frames, skipping STATUS_PENDING interim responses
        loop {
            let mut len_buf = [0u8; 4];
            self.read_exact_timeout(&mut stream, &mut len_buf).await?;
            let msg_len = u32::from_be_bytes(len_buf) as usize;

            if !(SMB2_HEADER_SIZE..=16 * 1024 * 1024).contains(&msg_len) {
                crate::serr!("[spiceio] smb invalid message length: {msg_len}");
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid SMB2 message length: {msg_len}"),
                ));
            }

            let mut msg = vec![0u8; msg_len];
            self.read_exact_timeout(&mut stream, &mut msg).await?;

            // Single STATUS_PENDING interim — skip
            if let Some(h) = Header::decode(&msg)
                && h.status == 0x0000_0103
                && h.next_command == 0
            {
                continue;
            }

            return Ok(parse_compound_response(&msg));
        }
    }

    /// Compound Create + Close (1 round trip). Returns create and close
    /// metadata. Used for head_object and delete_object.
    pub async fn create_close(
        &self,
        tree_id: u32,
        path: &str,
        desired_access: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
    ) -> io::Result<(CreateResponse, CloseResponse)> {
        let base = self.message_id.fetch_add(2, Ordering::Relaxed);

        let mut h1 = Header::new(Command::Create, base);
        h1.session_id = self.session_id;
        h1.tree_id = tree_id;
        let mut b1 = BytesMut::with_capacity(128);
        encode_create_request(
            &mut b1,
            path,
            desired_access,
            share_access,
            create_disposition,
            create_options,
        );

        let mut h2 = Header::new(Command::Close, base + 1);
        h2.session_id = self.session_id;
        h2.tree_id = tree_id;
        h2.flags |= SMB2_FLAGS_RELATED;
        let mut b2 = BytesMut::with_capacity(32);
        encode_close_request_ex(&mut b2, &SENTINEL_FILE_ID, true);

        let resp = self.send_compound(vec![(h1, b1), (h2, b2)]).await?;
        if resp.len() < 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "compound response too short",
            ));
        }

        if NtStatus::from_u32(resp[0].0.status).is_error() {
            return Err(smb_status_to_io_error(resp[0].0.status, path));
        }
        let cr = decode_create_response(&resp[0].1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid create response"))?;
        if NtStatus::from_u32(resp[1].0.status).is_error() {
            crate::serr!(
                "[spiceio] smb compound close failed: 0x{:08X}",
                resp[1].0.status
            );
        }
        let cl = decode_close_response(&resp[1].1).unwrap_or(CloseResponse {
            last_write_time: cr.last_write_time,
            file_size: cr.file_size,
        });

        Ok((cr, cl))
    }

    /// Compound Create + Read + Close (1 round trip). For small-file reads.
    pub async fn create_read_close(
        &self,
        tree_id: u32,
        path: &str,
        max_read: u32,
    ) -> io::Result<(CreateResponse, bytes::Bytes)> {
        let base = self.message_id.fetch_add(3, Ordering::Relaxed);

        let mut h1 = Header::new(Command::Create, base);
        h1.session_id = self.session_id;
        h1.tree_id = tree_id;
        let mut b1 = BytesMut::with_capacity(128);
        encode_create_request(
            &mut b1,
            path,
            DesiredAccess::GenericRead as u32,
            ShareAccess::All as u32,
            CreateDisposition::Open as u32,
            CreateOptions::NonDirectoryFile as u32,
        );

        let mut h2 = Header::new(Command::Read, base + 1).with_credit_charge(max_read);
        h2.session_id = self.session_id;
        h2.tree_id = tree_id;
        h2.flags |= SMB2_FLAGS_RELATED;
        let mut b2 = BytesMut::with_capacity(64);
        encode_read_request(&mut b2, &SENTINEL_FILE_ID, 0, max_read);

        let mut h3 = Header::new(Command::Close, base + 2);
        h3.session_id = self.session_id;
        h3.tree_id = tree_id;
        h3.flags |= SMB2_FLAGS_RELATED;
        let mut b3 = BytesMut::with_capacity(32);
        encode_close_request(&mut b3, &SENTINEL_FILE_ID);

        let resp = self
            .send_compound(vec![(h1, b1), (h2, b2), (h3, b3)])
            .await?;
        if resp.len() < 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "compound response too short",
            ));
        }

        if NtStatus::from_u32(resp[0].0.status).is_error() {
            return Err(smb_status_to_io_error(resp[0].0.status, path));
        }
        let cr = decode_create_response(&resp[0].1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid create response"))?;

        let data = if NtStatus::from_u32(resp[1].0.status) == NtStatus::EndOfFile {
            bytes::Bytes::new()
        } else if NtStatus::from_u32(resp[1].0.status).is_error() {
            return Err(io::Error::other(format!(
                "read failed: 0x{:08X}",
                resp[1].0.status
            )));
        } else {
            decode_read_response(&resp[1].1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid read response")
            })?
        };

        Ok((cr, data))
    }

    /// Compound Create + Write + Close (1 round trip). For small-file writes.
    /// Returns the Close response with post-query metadata.
    pub async fn create_write_close(
        &self,
        tree_id: u32,
        path: &str,
        data: &[u8],
    ) -> io::Result<CloseResponse> {
        let base = self.message_id.fetch_add(3, Ordering::Relaxed);

        let mut h1 = Header::new(Command::Create, base);
        h1.session_id = self.session_id;
        h1.tree_id = tree_id;
        let mut b1 = BytesMut::with_capacity(128);
        encode_create_request(
            &mut b1,
            path,
            DesiredAccess::GenericWrite as u32,
            ShareAccess::Read as u32,
            CreateDisposition::OverwriteIf as u32,
            CreateOptions::NonDirectoryFile as u32,
        );

        let mut h2 = Header::new(Command::Write, base + 1).with_credit_charge(data.len() as u32);
        h2.session_id = self.session_id;
        h2.tree_id = tree_id;
        h2.flags |= SMB2_FLAGS_RELATED;
        let mut b2 = BytesMut::with_capacity(64 + data.len());
        encode_write_request(&mut b2, &SENTINEL_FILE_ID, 0, data);

        let mut h3 = Header::new(Command::Close, base + 2);
        h3.session_id = self.session_id;
        h3.tree_id = tree_id;
        h3.flags |= SMB2_FLAGS_RELATED;
        let mut b3 = BytesMut::with_capacity(32);
        encode_close_request_ex(&mut b3, &SENTINEL_FILE_ID, true);

        let resp = self
            .send_compound(vec![(h1, b1), (h2, b2), (h3, b3)])
            .await?;
        if resp.len() < 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "compound response too short",
            ));
        }

        if NtStatus::from_u32(resp[0].0.status).is_error() {
            return Err(smb_status_to_io_error(resp[0].0.status, path));
        }
        if resp[1].0.status & 0xC000_0000 == 0xC000_0000 {
            return Err(io::Error::other(format!(
                "write failed: 0x{:08X}",
                resp[1].0.status
            )));
        }

        Ok(decode_close_response(&resp[2].1).unwrap_or(CloseResponse {
            last_write_time: 0,
            file_size: data.len() as u64,
        }))
    }

    /// Compound batch of Create+Close pairs for directory creation (1 round trip).
    /// Each pair forms a related chain; different pairs are unrelated.
    pub async fn ensure_dirs(&self, tree_id: u32, dirs: &[String]) -> io::Result<()> {
        if dirs.is_empty() {
            return Ok(());
        }

        let count = dirs.len() * 2;
        let base = self.message_id.fetch_add(count as u64, Ordering::Relaxed);
        let mut requests = Vec::with_capacity(count);

        for (i, dir) in dirs.iter().enumerate() {
            // Create (unrelated — starts new chain)
            let mut h1 = Header::new(Command::Create, base + (i as u64) * 2);
            h1.session_id = self.session_id;
            h1.tree_id = tree_id;
            let mut b1 = BytesMut::with_capacity(128);
            encode_create_request(
                &mut b1,
                dir,
                DesiredAccess::ReadAttributes as u32,
                ShareAccess::All as u32,
                CreateDisposition::OpenIf as u32,
                CreateOptions::DirectoryFile as u32,
            );
            requests.push((h1, b1));

            // Close (related — sentinel file ID from preceding Create)
            let mut h2 = Header::new(Command::Close, base + (i as u64) * 2 + 1);
            h2.session_id = self.session_id;
            h2.tree_id = tree_id;
            h2.flags |= SMB2_FLAGS_RELATED;
            let mut b2 = BytesMut::with_capacity(32);
            encode_close_request(&mut b2, &SENTINEL_FILE_ID);
            requests.push((h2, b2));
        }

        let responses = self.send_compound(requests).await?;

        // Check Create responses (every other response)
        for i in (0..responses.len()).step_by(2) {
            let status = NtStatus::from_u32(responses[i].0.status);
            if status.is_error() {
                return Err(smb_status_to_io_error(responses[i].0.status, &dirs[i / 2]));
            }
        }

        Ok(())
    }
}

/// Effective per-connection I/O sizes derived from the SMB negotiate
/// response, with any zero fields substituted by the configured `io_cap`.
///
/// Returning a struct (rather than a tuple) makes the relationship between
/// `max_read`/`compound_max_read` self-documenting.
pub(crate) struct EffectiveIoSizes {
    pub max_read: u32,
    pub max_write: u32,
    pub compound_max_read: u32,
    pub compound_max_write: u32,
}

/// Compute the effective I/O sizes for a session given the server's
/// negotiate response and our configured cap. Any zero negotiated field
/// is substituted with `io_cap` (and `on_zero` is invoked so the caller
/// can log it). The result is then capped to `min(value, transact, io_cap)`
/// for standalone I/O and further to 64 KiB for compound operations.
///
/// Extracted as a free function so its zero-handling is unit-testable
/// without needing a real SMB connection.
pub(crate) fn effective_io_sizes(
    neg_max_read: u32,
    neg_max_write: u32,
    neg_max_transact: u32,
    io_cap: u32,
    mut on_zero: impl FnMut(&'static str, u32),
) -> EffectiveIoSizes {
    let nonzero = |name: &'static str, v: u32, on_zero: &mut dyn FnMut(&'static str, u32)| {
        if v == 0 {
            on_zero(name, v);
            io_cap
        } else {
            v
        }
    };
    let read = nonzero("max_read_size", neg_max_read, &mut on_zero);
    let write = nonzero("max_write_size", neg_max_write, &mut on_zero);
    let transact = nonzero("max_transact_size", neg_max_transact, &mut on_zero);
    // Cap standalone I/O by: min(server_advertised, max_transact, configured_cap).
    // Many NAS servers advertise multi-MB limits but fail at much smaller sizes.
    let max_read = read.min(transact).min(io_cap);
    let max_write = write.min(transact).min(io_cap);
    // Cap at 64KB for compound requests — some NAS servers reject larger
    // payloads inside compound (chained) operations.
    EffectiveIoSizes {
        max_read,
        max_write,
        compound_max_read: max_read.min(65536),
        compound_max_write: max_write.min(65536),
    }
}

/// Sign an SMB2 packet in-place. `packet` includes the 4-byte NetBIOS header.
/// Sets the SMB2_FLAGS_SIGNED bit and computes AES-128-CMAC over the SMB2 message.
fn sign_packet(packet: &mut [u8], key: &[u8; 16]) {
    use crate::crypto;

    const NETBIOS_HEADER: usize = 4;
    const FLAGS_OFFSET: usize = NETBIOS_HEADER + 16; // Flags field at header offset 16
    const SIGNATURE_OFFSET: usize = NETBIOS_HEADER + 48; // Signature at header offset 48

    // Set SMB2_FLAGS_SIGNED (0x00000008)
    let flags = u32::from_le_bytes(packet[FLAGS_OFFSET..FLAGS_OFFSET + 4].try_into().unwrap());
    packet[FLAGS_OFFSET..FLAGS_OFFSET + 4].copy_from_slice(&(flags | 0x0000_0008).to_le_bytes());

    // Zero the signature field
    packet[SIGNATURE_OFFSET..SIGNATURE_OFFSET + 16].fill(0);

    // Compute AES-128-CMAC over the SMB2 message (skip NetBIOS header)
    let smb2_msg = &packet[NETBIOS_HEADER..];
    let signature = crypto::aes128_cmac(key, smb2_msg);

    // Write the signature
    packet[SIGNATURE_OFFSET..SIGNATURE_OFFSET + 16].copy_from_slice(&signature);
}

/// Update preauth integrity hash: hash = SHA-512(hash || message_bytes).
fn update_preauth_hash(hash: &mut [u8; 64], message: &[u8]) {
    use crate::crypto;
    let mut input = Vec::with_capacity(64 + message.len());
    input.extend_from_slice(hash);
    input.extend_from_slice(message);
    *hash = crypto::sha512(&input);
}

fn smb_status_to_io_error(status: u32, path: &str) -> io::Error {
    // Map raw status codes directly to avoid losing info through NtStatus enum.
    // We deliberately do NOT log for mapped statuses — many of these are
    // expected (NotFound on HEAD probes, SharingViolation during cleanup) and
    // the typed `io::ErrorKind` is enough for callers to handle them. Only the
    // fallback arm (truly unknown statuses) includes the raw hex code in the
    // error string and logs at error level.
    match status {
        0xC000_000F // STATUS_NO_SUCH_FILE
        | 0xC000_0034 // STATUS_OBJECT_NAME_NOT_FOUND
        | 0xC000_003A // STATUS_OBJECT_PATH_NOT_FOUND
        | 0xC000_0033 // STATUS_OBJECT_NAME_INVALID
        => io::Error::new(io::ErrorKind::NotFound, format!("not found: {path}")),

        0xC000_0022 => io::Error::new( // STATUS_ACCESS_DENIED
            io::ErrorKind::PermissionDenied,
            format!("access denied: {path}"),
        ),

        0xC000_0035 => io::Error::new( // STATUS_OBJECT_NAME_COLLISION
            io::ErrorKind::AlreadyExists,
            format!("already exists: {path}"),
        ),

        0xC000_0043 => io::Error::new( // STATUS_SHARING_VIOLATION
            io::ErrorKind::ResourceBusy,
            format!("sharing violation: {path}"),
        ),

        // Server capacity / limit statuses all map to retryable ResourceBusy.
        // Classified via `is_server_capacity_status` (the single source of truth
        // for these codes) so there is no third hand-maintained list here; the
        // NtStatus name in the message says which limit was hit.
        s if is_server_capacity_status(s) => io::Error::new(
            io::ErrorKind::ResourceBusy,
            format!("server at capacity ({:?}): {path}", NtStatus::from_u32(s)),
        ),

        _ => {
            crate::serr!("[spiceio] smb error 0x{status:08X}: {path}");
            io::Error::other(format!("SMB error 0x{status:08X} for {path}"))
        }
    }
}

/// True for NTSTATUS values that indicate the SMB server has hit a connection,
/// session, or resource limit and is refusing new sessions/connections.
/// These surface as ResourceBusy (mapped to 503 SlowDown by the S3 layer)
/// so clients retry, and the pool healer / connect backoff treat them as
/// transient.
pub(crate) fn is_server_capacity_status(status: u32) -> bool {
    matches!(
        NtStatus::from_u32(status),
        NtStatus::InsufficientResources
            | NtStatus::TooManySessions
            | NtStatus::RequestNotAccepted
            | NtStatus::SharingPaused
            | NtStatus::RemoteSessionLimit
    )
}

/// Returns whether the given error indicates the SMB server rejected a new
/// connection or session due to a capacity limit (too many sessions,
/// insufficient resources, request not accepted, etc.). Used by the pool to
/// shrink itself instead of failing or retrying the same limit forever.
///
/// At the connect / tree-connect layer the *only* source of `ResourceBusy` is a
/// server-capacity NTSTATUS — no file operations run there, so a sharing
/// violation (the other `ResourceBusy` producer) can't occur. The typed kind is
/// therefore a reliable single signal, so we don't re-parse the message text
/// (which would be a fourth copy of the capacity-code list to keep in sync).
/// `handshake_error` and `is_server_capacity_status` uphold the invariant:
/// capacity statuses map to `ResourceBusy`, everything else does not.
pub(crate) fn is_capacity_error(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::ResourceBusy
}

/// Build the `io::Error` for a failed SMB handshake step (negotiate, session
/// setup, tree connect). Server-capacity statuses become retryable
/// `ResourceBusy` and are logged quietly — they are expected back-pressure, not
/// bugs, and the pool shrinks / retries on them. `STATUS_ACCESS_DENIED` maps to
/// `PermissionDenied`; every other status uses `fallback`. Non-capacity errors
/// are logged at error level. `context` names the step for the log/message.
fn handshake_error(context: &str, status: u32, fallback: io::ErrorKind) -> io::Error {
    if is_server_capacity_status(status) {
        crate::slog!("[spiceio] smb {context} rejected by server capacity: 0x{status:08X}");
        return io::Error::new(
            io::ErrorKind::ResourceBusy,
            format!("{context} rejected by server capacity: status=0x{status:08X}"),
        );
    }
    crate::serr!("[spiceio] smb {context} failed: 0x{status:08X}");
    // STATUS_ACCESS_DENIED is an auth/ACL failure at any step — surface it as
    // PermissionDenied rather than the step's generic fallback (e.g. tree
    // connect's NotFound), so it is not misreported as a missing share.
    let kind = if NtStatus::from_u32(status) == NtStatus::AccessDenied {
        io::ErrorKind::PermissionDenied
    } else {
        fallback
    };
    io::Error::new(kind, format!("{context} failed: status=0x{status:08X}"))
}

/// Sign a single SMB2 message in-place (no NetBIOS header prefix).
/// Used for compound requests where each message is signed individually.
fn sign_message(msg: &mut [u8], key: &[u8; 16]) {
    use crate::crypto;
    const FLAGS_OFFSET: usize = 16;
    const SIGNATURE_OFFSET: usize = 48;

    let flags = u32::from_le_bytes(msg[FLAGS_OFFSET..FLAGS_OFFSET + 4].try_into().unwrap());
    msg[FLAGS_OFFSET..FLAGS_OFFSET + 4].copy_from_slice(&(flags | 0x0000_0008).to_le_bytes());

    msg[SIGNATURE_OFFSET..SIGNATURE_OFFSET + 16].fill(0);

    let signature = crypto::aes128_cmac(key, msg);
    msg[SIGNATURE_OFFSET..SIGNATURE_OFFSET + 16].copy_from_slice(&signature);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_kind_and_path(err: &io::Error, kind: io::ErrorKind, needle: &str) {
        assert_eq!(err.kind(), kind, "wrong kind for {err}");
        let s = err.to_string();
        assert!(s.contains(needle), "expected {needle:?} in {s:?}");
    }

    #[test]
    fn maps_no_such_file_to_not_found() {
        let e = smb_status_to_io_error(0xC000_000F, "a\\b");
        assert_kind_and_path(&e, io::ErrorKind::NotFound, "a\\b");
    }

    #[test]
    fn maps_object_name_not_found_to_not_found() {
        let e = smb_status_to_io_error(0xC000_0034, "missing.txt");
        assert_kind_and_path(&e, io::ErrorKind::NotFound, "missing.txt");
    }

    #[test]
    fn maps_object_path_not_found_to_not_found() {
        let e = smb_status_to_io_error(0xC000_003A, "dir\\file");
        assert_kind_and_path(&e, io::ErrorKind::NotFound, "dir\\file");
    }

    #[test]
    fn maps_object_name_invalid_to_not_found() {
        let e = smb_status_to_io_error(0xC000_0033, "bad?name");
        assert_kind_and_path(&e, io::ErrorKind::NotFound, "bad?name");
    }

    #[test]
    fn maps_access_denied_to_permission_denied() {
        let e = smb_status_to_io_error(0xC000_0022, "secret");
        assert_kind_and_path(&e, io::ErrorKind::PermissionDenied, "secret");
    }

    #[test]
    fn maps_name_collision_to_already_exists() {
        let e = smb_status_to_io_error(0xC000_0035, "dup");
        assert_kind_and_path(&e, io::ErrorKind::AlreadyExists, "dup");
    }

    #[test]
    fn maps_sharing_violation_to_resource_busy() {
        let e = smb_status_to_io_error(0xC000_0043, ".spiceio-wal\\01-0000");
        assert_kind_and_path(&e, io::ErrorKind::ResourceBusy, ".spiceio-wal\\01-0000");
    }

    #[test]
    fn maps_insufficient_resources_to_resource_busy() {
        let e = smb_status_to_io_error(0xC000009A, "conn");
        assert_kind_and_path(&e, io::ErrorKind::ResourceBusy, "InsufficientResources");
    }

    #[test]
    fn maps_too_many_sessions_to_resource_busy() {
        let e = smb_status_to_io_error(0xC00000CE, "srv");
        assert_kind_and_path(&e, io::ErrorKind::ResourceBusy, "TooManySessions");
    }

    #[test]
    fn maps_request_not_accepted_to_resource_busy() {
        let e = smb_status_to_io_error(0xC00000D0, "share");
        assert_kind_and_path(&e, io::ErrorKind::ResourceBusy, "RequestNotAccepted");
    }

    #[test]
    fn is_server_capacity_status_recognizes_common_limit_codes() {
        assert!(is_server_capacity_status(0xC000009A));
        assert!(is_server_capacity_status(0xC00000CE));
        assert!(is_server_capacity_status(0xC00000D0));
        assert!(is_server_capacity_status(0xC00000CF));
        assert!(is_server_capacity_status(0xC0000196));
        assert!(!is_server_capacity_status(0xC000000F)); // no such file
        assert!(!is_server_capacity_status(0));
    }

    #[test]
    fn handshake_error_classifies_capacity_as_retryable_resource_busy() {
        // A capacity rejection at any handshake step — including the first
        // session-setup leg — must be retryable ResourceBusy, not the fallback,
        // so the pool shrinks instead of hard-failing.
        let e = handshake_error("session setup", 0xC00000CE, io::ErrorKind::PermissionDenied);
        assert_eq!(e.kind(), io::ErrorKind::ResourceBusy);
        assert!(e.to_string().contains("0xC00000CE"), "expected hex in {e}");
    }

    #[test]
    fn handshake_error_uses_fallback_for_non_capacity() {
        // 0xC000000D (STATUS_INVALID_PARAMETER): not capacity, not access-denied.
        let e = handshake_error("negotiate", 0xC000000D, io::ErrorKind::ConnectionRefused);
        assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused);
        assert!(e.to_string().contains("0xC000000D"), "expected hex in {e}");
    }

    #[test]
    fn handshake_error_maps_access_denied_to_permission_denied() {
        // tree_connect's fallback is NotFound, but ACCESS_DENIED must surface as
        // PermissionDenied — not a misleading "share not found".
        let e = handshake_error(
            "tree connect to 'share'",
            0xC0000022,
            io::ErrorKind::NotFound,
        );
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert!(e.to_string().contains("0xC0000022"), "expected hex in {e}");
    }

    #[test]
    fn is_capacity_error_true_only_for_resource_busy() {
        // The pool relies on this to decide whether to shrink. Capacity statuses
        // map to ResourceBusy (via handshake_error / smb_status_to_io_error);
        // auth / not-found / refused / timeout must NOT trigger a shrink.
        assert!(is_capacity_error(&handshake_error(
            "session setup",
            0xC00000D0,
            io::ErrorKind::PermissionDenied,
        )));
        assert!(is_capacity_error(&smb_status_to_io_error(0xC000009A, "x")));
        assert!(!is_capacity_error(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            "auth failed",
        )));
        assert!(!is_capacity_error(&io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "refused",
        )));
        assert!(!is_capacity_error(&io::Error::from(
            io::ErrorKind::TimedOut
        )));
    }

    #[test]
    fn unknown_status_falls_back_to_other_and_includes_hex() {
        let e = smb_status_to_io_error(0xC000_00BB, "x");
        assert_eq!(e.kind(), io::ErrorKind::Other);
        let s = e.to_string();
        assert!(s.contains("0xC00000BB"), "expected hex in: {s}");
        assert!(s.contains("x"), "expected path in: {s}");
    }

    #[test]
    fn success_status_zero_falls_through_to_other() {
        // STATUS_SUCCESS is not really an error, but the mapper must never panic.
        let e = smb_status_to_io_error(0x0000_0000, "ok");
        assert_eq!(e.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn error_path_is_preserved_verbatim() {
        // Path containing backslashes, dots, and the WAL prefix must round-trip.
        let path = ".spiceio-wal\\01778725545751751000-0000";
        let e = smb_status_to_io_error(0xC000_0043, path);
        assert!(e.to_string().contains(path));
    }

    // ── effective_io_sizes ──────────────────────────────────────────────────

    fn no_op_logger() -> impl FnMut(&'static str, u32) {
        |_name, _value| {}
    }

    #[test]
    fn effective_io_sizes_typical_negotiate() {
        // Server advertises 1 MiB, transact 1 MiB; configured cap 64 KiB
        // (the default). Result: 64 KiB everywhere, compound also 64 KiB.
        let s = effective_io_sizes(1_048_576, 1_048_576, 1_048_576, 65536, no_op_logger());
        assert_eq!(s.max_read, 65536);
        assert_eq!(s.max_write, 65536);
        assert_eq!(s.compound_max_read, 65536);
        assert_eq!(s.compound_max_write, 65536);
    }

    #[test]
    fn effective_io_sizes_compound_cap_at_64k_when_max_higher() {
        // io_cap raised to 1 MiB so the standalone path opens up; compound
        // must still cap at 64 KiB.
        let s = effective_io_sizes(1_048_576, 1_048_576, 1_048_576, 1_048_576, no_op_logger());
        assert_eq!(s.max_read, 1_048_576);
        assert_eq!(s.max_write, 1_048_576);
        assert_eq!(s.compound_max_read, 65536);
        assert_eq!(s.compound_max_write, 65536);
    }

    #[test]
    fn effective_io_sizes_floors_zero_max_read() {
        // The core regression test: a server returning max_read_size = 0
        // must not propagate as a 0 chunk size to callers.
        let mut zero_calls: Vec<&'static str> = Vec::new();
        let s = effective_io_sizes(0, 1_048_576, 1_048_576, 65536, |name, _v| {
            zero_calls.push(name);
        });
        assert_eq!(s.max_read, 65536);
        assert_eq!(s.max_write, 65536);
        assert_eq!(zero_calls, vec!["max_read_size"]);
    }

    #[test]
    fn effective_io_sizes_floors_zero_max_write() {
        let mut zero_calls: Vec<&'static str> = Vec::new();
        let s = effective_io_sizes(1_048_576, 0, 1_048_576, 65536, |name, _v| {
            zero_calls.push(name);
        });
        assert_eq!(s.max_read, 65536);
        assert_eq!(s.max_write, 65536);
        assert_eq!(zero_calls, vec!["max_write_size"]);
    }

    #[test]
    fn effective_io_sizes_floors_zero_transact() {
        let mut zero_calls: Vec<&'static str> = Vec::new();
        let s = effective_io_sizes(1_048_576, 1_048_576, 0, 65536, |name, _v| {
            zero_calls.push(name);
        });
        assert_eq!(s.max_read, 65536);
        assert_eq!(s.max_write, 65536);
        assert_eq!(zero_calls, vec!["max_transact_size"]);
    }

    #[test]
    fn effective_io_sizes_floors_all_zeros() {
        // All three zero — every callback fires, and we end up at io_cap.
        let mut zero_calls: Vec<&'static str> = Vec::new();
        let s = effective_io_sizes(0, 0, 0, 65536, |name, _v| zero_calls.push(name));
        assert_eq!(s.max_read, 65536);
        assert_eq!(s.max_write, 65536);
        assert_eq!(s.compound_max_read, 65536);
        assert_eq!(s.compound_max_write, 65536);
        assert_eq!(
            zero_calls,
            vec!["max_read_size", "max_write_size", "max_transact_size"]
        );
    }

    #[test]
    fn effective_io_sizes_transact_clamps_read_and_write() {
        // Server advertises 1 MiB read/write but only 64 KiB transact —
        // the smaller transact dominates the min().
        let s = effective_io_sizes(1_048_576, 1_048_576, 65536, 1_048_576, no_op_logger());
        assert_eq!(s.max_read, 65536);
        assert_eq!(s.max_write, 65536);
    }
}
