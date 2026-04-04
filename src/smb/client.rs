//! SMB2 client — manages TCP connections and speaks the protocol.

use bytes::Buf;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use bytes::{BufMut, BytesMut};

/// Timeout for a single SMB response read. Prevents indefinite mutex hold when
/// the SMB server is slow or unresponsive under heavy load.
const SMB_READ_TIMEOUT: Duration = Duration::from_secs(30);

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
/// Many NAS servers advertise multi-MB maximums in negotiate but fail at sizes
/// well below the advertised limit. 64 KB is the safe conservative default;
/// override via `SPICEIO_SMB_MAX_IO` for servers that handle larger I/O
/// (e.g., Windows Server, enterprise NAS). Even at 64 KB the connection pool
/// and pipelined reads still deliver major throughput gains.
const DEFAULT_MAX_IO: u32 = 65536;

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
}

impl SmbClient {
    /// Connect to the SMB server and authenticate.
    pub async fn connect(config: SmbConfig) -> io::Result<Arc<Self>> {
        let addr = format!("{}:{}", config.server, config.port);
        let stream = match TcpStream::connect(&addr).await {
            Ok(s) => {
                crate::slog!("[spiceio] smb tcp connected: {addr}");
                s
            }
            Err(e) => {
                crate::serr!("[spiceio] smb tcp connect failed: {addr}: {e}");
                return Err(e);
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
        };

        client.negotiate_and_auth().await?;
        Ok(Arc::new(client))
    }

    fn next_message_id(&self) -> u64 {
        self.message_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Read exactly `buf.len()` bytes from the stream with a timeout.
    /// Returns `TimedOut` if the SMB server doesn't respond within the deadline.
    ///
    /// A timeout may leave the stream mid-frame, so we shut it down to prevent
    /// desynchronized reuse.
    async fn read_exact_timeout(
        stream: &mut TcpStream,
        buf: &mut [u8],
    ) -> io::Result<()> {
        match tokio::time::timeout(SMB_READ_TIMEOUT, stream.read_exact(buf)).await {
            Ok(result) => result.map(|_| ()),
            Err(_) => {
                let _ = stream.shutdown().await;
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "SMB server read timed out; connection closed",
                ))
            }
        }
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
        let mut stream = self.stream.lock().await;

        // Sign the packet if we have a signing key
        if let Some(ref key) = self.signing_key {
            let mut signed = packet.to_vec();
            sign_packet(&mut signed, key);
            stream.write_all(&signed).await?;
        } else {
            stream.write_all(packet).await?;
        }
        stream.flush().await?;

        // Read responses, looping past STATUS_PENDING interim responses
        loop {
            let mut len_buf = [0u8; 4];
            Self::read_exact_timeout(&mut stream, &mut len_buf).await?;
            let msg_len = u32::from_be_bytes(len_buf) as usize;

            if !(SMB2_HEADER_SIZE..=16 * 1024 * 1024).contains(&msg_len) {
                crate::serr!("[spiceio] smb invalid message length: {msg_len}");
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid SMB2 message length: {msg_len}"),
                ));
            }

            let mut msg = vec![0u8; msg_len];
            Self::read_exact_timeout(&mut stream, &mut msg).await?;

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
            crate::serr!("[spiceio] smb negotiate failed: 0x{:08X}", resp_hdr.status);
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("negotiate failed: status=0x{:08X}", resp_hdr.status),
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
            crate::serr!("[spiceio] smb auth failed: 0x{:08X}", resp_hdr.status);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("authentication failed: status=0x{:08X}", resp_hdr.status),
            ));
        }

        // Derive the signing key
        let signing_key = auth::derive_signing_key(&session_base_key, &preauth_hash);
        crate::slog!("[spiceio] authenticated, signing key derived");

        self.session_id = resp_hdr.session_id;
        // Cap standalone I/O by: min(server_advertised, max_transact, configured_cap).
        // Many NAS servers advertise multi-MB limits but fail at much smaller sizes.
        let transact = neg_resp.max_transact_size;
        let io_cap = if self.config.max_io_size > 0 {
            self.config.max_io_size
        } else {
            DEFAULT_MAX_IO
        };
        self.max_read_size = neg_resp.max_read_size.min(transact).min(io_cap);
        self.max_write_size = neg_resp.max_write_size.min(transact).min(io_cap);
        // Cap at 64KB for compound requests — some NAS servers reject larger
        // payloads inside compound (chained) operations.
        self.compound_max_read_size = self.max_read_size.min(65536);
        self.compound_max_write_size = self.max_write_size.min(65536);
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
        let status = NtStatus::from_u32(resp_hdr.status);
        if status.is_error() {
            crate::serr!(
                "[spiceio] smb tree connect failed: '{}': 0x{:08X}",
                share,
                resp_hdr.status
            );
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "tree connect to '{}' failed: 0x{:08X}",
                    share, resp_hdr.status
                ),
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
        let msg_id = self.next_message_id();
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
        if count == 0 {
            return Ok(Vec::new());
        }

        // Allocate message IDs in a contiguous batch so we can map
        // response.message_id → slot index via simple subtraction.
        let base_msg_id = self.message_id.fetch_add(count as u64, Ordering::Relaxed);

        let mut packets = Vec::with_capacity(count);
        for i in 0..count {
            let offset = start_offset + (i as u64) * (chunk_size as u64);
            let msg_id = base_msg_id + i as u64;
            let mut hdr = Header::new(Command::Read, msg_id).with_credit_charge(chunk_size);
            hdr.session_id = self.session_id;
            hdr.tree_id = tree_id;
            let packet = build_request(&hdr, |buf| {
                encode_read_request(buf, file_id, offset, chunk_size);
            });
            packets.push(packet);
        }

        let mut stream = self.stream.lock().await;

        // Send all requests
        for packet in &packets {
            if let Some(ref key) = self.signing_key {
                let mut signed = packet.to_vec();
                sign_packet(&mut signed, key);
                stream.write_all(&signed).await?;
            } else {
                stream.write_all(packet).await?;
            }
        }
        stream.flush().await?;

        // Receive responses into ordered slots (handles out-of-order delivery).
        let mut slots: Vec<Option<bytes::Bytes>> = (0..count).map(|_| None).collect();
        let mut received = 0usize;
        let mut eof_after = count; // trim to this length on EOF

        while received < count {
            let mut len_buf = [0u8; 4];
            Self::read_exact_timeout(&mut stream, &mut len_buf).await?;
            let msg_len = u32::from_be_bytes(len_buf) as usize;

            if !(SMB2_HEADER_SIZE..=16 * 1024 * 1024).contains(&msg_len) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid SMB2 message length: {msg_len}"),
                ));
            }

            let mut msg = vec![0u8; msg_len];
            Self::read_exact_timeout(&mut stream, &mut msg).await?;

            let header = Header::decode(&msg)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid SMB2 header"))?;

            // Skip STATUS_PENDING interim responses
            if header.status == 0x0000_0103 {
                continue;
            }

            let slot = (header.message_id.wrapping_sub(base_msg_id)) as usize;
            if slot >= count {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "unexpected message_id {} (base={}, count={})",
                        header.message_id, base_msg_id, count
                    ),
                ));
            }

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

            let body = msg[SMB2_HEADER_SIZE..].to_vec();
            let data = decode_read_response_owned(body).ok_or_else(|| {
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
        let msg_id = self.next_message_id();
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
    /// Responses may arrive out of order; each is matched by message_id.
    pub async fn pipelined_write(
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
        let base_msg_id = self.message_id.fetch_add(n as u64, Ordering::Relaxed);

        let mut packets = Vec::with_capacity(n);
        let mut offset = start_offset;
        for (i, chunk) in chunks.iter().enumerate() {
            let msg_id = base_msg_id + i as u64;
            let mut hdr =
                Header::new(Command::Write, msg_id).with_credit_charge(chunk.len() as u32);
            hdr.session_id = self.session_id;
            hdr.tree_id = tree_id;
            let packet = build_request(&hdr, |buf| {
                encode_write_request(buf, file_id, offset, chunk);
            });
            packets.push(packet);
            offset += chunk.len() as u64;
        }

        let mut stream = self.stream.lock().await;

        // Send all requests
        for packet in &packets {
            if let Some(ref key) = self.signing_key {
                let mut signed = packet.to_vec();
                sign_packet(&mut signed, key);
                stream.write_all(&signed).await?;
            } else {
                stream.write_all(packet).await?;
            }
        }
        stream.flush().await?;

        // Receive all responses (handles out-of-order delivery)
        let mut total_written = 0u64;
        let mut received = 0usize;
        while received < n {
            let mut len_buf = [0u8; 4];
            Self::read_exact_timeout(&mut stream, &mut len_buf).await?;
            let msg_len = u32::from_be_bytes(len_buf) as usize;

            if !(SMB2_HEADER_SIZE..=16 * 1024 * 1024).contains(&msg_len) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid SMB2 message length: {msg_len}"),
                ));
            }

            let mut msg = vec![0u8; msg_len];
            Self::read_exact_timeout(&mut stream, &mut msg).await?;

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
        stream.write_all(&buf).await?;
        stream.flush().await?;

        // Read response frames, skipping STATUS_PENDING interim responses
        loop {
            let mut len_buf = [0u8; 4];
            Self::read_exact_timeout(&mut stream, &mut len_buf).await?;
            let msg_len = u32::from_be_bytes(len_buf) as usize;

            if !(SMB2_HEADER_SIZE..=16 * 1024 * 1024).contains(&msg_len) {
                crate::serr!("[spiceio] smb invalid message length: {msg_len}");
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid SMB2 message length: {msg_len}"),
                ));
            }

            let mut msg = vec![0u8; msg_len];
            Self::read_exact_timeout(&mut stream, &mut msg).await?;

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
    crate::serr!("[spiceio] smb error 0x{status:08X}: {path}");
    // Map raw status codes directly to avoid losing info through NtStatus enum
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

        _ => io::Error::other(format!("SMB error 0x{status:08X} for {path}")),
    }
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

/// Parse a compound response (multiple SMB2 messages in one frame).
fn parse_compound_response(msg: &[u8]) -> Vec<(Header, Vec<u8>)> {
    let mut results = Vec::new();
    let mut offset = 0;

    loop {
        if offset + SMB2_HEADER_SIZE > msg.len() {
            break;
        }
        let header = match Header::decode(&msg[offset..]) {
            Some(h) => h,
            None => break,
        };

        let next = header.next_command as usize;
        let body_start = offset + SMB2_HEADER_SIZE;
        let body_end = if next > 0 {
            let end = offset + next;
            if end > msg.len() || end < body_start {
                break;
            }
            end
        } else {
            msg.len()
        };
        if body_start > body_end || body_end > msg.len() {
            break;
        }

        let body = msg[body_start..body_end].to_vec();
        results.push((header, body));

        if next == 0 {
            break;
        }
        offset += next;
    }

    results
}

// Need this for from_raw_fd
