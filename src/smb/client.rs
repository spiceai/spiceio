//! SMB2 client — manages TCP connections and speaks the protocol.

use bytes::Buf;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

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
}

impl SmbConfig {
    pub fn share_path(&self, share: &str) -> String {
        format!("\\\\{}\\{}", self.server, share)
    }
}

/// An authenticated SMB2 session.
pub struct SmbClient {
    stream: Mutex<TcpStream>,
    message_id: AtomicU64,
    session_id: u64,
    config: SmbConfig,
    pub max_read_size: u32,
    pub max_write_size: u32,
    /// 16-byte client GUID
    client_guid: [u8; 16],
    /// SMB 3.1.1 signing key (derived after auth)
    signing_key: Option<[u8; 16]>,
}

impl SmbClient {
    /// Connect to the SMB server and authenticate.
    pub async fn connect(config: SmbConfig) -> io::Result<Arc<Self>> {
        let addr = format!("{}:{}", config.server, config.port);
        let stream = TcpStream::connect(&addr).await?;
        stream.set_nodelay(true)?;

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
            client_guid,
            signing_key: None,
        };

        client.negotiate_and_auth().await?;
        Ok(Arc::new(client))
    }

    fn next_message_id(&self) -> u64 {
        self.message_id.fetch_add(1, Ordering::Relaxed)
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
            stream.read_exact(&mut len_buf).await?;
            let msg_len = u32::from_be_bytes(len_buf) as usize;

            if !(SMB2_HEADER_SIZE..=16 * 1024 * 1024).contains(&msg_len) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid SMB2 message length: {msg_len}"),
                ));
            }

            let mut msg = vec![0u8; msg_len];
            stream.read_exact(&mut msg).await?;

            let header = Header::decode(&msg)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid SMB2 header"))?;

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
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("negotiate failed: status=0x{:08X}", resp_hdr.status),
            ));
        }

        // Hash the negotiate response
        update_preauth_hash(&mut preauth_hash, &resp_raw);

        let neg_resp = decode_negotiate_response(&resp_body).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid negotiate response")
        })?;
        eprintln!(
            "[spio] negotiated SMB 0x{:04X}, max_rw={}K",
            neg_resp.dialect_revision,
            neg_resp.max_write_size.min(65536) / 1024,
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
            io::Error::new(io::ErrorKind::InvalidData, "invalid session setup response")
        })?;

        // Parse NTLM challenge from SPNEGO wrapper
        let challenge_data = auth::unwrap_spnego(&sess_resp.security_buffer);
        let challenge = auth::parse_challenge_message(challenge_data)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid NTLM challenge"))?;

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
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("authentication failed: status=0x{:08X}", resp_hdr.status),
            ));
        }

        // Derive the signing key
        let signing_key = auth::derive_signing_key(&session_base_key, &preauth_hash);
        eprintln!("[spio] authenticated, signing key derived");

        self.session_id = resp_hdr.session_id;
        // Cap at 64KB to avoid oversized SMB messages; the negotiate value is often
        // the max transaction size, but doesn't account for header overhead.
        self.max_read_size = neg_resp.max_read_size.min(65536);
        self.max_write_size = neg_resp.max_write_size.min(65536);
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
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "tree connect to '{}' failed: 0x{:08X}",
                    share, resp_hdr.status
                ),
            ));
        }

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

        decode_create_response(&resp_body)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid create response"))
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
        let mut hdr = Header::new(Command::Read, msg_id);
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
            return Err(io::Error::other(format!(
                "read failed: 0x{:08X}",
                resp_hdr.status
            )));
        }

        decode_read_response(&resp_body)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid read response"))
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
        let mut hdr = Header::new(Command::Write, msg_id);
        hdr.session_id = self.session_id;
        hdr.tree_id = tree_id;

        let packet = build_request(&hdr, |buf| {
            encode_write_request(buf, file_id, offset, data);
        });

        let (resp_hdr, resp_body) = self.send_recv(&packet).await?;
        // Check raw status: high two bits indicate severity
        // 0x00 = success, 0x40 = info, 0x80 = warning, 0xC0 = error
        if resp_hdr.status & 0xC000_0000 == 0xC000_0000 {
            return Err(io::Error::other(format!(
                "write failed: status=0x{:08X} offset={} len={}",
                resp_hdr.status, offset, data.len()
            )));
        }

        decode_write_response(&resp_body)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid write response"))
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

// Need this for from_raw_fd
