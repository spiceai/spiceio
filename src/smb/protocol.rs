//! SMB 3.1.1 wire protocol definitions (macOS 26 dialect only).
//!
//! All structures are little-endian on the wire. We define the constants,
//! header layout, and per-command request/response formats needed for
//! basic file I/O operations.

use bytes::{Buf, BufMut, Bytes, BytesMut};

// ── SMB2 magic ──────────────────────────────────────────────────────────────

pub const SMB2_MAGIC: &[u8; 4] = b"\xfeSMB";
pub const SMB2_HEADER_SIZE: usize = 64;

// ── Commands ────────────────────────────────────────────────────────────────

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Negotiate = 0x0000,
    SessionSetup = 0x0001,
    TreeConnect = 0x0003,
    Create = 0x0005,
    Close = 0x0006,
    Read = 0x0008,
    Write = 0x0009,
    QueryDirectory = 0x000E,
}

// ── NT Status codes we care about ───────────────────────────────────────────

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtStatus {
    Success = 0x00000000,
    MoreProcessingRequired = 0xC0000016,
    NoSuchFile = 0xC000000F,
    ObjectNameNotFound = 0xC0000034,
    ObjectNameCollision = 0xC0000035,
    AccessDenied = 0xC0000022,
    EndOfFile = 0xC0000011,
    NoMoreFiles = 0x80000006,
    ObjectPathNotFound = 0xC000003A,
}

impl NtStatus {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0x00000000 => Self::Success,
            0xC0000016 => Self::MoreProcessingRequired,
            0xC000000F => Self::NoSuchFile,
            0xC0000034 => Self::ObjectNameNotFound,
            0xC0000035 => Self::ObjectNameCollision,
            0xC0000022 => Self::AccessDenied,
            0xC0000011 => Self::EndOfFile,
            0x80000006 => Self::NoMoreFiles,
            0xC000003A => Self::ObjectPathNotFound,
            other => {
                // Treat unknown as success if zero high-bit, else generic error
                if other == 0 {
                    Self::Success
                } else {
                    // store as-is via MoreProcessingRequired trick — caller checks raw
                    Self::AccessDenied
                }
            }
        }
    }

    pub fn is_error(self) -> bool {
        (self as u32) & 0xC0000000 == 0xC0000000
    }
}

// ── SMB2 Header ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Header {
    pub command: u16,
    pub credit_charge: u16,
    pub status: u32,
    pub credits_requested: u16,
    pub flags: u32,
    pub next_command: u32,
    pub message_id: u64,
    pub tree_id: u32,
    pub session_id: u64,
}

impl Header {
    pub fn new(command: Command, message_id: u64) -> Self {
        Self {
            command: command as u16,
            credit_charge: 1,
            status: 0,
            credits_requested: 256,
            flags: 0,
            next_command: 0,
            message_id,
            tree_id: 0,
            session_id: 0,
        }
    }

    /// Encode the 64-byte SMB2 header into a buffer.
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_slice(SMB2_MAGIC); // 0: ProtocolId
        buf.put_u16_le(64); // 4: StructureSize
        buf.put_u16_le(self.credit_charge); // 6: CreditCharge
        buf.put_u32_le(self.status); // 8: Status
        buf.put_u16_le(self.command); // 12: Command
        buf.put_u16_le(self.credits_requested); // 14: CreditRequest
        buf.put_u32_le(self.flags); // 16: Flags
        buf.put_u32_le(self.next_command); // 20: NextCommand
        buf.put_u64_le(self.message_id); // 24: MessageID
        buf.put_u32_le(0); // 32: Reserved (async: AsyncId high)
        buf.put_u32_le(self.tree_id); // 36: TreeId (sync)
        buf.put_u64_le(self.session_id); // 40: SessionId
        buf.put_slice(&[0u8; 16]); // 48: Signature
    }

    /// Decode a 64-byte SMB2 header from bytes.
    pub fn decode(mut buf: &[u8]) -> Option<Self> {
        if buf.len() < SMB2_HEADER_SIZE {
            return None;
        }
        let magic = &buf[..4];
        if magic != SMB2_MAGIC {
            return None;
        }
        buf = &buf[4..];
        let _structure_size = (&buf[..2]).get_u16_le(); // skip past
        let buf = &buf[2..];
        let credit_charge = (&buf[..2]).get_u16_le();
        let status = (&buf[2..6]).get_u32_le();
        let command = (&buf[6..8]).get_u16_le();
        let credits_requested = (&buf[8..10]).get_u16_le();
        let flags = (&buf[10..14]).get_u32_le();
        let next_command = (&buf[14..18]).get_u32_le();
        let message_id = (&buf[18..26]).get_u64_le();
        let _reserved = (&buf[26..30]).get_u32_le();
        let tree_id = (&buf[30..34]).get_u32_le();
        let session_id = (&buf[34..42]).get_u64_le();
        // signature at 42..58 — skip for now

        Some(Self {
            command,
            credit_charge,
            status,
            credits_requested,
            flags,
            next_command,
            message_id,
            tree_id,
            session_id,
        })
    }
}

// ── Negotiate ───────────────────────────────────────────────────────────────

/// SMB 3.1.x dialect family
pub const DIALECT_SMB3_1_1: u16 = 0x0311;
pub const DIALECT_SMB3_0_2: u16 = 0x0302;
pub const DIALECT_SMB3_0_0: u16 = 0x0300;

// Offered dialects in preference order (highest first)
const DIALECTS: [u16; 3] = [DIALECT_SMB3_1_1, DIALECT_SMB3_0_2, DIALECT_SMB3_0_0];

// Negotiate context types for SMB 3.1.1
const SMB2_PREAUTH_INTEGRITY_CAPABILITIES: u16 = 0x0001;
const SMB2_ENCRYPTION_CAPABILITIES: u16 = 0x0002;

// Hash algorithm: SHA-512
const SHA_512: u16 = 0x0001;
// Cipher: AES-128-GCM (preferred by macOS)
const AES_128_GCM: u16 = 0x0002;
const AES_128_CCM: u16 = 0x0001;

pub fn encode_negotiate_request(buf: &mut BytesMut, client_guid: &[u8; 16]) {
    let dialect_count = DIALECTS.len() as u16;
    let dialects_len = DIALECTS.len() * 2;

    // Build negotiate contexts (required when offering 3.1.1)
    let mut contexts = BytesMut::new();

    // Preauth Integrity Capabilities context
    let preauth_data_len: u16 = 2 + 2 + 2 + 32; // HashAlgCount + SaltLength + HashAlg + Salt
    contexts.put_u16_le(SMB2_PREAUTH_INTEGRITY_CAPABILITIES);
    contexts.put_u16_le(preauth_data_len);
    contexts.put_u32_le(0); // Reserved
    contexts.put_u16_le(1); // HashAlgorithmCount
    contexts.put_u16_le(32); // SaltLength
    contexts.put_u16_le(SHA_512);
    let salt = random_bytes::<32>();
    contexts.put_slice(&salt);
    // Pad to 8-byte alignment
    let pad = (8 - (contexts.len() % 8)) % 8;
    contexts.put_slice(&vec![0u8; pad]);

    // Encryption Capabilities context
    let enc_data_len: u16 = 2 + 2 * 2; // CipherCount + 2 ciphers
    contexts.put_u16_le(SMB2_ENCRYPTION_CAPABILITIES);
    contexts.put_u16_le(enc_data_len);
    contexts.put_u32_le(0); // Reserved
    contexts.put_u16_le(2); // CipherCount
    contexts.put_u16_le(AES_128_GCM); // Preferred
    contexts.put_u16_le(AES_128_CCM); // Fallback

    let body_fixed_len = 36 + dialects_len;
    let ctx_padding = (8 - (body_fixed_len % 8)) % 8;
    let ctx_offset = (SMB2_HEADER_SIZE + body_fixed_len + ctx_padding) as u32;

    buf.put_u16_le(36); // StructureSize
    buf.put_u16_le(dialect_count);
    buf.put_u16_le(0x0001); // SecurityMode: signing enabled
    buf.put_u16_le(0); // Reserved
    buf.put_u32_le(0x00000041); // Capabilities: DFS | Leasing
    buf.put_slice(client_guid);
    buf.put_u32_le(ctx_offset); // NegotiateContextOffset
    buf.put_u16_le(2); // NegotiateContextCount
    buf.put_u16_le(0); // Reserved2
    for &d in &DIALECTS {
        buf.put_u16_le(d);
    }
    buf.put_slice(&vec![0u8; ctx_padding]);
    buf.put_slice(&contexts);
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    unsafe extern "C" {
        fn arc4random_buf(buf: *mut u8, nbytes: usize);
    }
    unsafe {
        arc4random_buf(buf.as_mut_ptr(), N);
    }
    buf
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct NegotiateResponse {
    pub security_mode: u16,
    pub dialect_revision: u16,
    pub max_read_size: u32,
    pub max_write_size: u32,
}

pub fn decode_negotiate_response(body: &[u8]) -> Option<NegotiateResponse> {
    if body.len() < 40 {
        return None;
    }
    let security_mode = (&body[2..4]).get_u16_le();
    let dialect_revision = (&body[4..6]).get_u16_le();
    let max_read_size = (&body[32..36]).get_u32_le();
    let max_write_size = (&body[36..40]).get_u32_le();

    Some(NegotiateResponse {
        security_mode,
        dialect_revision,
        max_read_size,
        max_write_size,
    })
}

// ── Session Setup ───────────────────────────────────────────────────────────

pub fn encode_session_setup_request(buf: &mut BytesMut, security_blob: &[u8]) {
    let offset = (SMB2_HEADER_SIZE + 24) as u16; // header + fixed part of this request
    buf.put_u16_le(25); // StructureSize
    buf.put_u8(0); // Flags
    buf.put_u8(0x01); // SecurityMode: signing enabled
    buf.put_u32_le(0); // Capabilities
    buf.put_u32_le(0); // Channel
    buf.put_u16_le(offset); // SecurityBufferOffset
    buf.put_u16_le(security_blob.len() as u16); // SecurityBufferLength
    buf.put_u64_le(0); // PreviousSessionId
    buf.put_slice(security_blob);
}

#[derive(Debug)]
pub struct SessionSetupResponse {
    pub session_id: u64,
    pub security_buffer: Bytes,
}

pub fn decode_session_setup_response(header: &Header, body: &[u8]) -> Option<SessionSetupResponse> {
    if body.len() < 9 {
        return None;
    }
    let security_buffer_offset = (&body[4..6]).get_u16_le() as usize;
    let security_buffer_length = (&body[6..8]).get_u16_le() as usize;

    let sec_start = security_buffer_offset.saturating_sub(SMB2_HEADER_SIZE);
    let sec_end = sec_start + security_buffer_length;
    let security_buffer = if sec_end <= body.len() {
        Bytes::copy_from_slice(&body[sec_start..sec_end])
    } else {
        Bytes::new()
    };

    Some(SessionSetupResponse {
        session_id: header.session_id,
        security_buffer,
    })
}

// ── Tree Connect ────────────────────────────────────────────────────────────

pub fn encode_tree_connect_request(buf: &mut BytesMut, path: &str) {
    let path_bytes: Vec<u8> = path.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let offset = (SMB2_HEADER_SIZE + 8) as u16;
    buf.put_u16_le(9); // StructureSize
    buf.put_u16_le(0); // Reserved / Flags
    buf.put_u16_le(offset); // PathOffset
    buf.put_u16_le(path_bytes.len() as u16); // PathLength
    buf.put_slice(&path_bytes);
}

// ── Create (Open) ───────────────────────────────────────────────────────────

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum DesiredAccess {
    GenericRead = 0x80000000,
    GenericWrite = 0x40000000,
    Delete = 0x00010000,
    ReadAttributes = 0x00000080,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum ShareAccess {
    Read = 0x00000001,
    Delete = 0x00000004,
    All = 0x00000007,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum CreateDisposition {
    Open = 0x00000001,
    OpenIf = 0x00000003,
    OverwriteIf = 0x00000005,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum CreateOptions {
    DirectoryFile = 0x00000001,
    NonDirectoryFile = 0x00000040,
}

pub fn encode_create_request(
    buf: &mut BytesMut,
    path: &str,
    desired_access: u32,
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
) {
    let name_bytes: Vec<u8> = path.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let name_offset = (SMB2_HEADER_SIZE + 56) as u16; // header + create request fixed part (57 - 1 buffer byte)
    // StructureSize for Create request is 57
    buf.put_u16_le(57); // StructureSize
    buf.put_u8(0); // SecurityFlags
    buf.put_u8(0x02); // RequestedOplockLevel: SMB2_OPLOCK_LEVEL_NONE = 0, BATCH=0x09, LEASE=0xFF, let's try none
    buf.put_u32_le(0x00000002); // ImpersonationLevel: Impersonation
    buf.put_u64_le(0); // SmbCreateFlags
    buf.put_u64_le(0); // Reserved
    buf.put_u32_le(desired_access); // DesiredAccess
    buf.put_u32_le(0x00000080); // FileAttributes: NORMAL
    buf.put_u32_le(share_access); // ShareAccess
    buf.put_u32_le(create_disposition); // CreateDisposition
    buf.put_u32_le(create_options); // CreateOptions
    buf.put_u16_le(name_offset); // NameOffset
    buf.put_u16_le(name_bytes.len() as u16); // NameLength
    buf.put_u32_le(0); // CreateContextsOffset
    buf.put_u32_le(0); // CreateContextsLength
    buf.put_slice(&name_bytes);
}

#[derive(Debug, Clone)]
pub struct CreateResponse {
    pub file_id: [u8; 16],
    pub last_write_time: u64,
    pub file_size: u64,
}

pub fn decode_create_response(body: &[u8]) -> Option<CreateResponse> {
    // Minimum: 88 bytes (StructureSize says 89, but the last byte is variable-length CreateContexts)
    if body.len() < 88 {
        return None;
    }
    let last_write_time = (&body[24..32]).get_u64_le();
    // AllocationSize at 40..48
    let file_size = (&body[48..56]).get_u64_le();
    // Reserved2 at 60..64
    let mut file_id = [0u8; 16];
    file_id.copy_from_slice(&body[64..80]);

    Some(CreateResponse {
        file_id,
        last_write_time,
        file_size,
    })
}

// ── Close ───────────────────────────────────────────────────────────────────

pub fn encode_close_request(buf: &mut BytesMut, file_id: &[u8; 16]) {
    buf.put_u16_le(24); // StructureSize
    buf.put_u16_le(0); // Flags
    buf.put_u32_le(0); // Reserved
    buf.put_slice(file_id); // FileId
}

// ── Read ────────────────────────────────────────────────────────────────────

pub fn encode_read_request(buf: &mut BytesMut, file_id: &[u8; 16], offset: u64, length: u32) {
    buf.put_u16_le(49); // StructureSize
    buf.put_u8(0); // Padding
    buf.put_u8(0); // Flags
    buf.put_u32_le(length); // Length
    buf.put_u64_le(offset); // Offset
    buf.put_slice(file_id); // FileId
    buf.put_u32_le(1); // MinimumCount
    buf.put_u32_le(0); // Channel
    buf.put_u32_le(0); // RemainingBytes
    buf.put_u16_le(0); // ReadChannelInfoOffset
    buf.put_u16_le(0); // ReadChannelInfoLength
    buf.put_u8(0); // Buffer (padding byte)
}

pub fn decode_read_response(body: &[u8]) -> Option<Bytes> {
    if body.len() < 17 {
        return None;
    }
    let data_offset = (&body[2..3])[0] as usize;
    let data_length = (&body[4..8]).get_u32_le() as usize;

    let start = data_offset.saturating_sub(SMB2_HEADER_SIZE);
    let end = start + data_length;
    if end > body.len() {
        return None;
    }
    Some(Bytes::copy_from_slice(&body[start..end]))
}

// ── Write ───────────────────────────────────────────────────────────────────

pub fn encode_write_request(buf: &mut BytesMut, file_id: &[u8; 16], offset: u64, data: &[u8]) {
    let data_offset = (SMB2_HEADER_SIZE + 48) as u16;
    buf.put_u16_le(49); // StructureSize
    buf.put_u16_le(data_offset); // DataOffset
    buf.put_u32_le(data.len() as u32); // Length
    buf.put_u64_le(offset); // Offset
    buf.put_slice(file_id); // FileId
    buf.put_u32_le(0); // Channel
    buf.put_u32_le(0); // RemainingBytes
    buf.put_u16_le(0); // WriteChannelInfoOffset
    buf.put_u16_le(0); // WriteChannelInfoLength
    buf.put_u32_le(0); // Flags
    buf.put_slice(data);
}

pub fn decode_write_response(body: &[u8]) -> Option<u32> {
    if body.len() < 16 {
        return None;
    }
    Some((&body[4..8]).get_u32_le()) // Count (bytes written)
}

// ── Query Directory ─────────────────────────────────────────────────────────

pub const FILE_ID_BOTH_DIRECTORY_INFORMATION: u8 = 0x25;

pub fn encode_query_directory_request(
    buf: &mut BytesMut,
    file_id: &[u8; 16],
    pattern: &str,
    info_class: u8,
    restart: bool,
) {
    let pattern_bytes: Vec<u8> = pattern
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let name_offset = (SMB2_HEADER_SIZE + 32 + 1) as u16;
    let mut flags: u8 = 0;
    if restart {
        flags |= 0x01; // SMB2_RESTART_SCANS
    }
    buf.put_u16_le(33); // StructureSize
    buf.put_u8(info_class); // FileInformationClass
    buf.put_u8(flags); // Flags
    buf.put_u32_le(0); // FileIndex
    buf.put_slice(file_id); // FileId
    buf.put_u16_le(name_offset); // FileNameOffset
    buf.put_u16_le(pattern_bytes.len() as u16); // FileNameLength
    buf.put_u32_le(65536); // OutputBufferLength
    buf.put_slice(&pattern_bytes);
}

/// A directory entry from FileIdBothDirectoryInformation
#[derive(Debug, Clone)]
pub struct DirectoryEntry {
    pub file_name: String,
    pub file_size: u64,
    pub file_attributes: u32,
    pub last_write_time: u64,
}

impl DirectoryEntry {
    pub fn is_directory(&self) -> bool {
        self.file_attributes & 0x10 != 0
    }
}

/// Parse FILE_ID_BOTH_DIRECTORY_INFORMATION entries from a query directory response.
pub fn parse_directory_entries(data: &[u8]) -> Vec<DirectoryEntry> {
    let mut entries = Vec::new();
    let mut offset = 0usize;

    loop {
        if offset + 104 > data.len() {
            break;
        }
        let entry = &data[offset..];

        let next_entry_offset = (&entry[0..4]).get_u32_le() as usize;
        let _file_index = (&entry[4..8]).get_u32_le();
        let _creation_time = (&entry[8..16]).get_u64_le();
        let _last_access_time = (&entry[16..24]).get_u64_le();
        let last_write_time = (&entry[24..32]).get_u64_le();
        let _change_time = (&entry[32..40]).get_u64_le();
        let file_size = (&entry[40..48]).get_u64_le(); // EndOfFile
        let _allocation_size = (&entry[48..56]).get_u64_le();
        let file_attributes = (&entry[56..60]).get_u32_le();
        let file_name_length = (&entry[60..64]).get_u32_le() as usize;

        // FileIdBothDirectoryInformation: filename starts at offset 104
        let name_start = 104;
        let name_end = name_start + file_name_length;
        if name_end > entry.len() {
            break;
        }
        let name_bytes = &entry[name_start..name_end];
        let file_name = String::from_utf16_lossy(
            &name_bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
        );

        // Skip . and ..
        if file_name != "." && file_name != ".." {
            entries.push(DirectoryEntry {
                file_name,
                file_size,
                file_attributes,
                last_write_time,
            });
        }

        if next_entry_offset == 0 {
            break;
        }
        offset += next_entry_offset;
    }

    entries
}

// ── Frame helpers ───────────────────────────────────────────────────────────

/// Prepend a 4-byte NetBIOS session length prefix to the packet.
pub fn frame_packet(header: &Header, body: &[u8]) -> BytesMut {
    let total = SMB2_HEADER_SIZE + body.len();
    let mut buf = BytesMut::with_capacity(4 + total);
    buf.put_u32(total as u32); // NetBIOS length (big-endian, no flags)
    header.encode(&mut buf);
    buf.put_slice(body);
    buf
}

/// Build a complete SMB2 request packet: \[NetBIOS length]\[Header]\[Body]
pub fn build_request<F>(header: &Header, body_builder: F) -> BytesMut
where
    F: FnOnce(&mut BytesMut),
{
    let mut body = BytesMut::with_capacity(256);
    body_builder(&mut body);
    frame_packet(header, &body)
}
