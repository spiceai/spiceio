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
    Ioctl = 0x000B,
    Echo = 0x000D,
    QueryDirectory = 0x000E,
    SetInfo = 0x0011,
}

// ── NT Status codes we care about ───────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtStatus {
    Success,
    MoreProcessingRequired,
    NoSuchFile,
    ObjectNameNotFound,
    ObjectNameCollision,
    AccessDenied,
    EndOfFile,
    NoMoreFiles,
    ObjectPathNotFound,
    // Server capacity / limit statuses. Treated as retryable ResourceBusy at the
    // connection layer, not as auth or file errors.
    InsufficientResources,
    TooManySessions,
    RequestNotAccepted,
    SharingPaused,
    RemoteSessionLimit,
    Unknown(u32),
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
            0xC000009A => Self::InsufficientResources,
            0xC00000CE => Self::TooManySessions,
            0xC00000D0 => Self::RequestNotAccepted,
            0xC00000CF => Self::SharingPaused,
            0xC0000196 => Self::RemoteSessionLimit,
            other => Self::Unknown(other),
        }
    }

    pub fn is_error(self) -> bool {
        let code = match self {
            Self::Success => 0x00000000,
            Self::MoreProcessingRequired => 0xC0000016,
            Self::NoSuchFile => 0xC000000F,
            Self::ObjectNameNotFound => 0xC0000034,
            Self::ObjectNameCollision => 0xC0000035,
            Self::AccessDenied => 0xC0000022,
            Self::EndOfFile => 0xC0000011,
            Self::NoMoreFiles => 0x80000006,
            Self::ObjectPathNotFound => 0xC000003A,
            Self::InsufficientResources => 0xC000009A,
            Self::TooManySessions => 0xC00000CE,
            Self::RequestNotAccepted => 0xC00000D0,
            Self::SharingPaused => 0xC00000CF,
            Self::RemoteSessionLimit => 0xC0000196,
            Self::Unknown(v) => v,
        };
        code & 0xC0000000 == 0xC0000000
    }
}

// ── SMB2 Header ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Header {
    pub command: u16,
    pub credit_charge: u16,
    pub status: u32,
    /// `CreditRequest` in requests (credits we ask the server to grant),
    /// `CreditResponse` in responses (credits the server granted). The client
    /// banks every response's grant into its per-connection credit balance.
    pub credits: u16,
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
            // Ask for a healthy window on every request so the server keeps
            // the connection's credit balance topped up for pipelined bursts.
            credits: 256,
            flags: 0,
            next_command: 0,
            message_id,
            tree_id: 0,
            session_id: 0,
        }
    }

    /// Set credit charge for operations transferring `payload_size` bytes.
    /// Required for Read/Write/QueryDirectory with payloads >64KB.
    pub fn with_credit_charge(mut self, payload_size: u32) -> Self {
        self.credit_charge = credit_charge_for(payload_size);
        self
    }

    /// Encode the 64-byte SMB2 header into a buffer.
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_slice(SMB2_MAGIC); // 0: ProtocolId
        buf.put_u16_le(64); // 4: StructureSize
        buf.put_u16_le(self.credit_charge); // 6: CreditCharge
        buf.put_u32_le(self.status); // 8: Status
        buf.put_u16_le(self.command); // 12: Command
        buf.put_u16_le(self.credits); // 14: CreditRequest/CreditResponse
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
        let credits = (&buf[8..10]).get_u16_le();
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
            credits,
            flags,
            next_command,
            message_id,
            tree_id,
            session_id,
        })
    }
}

/// Compute the credit charge for a payload of the given size.
/// CreditCharge = max(1, ceil(payload_size / 65536))
pub fn credit_charge_for(payload_size: u32) -> u16 {
    1.max(payload_size.div_ceil(65536) as u16)
}

// ── Negotiate ───────────────────────────────────────────────────────────────

/// SMB 3.1.x dialect family
pub const DIALECT_SMB3_1_1: u16 = 0x0311;

// Offer 3.1.1 only. Our signing-key derivation is the 3.1.1 KDF
// (preauth-integrity-hash context, "SMBSigningKey" label); SMB 3.0.x derives
// signing keys differently ("SMB2AESCMAC"/"SmbSign"), so a server that
// negotiated 3.0.x would reject every signed request we send. Offering a
// dialect we cannot actually sign for turns "unsupported server" into a
// confusing mid-session auth failure — refuse it at negotiate instead.
const DIALECTS: [u16; 1] = [DIALECT_SMB3_1_1];

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
    // Capabilities: DFS (0x01) | LARGE_MTU (0x04) | ENCRYPTION (0x40).
    // LARGE_MTU is required to use multi-credit reads/writes (>64 KiB in one
    // request); without it, multi-credit I/O violates the credit/sequence
    // window and the server resets the connection under load.
    buf.put_u32_le(0x00000045);
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
    pub max_transact_size: u32,
    pub max_read_size: u32,
    pub max_write_size: u32,
}

pub fn decode_negotiate_response(body: &[u8]) -> Option<NegotiateResponse> {
    if body.len() < 40 {
        return None;
    }
    let security_mode = (&body[2..4]).get_u16_le();
    let dialect_revision = (&body[4..6]).get_u16_le();
    let max_transact_size = (&body[28..32]).get_u32_le();
    let max_read_size = (&body[32..36]).get_u32_le();
    let max_write_size = (&body[36..40]).get_u32_le();

    Some(NegotiateResponse {
        security_mode,
        dialect_revision,
        max_transact_size,
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

    // A valid SecurityBufferOffset points at or past the SMB2 header. Reject an
    // offset inside the header (checked_sub -> None) rather than clamping to 0
    // and handing the auth layer garbage from the start of the body.
    let sec_start = security_buffer_offset.checked_sub(SMB2_HEADER_SIZE)?;
    let sec_end = sec_start.checked_add(security_buffer_length)?;
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
    /// FILE_DELETE_ON_CLOSE — the file/dir is deleted when its last handle
    /// closes. OR with `DirectoryFile`/`NonDirectoryFile` for a delete-on-close.
    DeleteOnClose = 0x00001000,
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
    buf.put_u8(0x00); // RequestedOplockLevel: SMB2_OPLOCK_LEVEL_NONE
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
    if name_bytes.is_empty() {
        // StructureSize is 57 = 56-byte fixed part + 1 mandatory buffer byte.
        // The variable-length buffer must always be present, so when opening the
        // share root (empty name) we still emit a single padding byte. Omitting
        // it yields a 56-byte body that servers reject with
        // STATUS_INVALID_PARAMETER (0xC000000D). Mirrors the trailing buffer
        // byte the Read request always sends.
        buf.put_u8(0);
    } else {
        buf.put_slice(&name_bytes);
    }
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

/// `remaining_after` tells the server how many more bytes the client intends
/// to read past this request — MS-SMB2 provides it so the server can start
/// reading ahead from its own storage instead of waiting for the next request.
/// Streaming GETs know exactly how much is left, so the hint is free to supply.
pub fn encode_read_request(
    buf: &mut BytesMut,
    file_id: &[u8; 16],
    offset: u64,
    length: u32,
    remaining_after: u32,
) {
    buf.put_u16_le(49); // StructureSize
    buf.put_u8(0); // Padding
    buf.put_u8(0); // Flags
    buf.put_u32_le(length); // Length
    buf.put_u64_le(offset); // Offset
    buf.put_slice(file_id); // FileId
    buf.put_u32_le(1); // MinimumCount
    buf.put_u32_le(0); // Channel
    buf.put_u32_le(remaining_after); // RemainingBytes (read-ahead hint)
    buf.put_u16_le(0); // ReadChannelInfoOffset
    buf.put_u16_le(0); // ReadChannelInfoLength
    buf.put_u8(0); // Buffer (padding byte)
}

/// Locate a read response's payload within its body (the bytes following the
/// 64-byte SMB2 header), as a `start..end` range into `body`.
///
/// `DataOffset` on the wire is absolute from the start of the SMB2 message, so
/// the minimum legitimate value points at the first byte of the Buffer field.
/// Anything below that overlaps the header or the read response's own fixed
/// fields (StructureSize, DataOffset, Reserved, DataLength, DataRemaining,
/// Flags = 16 bytes), and a malformed server response could otherwise make us
/// return header bytes — or the length fields themselves — as file payload.
/// Every read decoder below shares this one bounds check.
/// A successful READ must also carry at least one byte: MS-SMB2 requires the
/// response Buffer to be non-empty and signals "nothing left" with
/// `STATUS_END_OF_FILE`, which callers handle separately. Accepting a
/// zero-length payload here would hand the streaming loops a chunk that
/// advances their offset by nothing — a request for the same range, forever.
fn read_payload_range(body: &[u8]) -> Option<std::ops::Range<usize>> {
    if body.len() < READ_RESPONSE_FIXED_PART + 1 {
        return None;
    }
    let data_offset = u16::from_le_bytes(body[2..4].try_into().unwrap()) as usize;
    let data_length = u32::from_le_bytes(body[4..8].try_into().unwrap()) as usize;

    if data_length == 0 {
        return None;
    }
    let min_offset = SMB2_HEADER_SIZE + READ_RESPONSE_FIXED_PART;
    if data_offset < min_offset {
        return None;
    }
    let start = data_offset - SMB2_HEADER_SIZE;
    let end = start.checked_add(data_length)?;
    if end > body.len() {
        return None;
    }
    Some(start..end)
}

/// Zero-copy read decode — slices the payload out of a body that is already
/// reference-counted, without copying it. This is the form the transport uses:
/// every SMB response is read into one allocation and handed out as `Bytes`,
/// so a 256 KiB read costs one allocation and no payload memcpy.
pub fn decode_read_response_bytes(body: &Bytes) -> Option<Bytes> {
    let range = read_payload_range(body)?;
    Some(body.slice(range))
}

/// Zero-copy decode that takes ownership of the full SMB2 message (header +
/// body) and returns a `Bytes` slice referencing the response payload — for
/// the pipelined reader, which owns each frame as a `Bytes` and would otherwise
/// have to split the body off first.
pub fn decode_read_response_from_msg(msg: Bytes) -> Option<Bytes> {
    if msg.len() < SMB2_HEADER_SIZE {
        return None;
    }
    let range = read_payload_range(&msg[SMB2_HEADER_SIZE..])?;
    // Shift the body-relative range to absolute message offsets.
    let start = range.start + SMB2_HEADER_SIZE;
    let end = range.end + SMB2_HEADER_SIZE;
    Some(msg.slice(start..end))
}

/// Size of the read response's fixed fields (preceding the Buffer):
/// StructureSize(2) + DataOffset(1) + Reserved(1) + DataLength(4)
/// + DataRemaining(4) + Flags(4) = 16 bytes.
pub const READ_RESPONSE_FIXED_PART: usize = 16;

// ── Write ───────────────────────────────────────────────────────────────────

pub fn encode_write_request(buf: &mut BytesMut, file_id: &[u8; 16], offset: u64, data: &[u8]) {
    encode_write_request_header(buf, file_id, offset, data.len() as u32);
    buf.put_slice(data);
}

/// Fixed 48-byte WRITE request body (no payload). Used with vectored send so
/// the data slice is signed and written without a second memcpy into the frame.
pub fn encode_write_request_header(
    buf: &mut BytesMut,
    file_id: &[u8; 16],
    offset: u64,
    data_len: u32,
) {
    let data_offset = (SMB2_HEADER_SIZE + 48) as u16;
    buf.put_u16_le(49); // StructureSize
    buf.put_u16_le(data_offset); // DataOffset
    buf.put_u32_le(data_len); // Length
    buf.put_u64_le(offset); // Offset
    buf.put_slice(file_id); // FileId
    buf.put_u32_le(0); // Channel
    buf.put_u32_le(0); // RemainingBytes
    buf.put_u16_le(0); // WriteChannelInfoOffset
    buf.put_u16_le(0); // WriteChannelInfoLength
    buf.put_u32_le(0); // Flags
}

pub fn decode_write_response(body: &[u8]) -> Option<u32> {
    if body.len() < 16 {
        return None;
    }
    Some((&body[4..8]).get_u32_le()) // Count (bytes written)
}

// ── IOCTL / server-side copy ───────────────────────────────────────────────

/// Fetch an opaque 24-byte token identifying an open file, to be handed to the
/// server as the *source* of a server-side copy.
pub const FSCTL_SRV_REQUEST_RESUME_KEY: u32 = 0x0014_0078;

/// Ask the server to copy ranges from the resume-key'd source into the file the
/// request is issued on. The bytes never traverse the client connection.
pub const FSCTL_SRV_COPYCHUNK_WRITE: u32 = 0x0014_80F2;

/// `SMB2_0_IOCTL_IS_FSCTL` — the request is a file-system control code.
const SMB2_0_IOCTL_IS_FSCTL: u32 = 0x0000_0001;

/// One range to copy, as carried in an `SRV_COPYCHUNK_COPY` request.
#[derive(Debug, Clone, Copy)]
pub struct CopyChunk {
    pub source_offset: u64,
    pub target_offset: u64,
    pub length: u32,
}

/// Server's answer to a copychunk request. On success `total_bytes_written`
/// is what actually landed; on `STATUS_INVALID_PARAMETER` the same structure
/// carries the server's limits instead, which is how a client discovers how
/// to re-chunk the request (MS-SMB2 2.2.32.1).
#[derive(Debug, Clone, Copy)]
pub struct CopyChunkResponse {
    pub chunks_written: u32,
    pub chunk_bytes_written: u32,
    pub total_bytes_written: u32,
}

/// Encode an SMB2 IOCTL request carrying `input` for `ctl_code` on `file_id`.
///
/// `max_output_response` bounds what the server may return; callers charge
/// credits for it the same way reads do.
pub fn encode_ioctl_request(
    buf: &mut BytesMut,
    ctl_code: u32,
    file_id: &[u8; 16],
    input: &[u8],
    max_output_response: u32,
) {
    let input_offset = (SMB2_HEADER_SIZE + 56) as u32;
    buf.put_u16_le(57); // StructureSize
    buf.put_u16_le(0); // Reserved
    buf.put_u32_le(ctl_code); // CtlCode
    buf.put_slice(file_id); // FileId
    buf.put_u32_le(if input.is_empty() { 0 } else { input_offset }); // InputOffset
    buf.put_u32_le(input.len() as u32); // InputCount
    buf.put_u32_le(0); // MaxInputResponse
    buf.put_u32_le(0); // OutputOffset
    buf.put_u32_le(0); // OutputCount
    buf.put_u32_le(max_output_response); // MaxOutputResponse
    buf.put_u32_le(SMB2_0_IOCTL_IS_FSCTL); // Flags
    buf.put_u32_le(0); // Reserved2
    if input.is_empty() {
        // The fixed part claims 57 bytes, i.e. one byte of Buffer.
        buf.put_u8(0);
    } else {
        buf.put_slice(input);
    }
}

/// Extract an IOCTL response's output buffer.
///
/// Field layout (MS-SMB2 2.2.32): StructureSize(2) Reserved(2) CtlCode(4)
/// FileId(16) InputOffset(4) InputCount(4) OutputOffset(4) OutputCount(4)
/// Flags(4) Reserved2(4) — so OutputOffset starts at 32 and OutputCount at 36.
pub fn decode_ioctl_output(body: &[u8]) -> Option<&[u8]> {
    const IOCTL_RESPONSE_FIXED_PART: usize = 48;
    if body.len() < IOCTL_RESPONSE_FIXED_PART {
        return None;
    }
    let output_offset = u32::from_le_bytes(body[32..36].try_into().unwrap()) as usize;
    let output_count = u32::from_le_bytes(body[36..40].try_into().unwrap()) as usize;
    if output_count == 0 {
        return Some(&[]);
    }
    // OutputOffset is absolute from the start of the SMB2 message; anything
    // inside the header or the response's own fixed fields is malformed.
    if output_offset < SMB2_HEADER_SIZE + IOCTL_RESPONSE_FIXED_PART {
        return None;
    }
    let start = output_offset - SMB2_HEADER_SIZE;
    let end = start.checked_add(output_count)?;
    if end > body.len() {
        return None;
    }
    Some(&body[start..end])
}

/// The 24-byte resume key from an `FSCTL_SRV_REQUEST_RESUME_KEY` response.
pub fn decode_resume_key(output: &[u8]) -> Option<[u8; 24]> {
    if output.len() < 24 {
        return None;
    }
    let mut key = [0u8; 24];
    key.copy_from_slice(&output[..24]);
    Some(key)
}

/// Encode an `SRV_COPYCHUNK_COPY` structure: the source's resume key followed
/// by the ranges to copy (MS-SMB2 2.2.31.1).
pub fn encode_copychunk_input(buf: &mut BytesMut, resume_key: &[u8; 24], chunks: &[CopyChunk]) {
    buf.put_slice(resume_key); // SourceKey
    buf.put_u32_le(chunks.len() as u32); // ChunkCount
    buf.put_u32_le(0); // Reserved
    for c in chunks {
        buf.put_u64_le(c.source_offset);
        buf.put_u64_le(c.target_offset);
        buf.put_u32_le(c.length);
        buf.put_u32_le(0); // Reserved
    }
}

/// Decode an `SRV_COPYCHUNK_RESPONSE` (MS-SMB2 2.2.32.1).
pub fn decode_copychunk_response(output: &[u8]) -> Option<CopyChunkResponse> {
    if output.len() < 12 {
        return None;
    }
    Some(CopyChunkResponse {
        chunks_written: u32::from_le_bytes(output[0..4].try_into().unwrap()),
        chunk_bytes_written: u32::from_le_bytes(output[4..8].try_into().unwrap()),
        total_bytes_written: u32::from_le_bytes(output[8..12].try_into().unwrap()),
    })
}

// ── Echo (keepalive) ───────────────────────────────────────────────────────

/// SMB2 ECHO request — the protocol's keepalive. Body is just
/// `StructureSize(2) + Reserved(2)`; the server answers with the same shape.
/// Sent on connections that have been idle long enough for a server (or a
/// NAT/firewall in between) to have dropped the session without telling us:
/// the round trip proves the connection still carries traffic, and a transport
/// failure poisons it so the healer reconnects *before* a client request lands
/// on a dead connection.
pub fn encode_echo_request(buf: &mut BytesMut) {
    buf.put_u16_le(4); // StructureSize
    buf.put_u16_le(0); // Reserved
}

// ── Set Info (rename) ──────────────────────────────────────────────────────

/// SMB2 SET_INFO InfoType for file information.
const SMB2_0_INFO_FILE: u8 = 0x01;

/// FileRenameInformation class (MS-FSCC 2.4.34.2).
const FILE_RENAME_INFORMATION: u8 = 0x0A;

/// Encode a SET_INFO request for FileRenameInformation (rename/move a file).
///
/// `new_name` is the destination path relative to the share root, using
/// backslash separators (SMB convention). `replace_if_exists` controls
/// whether an existing file at the destination is overwritten.
pub fn encode_set_info_rename(
    buf: &mut BytesMut,
    file_id: &[u8; 16],
    new_name: &str,
    replace_if_exists: bool,
) {
    let name_bytes: Vec<u8> = new_name
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    // FileRenameInformation buffer:
    //   ReplaceIfExists (1) + Reserved (7) + RootDirectory (8) +
    //   FileNameLength (4) + FileName (variable)
    let info_len = 1 + 7 + 8 + 4 + name_bytes.len();

    // SET_INFO request StructureSize = 33 (fixed part = 32 + 1 buffer byte)
    let buffer_offset = (SMB2_HEADER_SIZE + 32) as u16;

    buf.put_u16_le(33); // StructureSize
    buf.put_u8(SMB2_0_INFO_FILE); // InfoType: SMB2_0_INFO_FILE
    buf.put_u8(FILE_RENAME_INFORMATION); // FileInfoClass
    buf.put_u32_le(info_len as u32); // BufferLength
    buf.put_u16_le(buffer_offset); // BufferOffset
    buf.put_u16_le(0); // Reserved
    buf.put_u32_le(0); // AdditionalInformation
    buf.put_slice(file_id); // FileId (16 bytes)

    // FileRenameInformation structure
    buf.put_u8(u8::from(replace_if_exists)); // ReplaceIfExists
    buf.put_slice(&[0u8; 7]); // Reserved
    buf.put_u64_le(0); // RootDirectory (0 = relative to share root)
    buf.put_u32_le(name_bytes.len() as u32); // FileNameLength
    buf.put_slice(&name_bytes); // FileName (UTF-16LE)
}

// ── Query Directory ─────────────────────────────────────────────────────────

pub const FILE_ID_BOTH_DIRECTORY_INFORMATION: u8 = 0x25;

/// `output_buffer_length` is how much directory data the server may return in
/// one response. It is the dominant cost of a large listing: at 64 KiB a
/// directory of ten thousand entries needs dozens of round trips, and each one
/// is a full RTT to the NAS. Callers pass the negotiated transact size (capped
/// — see `QUERY_DIR_BUFFER_MAX`) and must charge credits for the response they are
/// asking for, since the SMB2 credit charge is computed from the *expected
/// response* size, not the request.
pub fn encode_query_directory_request(
    buf: &mut BytesMut,
    file_id: &[u8; 16],
    pattern: &str,
    info_class: u8,
    restart: bool,
    output_buffer_length: u32,
) {
    let pattern_bytes: Vec<u8> = pattern
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let name_offset = (SMB2_HEADER_SIZE + 32) as u16;
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
    buf.put_u32_le(output_buffer_length); // OutputBufferLength
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
                .as_chunks::<2>()
                .0
                .iter()
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
        // A real entry is at least the 104-byte fixed header. A smaller nonzero
        // advance is malformed and would make the loop re-parse overlapping
        // bytes up to data.len() times (CPU/memory amplification) — stop.
        if next_entry_offset < 104 {
            break;
        }
        offset += next_entry_offset;
    }

    entries
}

// ── Compound request support ───────────────────────────────────────────────

/// Flag bit for related compound operations.
pub const SMB2_FLAGS_RELATED: u32 = 0x0000_0004;

/// Sentinel file ID — server substitutes the file ID from the preceding
/// Create response in a related compound chain.
pub const SENTINEL_FILE_ID: [u8; 16] = [0xFF; 16];

/// Encode a Close request with optional post-query attribute retrieval.
/// When `postquery` is true, the server returns file metadata in the response.
pub fn encode_close_request_ex(buf: &mut BytesMut, file_id: &[u8; 16], postquery: bool) {
    buf.put_u16_le(24); // StructureSize
    buf.put_u16_le(u16::from(postquery)); // Flags: SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB
    buf.put_u32_le(0); // Reserved
    buf.put_slice(file_id);
}

/// Parsed Close response (meaningful when postquery was requested).
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CloseResponse {
    pub last_write_time: u64,
    pub file_size: u64,
}

pub fn decode_close_response(body: &[u8]) -> Option<CloseResponse> {
    // Layout: StructureSize(2) + Flags(2) + Reserved(4) + CreationTime(8)
    // + LastAccessTime(8) + LastWriteTime(8) + ChangeTime(8)
    // + AllocationSize(8) + EndOfFile(8) + FileAttributes(4) = 60 bytes
    if body.len() < 56 {
        return None;
    }
    let last_write_time = u64::from_le_bytes(body[24..32].try_into().unwrap());
    let file_size = u64::from_le_bytes(body[48..56].try_into().unwrap());
    Some(CloseResponse {
        last_write_time,
        file_size,
    })
}

// ── Frame helpers ───────────────────────────────────────────────────────────

/// Prepend a 4-byte NetBIOS session length prefix to the packet.
pub fn frame_packet(header: &Header, body: &[u8]) -> BytesMut {
    let total = SMB2_HEADER_SIZE + body.len();
    let mut buf = BytesMut::with_capacity(4 + total);
    buf.put_u32((total as u32) & 0x00FF_FFFF); // NetBIOS length (big-endian, masked to 24 bits)
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

/// Parse an SMB2 compound response (multiple chained messages in one frame).
/// Each returned tuple is `(header, body)` where `body` is a zero-copy view of
/// the per-message payload following the 64-byte header — the whole frame
/// stays in the single allocation the transport read it into, so a compound
/// create+read+close does not memcpy its 64 KiB payload out. Returns the
/// messages successfully parsed up to the first malformed boundary (callers
/// rely on this for partial recovery).
pub fn parse_compound_response(msg: &Bytes) -> Vec<(Header, Bytes)> {
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

        results.push((header, msg.slice(body_start..body_end)));

        if next == 0 {
            break;
        }
        offset += next;
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Multi-credit charge ──────────────────────────────────────────

    #[test]
    fn credit_charge_matches_smb2_rule() {
        // CreditCharge = max(1, ceil(payload / 65536)). Single-credit up to and
        // including 64 KiB; multi-credit above. These charges are also the
        // MessageId stride the send paths must advance by.
        assert_eq!(credit_charge_for(0), 1);
        assert_eq!(credit_charge_for(1), 1);
        assert_eq!(credit_charge_for(65536), 1); // exactly 64 KiB = 1 credit
        assert_eq!(credit_charge_for(65537), 2);
        assert_eq!(credit_charge_for(131072), 2); // 128 KiB
        assert_eq!(credit_charge_for(262144), 4); // 256 KiB (default I/O)
        assert_eq!(credit_charge_for(1048576), 16); // 1 MiB
        assert_eq!(credit_charge_for(8 * 1024 * 1024), 128); // 8 MiB (server max)
    }

    // ── Header encode/decode round-trip ──────────────────────────────

    #[test]
    fn header_round_trip() {
        let mut hdr = Header::new(Command::Create, 42);
        hdr.session_id = 0xDEAD;
        hdr.tree_id = 7;
        hdr.flags = 0x04;
        hdr.credit_charge = 4;
        hdr.credits = 33;

        let mut buf = BytesMut::with_capacity(64);
        hdr.encode(&mut buf);

        let decoded = Header::decode(&buf).unwrap();
        assert_eq!(decoded.command, Command::Create as u16);
        assert_eq!(decoded.message_id, 42);
        assert_eq!(decoded.session_id, 0xDEAD);
        assert_eq!(decoded.tree_id, 7);
        assert_eq!(decoded.flags, 0x04);
        assert_eq!(decoded.credit_charge, 4);
        // The credits field round-trips — credit accounting banks this value
        // from every response (where it is CreditResponse, the grant).
        assert_eq!(decoded.credits, 33);
    }

    #[test]
    fn header_decode_too_short() {
        assert!(Header::decode(&[0u8; 32]).is_none());
    }

    #[test]
    fn header_decode_bad_magic() {
        let mut buf = [0u8; 64];
        buf[0..4].copy_from_slice(b"XXXX");
        assert!(Header::decode(&buf).is_none());
    }

    // ── NtStatus ─────────────────────────────────────────────────────

    #[test]
    fn nt_status_success_not_error() {
        assert!(!NtStatus::Success.is_error());
    }

    #[test]
    fn nt_status_not_found_is_error() {
        assert!(NtStatus::ObjectNameNotFound.is_error());
    }

    #[test]
    fn nt_status_no_more_files_not_error() {
        // 0x80000006 has high bit set but not both high bits
        assert!(!NtStatus::NoMoreFiles.is_error());
    }

    #[test]
    fn nt_status_known_codes() {
        assert_eq!(NtStatus::from_u32(0x00000000), NtStatus::Success);
        assert_eq!(NtStatus::from_u32(0xC000000F), NtStatus::NoSuchFile);
        assert_eq!(NtStatus::from_u32(0x80000006), NtStatus::NoMoreFiles);
        assert_eq!(
            NtStatus::from_u32(0xC000009A),
            NtStatus::InsufficientResources
        );
        assert_eq!(NtStatus::from_u32(0xC00000CE), NtStatus::TooManySessions);
        assert_eq!(NtStatus::from_u32(0xC00000D0), NtStatus::RequestNotAccepted);
    }

    #[test]
    fn nt_status_capacity_codes_are_errors() {
        assert!(NtStatus::InsufficientResources.is_error());
        assert!(NtStatus::TooManySessions.is_error());
        assert!(NtStatus::RequestNotAccepted.is_error());
        assert!(NtStatus::RemoteSessionLimit.is_error());
    }

    // ── Decode responses ─────────────────────────────────────────────

    #[test]
    fn decode_create_response_valid() {
        let mut body = vec![0u8; 88];
        // last_write_time at offset 24
        body[24..32].copy_from_slice(&100u64.to_le_bytes());
        // file_size at offset 48
        body[48..56].copy_from_slice(&42u64.to_le_bytes());
        // file_id at offset 64
        body[64..80].copy_from_slice(&[1u8; 16]);

        let resp = decode_create_response(&body).unwrap();
        assert_eq!(resp.last_write_time, 100);
        assert_eq!(resp.file_size, 42);
        assert_eq!(resp.file_id, [1u8; 16]);
    }

    #[test]
    fn decode_create_response_too_short() {
        assert!(decode_create_response(&[0u8; 10]).is_none());
    }

    #[test]
    fn encode_create_request_empty_path_emits_buffer_byte() {
        // Opening the share root (e.g. ListObjectsV2 with no prefix) uses an
        // empty name. StructureSize is 57 = 56 fixed bytes + 1 mandatory buffer
        // byte, so the body must be 57 bytes even with no name. A 56-byte body
        // is rejected by servers with STATUS_INVALID_PARAMETER (0xC000000D).
        let mut buf = BytesMut::new();
        encode_create_request(&mut buf, "", 0, 0, 0, 0);
        assert_eq!(buf.len(), 57, "empty-name CREATE body must be 57 bytes");
        assert_eq!((&buf[0..2]).get_u16_le(), 57, "StructureSize"); // StructureSize
        assert_eq!((&buf[46..48]).get_u16_le(), 0, "NameLength"); // NameLength
    }

    #[test]
    fn encode_create_request_named_path() {
        let mut buf = BytesMut::new();
        encode_create_request(&mut buf, "x", 0, 0, 0, 0);
        // 56-byte fixed part + UTF-16 name ("x" = 2 bytes).
        assert_eq!(buf.len(), 58);
        assert_eq!((&buf[46..48]).get_u16_le(), 2, "NameLength"); // NameLength
    }

    #[test]
    fn encode_create_request_delete_on_close() {
        // DeleteObject opens the file with FILE_DELETE_ON_CLOSE (0x1000) set in
        // CreateOptions, alongside NON_DIRECTORY_FILE (0x40) — exactly what
        // `ShareSession::delete_object` passes so the file is removed when the
        // handle closes. Verify the delete access, Open disposition, and the
        // delete-on-close option all land at their wire offsets in the body.
        const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;
        let create_options = CreateOptions::NonDirectoryFile as u32 | FILE_DELETE_ON_CLOSE;
        let mut buf = BytesMut::new();
        encode_create_request(
            &mut buf,
            "stale.bin",
            DesiredAccess::Delete as u32,
            ShareAccess::Delete as u32,
            CreateDisposition::Open as u32,
            create_options,
        );
        // Field offsets within the CREATE request body (SMB2 header excluded).
        assert_eq!(
            (&buf[24..28]).get_u32_le(),
            DesiredAccess::Delete as u32,
            "DesiredAccess"
        );
        assert_eq!(
            (&buf[36..40]).get_u32_le(),
            CreateDisposition::Open as u32,
            "CreateDisposition"
        );
        let opts = (&buf[40..44]).get_u32_le();
        assert_eq!(opts, create_options, "CreateOptions");
        assert_ne!(opts & FILE_DELETE_ON_CLOSE, 0, "DELETE_ON_CLOSE bit set");
    }

    /// Build a read-response body carrying `payload` at the minimum legal
    /// data offset — the shape every read decoder is expected to accept.
    fn read_response_body(payload: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8; READ_RESPONSE_FIXED_PART + payload.len()];
        let offset = (SMB2_HEADER_SIZE + READ_RESPONSE_FIXED_PART) as u16;
        body[2..4].copy_from_slice(&offset.to_le_bytes());
        body[4..8].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        body[READ_RESPONSE_FIXED_PART..].copy_from_slice(payload);
        body
    }

    /// Build an IOCTL response body carrying `output` at the minimum legal
    /// offset, per MS-SMB2 2.2.32.
    fn ioctl_response_body(output: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8; 48 + output.len()];
        body[0..2].copy_from_slice(&49u16.to_le_bytes()); // StructureSize
        let offset = (SMB2_HEADER_SIZE + 48) as u32;
        body[32..36].copy_from_slice(&offset.to_le_bytes()); // OutputOffset
        body[36..40].copy_from_slice(&(output.len() as u32).to_le_bytes()); // OutputCount
        body[48..].copy_from_slice(output);
        body
    }

    #[test]
    fn decode_ioctl_output_reads_the_output_buffer() {
        // Guards the field offsets: landing on Flags/Reserved2 instead of
        // OutputOffset/OutputCount yields a zero-length or rejected buffer,
        // which is exactly how a wrong layout shows up against a real server.
        let body = ioctl_response_body(b"payload-bytes");
        assert_eq!(decode_ioctl_output(&body).unwrap(), b"payload-bytes");

        // An offset inside the response's own fixed fields is rejected.
        let mut bad = ioctl_response_body(b"payload-bytes");
        bad[32..36].copy_from_slice(&((SMB2_HEADER_SIZE + 4) as u32).to_le_bytes());
        assert!(decode_ioctl_output(&bad).is_none());

        // A length running past the body is rejected.
        let mut over = ioctl_response_body(b"short");
        over[36..40].copy_from_slice(&9999u32.to_le_bytes());
        assert!(decode_ioctl_output(&over).is_none());
    }

    #[test]
    fn decode_resume_key_needs_24_bytes() {
        let key: Vec<u8> = (0..24u8).collect();
        let body = ioctl_response_body(&key);
        let decoded = decode_resume_key(decode_ioctl_output(&body).unwrap()).unwrap();
        assert_eq!(&decoded[..], &key[..]);
        assert!(decode_resume_key(&key[..23]).is_none());
    }

    #[test]
    fn copychunk_round_trips_through_the_wire_format() {
        let key = [7u8; 24];
        let chunks = [
            CopyChunk {
                source_offset: 0,
                target_offset: 0,
                length: 1024,
            },
            CopyChunk {
                source_offset: 1024,
                target_offset: 1024,
                length: 512,
            },
        ];
        let mut buf = BytesMut::new();
        encode_copychunk_input(&mut buf, &key, &chunks);
        // SourceKey(24) + ChunkCount(4) + Reserved(4) + 2 * Chunk(24)
        assert_eq!(buf.len(), 24 + 8 + 2 * 24);
        assert_eq!(&buf[..24], &key[..]);
        assert_eq!(u32::from_le_bytes(buf[24..28].try_into().unwrap()), 2);
        assert_eq!(u64::from_le_bytes(buf[32..40].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(buf[48..52].try_into().unwrap()), 1024);

        let mut out = vec![0u8; 12];
        out[0..4].copy_from_slice(&2u32.to_le_bytes());
        out[4..8].copy_from_slice(&1024u32.to_le_bytes());
        out[8..12].copy_from_slice(&1536u32.to_le_bytes());
        let resp = decode_copychunk_response(&out).unwrap();
        assert_eq!(resp.chunks_written, 2);
        assert_eq!(resp.total_bytes_written, 1536);
    }

    #[test]
    fn decode_read_response_bytes_valid() {
        let shared = Bytes::from(read_response_body(b"hello"));
        assert_eq!(&decode_read_response_bytes(&shared).unwrap()[..], b"hello");
    }

    #[test]
    fn decode_read_response_bytes_too_short() {
        assert!(decode_read_response_bytes(&Bytes::from_static(&[0u8; 5])).is_none());
    }

    #[test]
    fn decode_read_response_bytes_rejects_offset_in_response_fixed_fields() {
        // An offset pointing inside the 16-byte read-response fixed fields
        // would otherwise leak those bytes as the file payload.
        let mut bad = read_response_body(b"payload");
        bad[2..4].copy_from_slice(&((SMB2_HEADER_SIZE + 4) as u16).to_le_bytes());
        assert!(decode_read_response_bytes(&Bytes::from(bad)).is_none());
    }

    #[test]
    fn decode_read_response_bytes_is_a_view_not_a_copy() {
        // The whole point of the Bytes variant: the payload must alias the
        // response buffer rather than allocate a second copy of it.
        let shared = Bytes::from(read_response_body(b"aliased"));
        let payload = decode_read_response_bytes(&shared).unwrap();
        assert_eq!(
            payload.as_ptr(),
            shared[READ_RESPONSE_FIXED_PART..].as_ptr(),
            "payload should point into the response buffer"
        );
    }

    #[test]
    fn decode_read_response_rejects_zero_length_payload() {
        // MS-SMB2 requires a successful READ to carry at least one byte and
        // reports "nothing left" as STATUS_END_OF_FILE. Accepting a
        // zero-length payload would hand the streaming loops a chunk that
        // advances their offset by nothing — re-reading the same range
        // forever. Both decoders must refuse it.
        let body = read_response_body(b"");
        assert!(decode_read_response_bytes(&Bytes::from(body.clone())).is_none());

        let mut msg = vec![0u8; SMB2_HEADER_SIZE];
        msg.extend_from_slice(&body);
        assert!(decode_read_response_from_msg(Bytes::from(msg)).is_none());
    }

    #[test]
    fn decode_read_response_from_msg_valid() {
        // Build a complete SMB2 message: 64-byte header + body. data_offset
        // and data_length are measured from the start of the SMB2 message,
        // matching the wire format.
        let mut msg = vec![0u8; SMB2_HEADER_SIZE + 32];
        let body = &mut msg[SMB2_HEADER_SIZE..];
        let data_offset = (SMB2_HEADER_SIZE + 16) as u16;
        body[2..4].copy_from_slice(&data_offset.to_le_bytes());
        body[4..8].copy_from_slice(&5u32.to_le_bytes());
        body[16..21].copy_from_slice(b"hello");

        let data = decode_read_response_from_msg(Bytes::from(msg)).unwrap();
        assert_eq!(&data[..], b"hello");
    }

    #[test]
    fn decode_read_response_from_msg_too_short() {
        assert!(
            decode_read_response_from_msg(Bytes::from(vec![0u8; SMB2_HEADER_SIZE + 5])).is_none()
        );
        assert!(decode_read_response_from_msg(Bytes::from(vec![0u8; 10])).is_none());
    }

    #[test]
    fn decode_read_response_from_msg_rejects_overflow_length() {
        // data_length that would extend past the buffer is rejected.
        let mut msg = vec![0u8; SMB2_HEADER_SIZE + 32];
        let body = &mut msg[SMB2_HEADER_SIZE..];
        let data_offset = (SMB2_HEADER_SIZE + 16) as u16;
        body[2..4].copy_from_slice(&data_offset.to_le_bytes());
        body[4..8].copy_from_slice(&1_000_000u32.to_le_bytes());
        assert!(decode_read_response_from_msg(Bytes::from(msg)).is_none());
    }

    #[test]
    fn decode_read_response_from_msg_rejects_offset_inside_header() {
        // A malformed server response with data_offset < SMB2_HEADER_SIZE
        // would otherwise have us slice into the SMB2 header bytes and return
        // them as payload. The decoder must reject that case.
        let mut msg = vec![0u8; SMB2_HEADER_SIZE + 32];
        // Seed the header with a sentinel so we'd notice if it ever leaked
        // back as payload.
        for (i, b) in msg[..SMB2_HEADER_SIZE].iter_mut().enumerate() {
            *b = 0xA0 | (i as u8 & 0x0F);
        }
        let body = &mut msg[SMB2_HEADER_SIZE..];
        // data_offset = 16 (inside the header, well before SMB2_HEADER_SIZE).
        body[2..4].copy_from_slice(&16u16.to_le_bytes());
        body[4..8].copy_from_slice(&8u32.to_le_bytes());
        assert!(decode_read_response_from_msg(Bytes::from(msg)).is_none());
    }

    #[test]
    fn decode_read_response_from_msg_rejects_offset_zero() {
        // data_offset = 0 is also inside the header.
        let mut msg = vec![0u8; SMB2_HEADER_SIZE + 32];
        let body = &mut msg[SMB2_HEADER_SIZE..];
        body[2..4].copy_from_slice(&0u16.to_le_bytes());
        body[4..8].copy_from_slice(&4u32.to_le_bytes());
        assert!(decode_read_response_from_msg(Bytes::from(msg)).is_none());
    }

    #[test]
    fn decode_read_response_from_msg_rejects_offset_in_response_fixed_fields() {
        // data_offset that points inside the read response's fixed fields
        // (StructureSize/DataOffset/Reserved/DataLength/DataRemaining/Flags
        // — 16 bytes after the SMB2 header) would otherwise leak the
        // response's own structural fields back as the file payload.
        let mut msg = vec![0u8; SMB2_HEADER_SIZE + 32];
        let body = &mut msg[SMB2_HEADER_SIZE..];
        // Offset = SMB2_HEADER_SIZE + 4 — points inside DataLength.
        let bad_offset = (SMB2_HEADER_SIZE + 4) as u16;
        body[2..4].copy_from_slice(&bad_offset.to_le_bytes());
        body[4..8].copy_from_slice(&4u32.to_le_bytes());
        assert!(decode_read_response_from_msg(Bytes::from(msg)).is_none());

        // Offset = SMB2_HEADER_SIZE + 15 — one byte short of the buffer.
        let mut msg = vec![0u8; SMB2_HEADER_SIZE + 32];
        let body = &mut msg[SMB2_HEADER_SIZE..];
        let bad_offset = (SMB2_HEADER_SIZE + 15) as u16;
        body[2..4].copy_from_slice(&bad_offset.to_le_bytes());
        body[4..8].copy_from_slice(&4u32.to_le_bytes());
        assert!(decode_read_response_from_msg(Bytes::from(msg)).is_none());
    }

    #[test]
    fn decode_read_response_from_msg_accepts_minimum_valid_offset() {
        // SMB2_HEADER_SIZE + 16 is the first byte of the Buffer field —
        // the smallest legitimate data_offset. Make sure we don't
        // over-reject the boundary.
        let payload = b"data";
        let mut msg = vec![0u8; SMB2_HEADER_SIZE + READ_RESPONSE_FIXED_PART + payload.len()];
        let body = &mut msg[SMB2_HEADER_SIZE..];
        let min_offset = (SMB2_HEADER_SIZE + READ_RESPONSE_FIXED_PART) as u16;
        body[2..4].copy_from_slice(&min_offset.to_le_bytes());
        body[4..8].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        let buf_start = SMB2_HEADER_SIZE + READ_RESPONSE_FIXED_PART;
        msg[buf_start..buf_start + payload.len()].copy_from_slice(payload);

        let data = decode_read_response_from_msg(Bytes::from(msg)).unwrap();
        assert_eq!(&data[..], payload);
    }

    #[test]
    fn decode_write_response_valid() {
        let mut body = vec![0u8; 16];
        body[4..8].copy_from_slice(&1024u32.to_le_bytes());
        assert_eq!(decode_write_response(&body), Some(1024));
    }

    #[test]
    fn decode_write_response_too_short() {
        assert!(decode_write_response(&[0u8; 8]).is_none());
    }

    #[test]
    fn decode_close_response_valid() {
        let mut body = vec![0u8; 60];
        body[24..32].copy_from_slice(&999u64.to_le_bytes()); // last_write_time
        body[48..56].copy_from_slice(&4096u64.to_le_bytes()); // file_size
        let resp = decode_close_response(&body).unwrap();
        assert_eq!(resp.last_write_time, 999);
        assert_eq!(resp.file_size, 4096);
    }

    #[test]
    fn decode_close_response_too_short() {
        assert!(decode_close_response(&[0u8; 20]).is_none());
    }

    // ── Directory entry parsing ──────────────────────────────────────

    #[test]
    fn parse_directory_entries_single() {
        // Build a minimal FileIdBothDirectoryInformation entry
        let name = "test.txt";
        let name_utf16: Vec<u8> = name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let entry_size = 104 + name_utf16.len();
        let mut data = vec![0u8; entry_size];
        // next_entry_offset = 0 (last entry)
        // file_size at offset 40
        data[40..48].copy_from_slice(&512u64.to_le_bytes());
        // file_attributes at offset 56 (0x20 = ARCHIVE = regular file)
        data[56..60].copy_from_slice(&0x20u32.to_le_bytes());
        // file_name_length at offset 60
        data[60..64].copy_from_slice(&(name_utf16.len() as u32).to_le_bytes());
        // file_name at offset 104
        data[104..].copy_from_slice(&name_utf16);

        let entries = parse_directory_entries(&data);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].file_name, "test.txt");
        assert_eq!(entries[0].file_size, 512);
        assert!(!entries[0].is_directory());
    }

    #[test]
    fn parse_directory_entries_skips_dot() {
        let name = ".";
        let name_utf16: Vec<u8> = name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let entry_size = 104 + name_utf16.len();
        let mut data = vec![0u8; entry_size];
        data[56..60].copy_from_slice(&0x10u32.to_le_bytes()); // directory
        data[60..64].copy_from_slice(&(name_utf16.len() as u32).to_le_bytes());
        data[104..].copy_from_slice(&name_utf16);

        let entries = parse_directory_entries(&data);
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_directory_entries_empty() {
        assert!(parse_directory_entries(&[]).is_empty());
    }

    #[test]
    fn parse_directory_entries_stops_on_sub_entry_advance() {
        // A nonzero next_entry_offset smaller than the 104-byte fixed header is
        // malformed; the parser must stop rather than re-parse overlapping
        // bytes (a CPU/memory amplification vector). With the guard, a single
        // entry is returned; without it, the small advance would yield more.
        let mut data = vec![0u8; 300];
        data[0..4].copy_from_slice(&50u32.to_le_bytes()); // next_entry_offset = 50 (< 104)
        // file_name_length (offset 60) stays 0.
        assert_eq!(parse_directory_entries(&data).len(), 1);
    }

    #[test]
    fn session_setup_rejects_offset_inside_header() {
        // A SecurityBufferOffset below the 64-byte SMB2 header is malformed and
        // must be rejected, not clamped to read garbage as the auth blob.
        let hdr = Header::new(Command::SessionSetup, 1);
        let mut body = vec![0u8; 16];
        body[4..6].copy_from_slice(&10u16.to_le_bytes()); // offset 10 (< 64)
        body[6..8].copy_from_slice(&4u16.to_le_bytes());
        assert!(decode_session_setup_response(&hdr, &body).is_none());
    }

    #[test]
    fn directory_entry_is_directory() {
        let entry = DirectoryEntry {
            file_name: "dir".into(),
            file_size: 0,
            file_attributes: 0x10,
            last_write_time: 0,
        };
        assert!(entry.is_directory());

        let file = DirectoryEntry {
            file_name: "f".into(),
            file_size: 100,
            file_attributes: 0x20,
            last_write_time: 0,
        };
        assert!(!file.is_directory());
    }

    // ── Frame helpers ────────────────────────────────────────────────

    #[test]
    fn build_request_has_netbios_header() {
        let hdr = Header::new(Command::Close, 0);
        let packet = build_request(&hdr, |buf| {
            encode_close_request(buf, &[0u8; 16]);
        });
        // First 4 bytes are big-endian NetBIOS length
        let netbios_len = u32::from_be_bytes(packet[0..4].try_into().unwrap());
        assert_eq!(netbios_len as usize, packet.len() - 4);
        // SMB2 magic at offset 4
        assert_eq!(&packet[4..8], SMB2_MAGIC);
    }

    // ── Encode request sizes ─────────────────────────────────────────

    #[test]
    fn encode_close_request_size() {
        let mut buf = BytesMut::new();
        encode_close_request(&mut buf, &[0u8; 16]);
        assert_eq!(buf.len(), 24); // StructureSize(2) + Flags(2) + Reserved(4) + FileId(16)
    }

    #[test]
    fn encode_close_request_ex_postquery_flag() {
        let mut buf = BytesMut::new();
        encode_close_request_ex(&mut buf, &SENTINEL_FILE_ID, true);
        assert_eq!(u16::from_le_bytes(buf[2..4].try_into().unwrap()), 1);

        let mut buf2 = BytesMut::new();
        encode_close_request_ex(&mut buf2, &SENTINEL_FILE_ID, false);
        assert_eq!(u16::from_le_bytes(buf2[2..4].try_into().unwrap()), 0);
    }

    #[test]
    fn encode_read_request_size() {
        let mut buf = BytesMut::new();
        encode_read_request(&mut buf, &[0u8; 16], 0, 65536, 0);
        assert_eq!(buf.len(), 49);
    }

    #[test]
    fn encode_write_request_includes_data() {
        let mut buf = BytesMut::new();
        let data = b"hello";
        encode_write_request(&mut buf, &[0u8; 16], 0, data);
        assert_eq!(buf.len(), 48 + data.len()); // fixed part + data
    }

    // ── encode_set_info_rename ──────────────────────────────────────

    #[test]
    fn set_info_rename_structure_size() {
        let mut buf = BytesMut::new();
        encode_set_info_rename(&mut buf, &[0u8; 16], "test", false);
        assert_eq!(u16::from_le_bytes(buf[0..2].try_into().unwrap()), 33);
    }

    #[test]
    fn set_info_rename_info_type_and_class() {
        let mut buf = BytesMut::new();
        encode_set_info_rename(&mut buf, &[0u8; 16], "test", false);
        assert_eq!(buf[2], 0x01); // SMB2_0_INFO_FILE
        assert_eq!(buf[3], 0x0A); // FILE_RENAME_INFORMATION
    }

    #[test]
    fn set_info_rename_buffer_offset() {
        let mut buf = BytesMut::new();
        encode_set_info_rename(&mut buf, &[0u8; 16], "test", false);
        let offset = u16::from_le_bytes(buf[8..10].try_into().unwrap());
        // BufferOffset = SMB2_HEADER_SIZE (64) + fixed part (32)
        assert_eq!(offset as usize, SMB2_HEADER_SIZE + 32);
    }

    #[test]
    fn set_info_rename_file_id() {
        let file_id = [0xAA; 16];
        let mut buf = BytesMut::new();
        encode_set_info_rename(&mut buf, &file_id, "x", false);
        // FileId at offset 16 (after StructureSize+InfoType+Class+BufferLength+BufferOffset+Reserved+AdditionalInfo)
        assert_eq!(&buf[16..32], &file_id);
    }

    #[test]
    fn set_info_rename_buffer_length() {
        let path = "dir\\file.txt";
        let mut buf = BytesMut::new();
        encode_set_info_rename(&mut buf, &[0u8; 16], path, false);
        let buffer_length = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let name_utf16_len = path.encode_utf16().count() * 2;
        // info_len = ReplaceIfExists(1) + Reserved(7) + RootDirectory(8) + FileNameLength(4) + FileName
        assert_eq!(buffer_length as usize, 1 + 7 + 8 + 4 + name_utf16_len);
    }

    #[test]
    fn set_info_rename_replace_flag_false() {
        let mut buf = BytesMut::new();
        encode_set_info_rename(&mut buf, &[0u8; 16], "test", false);
        // FileRenameInformation starts at byte 32 (after SetInfo fixed part)
        assert_eq!(buf[32], 0);
    }

    #[test]
    fn set_info_rename_replace_flag_true() {
        let mut buf = BytesMut::new();
        encode_set_info_rename(&mut buf, &[0u8; 16], "test", true);
        assert_eq!(buf[32], 1);
    }

    #[test]
    fn set_info_rename_reserved_zeroed() {
        let mut buf = BytesMut::new();
        encode_set_info_rename(&mut buf, &[0u8; 16], "test", false);
        // Reserved (7 bytes) at offset 33..40
        assert_eq!(&buf[33..40], &[0u8; 7]);
        // RootDirectory (8 bytes) at offset 40..48
        assert_eq!(
            u64::from_le_bytes(buf[40..48].try_into().unwrap()),
            0,
            "RootDirectory must be zero for share-relative renames"
        );
    }

    #[test]
    fn set_info_rename_file_name_utf16() {
        let path = "foo\\bar.txt";
        let mut buf = BytesMut::new();
        encode_set_info_rename(&mut buf, &[0u8; 16], path, false);

        // FileNameLength at offset 48..52
        let name_len = u32::from_le_bytes(buf[48..52].try_into().unwrap()) as usize;
        let expected: Vec<u8> = path.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        assert_eq!(name_len, expected.len());

        // FileName starts at offset 52
        assert_eq!(&buf[52..52 + name_len], &expected[..]);
    }

    #[test]
    fn set_info_rename_empty_path() {
        let mut buf = BytesMut::new();
        encode_set_info_rename(&mut buf, &[0u8; 16], "", false);
        let name_len = u32::from_le_bytes(buf[48..52].try_into().unwrap());
        assert_eq!(name_len, 0);
        // Total buffer: fixed SetInfo (32) + FileRenameInfo fixed (20) + name (0) = 52
        assert_eq!(buf.len(), 52);
    }

    #[test]
    fn set_info_rename_total_size() {
        let path = "test";
        let mut buf = BytesMut::new();
        encode_set_info_rename(&mut buf, &[0u8; 16], path, false);
        let name_utf16_len = path.encode_utf16().count() * 2;
        // SetInfo fixed (32) + ReplaceIfExists(1) + Reserved(7) + RootDirectory(8)
        // + FileNameLength(4) + FileName
        assert_eq!(buf.len(), 32 + 1 + 7 + 8 + 4 + name_utf16_len);
    }

    #[test]
    fn set_info_rename_unicode_path() {
        // Test with non-ASCII characters
        let path = "données\\fichier.txt";
        let mut buf = BytesMut::new();
        encode_set_info_rename(&mut buf, &[0u8; 16], path, true);
        let name_len = u32::from_le_bytes(buf[48..52].try_into().unwrap()) as usize;
        let expected: Vec<u8> = path.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        assert_eq!(name_len, expected.len());
        assert_eq!(&buf[52..52 + name_len], &expected[..]);
    }

    // ── parse_compound_response ──────────────────────────────────────

    /// Build a synthetic compound response payload of `n` chained messages,
    /// each carrying `body_len` bytes of body. Returns the wire-format bytes
    /// (with each message's `next_command` set to point at the next).
    fn build_compound(n: usize, body_len: usize) -> Bytes {
        let entry_size = SMB2_HEADER_SIZE + body_len;
        let mut out = Vec::with_capacity(entry_size * n);
        for i in 0..n {
            let mut hdr = Header::new(Command::Read, i as u64);
            hdr.next_command = if i + 1 < n { entry_size as u32 } else { 0 };
            let mut buf = BytesMut::with_capacity(entry_size);
            hdr.encode(&mut buf);
            buf.extend_from_slice(&vec![0xABu8; body_len]);
            out.extend_from_slice(&buf);
        }
        Bytes::from(out)
    }

    #[test]
    fn parse_compound_response_single_message() {
        let msg = build_compound(1, 32);
        let parts = parse_compound_response(&msg);
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].0.message_id, 0);
        assert_eq!(parts[0].1.len(), 32);
        assert!(parts[0].1.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn parse_compound_response_multiple_messages() {
        let msg = build_compound(4, 24);
        let parts = parse_compound_response(&msg);
        assert_eq!(parts.len(), 4);
        for (i, (h, body)) in parts.iter().enumerate() {
            assert_eq!(h.message_id, i as u64);
            assert_eq!(body.len(), 24);
        }
    }

    #[test]
    fn parse_compound_response_empty_input() {
        assert!(parse_compound_response(&Bytes::new()).is_empty());
    }

    #[test]
    fn parse_compound_response_truncated_header() {
        let msg = build_compound(2, 16);
        // Lop off bytes inside the second message's header — should yield only the first.
        let truncated = msg.slice(..SMB2_HEADER_SIZE + 16 + 32);
        let parts = parse_compound_response(&truncated);
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].0.message_id, 0);
    }

    #[test]
    fn parse_compound_response_bad_next_command_yields_no_parts() {
        // Forge a next_command that points past end of buffer.
        let mut msg = build_compound(2, 8).to_vec();
        // next_command field is at byte offset 20 (header offset of next_command).
        msg[20..24].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let parts = parse_compound_response(&Bytes::from(msg));
        // When the first message's `next_command` overflows the buffer, the
        // parser bails before pushing anything — both messages are dropped.
        // This documents the current behavior rather than implying partial
        // recovery.
        assert_eq!(parts.len(), 0);
    }
}
