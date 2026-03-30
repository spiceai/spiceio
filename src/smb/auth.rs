//! NTLMv2 authentication for SMB2 sessions.
//!
//! Implements the NTLM challenge-response protocol using macOS CommonCrypto
//! (via our `crypto` module). No external auth crate needed.

use crate::crypto;
use bytes::{BufMut, Bytes, BytesMut};

// ── NTLMSSP message types ───────────────────────────────────────────────────

const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";
const NTLMSSP_NEGOTIATE: u32 = 1;
const NTLMSSP_CHALLENGE: u32 = 2;
const NTLMSSP_AUTH: u32 = 3;

// Negotiate flags
const NTLMSSP_NEGOTIATE_UNICODE: u32 = 0x00000001;
const NTLMSSP_NEGOTIATE_NTLM: u32 = 0x00000200;
const NTLMSSP_REQUEST_TARGET: u32 = 0x00000004;
const NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x00080000;
const NTLMSSP_NEGOTIATE_VERSION: u32 = 0x02000000;

/// Build the NTLMSSP Negotiate (Type 1) message.
pub fn build_negotiate_message() -> Bytes {
    let mut buf = BytesMut::with_capacity(40);
    buf.put_slice(NTLMSSP_SIGNATURE);
    buf.put_u32_le(NTLMSSP_NEGOTIATE);
    // Flags
    let flags = NTLMSSP_NEGOTIATE_UNICODE
        | NTLMSSP_NEGOTIATE_NTLM
        | NTLMSSP_REQUEST_TARGET
        | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        | NTLMSSP_NEGOTIATE_VERSION;
    buf.put_u32_le(flags);
    // DomainNameFields (Len, MaxLen, Offset) = 0
    buf.put_u16_le(0);
    buf.put_u16_le(0);
    buf.put_u32_le(0);
    // WorkstationFields = 0
    buf.put_u16_le(0);
    buf.put_u16_le(0);
    buf.put_u32_le(0);
    // Version (8 bytes)
    put_ntlm_version(&mut buf);
    buf.freeze()
}

fn put_ntlm_version(buf: &mut BytesMut) {
    buf.put_u8(10); // ProductMajorVersion
    buf.put_u8(0); // ProductMinorVersion
    buf.put_u16_le(0); // ProductBuild
    buf.put_slice(&[0u8; 3]); // Reserved
    buf.put_u8(0x0f); // NTLMRevisionCurrent
}

/// Parsed NTLMSSP Challenge (Type 2) message fields.
#[derive(Debug)]
pub struct ChallengeMessage {
    pub server_challenge: [u8; 8],
    pub negotiate_flags: u32,
    pub target_info: Vec<u8>,
}

/// Parse an NTLMSSP Challenge (Type 2) message.
pub fn parse_challenge_message(data: &[u8]) -> Option<ChallengeMessage> {
    if data.len() < 32 || &data[0..8] != NTLMSSP_SIGNATURE {
        return None;
    }
    let msg_type = u32::from_le_bytes(data[8..12].try_into().ok()?);
    if msg_type != NTLMSSP_CHALLENGE {
        return None;
    }

    let negotiate_flags = u32::from_le_bytes(data[20..24].try_into().ok()?);

    let mut server_challenge = [0u8; 8];
    server_challenge.copy_from_slice(&data[24..32]);

    // TargetInfo is at TargetInfoFields (offset 40 in the message)
    let target_info = if data.len() >= 48 {
        let ti_len = u16::from_le_bytes(data[40..42].try_into().ok()?) as usize;
        let ti_offset = u32::from_le_bytes(data[44..48].try_into().ok()?) as usize;
        if ti_offset + ti_len <= data.len() {
            data[ti_offset..ti_offset + ti_len].to_vec()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    Some(ChallengeMessage {
        server_challenge,
        negotiate_flags,
        target_info,
    })
}

/// Compute NTLMv2 hash: HMAC_MD5(MD4(UTF16LE(password)), UTF16LE(UPPER(username) + domain))
fn ntlmv2_hash(username: &str, password: &str, domain: &str) -> [u8; 16] {
    // NT hash = MD4(UTF16LE(password))
    let password_utf16: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let nt_hash = crypto::md4(&password_utf16);

    // NTLMv2 hash = HMAC_MD5(nt_hash, UTF16LE(UPPER(username) + domain))
    let user_domain = format!("{}{}", username.to_uppercase(), domain);
    let ud_utf16: Vec<u8> = user_domain
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    crypto::hmac_md5(&nt_hash, &ud_utf16)
}

/// Build the NTLMSSP Authenticate (Type 3) message.
/// Returns (message_bytes, session_base_key).
pub fn build_authenticate_message(
    challenge: &ChallengeMessage,
    username: &str,
    password: &str,
    domain: &str,
    workstation: &str,
) -> (Bytes, [u8; 16]) {
    let ntlmv2_hash = ntlmv2_hash(username, password, domain);

    // Generate client challenge (8 random bytes)
    let client_challenge = generate_client_challenge();

    // Build NTLMv2 client blob
    let blob = build_ntlmv2_blob(&client_challenge, &challenge.target_info);

    // Concatenate server challenge + blob for HMAC input
    let mut hmac_input = Vec::with_capacity(8 + blob.len());
    hmac_input.extend_from_slice(&challenge.server_challenge);
    hmac_input.extend_from_slice(&blob);

    // NTProofStr = HMAC_MD5(ntlmv2_hash, server_challenge + blob)
    let nt_proof_str = crypto::hmac_md5(&ntlmv2_hash, &hmac_input);

    // NtChallengeResponse = NTProofStr + blob
    let mut nt_response = Vec::with_capacity(16 + blob.len());
    nt_response.extend_from_slice(&nt_proof_str);
    nt_response.extend_from_slice(&blob);

    // Session base key = HMAC_MD5(ntlmv2_hash, NTProofStr)
    let session_base_key = crypto::hmac_md5(&ntlmv2_hash, &nt_proof_str);

    // Encode fields in UTF-16LE
    let domain_bytes: Vec<u8> = domain
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let user_bytes: Vec<u8> = username
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let ws_bytes: Vec<u8> = workstation
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    // LM response — for NTLMv2, just 24 zero bytes
    let lm_response = [0u8; 24];

    // Calculate offsets (Type 3 header: 64 base + 8 Version = 72 bytes)
    let payload_offset = 72u32;
    let lm_offset = payload_offset;
    let nt_offset = lm_offset + lm_response.len() as u32;
    let domain_offset = nt_offset + nt_response.len() as u32;
    let user_offset = domain_offset + domain_bytes.len() as u32;
    let ws_offset = user_offset + user_bytes.len() as u32;

    // Echo back the server's negotiate flags with VERSION set
    let flags = challenge.negotiate_flags | NTLMSSP_NEGOTIATE_VERSION;

    let mut buf = BytesMut::with_capacity(ws_offset as usize + ws_bytes.len());
    buf.put_slice(NTLMSSP_SIGNATURE); // Signature
    buf.put_u32_le(NTLMSSP_AUTH); // MessageType

    // LmChallengeResponse
    buf.put_u16_le(lm_response.len() as u16);
    buf.put_u16_le(lm_response.len() as u16);
    buf.put_u32_le(lm_offset);

    // NtChallengeResponse
    buf.put_u16_le(nt_response.len() as u16);
    buf.put_u16_le(nt_response.len() as u16);
    buf.put_u32_le(nt_offset);

    // DomainName
    buf.put_u16_le(domain_bytes.len() as u16);
    buf.put_u16_le(domain_bytes.len() as u16);
    buf.put_u32_le(domain_offset);

    // UserName
    buf.put_u16_le(user_bytes.len() as u16);
    buf.put_u16_le(user_bytes.len() as u16);
    buf.put_u32_le(user_offset);

    // Workstation
    buf.put_u16_le(ws_bytes.len() as u16);
    buf.put_u16_le(ws_bytes.len() as u16);
    buf.put_u32_le(ws_offset);

    // EncryptedRandomSessionKey (empty, offset points past all payloads)
    let enc_key_offset = ws_offset + ws_bytes.len() as u32;
    buf.put_u16_le(0);
    buf.put_u16_le(0);
    buf.put_u32_le(enc_key_offset);

    // NegotiateFlags
    buf.put_u32_le(flags);

    // Version (8 bytes)
    put_ntlm_version(&mut buf);

    // Payload
    buf.put_slice(&lm_response);
    buf.put_slice(&nt_response);
    buf.put_slice(&domain_bytes);
    buf.put_slice(&user_bytes);
    buf.put_slice(&ws_bytes);

    (buf.freeze(), session_base_key)
}

/// Derive the SMB 3.1.1 signing key using SP800-108 Counter Mode KDF.
/// `session_key` is the NTLMv2 session base key.
/// `preauth_hash` is the 64-byte SHA-512 preauth integrity hash.
pub fn derive_signing_key(session_key: &[u8; 16], preauth_hash: &[u8; 64]) -> [u8; 16] {
    // KDF = HMAC-SHA256(Key, i || Label || 0x00 || Context || L)
    // i = 0x00000001 (32-bit big-endian counter)
    // Label = "SMBSigningKey\0"
    // Context = preauth integrity hash (64 bytes)
    // L = 0x00000080 (128 bits, big-endian)
    let label = b"SMBSigningKey\0";

    let mut input = Vec::with_capacity(4 + label.len() + 1 + 64 + 4);
    input.extend_from_slice(&1u32.to_be_bytes()); // counter = 1
    input.extend_from_slice(label);
    input.push(0x00); // separator
    input.extend_from_slice(preauth_hash);
    input.extend_from_slice(&128u32.to_be_bytes()); // L = 128 bits

    let derived = crypto::hmac_sha256(session_key, &input);
    let mut key = [0u8; 16];
    key.copy_from_slice(&derived[..16]);
    key
}

/// Build NTLMv2 client blob (temp structure).
fn build_ntlmv2_blob(client_challenge: &[u8; 8], target_info: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(28 + target_info.len() + 4);
    blob.push(0x01); // RespType
    blob.push(0x01); // HiRespType
    blob.extend_from_slice(&[0u8; 2]); // Reserved1
    blob.extend_from_slice(&[0u8; 4]); // Reserved2
    // Timestamp — use current time as Windows FILETIME
    let ts = windows_filetime_now();
    blob.extend_from_slice(&ts.to_le_bytes());
    blob.extend_from_slice(client_challenge); // ClientChallenge
    blob.extend_from_slice(&[0u8; 4]); // Reserved3
    blob.extend_from_slice(target_info); // AvPairs from challenge
    blob.extend_from_slice(&[0u8; 4]); // End padding
    blob
}

/// Get current time as Windows FILETIME (100ns intervals since 1601-01-01).
fn windows_filetime_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Offset between 1601-01-01 and 1970-01-01 in 100ns intervals
    const EPOCH_DIFF: u64 = 116444736000000000;
    let unix_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let filetime_100ns = unix_ns / 100;
    filetime_100ns + EPOCH_DIFF
}

/// Generate 8 random bytes for client challenge using macOS arc4random.
fn generate_client_challenge() -> [u8; 8] {
    let mut buf = [0u8; 8];
    unsafe extern "C" {
        fn arc4random_buf(buf: *mut u8, nbytes: usize);
    }
    unsafe {
        arc4random_buf(buf.as_mut_ptr(), 8);
    }
    buf
}

/// Extract an NTLMSSP token from a GSS-API / SPNEGO wrapper if present,
/// or return the data as-is if it's already raw NTLMSSP.
pub fn unwrap_spnego(data: &[u8]) -> &[u8] {
    // Look for the NTLMSSP signature anywhere in the buffer
    if let Some(pos) = data.windows(8).position(|w| w == NTLMSSP_SIGNATURE) {
        &data[pos..]
    } else {
        data
    }
}

/// Wrap an NTLMSSP token in a minimal SPNEGO NegTokenInit for the first
/// message, or NegTokenResp for subsequent messages.
pub fn wrap_spnego_negotiate(ntlmssp: &[u8]) -> Vec<u8> {
    let oid_spnego: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
    let oid_ntlmssp: &[u8] = &[
        0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
    ];

    // Build inside-out for correct DER lengths
    let mech_list = der_wrap(0x30, oid_ntlmssp);           // SEQUENCE { OID }
    let mech_types = der_wrap(0xa0, &mech_list);            // [0] mechTypes
    let mech_token_inner = der_wrap(0x04, ntlmssp);         // OCTET STRING
    let mech_token = der_wrap(0xa2, &mech_token_inner);     // [2] mechToken

    let mut inner = Vec::with_capacity(mech_types.len() + mech_token.len());
    inner.extend_from_slice(&mech_types);
    inner.extend_from_slice(&mech_token);

    let neg_token_init = der_wrap(0x30, &inner);            // SEQUENCE
    let neg_token = der_wrap(0xa0, &neg_token_init);        // [0] NegTokenInit

    // APPLICATION [0] { OID, NegotiationToken }
    let mut app_content = Vec::with_capacity(oid_spnego.len() + neg_token.len());
    app_content.extend_from_slice(oid_spnego);
    app_content.extend_from_slice(&neg_token);
    der_wrap(0x60, &app_content)
}

/// Wrap an NTLMSSP auth token in SPNEGO NegTokenResp.
pub fn wrap_spnego_auth(ntlmssp: &[u8]) -> Vec<u8> {
    // NegTokenResp ::= SEQUENCE { responseToken [2] OCTET STRING }
    //
    // Build inside-out so lengths are exact.
    // OCTET STRING wrapping the NTLMSSP token
    let octet_string = der_wrap(0x04, ntlmssp);
    // [2] responseToken
    let resp_token = der_wrap(0xa2, &octet_string);
    // SEQUENCE containing the responseToken
    let seq = der_wrap(0x30, &resp_token);
    // [1] NegTokenResp
    der_wrap(0xa1, &seq)
}

/// Wrap data in a DER TLV: [tag][length][data].
fn der_wrap(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 4 + data.len());
    buf.push(tag);
    push_der_length(&mut buf, data.len());
    buf.extend_from_slice(data);
    buf
}

/// Push a DER length encoding.
fn push_der_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(0x81);
        buf.push(len as u8);
    } else if len < 0x10000 {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    } else {
        buf.push(0x83);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}
