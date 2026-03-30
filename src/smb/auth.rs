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

/// Build the NTLMSSP Negotiate (Type 1) message.
pub fn build_negotiate_message() -> Bytes {
    let mut buf = BytesMut::with_capacity(40);
    buf.put_slice(NTLMSSP_SIGNATURE);
    buf.put_u32_le(NTLMSSP_NEGOTIATE);
    // Flags
    let flags = NTLMSSP_NEGOTIATE_UNICODE
        | NTLMSSP_NEGOTIATE_NTLM
        | NTLMSSP_REQUEST_TARGET
        | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;
    buf.put_u32_le(flags);
    // DomainNameFields (Len, MaxLen, Offset) = 0
    buf.put_u16_le(0);
    buf.put_u16_le(0);
    buf.put_u32_le(0);
    // WorkstationFields = 0
    buf.put_u16_le(0);
    buf.put_u16_le(0);
    buf.put_u32_le(0);
    buf.freeze()
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
pub fn build_authenticate_message(
    challenge: &ChallengeMessage,
    username: &str,
    password: &str,
    domain: &str,
    workstation: &str,
) -> Bytes {
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
    let _session_base_key = crypto::hmac_md5(&ntlmv2_hash, &nt_proof_str);

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

    // Calculate offsets (Type 3 header is 88 bytes)
    let payload_offset = 88u32;
    let lm_offset = payload_offset;
    let nt_offset = lm_offset + lm_response.len() as u32;
    let domain_offset = nt_offset + nt_response.len() as u32;
    let user_offset = domain_offset + domain_bytes.len() as u32;
    let ws_offset = user_offset + user_bytes.len() as u32;

    let flags = NTLMSSP_NEGOTIATE_UNICODE
        | NTLMSSP_NEGOTIATE_NTLM
        | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;

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

    // EncryptedRandomSession
    buf.put_u16_le(0);
    buf.put_u16_le(0);
    buf.put_u32_le(0);

    // NegotiateFlags
    buf.put_u32_le(flags);

    // MIC (16 bytes of zero for now)
    buf.put_slice(&[0u8; 16]);

    // Payload
    buf.put_slice(&lm_response);
    buf.put_slice(&nt_response);
    buf.put_slice(&domain_bytes);
    buf.put_slice(&user_bytes);
    buf.put_slice(&ws_bytes);

    buf.freeze()
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
    // Minimal ASN.1 SPNEGO wrapper for NegTokenInit
    let oid_spnego: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]; // OID 1.3.6.1.5.5.2
    let oid_ntlmssp: &[u8] = &[
        0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
    ]; // OID 1.3.6.1.4.1.311.2.2.10

    let mech_list_len = oid_ntlmssp.len();
    let mech_list_seq_len = 2 + mech_list_len;
    let mech_token_len = ntlmssp.len();

    // Build inner NegTokenInit sequence
    let mut inner = Vec::new();
    // mechTypes [0]
    inner.push(0xa0);
    push_der_length(&mut inner, mech_list_seq_len);
    inner.push(0x30);
    push_der_length(&mut inner, mech_list_len);
    inner.extend_from_slice(oid_ntlmssp);
    // mechToken [2]
    inner.push(0xa2);
    push_der_length(&mut inner, 2 + mech_token_len);
    inner.push(0x04);
    push_der_length(&mut inner, mech_token_len);
    inner.extend_from_slice(ntlmssp);

    // Wrap in NegotiationToken [0] SEQUENCE
    let mut neg_token = Vec::new();
    neg_token.push(0xa0);
    push_der_length(&mut neg_token, 2 + inner.len());
    neg_token.push(0x30);
    push_der_length(&mut neg_token, inner.len());
    neg_token.extend_from_slice(&inner);

    // Wrap in APPLICATION [0]
    let mut result = Vec::with_capacity(4 + oid_spnego.len() + neg_token.len());
    result.push(0x60);
    push_der_length(&mut result, oid_spnego.len() + neg_token.len());
    result.extend_from_slice(oid_spnego);
    result.extend_from_slice(&neg_token);

    result
}

/// Wrap an NTLMSSP auth token in SPNEGO NegTokenResp.
pub fn wrap_spnego_auth(ntlmssp: &[u8]) -> Vec<u8> {
    // NegTokenResp ::= SEQUENCE { responseToken [2] OCTET STRING }
    let mut inner = Vec::new();
    // responseToken [2]
    inner.push(0xa2);
    push_der_length(&mut inner, 2 + ntlmssp.len());
    inner.push(0x04);
    push_der_length(&mut inner, ntlmssp.len());
    inner.extend_from_slice(ntlmssp);

    let mut result = Vec::with_capacity(4 + inner.len());
    result.push(0xa1);
    push_der_length(&mut result, 2 + inner.len());
    result.push(0x30);
    push_der_length(&mut result, inner.len());
    result.extend_from_slice(&inner);

    result
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
