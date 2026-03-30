//! AWS Signature V4 authentication parsing and verification.
//!
//! Supports both Authorization header and query-string (presigned URL) auth.
//! We parse and optionally verify signatures using macOS CommonCrypto.

use crate::crypto;

/// Parsed AWS Signature V4 authentication info.
#[derive(Debug, Clone)]
pub struct SigV4Auth {
    pub access_key: String,
    pub date: String,
    pub region: String,
    pub service: String,
    pub signed_headers: Vec<String>,
    pub signature: String,
}

/// Parsed result from an incoming S3 request's auth.
#[derive(Debug)]
pub enum AuthInfo {
    /// SigV4 Authorization header
    SigV4(SigV4Auth),
    /// Presigned URL (query string auth)
    Presigned(SigV4Auth),
    /// Anonymous / no auth
    Anonymous,
}

/// Parse authentication from the request headers and query string.
pub fn parse_auth(headers: &http::HeaderMap, query: &str) -> AuthInfo {
    // Check for Authorization header first
    if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok())
        && let Some(parsed) = parse_auth_header(auth)
    {
        return AuthInfo::SigV4(parsed);
    }

    // Check for presigned URL query params
    if let Some(parsed) = parse_presigned_query(query) {
        return AuthInfo::Presigned(parsed);
    }

    AuthInfo::Anonymous
}

/// Parse the `Authorization: AWS4-HMAC-SHA256 Credential=.../.../.../s3/aws4_request, SignedHeaders=..., Signature=...` header.
fn parse_auth_header(header: &str) -> Option<SigV4Auth> {
    let header = header.strip_prefix("AWS4-HMAC-SHA256 ")?;

    let mut credential = "";
    let mut signed_headers_str = "";
    let mut signature = "";

    for part in header.split(", ") {
        if let Some(val) = part.strip_prefix("Credential=") {
            credential = val;
        } else if let Some(val) = part.strip_prefix("SignedHeaders=") {
            signed_headers_str = val;
        } else if let Some(val) = part.strip_prefix("Signature=") {
            signature = val;
        }
    }

    let cred_parts: Vec<&str> = credential.split('/').collect();
    if cred_parts.len() < 5 {
        return None;
    }

    Some(SigV4Auth {
        access_key: cred_parts[0].to_string(),
        date: cred_parts[1].to_string(),
        region: cred_parts[2].to_string(),
        service: cred_parts[3].to_string(),
        signed_headers: signed_headers_str.split(';').map(String::from).collect(),
        signature: signature.to_string(),
    })
}

/// Parse presigned URL query parameters (X-Amz-Credential, X-Amz-SignedHeaders, X-Amz-Signature, etc.).
fn parse_presigned_query(query: &str) -> Option<SigV4Auth> {
    let credential = extract_qp(query, "X-Amz-Credential")?;
    let signed_headers_str = extract_qp(query, "X-Amz-SignedHeaders").unwrap_or_default();
    let signature = extract_qp(query, "X-Amz-Signature")?;

    let cred_parts: Vec<&str> = credential.split('/').collect();
    if cred_parts.len() < 5 {
        return None;
    }

    Some(SigV4Auth {
        access_key: cred_parts[0].to_string(),
        date: cred_parts[1].to_string(),
        region: cred_parts[2].to_string(),
        service: cred_parts[3].to_string(),
        signed_headers: signed_headers_str.split(';').map(String::from).collect(),
        signature: signature.to_string(),
    })
}

fn extract_qp(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == key
        {
            return Some(percent_decode(v));
        }
    }
    None
}

fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

/// Compute the signing key for AWS Signature V4.
/// signing_key = HMAC-SHA256(HMAC-SHA256(HMAC-SHA256(HMAC-SHA256("AWS4" + secret, date), region), service), "aws4_request")
pub fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> [u8; 32] {
    let k_date = crypto::hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = crypto::hmac_sha256(&k_date, region.as_bytes());
    let k_service = crypto::hmac_sha256(&k_region, service.as_bytes());
    crypto::hmac_sha256(&k_service, b"aws4_request")
}

/// Compute the SHA-256 hex digest of the payload (for x-amz-content-sha256).
pub fn payload_hash(data: &[u8]) -> String {
    crypto::hex_encode(&crypto::sha256(data))
}

/// The hash for an empty payload.
pub const EMPTY_PAYLOAD_HASH: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// The special value indicating unsigned payload.
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// The special value indicating streaming payload.
pub const STREAMING_PAYLOAD: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
