//! AWS Signature Version 4 for S3: canonicalization and signature math.
//!
//! Everything here is a pure function of request bytes and a key. That is what
//! lets the tests check it against requests captured from independent signers
//! (curl, aws-cli, MinIO's mc — `testdata/sigv4/`) rather than against itself:
//! a verifier tested only with its own signer can agree with itself about a
//! canonicalization no real client produces. Policy (which keys exist, whether
//! a failure rejects or only logs) lives in `auth.rs`.
//!
//! Canonicalization follows what S3 does, which differs from generic SigV4 in
//! two ways that matter here: the path is URI-encoded once and never
//! normalized (no `//` collapsing or `.` removal — `a//b` and `a/b` are
//! different keys), and the payload hash is whatever `x-amz-content-sha256`
//! says, including the `UNSIGNED-PAYLOAD` and `STREAMING-*` sentinels.

use std::borrow::Cow;

use http::HeaderMap;

use crate::crypto::{Sha256, hmac_sha256};

pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
/// aws-chunked body, every chunk signed (minio-go / mc over plain HTTP).
pub const STREAMING_SIGNED: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
/// aws-chunked body, every chunk and the trailing checksum signed.
pub const STREAMING_SIGNED_TRAILER: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";
/// aws-chunked body, unsigned, with a trailing checksum (aws-cli v2's
/// `aws s3 cp` default — sent even with `--no-sign-request`).
pub const STREAMING_UNSIGNED_TRAILER: &str = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";
/// Lowercase hex SHA-256 of the empty string.
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
/// The only service this endpoint answers for.
pub const SERVICE: &str = "s3";
const TERMINATOR: &str = "aws4_request";

/// Largest `X-Amz-Expires` a presigned URL may carry (seven days, as in S3).
pub const MAX_PRESIGNED_EXPIRES: u64 = 7 * 24 * 3600;

// ── Encoding ────────────────────────────────────────────────────────────────

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~')
}

/// Append `input` URI-encoded the SigV4 way: RFC 3986 unreserved bytes pass
/// through, everything else becomes `%XX` with uppercase hex. `/` passes
/// through only in paths.
pub fn uri_encode_into(out: &mut Vec<u8>, input: &[u8], keep_slash: bool) {
    for &b in input {
        if is_unreserved(b) || (keep_slash && b == b'/') {
            out.push(b);
        } else {
            out.extend_from_slice(&[
                b'%',
                HEX_UPPER[(b >> 4) as usize],
                HEX_UPPER[(b & 0x0f) as usize],
            ]);
        }
    }
}

/// Percent-decode to raw bytes. `+` stays `+`: the router decodes keys and
/// query values the same way, and the signature has to cover what the request
/// will actually be executed as, not a form-encoding reinterpretation of it.
fn percent_decode(s: &str) -> Cow<'_, [u8]> {
    percent_encoding::percent_decode_str(s).into()
}

/// Lowercase hex of a 32-byte digest, on the stack.
pub fn hex32(bytes: &[u8; 32]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for (i, &b) in bytes.iter().enumerate() {
        out[2 * i] = HEX_LOWER[(b >> 4) as usize];
        out[2 * i + 1] = HEX_LOWER[(b & 0x0f) as usize];
    }
    out
}

/// Decode 64 hex digits (either case) into 32 bytes.
pub fn decode_hex32(s: &[u8]) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let nibble = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut out = [0u8; 32];
    for (i, pair) in s.as_chunks::<2>().0.iter().enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

/// Constant-time equality for MACs, so a mismatch does not leak how many
/// leading bytes of a forged signature were right.
pub fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    std::hint::black_box(diff) == 0
}

// ── Canonical request ───────────────────────────────────────────────────────

/// Canonical URI: the path decoded and re-encoded once, `/` preserved.
pub fn canonical_uri_into(out: &mut Vec<u8>, raw_path: &str) {
    if raw_path.is_empty() {
        out.push(b'/');
        return;
    }
    uri_encode_into(out, &percent_decode(raw_path), true);
}

/// Canonical query string: every parameter decoded and re-encoded (`/`
/// included), sorted by name then value, `name=value` joined with `&`. A
/// parameter without `=` canonicalizes as `name=`. `exclude` drops one
/// parameter by name — `X-Amz-Signature`, which a presigned URL cannot sign.
pub fn canonical_query_into(out: &mut Vec<u8>, raw_query: &str, exclude: Option<&str>) {
    if raw_query.is_empty() {
        return;
    }
    let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for pair in raw_query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let k = percent_decode(k);
        if exclude.is_some_and(|x| x.as_bytes() == &*k) {
            continue;
        }
        let mut ek = Vec::with_capacity(k.len());
        uri_encode_into(&mut ek, &k, false);
        let mut ev = Vec::with_capacity(v.len());
        uri_encode_into(&mut ev, &percent_decode(v), false);
        pairs.push((ek, ev));
    }
    pairs.sort_unstable();
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push(b'&');
        }
        out.extend_from_slice(k);
        out.push(b'=');
        out.extend_from_slice(v);
    }
}

/// Append a header value trimmed, with runs of spaces/tabs collapsed to one
/// space (SigV4's "trimall").
fn push_header_value(out: &mut Vec<u8>, value: &[u8]) {
    let mut prev_space = false;
    for &b in value.trim_ascii() {
        if b == b' ' || b == b'\t' {
            if !prev_space {
                out.push(b' ');
            }
            prev_space = true;
        } else {
            out.push(b);
            prev_space = false;
        }
    }
}

/// Inputs to the canonical request.
pub struct CanonicalRequest<'a> {
    pub method: &'a str,
    pub raw_path: &'a str,
    pub raw_query: &'a str,
    /// Query parameter left out of the canonical query (presigned URLs).
    pub exclude_query: Option<&'a str>,
    pub headers: &'a HeaderMap,
    /// `;`-separated lowercase header names, as the client listed them.
    pub signed_headers: &'a str,
    pub payload_hash: &'a str,
}

impl CanonicalRequest<'_> {
    /// Build the canonical request bytes.
    ///
    /// Headers are emitted in the order the client listed them. Compliant
    /// clients sort the list, and using it as given cannot widen what is
    /// covered — the set of signed headers is the same either way.
    pub fn build(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(self.method.as_bytes());
        out.push(b'\n');
        canonical_uri_into(&mut out, self.raw_path);
        out.push(b'\n');
        canonical_query_into(&mut out, self.raw_query, self.exclude_query);
        out.push(b'\n');
        for name in self.signed_headers.split(';') {
            out.extend_from_slice(name.as_bytes());
            out.push(b':');
            for (i, v) in self.headers.get_all(name).iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                push_header_value(&mut out, v.as_bytes());
            }
            out.push(b'\n');
        }
        out.push(b'\n');
        out.extend_from_slice(self.signed_headers.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(self.payload_hash.as_bytes());
        out
    }
}

// ── Signing ─────────────────────────────────────────────────────────────────

fn sha256_hex(data: &[u8]) -> [u8; 64] {
    let mut h = Sha256::new();
    h.update(data);
    hex32(&h.finalize())
}

/// `AWS4-HMAC-SHA256 \n timestamp \n scope \n hex(sha256(canonical))`.
pub fn string_to_sign(amz_date: &str, scope: &str, canonical_request: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ALGORITHM.len() + amz_date.len() + scope.len() + 67);
    out.extend_from_slice(ALGORITHM.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(amz_date.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(scope.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(&sha256_hex(canonical_request));
    out
}

/// Derive the signing key. `prefixed_secret` is `"AWS4" || secret`, stored
/// that way so the hot path does not rebuild it per request.
pub fn signing_key(prefixed_secret: &[u8], date: &str, region: &str) -> [u8; 32] {
    let k_date = hmac_sha256(prefixed_secret, date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, SERVICE.as_bytes());
    hmac_sha256(&k_service, TERMINATOR.as_bytes())
}

/// HMAC the string to sign with the derived key.
pub fn sign(key: &[u8; 32], string_to_sign: &[u8]) -> [u8; 32] {
    hmac_sha256(key, string_to_sign)
}

/// String to sign for one aws-chunked chunk; signatures chain through `prev`
/// (the seed signature from the `Authorization` header for the first chunk).
pub fn chunk_string_to_sign(
    amz_date: &str,
    scope: &str,
    prev: &[u8; 32],
    chunk_hash: &[u8; 32],
) -> Vec<u8> {
    const PREFIX: &[u8] = b"AWS4-HMAC-SHA256-PAYLOAD\n";
    let mut out = Vec::with_capacity(PREFIX.len() + amz_date.len() + scope.len() + 64 * 3 + 4);
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(amz_date.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(scope.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(&hex32(prev));
    out.push(b'\n');
    out.extend_from_slice(EMPTY_SHA256.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(&hex32(chunk_hash));
    out
}

/// String to sign for the trailing headers of a signed-trailer upload.
/// `trailer_hash` is SHA-256 over each trailer as `name:value\n`.
pub fn trailer_string_to_sign(
    amz_date: &str,
    scope: &str,
    prev: &[u8; 32],
    trailer_hash: &[u8; 32],
) -> Vec<u8> {
    const PREFIX: &[u8] = b"AWS4-HMAC-SHA256-TRAILER\n";
    let mut out = Vec::with_capacity(PREFIX.len() + amz_date.len() + scope.len() + 64 * 2 + 3);
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(amz_date.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(scope.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(&hex32(prev));
    out.push(b'\n');
    out.extend_from_slice(&hex32(trailer_hash));
    out
}

// ── Parsing ─────────────────────────────────────────────────────────────────

/// `AKID/yyyymmdd/region/s3/aws4_request`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Credential<'a> {
    pub access_key_id: &'a str,
    pub date: &'a str,
    pub region: &'a str,
    /// `yyyymmdd/region/s3/aws4_request` — the credential minus the key id.
    pub scope: &'a str,
}

/// Parse a credential string. Split from the right, so the scope is always the
/// last four components whatever the key id contains.
pub fn parse_credential(s: &str) -> Result<Credential<'_>, &'static str> {
    let mut it = s.rsplitn(5, '/');
    let (Some(terminator), Some(service), Some(region), Some(date), Some(akid)) =
        (it.next(), it.next(), it.next(), it.next(), it.next())
    else {
        return Err("Credential must be AccessKeyId/date/region/service/aws4_request");
    };
    if akid.is_empty() {
        return Err("Credential has an empty access key id");
    }
    if date.len() != 8 || !date.bytes().all(|b| b.is_ascii_digit()) {
        return Err("Credential date must be yyyymmdd");
    }
    if region.is_empty() {
        return Err("Credential has an empty region");
    }
    if service != SERVICE {
        return Err("Credential service must be s3");
    }
    if terminator != TERMINATOR {
        return Err("Credential must end in aws4_request");
    }
    Ok(Credential {
        access_key_id: akid,
        date,
        region,
        scope: &s[akid.len() + 1..],
    })
}

/// A parsed `Authorization: AWS4-HMAC-SHA256 …` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Authorization<'a> {
    pub credential: Credential<'a>,
    pub signed_headers: &'a str,
    pub signature: &'a str,
}

/// Parse the `Authorization` header. Components are comma-separated with or
/// without a following space (aws-cli and curl send `, `; minio-go sends `,`).
pub fn parse_authorization(value: &str) -> Result<Authorization<'_>, &'static str> {
    let rest = value
        .strip_prefix(ALGORITHM)
        .ok_or("Authorization must use AWS4-HMAC-SHA256")?;
    if !rest.starts_with([' ', '\t']) {
        return Err("Authorization must use AWS4-HMAC-SHA256");
    }
    let (mut credential, mut signed_headers, mut signature) = (None, None, None);
    for part in rest.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (k, v) = part
            .split_once('=')
            .ok_or("Authorization component is not key=value")?;
        let slot = match k {
            "Credential" => &mut credential,
            "SignedHeaders" => &mut signed_headers,
            "Signature" => &mut signature,
            _ => return Err("Authorization has an unknown component"),
        };
        if slot.replace(v).is_some() {
            return Err("Authorization repeats a component");
        }
    }
    let credential = parse_credential(credential.ok_or("Authorization is missing Credential")?)?;
    let signed_headers = signed_headers.ok_or("Authorization is missing SignedHeaders")?;
    let signature = signature.ok_or("Authorization is missing Signature")?;
    validate_signed_headers(signed_headers)?;
    Ok(Authorization {
        credential,
        signed_headers,
        signature,
    })
}

/// SignedHeaders must be non-empty lowercase names, unique, and include `host`.
pub fn validate_signed_headers(list: &str) -> Result<(), &'static str> {
    let mut has_host = false;
    for (i, name) in list.split(';').enumerate() {
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.".contains(&b))
        {
            return Err("SignedHeaders must be lowercase header names separated by ';'");
        }
        if list.split(';').take(i).any(|n| n == name) {
            return Err("SignedHeaders lists a header twice");
        }
        has_host |= name == "host";
    }
    if !has_host {
        return Err("SignedHeaders must include host");
    }
    Ok(())
}

/// True if `name` appears in a `;`-separated SignedHeaders list.
pub fn is_signed(signed_headers: &str, name: &str) -> bool {
    signed_headers.split(';').any(|n| n == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sha256;

    #[test]
    fn uri_encoding_matches_the_sigv4_rules() {
        let mut out = Vec::new();
        uri_encode_into(&mut out, b"a b+c/d~e_f-g.h*$\xc3\xbc", false);
        assert_eq!(out, b"a%20b%2Bc%2Fd~e_f-g.h%2A%24%C3%BC");
        out.clear();
        uri_encode_into(&mut out, b"dir/a b", true);
        assert_eq!(out, b"dir/a%20b");
    }

    #[test]
    fn canonical_uri_reencodes_once_and_never_normalizes() {
        let uri = |p: &str| {
            let mut out = Vec::new();
            canonical_uri_into(&mut out, p);
            String::from_utf8(out).unwrap()
        };
        assert_eq!(uri(""), "/");
        assert_eq!(uri("/"), "/");
        // Already-encoded and raw forms of the same key agree.
        assert_eq!(uri("/b/a%20b%2Bc"), "/b/a%20b%2Bc");
        assert_eq!(uri("/b/a+c"), "/b/a%2Bc");
        // Lowercase escapes are re-emitted uppercase.
        assert_eq!(uri("/b/%c3%bc"), "/b/%C3%BC");
        // S3 keys are not paths: no dot-segment removal, no slash collapsing.
        assert_eq!(uri("/b/./x//y/../z"), "/b/./x//y/../z");
    }

    #[test]
    fn canonical_query_sorts_and_encodes_every_parameter() {
        let q = |raw: &str, ex: Option<&str>| {
            let mut out = Vec::new();
            canonical_query_into(&mut out, raw, ex);
            String::from_utf8(out).unwrap()
        };
        assert_eq!(q("", None), "");
        assert_eq!(
            q("prefix=x/y&list-type=2", None),
            "list-type=2&prefix=x%2Fy"
        );
        // Valueless parameters canonicalize with an empty value.
        assert_eq!(q("uploads", None), "uploads=");
        assert_eq!(q("location=", None), "location=");
        // Same name twice: ordered by value.
        assert_eq!(q("a=2&a=1", None), "a=1&a=2");
        // Empty segments are dropped, not emitted as `=`.
        assert_eq!(q("&a=1&&", None), "a=1");
        assert_eq!(
            q("X-Amz-Signature=abc&X-Amz-Date=1", Some("X-Amz-Signature")),
            "X-Amz-Date=1"
        );
    }

    #[test]
    fn header_values_are_trimmed_and_whitespace_collapsed() {
        let mut out = Vec::new();
        push_header_value(&mut out, b"  attempt=1;   max=3 \t");
        assert_eq!(out, b"attempt=1; max=3");
    }

    #[test]
    fn hex_round_trips_and_rejects_garbage() {
        let d = sha256(b"x");
        assert_eq!(decode_hex32(&hex32(&d)), Some(d));
        assert_eq!(
            decode_hex32(&hex32(&d).to_ascii_uppercase()),
            Some(d),
            "uppercase hex decodes to the same bytes"
        );
        assert_eq!(decode_hex32(b"zz"), None);
        assert_eq!(decode_hex32(&[b'g'; 64]), None);
    }

    #[test]
    fn ct_eq_compares_every_byte() {
        let a = [7u8; 32];
        let mut b = a;
        assert!(ct_eq(&a, &b));
        b[31] ^= 1;
        assert!(!ct_eq(&a, &b));
    }

    #[test]
    fn credential_parses_from_the_right() {
        let c = parse_credential("AKID/20130524/us-east-1/s3/aws4_request").unwrap();
        assert_eq!(c.access_key_id, "AKID");
        assert_eq!(c.date, "20130524");
        assert_eq!(c.region, "us-east-1");
        assert_eq!(c.scope, "20130524/us-east-1/s3/aws4_request");
        // A key id containing '/' still leaves the scope intact.
        let c = parse_credential("team/ci/20130524/auto/s3/aws4_request").unwrap();
        assert_eq!(c.access_key_id, "team/ci");
        assert_eq!(c.region, "auto");
        for bad in [
            "",
            "AKID/20130524/us-east-1/s3",
            "/20130524/us-east-1/s3/aws4_request",
            "AKID/2013052/us-east-1/s3/aws4_request",
            "AKID/20130524//s3/aws4_request",
            "AKID/20130524/us-east-1/sts/aws4_request",
            "AKID/20130524/us-east-1/s3/aws4_requests",
        ] {
            assert!(parse_credential(bad).is_err(), "{bad:?} must not parse");
        }
    }

    #[test]
    fn authorization_parses_with_and_without_spaces() {
        let spaced = "AWS4-HMAC-SHA256 Credential=AKID/20130524/us-east-1/s3/aws4_request, \
                      SignedHeaders=host;x-amz-date, Signature=abc";
        let tight = "AWS4-HMAC-SHA256 Credential=AKID/20130524/us-east-1/s3/aws4_request,\
                     SignedHeaders=host;x-amz-date,Signature=abc";
        for v in [spaced, tight] {
            let a = parse_authorization(v).unwrap();
            assert_eq!(a.credential.access_key_id, "AKID");
            assert_eq!(a.signed_headers, "host;x-amz-date");
            assert_eq!(a.signature, "abc");
        }
        for bad in [
            "AWS AKID:sig",
            "AWS4-HMAC-SHA256Credential=x",
            "AWS4-HMAC-SHA256 Credential=AKID/20130524/us-east-1/s3/aws4_request, Signature=abc",
            "AWS4-HMAC-SHA256 Credential=AKID/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=x-amz-date, Signature=abc",
            "AWS4-HMAC-SHA256 Credential=AKID/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host, Signature=a, Signature=b",
            "AWS4-HMAC-SHA256 Credential=AKID/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host, Signature=a, Extra=b",
            "AWS4-HMAC-SHA256 Credential=AKID/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=Host, Signature=a",
            "AWS4-HMAC-SHA256 Credential=AKID/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;host, Signature=a",
        ] {
            assert!(parse_authorization(bad).is_err(), "{bad:?} must not parse");
        }
    }

    /// The AWS documentation's worked example (GET Object with a Range
    /// header). Independent of every client fixture: if this and the fixtures
    /// both pass, the canonicalization agrees with S3's own.
    #[test]
    fn aws_documentation_get_object_example() {
        let mut headers = HeaderMap::new();
        headers.insert("host", "examplebucket.s3.amazonaws.com".parse().unwrap());
        headers.insert("range", "bytes=0-9".parse().unwrap());
        headers.insert("x-amz-content-sha256", EMPTY_SHA256.parse().unwrap());
        headers.insert("x-amz-date", "20130524T000000Z".parse().unwrap());
        let canonical = CanonicalRequest {
            method: "GET",
            raw_path: "/test.txt",
            raw_query: "",
            exclude_query: None,
            headers: &headers,
            signed_headers: "host;range;x-amz-content-sha256;x-amz-date",
            payload_hash: EMPTY_SHA256,
        }
        .build();
        let sts = string_to_sign(
            "20130524T000000Z",
            "20130524/us-east-1/s3/aws4_request",
            &canonical,
        );
        let mut secret = b"AWS4".to_vec();
        secret.extend_from_slice(b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        let key = signing_key(&secret, "20130524", "us-east-1");
        assert_eq!(
            &hex32(&sign(&key, &sts)),
            b"f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }
}
