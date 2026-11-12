//! S3 request authentication: SigV4 verification against static access keys.
//!
//! Three modes, chosen by `SPICEIO_S3_AUTH`:
//!
//! - `off` — the historical behaviour: no signature is checked, and anyone who
//!   can reach the listener acts with spiceio's SMB credentials. The default
//!   when no access key is configured, so existing deployments are unchanged.
//! - `enforce` — every request except a CORS preflight must carry a valid
//!   SigV4 signature (`Authorization` header or presigned query) from a
//!   configured key; signed payloads and signed aws-chunked uploads are
//!   verified too. The default once any access key is configured, because a
//!   key that is configured but silently not required is a trap.
//! - `log` — verify exactly as `enforce` does, but serve the request anyway
//!   and log what would have been rejected. For rolling clients onto keys
//!   without an outage, and for catching a client whose signing disagrees
//!   with the verifier before it is locked out.
//!
//! Keys come from `SPICEIO_S3_ACCESS_KEY_ID` + `SPICEIO_S3_SECRET_ACCESS_KEY`
//! and/or `SPICEIO_S3_CREDENTIALS_FILE` (one `ACCESS_KEY_ID SECRET` per line,
//! so a key can be rotated by running old and new side by side). The SMB
//! credential is separate and unchanged: these keys authenticate clients *to
//! spiceio*, and spiceio still authenticates to the NAS with its own.
//!
//! Only long-term keys are supported. A request carrying a session token is
//! refused rather than having the token ignored, so a future token-issuing
//! path (STS-style temporary credentials) cannot be confused with this one.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

use http::{HeaderMap, HeaderValue, StatusCode, request::Parts};

use super::headers::{parse_amz_date, parse_http_date};
use super::request_body::{self, Framing};
use super::sigv4::{self, CanonicalRequest};

/// Largest accepted difference between a request's timestamp and the clock
/// (S3's own limit). Also bounds how long a captured request can be replayed.
pub const MAX_SKEW_SECS: u64 = 15 * 60;

/// Shortest secret accepted. A SigV4 signature sent over plain HTTP is an
/// offline guessing oracle for its secret, so a short one is not a secret.
pub const MIN_SECRET_LEN: usize = 16;

/// How requests are authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Off,
    Log,
    Enforce,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Mode::Off => "off",
            Mode::Log => "log",
            Mode::Enforce => "enforce",
        })
    }
}

/// A secret access key, stored as `"AWS4" || secret` (the first HMAC key of
/// the derivation) and zeroed on drop. Never printed.
struct Secret {
    prefixed: Box<[u8]>,
    /// Signing keys derived from this secret. A key depends only on the day
    /// and region, so this hits on all but about one request per day per
    /// region, and saves four of the five HMACs a verification costs
    /// (measured: 2.5 µs → 1.2 µs per request). Filled only after a
    /// signature verifies, so a client that knows a key id but not its
    /// secret cannot churn it with made-up regions.
    derived: RwLock<Vec<DerivedKey>>,
}

struct DerivedKey {
    date: [u8; 8],
    region: Box<str>,
    key: [u8; 32],
}

/// Regions a key is used from at once is one in practice; a little slack
/// covers clients configured differently and the hour around midnight UTC.
const DERIVED_KEYS: usize = 4;

impl Secret {
    fn new(secret: &str) -> Self {
        let mut v = Vec::with_capacity(4 + secret.len());
        v.extend_from_slice(b"AWS4");
        v.extend_from_slice(secret.as_bytes());
        Self {
            prefixed: v.into_boxed_slice(),
            derived: RwLock::new(Vec::with_capacity(DERIVED_KEYS)),
        }
    }

    /// The signing key for a scope, and whether it came from the cache.
    fn signing_key(&self, date: &str, region: &str) -> ([u8; 32], bool) {
        if let Ok(derived) = self.derived.read()
            && let Some(d) = derived
                .iter()
                .find(|d| d.date.as_slice() == date.as_bytes() && &*d.region == region)
        {
            return (d.key, true);
        }
        (sigv4::signing_key(&self.prefixed, date, region), false)
    }

    /// Cache a key that has just verified a signature.
    fn remember(&self, date: &str, region: &str, key: [u8; 32]) {
        let Ok(date) = <[u8; 8]>::try_from(date.as_bytes()) else {
            return;
        };
        if let Ok(mut derived) = self.derived.write() {
            if derived.len() == DERIVED_KEYS {
                derived.remove(0);
            }
            derived.push(DerivedKey {
                date,
                region: region.into(),
                key,
            });
        }
    }

    #[cfg(test)]
    fn derived_len(&self) -> usize {
        self.derived.read().map_or(0, |d| d.len())
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        for b in self.prefixed.iter_mut() {
            // Volatile so the zeroing is not elided as a dead store.
            unsafe { std::ptr::write_volatile(b, 0) };
        }
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Why a request was not authenticated, shaped as an S3 error.
#[derive(Debug)]
pub struct AuthFailure {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: Cow<'static, str>,
    /// S3's diagnostic extras, boxed: most failures carry none, and this
    /// travels in the `Err` of every request's check.
    detail: Option<Box<FailureDetail>>,
}

#[derive(Debug, Default)]
struct FailureDetail {
    access_key_id: Option<String>,
    /// For unsigned `x-amz-*` headers: which ones (S3's `HeadersNotSigned`).
    headers_not_signed: Option<String>,
    /// For `SignatureDoesNotMatch`: what spiceio signed, so a client whose
    /// canonicalization differs can be diagnosed (S3 returns the same).
    canonical_request: Option<String>,
    string_to_sign: Option<String>,
}

impl AuthFailure {
    fn new(status: StatusCode, code: &'static str, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            detail: None,
        }
    }

    fn detail_mut(&mut self) -> &mut FailureDetail {
        self.detail.get_or_insert_with(Box::default)
    }

    pub fn access_key_id(&self) -> Option<&str> {
        self.detail.as_ref()?.access_key_id.as_deref()
    }

    pub fn headers_not_signed(&self) -> Option<&str> {
        self.detail.as_ref()?.headers_not_signed.as_deref()
    }

    pub fn canonical_request(&self) -> Option<&str> {
        self.detail.as_ref()?.canonical_request.as_deref()
    }

    pub fn string_to_sign(&self) -> Option<&str> {
        self.detail.as_ref()?.string_to_sign.as_deref()
    }

    fn denied(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "AccessDenied", message)
    }

    fn header_malformed(message: &'static str) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "AuthorizationHeaderMalformed",
            message,
        )
    }

    fn query_malformed(message: &'static str) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "AuthorizationQueryParametersError",
            message,
        )
    }

    fn sigv2() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "Signature Version 2 is not supported; sign requests with AWS4-HMAC-SHA256.",
        )
    }
}

/// What an aws-chunked body must prove chunk by chunk: the derived key and
/// scope the seed signature was made with, and the seed itself, which the
/// first chunk's signature chains from.
#[derive(Clone)]
pub struct ChunkSigning {
    pub key: [u8; 32],
    pub amz_date: String,
    pub scope: String,
    pub seed: [u8; 32],
    /// `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`: the trailing headers
    /// carry their own signature, chained from the final chunk's.
    pub trailer_signed: bool,
}

impl fmt::Debug for ChunkSigning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChunkSigning")
            .field("amz_date", &self.amz_date)
            .field("scope", &self.scope)
            .field("trailer_signed", &self.trailer_signed)
            .finish_non_exhaustive()
    }
}

/// What the body must still prove once the headers have been verified.
#[derive(Debug, Clone)]
pub enum PayloadAuth {
    /// Nothing: auth is off, the request failed in log mode, or the client
    /// sent `UNSIGNED-PAYLOAD` / `STREAMING-UNSIGNED-PAYLOAD-TRAILER`.
    None,
    /// The body must hash to this (`x-amz-content-sha256` was a digest).
    Sha256([u8; 32]),
    /// Signed aws-chunked upload.
    Chunks(ChunkSigning),
}

/// The body-verification half of a request's authentication.
#[derive(Debug, Clone)]
pub struct PayloadPlan {
    pub auth: PayloadAuth,
    /// Reject on a payload mismatch (`enforce`), or only log it (`log`).
    pub enforce: bool,
}

impl PayloadPlan {
    pub fn unchecked() -> Self {
        Self {
            auth: PayloadAuth::None,
            enforce: false,
        }
    }
}

/// The configured mode and key set. Immutable after startup.
pub struct Authenticator {
    mode: Mode,
    keys: HashMap<String, Secret>,
}

impl fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authenticator")
            .field("mode", &self.mode)
            .field("access_key_ids", &self.access_key_ids())
            .finish()
    }
}

impl Authenticator {
    /// Authentication off — the historical behaviour.
    pub fn disabled() -> Self {
        Self {
            mode: Mode::Off,
            keys: HashMap::new(),
        }
    }

    /// Build from a mode and `(access key id, secret)` pairs, validating both.
    pub fn new(mode: Mode, credentials: Vec<(String, String)>) -> Result<Self, String> {
        let mut keys = HashMap::with_capacity(credentials.len());
        for (id, secret) in credentials {
            if id.is_empty()
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            {
                return Err(format!(
                    "access key id {id:?} must be non-empty ASCII letters, digits, '-', '_' or '.'"
                ));
            }
            if secret.len() < MIN_SECRET_LEN {
                return Err(format!(
                    "the secret for access key {id} is {} characters; at least {MIN_SECRET_LEN} are required",
                    secret.len()
                ));
            }
            if secret.chars().any(char::is_whitespace) {
                return Err(format!(
                    "the secret for access key {id} contains whitespace"
                ));
            }
            if keys.insert(id.clone(), Secret::new(&secret)).is_some() {
                return Err(format!("access key {id} is configured twice"));
            }
        }
        if mode != Mode::Off && keys.is_empty() {
            return Err(format!(
                "SPICEIO_S3_AUTH={mode} needs at least one access key \
                 (SPICEIO_S3_ACCESS_KEY_ID + SPICEIO_S3_SECRET_ACCESS_KEY, \
                 or SPICEIO_S3_CREDENTIALS_FILE)"
            ));
        }
        Ok(Self { mode, keys })
    }

    /// Read the configuration from the environment. Empty variables count as
    /// unset (CI forwards optional variables unconditionally).
    pub fn from_env() -> Result<Self, String> {
        Self::from_vars(|name| std::env::var(name).ok())
    }

    /// [`from_env`](Self::from_env) over any variable source, so the parsing
    /// is testable without mutating the process environment.
    pub fn from_vars(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let var = |name: &str| lookup(name).filter(|v| !v.is_empty());
        let mut credentials = Vec::new();
        match (
            var("SPICEIO_S3_ACCESS_KEY_ID"),
            var("SPICEIO_S3_SECRET_ACCESS_KEY"),
        ) {
            (Some(id), Some(secret)) => credentials.push((id, secret)),
            (None, None) => {}
            _ => {
                return Err(
                    "set both SPICEIO_S3_ACCESS_KEY_ID and SPICEIO_S3_SECRET_ACCESS_KEY, or neither"
                        .into(),
                );
            }
        }
        if let Some(path) = var("SPICEIO_S3_CREDENTIALS_FILE") {
            credentials.extend(read_credentials_file(std::path::Path::new(&path))?);
        }
        let mode = match var("SPICEIO_S3_AUTH").as_deref() {
            None if credentials.is_empty() => Mode::Off,
            None => Mode::Enforce,
            Some(v) if v.eq_ignore_ascii_case("off") => Mode::Off,
            Some(v) if v.eq_ignore_ascii_case("log") => Mode::Log,
            Some(v) if v.eq_ignore_ascii_case("enforce") => Mode::Enforce,
            Some(v) => {
                return Err(format!(
                    "SPICEIO_S3_AUTH={v:?} is not one of off, log, enforce"
                ));
            }
        };
        Self::new(mode, credentials)
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Configured access key ids, sorted (they are not secret; logged at startup).
    pub fn access_key_ids(&self) -> Vec<&str> {
        let mut ids: Vec<&str> = self.keys.keys().map(String::as_str).collect();
        ids.sort_unstable();
        ids
    }

    /// [`Self::check_framed`], reading the framing from the request's own
    /// headers.
    pub fn check(&self, parts: &Parts, now: u64) -> Result<PayloadPlan, AuthFailure> {
        self.check_framed(parts, request_body::framing(&parts.headers).ok(), now)
    }

    /// Authenticate a request's head. `framing` is how its body will be
    /// decoded (`request_body::framing`), or `None` when that is refused
    /// anyway; it must fit what the signature pins. `now` is the current Unix
    /// time.
    ///
    /// `Ok` carries what the body still has to prove; `Err` is the response
    /// to send instead (enforce mode only — log mode logs and returns `Ok`).
    pub fn check_framed(
        &self,
        parts: &Parts,
        framing: Option<Framing>,
        now: u64,
    ) -> Result<PayloadPlan, AuthFailure> {
        match self.mode {
            Mode::Off => Ok(PayloadPlan::unchecked()),
            Mode::Log => match self.verify(parts, framing, now) {
                Ok(auth) => Ok(PayloadPlan {
                    auth,
                    enforce: false,
                }),
                Err(f) => {
                    log_failure(parts, &f, true);
                    Ok(PayloadPlan::unchecked())
                }
            },
            Mode::Enforce => match self.verify(parts, framing, now) {
                Ok(auth) => Ok(PayloadPlan {
                    auth,
                    enforce: true,
                }),
                Err(f) => {
                    log_failure(parts, &f, false);
                    Err(f)
                }
            },
        }
    }

    fn verify(
        &self,
        parts: &Parts,
        framing: Option<Framing>,
        now: u64,
    ) -> Result<PayloadAuth, AuthFailure> {
        let query = parts.uri.query().unwrap_or("");
        let header = parts.headers.get(http::header::AUTHORIZATION);
        let presigned = query_param(query, "X-Amz-Algorithm").is_some()
            || query_param(query, "X-Amz-Signature").is_some();
        let auth = match (header, presigned) {
            (Some(_), true) => Err(AuthFailure::new(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "Only one auth mechanism allowed; send either the Authorization header \
                 or the X-Amz-* query parameters, not both.",
            )),
            (Some(h), false) => self.verify_header(parts, h, now),
            (None, true) => self.verify_presigned(parts, now),
            (None, false)
                if query_param(query, "AWSAccessKeyId").is_some()
                    && query_param(query, "Signature").is_some() =>
            {
                Err(AuthFailure::sigv2())
            }
            (None, false) => Err(AuthFailure::denied(
                "Access Denied: requests must be signed with AWS Signature Version 4.",
            )),
        }?;
        check_framing(framing, &auth)?;
        Ok(auth)
    }

    fn secret(&self, access_key_id: &str) -> Result<&Secret, AuthFailure> {
        self.keys.get(access_key_id).ok_or_else(|| {
            let mut f = AuthFailure::new(
                StatusCode::FORBIDDEN,
                "InvalidAccessKeyId",
                "The AWS Access Key Id you provided does not exist in our records.",
            );
            f.detail_mut().access_key_id = Some(access_key_id.to_string());
            f
        })
    }

    fn verify_header(
        &self,
        parts: &Parts,
        value: &HeaderValue,
        now: u64,
    ) -> Result<PayloadAuth, AuthFailure> {
        let headers = &parts.headers;
        let value = value
            .to_str()
            .map_err(|_| AuthFailure::header_malformed("The Authorization header is not ASCII."))?;
        if value.starts_with("AWS ") {
            return Err(AuthFailure::sigv2());
        }
        let auth = sigv4::parse_authorization(value).map_err(AuthFailure::header_malformed)?;
        let cred = auth.credential;

        // The timestamp the client signed: x-amz-date, or Date for a client
        // that signs that instead (both are allowed by SigV4).
        let (amz_date, ts): (Cow<'_, str>, u64) = if let Some(v) = headers.get("x-amz-date") {
            let parsed = v
                .to_str()
                .ok()
                .and_then(|s| parse_amz_date(s).map(|ts| (s, ts)));
            let Some((s, ts)) = parsed else {
                return Err(AuthFailure::denied(
                    "x-amz-date must be an ISO 8601 basic timestamp (yyyymmddThhmmssZ).",
                ));
            };
            (Cow::Borrowed(s), ts)
        } else if let Some(ts) = headers
            .get(http::header::DATE)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_http_date)
        {
            (Cow::Owned(basic_timestamp(ts)), ts)
        } else {
            return Err(AuthFailure::denied(
                "AWS authentication requires a valid Date or x-amz-date header.",
            ));
        };
        if !amz_date.starts_with(cred.date) {
            return Err(AuthFailure::header_malformed(
                "The Credential date does not match the request date.",
            ));
        }
        check_skew(ts, now)?;
        reject_session_token(headers, parts.uri.query().unwrap_or(""))?;
        // The string to sign carries x-amz-date and the canonical request the
        // payload hash, listed or not.
        reject_unsigned_amz_headers(
            headers,
            auth.signed_headers,
            &["x-amz-content-sha256", "x-amz-date"],
        )?;
        reject_rewritable(parts, auth.signed_headers)?;
        let payload_hash = header_payload_hash(headers)?;
        let secret = self.secret(cred.access_key_id)?;

        let canonical = CanonicalRequest {
            method: parts.method.as_str(),
            raw_path: parts.uri.path(),
            raw_query: parts.uri.query().unwrap_or(""),
            exclude_query: None,
            headers,
            signed_headers: auth.signed_headers,
            payload_hash: &payload_hash,
        }
        .build();
        let (key, cached) = secret.signing_key(cred.date, cred.region);
        let seed = verify_signature(
            &key,
            &amz_date,
            cred.scope,
            &canonical,
            auth.signature,
            cred.access_key_id,
        )?;
        if !cached {
            secret.remember(cred.date, cred.region, key);
        }
        Ok(payload_auth(
            &payload_hash,
            key,
            &amz_date,
            cred.scope,
            seed,
        ))
    }

    fn verify_presigned(&self, parts: &Parts, now: u64) -> Result<PayloadAuth, AuthFailure> {
        let headers = &parts.headers;
        let query = parts.uri.query().unwrap_or("");
        let param = |name: &'static str, missing: &'static str| {
            query_param(query, name).ok_or_else(|| AuthFailure::query_malformed(missing))
        };
        if param("X-Amz-Algorithm", "X-Amz-Algorithm is required.")? != sigv4::ALGORITHM {
            return Err(AuthFailure::query_malformed(
                "X-Amz-Algorithm only supports \"AWS4-HMAC-SHA256\".",
            ));
        }
        let credential = param("X-Amz-Credential", "X-Amz-Credential is required.")?;
        let cred = sigv4::parse_credential(&credential).map_err(AuthFailure::query_malformed)?;
        let amz_date = param("X-Amz-Date", "X-Amz-Date is required.")?;
        let ts = parse_amz_date(&amz_date)
            .ok_or_else(|| AuthFailure::query_malformed("X-Amz-Date must be yyyymmddThhmmssZ."))?;
        let expires: u64 = param("X-Amz-Expires", "X-Amz-Expires is required.")?
            .parse()
            .ok()
            .filter(|e| (1..=sigv4::MAX_PRESIGNED_EXPIRES).contains(e))
            .ok_or_else(|| {
                AuthFailure::query_malformed(
                    "X-Amz-Expires must be a number of seconds from 1 to 604800.",
                )
            })?;
        let signed_headers = param("X-Amz-SignedHeaders", "X-Amz-SignedHeaders is required.")?;
        sigv4::validate_signed_headers(&signed_headers).map_err(AuthFailure::query_malformed)?;
        let signature = param("X-Amz-Signature", "X-Amz-Signature is required.")?;
        if !amz_date.starts_with(cred.date) {
            return Err(AuthFailure::query_malformed(
                "The X-Amz-Credential date does not match X-Amz-Date.",
            ));
        }
        reject_session_token(headers, query)?;
        if ts > now.saturating_add(MAX_SKEW_SECS) {
            return Err(AuthFailure::denied("Request is not valid yet."));
        }
        if now > ts.saturating_add(expires) {
            return Err(AuthFailure::denied("Request has expired."));
        }
        // Here the date and payload hash are in the query, so the headers of
        // those names are covered only when listed, like any other.
        reject_unsigned_amz_headers(headers, &signed_headers, &[])?;
        reject_rewritable(parts, &signed_headers)?;
        // A presigned URL cannot sign a body it has not seen, so the canonical
        // payload is UNSIGNED-PAYLOAD unless the signer put a digest in the
        // query.
        let payload_hash: Cow<'_, str> = match query_param(query, "X-Amz-Content-Sha256") {
            Some(h)
                if h == sigv4::UNSIGNED_PAYLOAD || sigv4::decode_hex32(h.as_bytes()).is_some() =>
            {
                h
            }
            Some(_) => {
                return Err(AuthFailure::query_malformed(
                    "X-Amz-Content-Sha256 must be UNSIGNED-PAYLOAD or a SHA-256 hex digest.",
                ));
            }
            None => Cow::Borrowed(sigv4::UNSIGNED_PAYLOAD),
        };
        let payload = presigned_payload(headers, &payload_hash)?;
        let secret = self.secret(cred.access_key_id)?;

        let canonical = CanonicalRequest {
            method: parts.method.as_str(),
            raw_path: parts.uri.path(),
            raw_query: query,
            exclude_query: Some("X-Amz-Signature"),
            headers,
            signed_headers: &signed_headers,
            payload_hash: &payload_hash,
        }
        .build();
        let (key, cached) = secret.signing_key(cred.date, cred.region);
        let seed = verify_signature(
            &key,
            &amz_date,
            cred.scope,
            &canonical,
            &signature,
            cred.access_key_id,
        )?;
        if !cached {
            secret.remember(cred.date, cred.region, key);
        }
        Ok(payload_auth(payload, key, &amz_date, cred.scope, seed))
    }
}

/// What a presigned request's body must be. The canonical request carries the
/// query's payload hash, but the signer can also list `x-amz-content-sha256`
/// in SignedHeaders (unlisted, it is refused as unsigned). The body is then
/// held to that header, which must agree with any hash in the query.
fn presigned_payload<'a>(
    headers: &'a HeaderMap,
    query_hash: &'a str,
) -> Result<&'a str, AuthFailure> {
    let Some(v) = headers.get("x-amz-content-sha256") else {
        return Ok(query_hash);
    };
    let header = v.to_str().unwrap_or("");
    match header {
        sigv4::UNSIGNED_PAYLOAD | sigv4::STREAMING_UNSIGNED_TRAILER => {}
        sigv4::STREAMING_SIGNED | sigv4::STREAMING_SIGNED_TRAILER => {
            return Err(AuthFailure::new(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "Signed aws-chunked uploads need the Authorization header, not a presigned URL.",
            ));
        }
        _ if sigv4::decode_hex32(header.as_bytes()).is_some() => {}
        _ => {
            return Err(AuthFailure::new(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "x-amz-content-sha256 must be UNSIGNED-PAYLOAD, \
                 STREAMING-UNSIGNED-PAYLOAD-TRAILER, or a SHA-256 hex digest.",
            ));
        }
    }
    if header == query_hash || query_hash == sigv4::UNSIGNED_PAYLOAD {
        Ok(header)
    } else {
        Err(AuthFailure::new(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "The x-amz-content-sha256 header does not match X-Amz-Content-Sha256.",
        ))
    }
}

/// The router decodes the body as its headers say (`request_body::framing`),
/// and not all of those are signed: `Content-Encoding` never has to be, and a
/// presigned request's payload hash is in its query. So the framing is held to
/// what the signature pins. A whole-body digest cannot describe an aws-chunked
/// body (decoding one would leave the digest unchecked), and signed chunks
/// exist only inside aws-chunked framing. `None`: the router refuses the
/// framing itself.
fn check_framing(framing: Option<Framing>, auth: &PayloadAuth) -> Result<(), AuthFailure> {
    let chunked = match framing {
        Some(Framing::AwsChunked { .. }) => true,
        Some(Framing::Plain) => false,
        None => return Ok(()),
    };
    let fits = match auth {
        PayloadAuth::None => true,
        PayloadAuth::Sha256(_) => !chunked,
        PayloadAuth::Chunks(_) => chunked,
    };
    if fits {
        return Ok(());
    }
    Err(AuthFailure::new(
        StatusCode::BAD_REQUEST,
        "InvalidArgument",
        "The body's framing does not match its signed payload hash: a SHA-256 digest \
         needs a plain body, signed chunks an aws-chunked one.",
    ))
}

/// Check the client's signature; on success return it (the seed a signed
/// aws-chunked body chains from).
fn verify_signature(
    key: &[u8; 32],
    amz_date: &str,
    scope: &str,
    canonical: &[u8],
    provided: &str,
    access_key_id: &str,
) -> Result<[u8; 32], AuthFailure> {
    let sts = sigv4::string_to_sign(amz_date, scope, canonical);
    let expected = sigv4::sign(key, &sts);
    match sigv4::decode_hex32(provided.as_bytes()) {
        Some(p) if sigv4::ct_eq(&p, &expected) => Ok(p),
        _ => {
            let mut f = AuthFailure::new(
                StatusCode::FORBIDDEN,
                "SignatureDoesNotMatch",
                "The request signature we calculated does not match the signature you provided. \
                 Check your key and signing method.",
            );
            let d = f.detail_mut();
            d.access_key_id = Some(access_key_id.to_string());
            d.canonical_request = Some(String::from_utf8_lossy(canonical).into_owned());
            d.string_to_sign = Some(String::from_utf8_lossy(&sts).into_owned());
            Err(f)
        }
    }
}

fn payload_auth(
    payload_hash: &str,
    key: [u8; 32],
    amz_date: &str,
    scope: &str,
    seed: [u8; 32],
) -> PayloadAuth {
    let chunks = |trailer_signed| {
        PayloadAuth::Chunks(ChunkSigning {
            key,
            amz_date: amz_date.to_string(),
            scope: scope.to_string(),
            seed,
            trailer_signed,
        })
    };
    match payload_hash {
        sigv4::STREAMING_SIGNED => chunks(false),
        sigv4::STREAMING_SIGNED_TRAILER => chunks(true),
        h => match sigv4::decode_hex32(h.as_bytes()) {
            Some(d) => PayloadAuth::Sha256(d),
            // UNSIGNED-PAYLOAD / STREAMING-UNSIGNED-PAYLOAD-TRAILER
            None => PayloadAuth::None,
        },
    }
}

fn check_skew(ts: u64, now: u64) -> Result<(), AuthFailure> {
    if ts.abs_diff(now) > MAX_SKEW_SECS {
        return Err(AuthFailure::new(
            StatusCode::FORBIDDEN,
            "RequestTimeTooSkewed",
            "The difference between the request time and the server's time is too large.",
        ));
    }
    Ok(())
}

fn reject_session_token(headers: &HeaderMap, query: &str) -> Result<(), AuthFailure> {
    if headers.contains_key("x-amz-security-token")
        || query_param(query, "X-Amz-Security-Token").is_some()
    {
        return Err(AuthFailure::new(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            "Session tokens are not supported; sign with a long-term access key.",
        ));
    }
    Ok(())
}

/// Refuse what a signature cannot pin down, each a way to rewrite the request
/// in flight into one that does something else under the same signature:
/// - a repeated query parameter: the canonical query is sorted, so which one
///   comes first is not signed, and dispatch and the handlers read the first;
/// - a repeated signed header: its values are joined with `,`, so `X: a,b`
///   and two `X` lines sign alike, and readers take the first;
/// - an absent signed header: it canonicalizes like an empty one (`name:`),
///   so a signed empty `If-Match` could be dropped to make the write
///   unconditional.
fn reject_rewritable(parts: &Parts, signed: &str) -> Result<(), AuthFailure> {
    if let Some(name) = sigv4::repeated_query_param(parts.uri.query().unwrap_or("")) {
        return Err(AuthFailure::new(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            format!("Query parameter {name:?} appears more than once in a signed request."),
        ));
    }
    match sigv4::signed_header_not_once(&parts.headers, signed) {
        None => Ok(()),
        Some((name, 0)) => Err(AuthFailure::denied(format!(
            "Signed header {name:?} is not in the request."
        ))),
        Some((name, _)) => Err(AuthFailure::new(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            format!("Signed header {name:?} appears more than once."),
        )),
    }
}

/// S3 requires every `x-amz-*` header to be signed, so none can be added or
/// changed in flight to alter what the request does (`x-amz-copy-source`
/// turning a PUT into a copy, for one). `covered` names the headers the
/// signature covers whether listed or not.
fn reject_unsigned_amz_headers(
    headers: &HeaderMap,
    signed: &str,
    covered: &[&str],
) -> Result<(), AuthFailure> {
    let mut missing: Vec<&str> = Vec::new();
    for name in headers.keys() {
        let n = name.as_str();
        if n.starts_with("x-amz-") && !covered.contains(&n) && !sigv4::is_signed(signed, n) {
            missing.push(n);
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    let mut f =
        AuthFailure::denied("There were headers present in the request which were not signed.");
    f.detail_mut().headers_not_signed = Some(missing.join(","));
    Err(f)
}

/// The payload hash a header-signed request was signed with.
///
/// S3 requires `x-amz-content-sha256`; a request without one and without a
/// body is accepted with the empty-body digest (what a generic SigV4 signer
/// computes), but a body without a declared hash cannot be verified without
/// buffering it first, so it is refused.
fn header_payload_hash(headers: &HeaderMap) -> Result<Cow<'_, str>, AuthFailure> {
    let Some(v) = headers.get("x-amz-content-sha256") else {
        let bodyless = !headers.contains_key(http::header::TRANSFER_ENCODING)
            && headers
                .get(http::header::CONTENT_LENGTH)
                .is_none_or(|v| v.as_bytes() == b"0");
        if bodyless {
            return Ok(Cow::Borrowed(sigv4::EMPTY_SHA256));
        }
        return Err(AuthFailure::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "Missing required header for this request: x-amz-content-sha256",
        ));
    };
    let s = v.to_str().unwrap_or("");
    match s {
        sigv4::UNSIGNED_PAYLOAD
        | sigv4::STREAMING_SIGNED
        | sigv4::STREAMING_SIGNED_TRAILER
        | sigv4::STREAMING_UNSIGNED_TRAILER => Ok(Cow::Borrowed(s)),
        _ if sigv4::decode_hex32(s.as_bytes()).is_some() => Ok(Cow::Borrowed(s)),
        _ => Err(AuthFailure::new(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "x-amz-content-sha256 must be UNSIGNED-PAYLOAD, \
             STREAMING-AWS4-HMAC-SHA256-PAYLOAD[-TRAILER], \
             STREAMING-UNSIGNED-PAYLOAD-TRAILER, or a SHA-256 hex digest.",
        )),
    }
}

/// First query parameter named `name`, read the way the canonical query
/// reads it (see [`sigv4::query_pairs`]).
fn query_param<'a>(query: &'a str, name: &str) -> Option<Cow<'a, str>> {
    sigv4::query_pairs(query).find_map(|(k, v)| (k == name).then_some(v))
}

/// `yyyymmddThhmmssZ` for a Unix time (the form a `Date`-signed request's
/// string to sign uses).
fn basic_timestamp(epoch: u64) -> String {
    // "YYYY-MM-DDTHH:MM:SS.000Z"
    let iso = super::xml::epoch_to_iso8601(epoch);
    let b = iso.as_bytes();
    let mut out = String::with_capacity(16);
    for r in [0..4, 5..7, 8..10] {
        out.push_str(std::str::from_utf8(&b[r]).unwrap_or_default());
    }
    out.push('T');
    for r in [11..13, 14..16, 17..19] {
        out.push_str(std::str::from_utf8(&b[r]).unwrap_or_default());
    }
    out.push('Z');
    out
}

/// Read `ACCESS_KEY_ID SECRET_ACCESS_KEY` lines (blank lines and `#` comments
/// skipped). Refuses a file that group or others can read, as ssh does for a
/// private key: these secrets are the whole of the share's access control.
pub fn read_credentials_file(path: &std::path::Path) -> Result<Vec<(String, String)>, String> {
    use std::os::unix::fs::PermissionsExt;
    let shown = path.display();
    let meta = std::fs::metadata(path).map_err(|e| format!("{shown}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{shown} is not a regular file"));
    }
    let mode = meta.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(format!(
            "{shown} is accessible by group or others (mode {:04o}); chmod 600 it",
            mode & 0o7777
        ));
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("{shown}: {e}"))?;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        match (fields.next(), fields.next(), fields.next()) {
            (Some(id), Some(secret), None) => out.push((id.to_string(), secret.to_string())),
            _ => {
                return Err(format!(
                    "{shown}:{}: expected `ACCESS_KEY_ID SECRET_ACCESS_KEY`",
                    i + 1
                ));
            }
        }
    }
    Ok(out)
}

// ── Rate-limited logging ────────────────────────────────────────────────────

/// At most one auth log line per second, with a count of what was dropped.
/// A misconfigured client — or anyone probing — fails on every request, and
/// the log must not become the bottleneck or bury everything else.
struct RateLimitedLog {
    next_secs: AtomicU64,
    suppressed: AtomicU64,
}

static AUTH_LOG: RateLimitedLog = RateLimitedLog {
    next_secs: AtomicU64::new(0),
    suppressed: AtomicU64::new(0),
};

/// Log a client-caused failure (authentication, framing), rate-limited.
/// Callers include their own subsystem prefix (`auth: …`).
pub(crate) fn log_event(args: fmt::Arguments<'_>) {
    let now = crate::smb::ops::now_epoch_secs();
    let next = AUTH_LOG.next_secs.load(Ordering::Relaxed);
    if now >= next
        && AUTH_LOG
            .next_secs
            .compare_exchange(next, now + 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        let suppressed = AUTH_LOG.suppressed.swap(0, Ordering::Relaxed);
        if suppressed > 0 {
            crate::serr!("[spiceio] {args} (+{suppressed} more since the last rate-limited line)");
        } else {
            crate::serr!("[spiceio] {args}");
        }
    } else {
        AUTH_LOG.suppressed.fetch_add(1, Ordering::Relaxed);
    }
}

fn log_failure(parts: &Parts, f: &AuthFailure, log_only: bool) {
    let verdict = if log_only {
        "would reject (log mode)"
    } else {
        "rejected"
    };
    // The path only: a presigned query carries a usable signature.
    let key = f.access_key_id().unwrap_or("-");
    match (f.canonical_request(), f.headers_not_signed()) {
        (Some(canonical), _) => log_event(format_args!(
            "auth: {verdict} {} {} key={key}: {} — canonical request {canonical:?}",
            parts.method,
            parts.uri.path(),
            f.code,
        )),
        (None, Some(unsigned)) => log_event(format_args!(
            "auth: {verdict} {} {} key={key}: {} — unsigned headers: {unsigned}",
            parts.method,
            parts.uri.path(),
            f.code,
        )),
        (None, None) => log_event(format_args!(
            "auth: {verdict} {} {} key={key}: {} — {}",
            parts.method,
            parts.uri.path(),
            f.code,
            f.message
        )),
    }
}

#[cfg(test)]
mod tests;
