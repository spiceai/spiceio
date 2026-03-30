//! S3 header constants and parsing utilities.

use http::HeaderMap;

// ── Standard S3 request headers ─────────────────────────────────────────────

pub const X_AMZ_CONTENT_SHA256: &str = "x-amz-content-sha256";
pub const X_AMZ_DATE: &str = "x-amz-date";
pub const X_AMZ_SECURITY_TOKEN: &str = "x-amz-security-token";
pub const X_AMZ_COPY_SOURCE: &str = "x-amz-copy-source";
pub const X_AMZ_COPY_SOURCE_RANGE: &str = "x-amz-copy-source-range";
pub const X_AMZ_METADATA_DIRECTIVE: &str = "x-amz-metadata-directive";
pub const X_AMZ_TAGGING: &str = "x-amz-tagging";
pub const X_AMZ_TAGGING_DIRECTIVE: &str = "x-amz-tagging-directive";
pub const X_AMZ_STORAGE_CLASS: &str = "x-amz-storage-class";
pub const X_AMZ_ACL: &str = "x-amz-acl";
pub const X_AMZ_GRANT_READ: &str = "x-amz-grant-read";
pub const X_AMZ_GRANT_WRITE: &str = "x-amz-grant-write";
pub const X_AMZ_GRANT_FULL_CONTROL: &str = "x-amz-grant-full-control";
pub const X_AMZ_SERVER_SIDE_ENCRYPTION: &str = "x-amz-server-side-encryption";
pub const X_AMZ_SSE_CUSTOMER_ALGORITHM: &str = "x-amz-server-side-encryption-customer-algorithm";
pub const X_AMZ_SSE_CUSTOMER_KEY: &str = "x-amz-server-side-encryption-customer-key";
pub const X_AMZ_SSE_CUSTOMER_KEY_MD5: &str = "x-amz-server-side-encryption-customer-key-md5";
pub const X_AMZ_REQUEST_PAYER: &str = "x-amz-request-payer";
pub const X_AMZ_EXPECTED_BUCKET_OWNER: &str = "x-amz-expected-bucket-owner";
pub const X_AMZ_OBJECT_LOCK_MODE: &str = "x-amz-object-lock-mode";
pub const X_AMZ_OBJECT_LOCK_RETAIN_UNTIL: &str = "x-amz-object-lock-retain-until-date";
pub const X_AMZ_OBJECT_LOCK_LEGAL_HOLD: &str = "x-amz-object-lock-legal-hold";
pub const X_AMZ_DELETE_MARKER: &str = "x-amz-delete-marker";
pub const X_AMZ_VERSION_ID: &str = "x-amz-version-id";
pub const X_AMZ_MFA: &str = "x-amz-mfa";
pub const X_AMZ_ABORT_DATE: &str = "x-amz-abort-date";
pub const X_AMZ_ABORT_RULE_ID: &str = "x-amz-abort-rule-id";
pub const X_AMZ_MP_PARTS_COUNT: &str = "x-amz-mp-parts-count";
pub const X_AMZ_WRITE_OFFSET_BYTES: &str = "x-amz-write-offset-bytes";

// ── Conditional headers ─────────────────────────────────────────────────────

pub const IF_MATCH: &str = "if-match";
pub const IF_NONE_MATCH: &str = "if-none-match";
pub const IF_MODIFIED_SINCE: &str = "if-modified-since";
pub const IF_UNMODIFIED_SINCE: &str = "if-unmodified-since";

pub const X_AMZ_COPY_SOURCE_IF_MATCH: &str = "x-amz-copy-source-if-match";
pub const X_AMZ_COPY_SOURCE_IF_NONE_MATCH: &str = "x-amz-copy-source-if-none-match";
pub const X_AMZ_COPY_SOURCE_IF_MODIFIED_SINCE: &str = "x-amz-copy-source-if-modified-since";
pub const X_AMZ_COPY_SOURCE_IF_UNMODIFIED_SINCE: &str = "x-amz-copy-source-if-unmodified-since";

// ── Common S3 response headers ──────────────────────────────────────────────

pub const X_AMZ_REQUEST_ID: &str = "x-amz-request-id";
pub const X_AMZ_ID_2: &str = "x-amz-id-2";
pub const X_AMZ_BUCKET_REGION: &str = "x-amz-bucket-region";

// ── User metadata prefix ────────────────────────────────────────────────────

pub const X_AMZ_META_PREFIX: &str = "x-amz-meta-";

/// Extract all user metadata headers (x-amz-meta-*) as key-value pairs.
pub fn extract_user_metadata(headers: &HeaderMap) -> Vec<(String, String)> {
    let mut meta = Vec::new();
    for (key, value) in headers.iter() {
        let name = key.as_str();
        if let Some(suffix) = name.strip_prefix(X_AMZ_META_PREFIX)
            && let Ok(val) = value.to_str()
        {
            meta.push((suffix.to_string(), val.to_string()));
        }
    }
    meta
}

/// Get a header value as a string.
pub fn get_header<'a>(headers: &'a HeaderMap, key: &str) -> Option<&'a str> {
    headers.get(key).and_then(|v| v.to_str().ok())
}

/// Parse a Range header: `bytes=start-end` or `bytes=start-` or `bytes=-suffix`.
#[derive(Debug, Clone)]
pub struct RangeSpec {
    pub start: Option<u64>,
    pub end: Option<u64>,
}

pub fn parse_range(header: &str) -> Option<RangeSpec> {
    let range = header.strip_prefix("bytes=")?;
    if let Some(suffix) = range.strip_prefix('-') {
        let n: u64 = suffix.parse().ok()?;
        return Some(RangeSpec {
            start: None,
            end: Some(n),
        });
    }
    let (start_str, end_str) = range.split_once('-')?;
    let start: u64 = start_str.parse().ok()?;
    let end = if end_str.is_empty() {
        None
    } else {
        Some(end_str.parse().ok()?)
    };
    Some(RangeSpec {
        start: Some(start),
        end,
    })
}

impl RangeSpec {
    /// Resolve to absolute byte positions given total file size.
    pub fn resolve(&self, total: u64) -> (u64, u64) {
        match (self.start, self.end) {
            (Some(s), Some(e)) => (s, e.min(total - 1)),
            (Some(s), None) => (s, total - 1),
            (None, Some(suffix)) => (total.saturating_sub(suffix), total - 1),
            (None, None) => (0, total - 1),
        }
    }
}

/// Parse simple HTTP-date (RFC 7231 / IMF-fixdate) or ISO 8601 to epoch seconds.
/// Supports: "Sun, 06 Nov 1994 08:49:37 GMT" and "2024-01-01T00:00:00Z".
pub fn parse_http_date(s: &str) -> Option<u64> {
    // Try ISO 8601 first
    if s.contains('T') {
        return parse_iso8601(s);
    }
    // IMF-fixdate: "Day, DD Mon YYYY HH:MM:SS GMT"
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }
    let day: u64 = parts[1].parse().ok()?;
    let month = month_number(parts[2])?;
    let year: u64 = parts[3].parse().ok()?;
    let time_parts: Vec<&str> = parts[4].split(':').collect();
    if time_parts.len() < 3 {
        return None;
    }
    let hour: u64 = time_parts[0].parse().ok()?;
    let min: u64 = time_parts[1].parse().ok()?;
    let sec: u64 = time_parts[2].parse().ok()?;
    Some(date_to_epoch(year, month, day, hour, min, sec))
}

fn parse_iso8601(s: &str) -> Option<u64> {
    // "2024-01-01T00:00:00Z" or "2024-01-01T00:00:00.000Z"
    let s = s.trim_end_matches('Z');
    let (date, time) = s.split_once('T')?;
    let dp: Vec<&str> = date.split('-').collect();
    let tp: Vec<&str> = time.split(':').collect();
    if dp.len() < 3 || tp.len() < 3 {
        return None;
    }
    let year: u64 = dp[0].parse().ok()?;
    let month: u64 = dp[1].parse().ok()?;
    let day: u64 = dp[2].parse().ok()?;
    let hour: u64 = tp[0].parse().ok()?;
    let min: u64 = tp[1].parse().ok()?;
    let sec_str = tp[2].split('.').next().unwrap_or("0");
    let sec: u64 = sec_str.parse().ok()?;
    Some(date_to_epoch(year, month, day, hour, min, sec))
}

fn month_number(s: &str) -> Option<u64> {
    Some(match s {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    })
}

fn date_to_epoch(year: u64, month: u64, day: u64, hour: u64, min: u64, sec: u64) -> u64 {
    // Compute days from civil date (algorithm from Howard Hinnant)
    let (y, m) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    days * 86400 + hour * 3600 + min * 60 + sec
}

/// Generate a unique request ID.
pub fn generate_request_id() -> String {
    let mut buf = [0u8; 16];
    unsafe extern "C" {
        fn arc4random_buf(buf: *mut u8, nbytes: usize);
    }
    unsafe {
        arc4random_buf(buf.as_mut_ptr(), 16);
    }
    crate::crypto::hex_encode(&buf).to_uppercase()
}
