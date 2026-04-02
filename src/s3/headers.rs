//! S3 header constants and parsing utilities.

use http::HeaderMap;

// ── Standard S3 request headers ─────────────────────────────────────────────

pub const X_AMZ_COPY_SOURCE: &str = "x-amz-copy-source";

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
    /// Returns `None` if `total == 0` or `start >= total`.
    pub fn resolve(&self, total: u64) -> Option<(u64, u64)> {
        if total == 0 {
            return None;
        }
        match (self.start, self.end) {
            (Some(s), Some(e)) => {
                if s >= total {
                    return None;
                }
                Some((s, e.min(total - 1)))
            }
            (Some(s), None) => {
                if s >= total {
                    return None;
                }
                Some((s, total - 1))
            }
            (None, Some(suffix)) => Some((total.saturating_sub(suffix), total - 1)),
            (None, None) => Some((0, total - 1)),
        }
    }
}

/// Parse simple HTTP-date (RFC 7231 / IMF-fixdate) or ISO 8601 to epoch seconds.
/// Supports: "Sun, 06 Nov 1994 08:49:37 GMT" and "2024-01-01T00:00:00Z".
pub fn parse_http_date(s: &str) -> Option<u64> {
    // Try ISO 8601 first (contains 'T' between date and time, not in "GMT")
    if s.contains('T') && !s.ends_with("GMT") {
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_range ───────────────────────────────────────────────────

    #[test]
    fn parse_range_start_end() {
        let r = parse_range("bytes=0-499").unwrap();
        assert_eq!(r.start, Some(0));
        assert_eq!(r.end, Some(499));
    }

    #[test]
    fn parse_range_open_end() {
        let r = parse_range("bytes=100-").unwrap();
        assert_eq!(r.start, Some(100));
        assert_eq!(r.end, None);
    }

    #[test]
    fn parse_range_suffix() {
        let r = parse_range("bytes=-200").unwrap();
        assert_eq!(r.start, None);
        assert_eq!(r.end, Some(200));
    }

    #[test]
    fn parse_range_invalid() {
        assert!(parse_range("not-a-range").is_none());
    }

    // ── RangeSpec::resolve ────────────────────────────────────────────

    #[test]
    fn resolve_full_range() {
        let r = RangeSpec {
            start: Some(0),
            end: Some(99),
        };
        assert_eq!(r.resolve(100), Some((0, 99)));
    }

    #[test]
    fn resolve_clamps_end() {
        let r = RangeSpec {
            start: Some(0),
            end: Some(999),
        };
        assert_eq!(r.resolve(100), Some((0, 99)));
    }

    #[test]
    fn resolve_open_end() {
        let r = RangeSpec {
            start: Some(50),
            end: None,
        };
        assert_eq!(r.resolve(100), Some((50, 99)));
    }

    #[test]
    fn resolve_suffix() {
        let r = RangeSpec {
            start: None,
            end: Some(10),
        };
        assert_eq!(r.resolve(100), Some((90, 99)));
    }

    #[test]
    fn resolve_suffix_larger_than_file() {
        let r = RangeSpec {
            start: None,
            end: Some(200),
        };
        assert_eq!(r.resolve(100), Some((0, 99)));
    }

    #[test]
    fn resolve_zero_total() {
        let r = RangeSpec {
            start: Some(0),
            end: Some(99),
        };
        assert_eq!(r.resolve(0), None);
    }

    #[test]
    fn resolve_start_past_end() {
        let r = RangeSpec {
            start: Some(200),
            end: None,
        };
        assert_eq!(r.resolve(100), None);
    }

    // ── parse_http_date ──────────────────────────────────────────────

    #[test]
    fn parse_http_date_rfc7231() {
        // date_to_epoch independently verified
        assert_eq!(date_to_epoch(1994, 11, 6, 8, 49, 37), 784111777);

        // IMF-fixdate parser: "Day, DD Mon YYYY HH:MM:SS GMT"
        let input = "Sun, 06 Nov 1994 08:49:37 GMT";
        let parts: Vec<&str> = input.split_whitespace().collect();
        // Sanity: verify split produces expected tokens
        assert_eq!(parts.len(), 6);
        assert_eq!(parts[1], "06");
        assert_eq!(parts[2], "Nov");

        let result = parse_http_date(input);
        assert!(
            result.is_some(),
            "parse_http_date returned None for: {input:?}, parts: {parts:?}"
        );
        assert_eq!(result.unwrap(), 784111777);
    }

    #[test]
    fn parse_http_date_iso8601() {
        let ts = parse_http_date("2024-01-15T12:30:45Z").unwrap();
        assert_eq!(ts, 1705321845);
    }

    #[test]
    fn parse_http_date_iso8601_millis() {
        let ts = parse_http_date("2024-01-15T12:30:45.000Z").unwrap();
        assert_eq!(ts, 1705321845);
    }

    #[test]
    fn parse_http_date_invalid() {
        assert!(parse_http_date("not a date").is_none());
    }

    // ── date round-trip ──────────────────────────────────────────────

    #[test]
    fn http_date_round_trip() {
        let formatted = crate::s3::xml::epoch_to_http_date(784111777);
        let parsed = parse_http_date(&formatted).unwrap();
        assert_eq!(parsed, 784111777);
    }
}
