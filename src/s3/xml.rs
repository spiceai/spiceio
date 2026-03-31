//! Minimal XML builder for S3 responses. No external crate needed.

/// A tiny XML builder optimized for S3 response generation.
pub struct XmlWriter {
    buf: String,
}

impl Default for XmlWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl XmlWriter {
    pub fn new() -> Self {
        Self {
            buf: String::with_capacity(4096),
        }
    }

    pub fn declaration(&mut self) -> &mut Self {
        self.buf
            .push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        self
    }

    pub fn open(&mut self, tag: &str) -> &mut Self {
        self.buf.push('<');
        self.buf.push_str(tag);
        self.buf.push('>');
        self
    }

    pub fn open_ns(&mut self, tag: &str, ns: &str) -> &mut Self {
        self.buf.push('<');
        self.buf.push_str(tag);
        self.buf.push_str(" xmlns=\"");
        self.buf.push_str(ns);
        self.buf.push_str("\">");
        self
    }

    pub fn close(&mut self, tag: &str) -> &mut Self {
        self.buf.push_str("</");
        self.buf.push_str(tag);
        self.buf.push('>');
        self
    }

    pub fn element(&mut self, tag: &str, value: &str) -> &mut Self {
        self.buf.push('<');
        self.buf.push_str(tag);
        self.buf.push('>');
        xml_escape_into(&mut self.buf, value);
        self.buf.push_str("</");
        self.buf.push_str(tag);
        self.buf.push('>');
        self
    }

    pub fn finish(self) -> String {
        self.buf
    }

    /// Push raw string content (e.g., for LocationConstraint body).
    pub fn buf_push_str(&mut self, s: &str) {
        xml_escape_into(&mut self.buf, s);
    }
}

/// Escape XML special characters.
fn xml_escape_into(buf: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => buf.push_str("&amp;"),
            '<' => buf.push_str("&lt;"),
            '>' => buf.push_str("&gt;"),
            '"' => buf.push_str("&quot;"),
            '\'' => buf.push_str("&apos;"),
            _ => buf.push(c),
        }
    }
}

/// Format Unix epoch seconds as ISO 8601 (S3 format).
pub fn epoch_to_iso8601(epoch_secs: u64) -> String {
    // Manual formatting without chrono dependency
    const DAYS_PER_400Y: u64 = 146097;

    let secs = epoch_secs;
    let days = secs / 86400;
    let time = secs % 86400;
    let hours = time / 3600;
    let minutes = (time % 3600) / 60;
    let seconds = time % 60;

    // Days since 0000-03-01 (adjusted epoch)
    let days = days + 719468; // offset from Unix epoch to 0000-03-01

    let era = days / DAYS_PER_400Y;
    let doe = days % DAYS_PER_400Y;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    // Write directly to a fixed-size buffer to avoid format! overhead.
    let mut buf = [0u8; 24]; // "YYYY-MM-DDTHH:MM:SS.000Z"
    write_u64_pad4(&mut buf[0..4], y);
    buf[4] = b'-';
    write_u64_pad2(&mut buf[5..7], m);
    buf[7] = b'-';
    write_u64_pad2(&mut buf[8..10], d);
    buf[10] = b'T';
    write_u64_pad2(&mut buf[11..13], hours);
    buf[13] = b':';
    write_u64_pad2(&mut buf[14..16], minutes);
    buf[16] = b':';
    write_u64_pad2(&mut buf[17..19], seconds);
    buf[19..24].copy_from_slice(b".000Z");

    // SAFETY: all bytes are ASCII
    unsafe { String::from_utf8_unchecked(buf.to_vec()) }
}

/// Format Unix epoch seconds as RFC 7231 HTTP-date.
/// e.g., "Sun, 06 Nov 1994 08:49:37 GMT"
pub fn epoch_to_http_date(epoch_secs: u64) -> String {
    const DAYS_PER_400Y: u64 = 146097;
    const DAY_NAMES: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTH_NAMES: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let secs = epoch_secs;
    let total_days = secs / 86400;
    let time = secs % 86400;
    let hours = time / 3600;
    let minutes = (time % 3600) / 60;
    let seconds = time % 60;

    // Day of week: Jan 1 1970 was a Thursday (index 0)
    let dow = DAY_NAMES[(total_days % 7) as usize];

    let days = total_days + 719468;
    let era = days / DAYS_PER_400Y;
    let doe = days % DAYS_PER_400Y;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let month_name = MONTH_NAMES[(m - 1) as usize];

    // Write directly to a fixed-size buffer: "Dow, DD Mon YYYY HH:MM:SS GMT" = 29 bytes
    let mut buf = [b' '; 29];
    buf[0..3].copy_from_slice(dow.as_bytes());
    buf[3] = b',';
    // buf[4] = b' ' (already)
    write_u64_pad2(&mut buf[5..7], d);
    // buf[7] = b' '
    buf[8..11].copy_from_slice(month_name.as_bytes());
    // buf[11] = b' '
    write_u64_pad4(&mut buf[12..16], y);
    // buf[16] = b' '
    write_u64_pad2(&mut buf[17..19], hours);
    buf[19] = b':';
    write_u64_pad2(&mut buf[20..22], minutes);
    buf[22] = b':';
    write_u64_pad2(&mut buf[23..25], seconds);
    buf[25..29].copy_from_slice(b" GMT");

    // SAFETY: all bytes are ASCII
    unsafe { String::from_utf8_unchecked(buf.to_vec()) }
}

/// Write a u64 as 2 decimal digits into a byte slice.
fn write_u64_pad2(buf: &mut [u8], v: u64) {
    buf[0] = b'0' + (v / 10) as u8;
    buf[1] = b'0' + (v % 10) as u8;
}

/// Write a u64 as 4 decimal digits into a byte slice.
fn write_u64_pad4(buf: &mut [u8], v: u64) {
    buf[0] = b'0' + (v / 1000) as u8;
    buf[1] = b'0' + ((v / 100) % 10) as u8;
    buf[2] = b'0' + ((v / 10) % 10) as u8;
    buf[3] = b'0' + (v % 10) as u8;
}

/// Minimal XML "parser" — extract text content of a named element.
/// Only handles simple flat elements like `<Key>value</Key>`.
pub fn extract_element<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(&xml[start..end])
}

/// Extract text between two sections — used for parsing Delete requests.
pub fn extract_sections<'a>(xml: &'a str, open_tag: &str, close_tag: &str) -> Vec<&'a str> {
    let mut results = Vec::new();
    let mut search = xml;
    while let Some(start_pos) = search.find(open_tag) {
        let content_start = start_pos + open_tag.len();
        if let Some(end_pos) = search[content_start..].find(close_tag) {
            results.push(&search[content_start..content_start + end_pos]);
            search = &search[content_start + end_pos + close_tag.len()..];
        } else {
            break;
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_writer_basic() {
        let mut w = XmlWriter::new();
        w.declaration();
        w.open_ns("Root", "http://example.com");
        w.element("Name", "hello");
        w.close("Root");
        let xml = w.finish();
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(xml.contains("<Root xmlns=\"http://example.com\">"));
        assert!(xml.contains("<Name>hello</Name>"));
        assert!(xml.ends_with("</Root>"));
    }

    #[test]
    fn xml_escape_special_chars() {
        let mut w = XmlWriter::new();
        w.element("Key", "a&b<c>d\"e'f");
        let xml = w.finish();
        assert_eq!(xml, "<Key>a&amp;b&lt;c&gt;d&quot;e&apos;f</Key>");
    }

    #[test]
    fn epoch_to_iso8601_unix_epoch() {
        assert_eq!(epoch_to_iso8601(0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn epoch_to_iso8601_known_date() {
        // 2024-01-15T12:30:45Z = 1705321845
        assert_eq!(epoch_to_iso8601(1705321845), "2024-01-15T12:30:45.000Z");
    }

    #[test]
    fn epoch_to_http_date_unix_epoch() {
        assert_eq!(epoch_to_http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    #[test]
    fn epoch_to_http_date_known_date() {
        // Sun, 06 Nov 1994 08:49:37 GMT = 784111777
        assert_eq!(
            epoch_to_http_date(784111777),
            "Sun, 06 Nov 1994 08:49:37 GMT"
        );
    }

    #[test]
    fn extract_element_found() {
        let xml = "<Root><Key>my/file.txt</Key><Other>x</Other></Root>";
        assert_eq!(extract_element(xml, "Key"), Some("my/file.txt"));
    }

    #[test]
    fn extract_element_missing() {
        assert_eq!(extract_element("<Root></Root>", "Key"), None);
    }

    #[test]
    fn extract_sections_multiple() {
        let xml = "<Delete><Object><Key>a</Key></Object><Object><Key>b</Key></Object></Delete>";
        let keys = extract_sections(xml, "<Key>", "</Key>");
        assert_eq!(keys, vec!["a", "b"]);
    }

    #[test]
    fn extract_sections_empty() {
        assert!(extract_sections("<Root/>", "<Key>", "</Key>").is_empty());
    }
}
