//! Minimal XML builder for S3 responses. No external crate needed.

/// A tiny XML builder optimized for S3 response generation.
pub struct XmlWriter {
    buf: String,
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

    format!("{y:04}-{m:02}-{d:02}T{hours:02}:{minutes:02}:{seconds:02}.000Z")
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

    format!("{dow}, {d:02} {month_name} {y:04} {hours:02}:{minutes:02}:{seconds:02} GMT")
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
