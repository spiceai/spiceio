//! Parse write validators strictly: an invalid header must never become an
//! unconditional overwrite. Read validators have separate HTTP semantics.

use crate::smb::condition::WriteCondition;

pub(super) fn parse(headers: &http::HeaderMap) -> Result<WriteCondition, &'static str> {
    let value = |name| -> Result<Option<&str>, &'static str> {
        if headers.get_all(name).iter().count() > 1 {
            return Err("Duplicate conditional header");
        }
        headers
            .get(name)
            .map(|v| {
                v.to_str()
                    .map(str::trim)
                    .map_err(|_| "Invalid conditional header")
            })
            .transpose()
    };
    match (value("if-match")?, value("if-none-match")?) {
        (None, None) => Ok(WriteCondition::None),
        (None, Some("*")) => Ok(WriteCondition::Absent),
        (None, Some(_)) => Err("If-None-Match must be * for a write"),
        (Some(_), Some(_)) => Err("Specify only one write precondition"),
        (Some("*"), None) => Ok(WriteCondition::Exists),
        (Some(tag), None) => {
            if tag.starts_with("W/") || tag.contains(',') || tag.is_empty() {
                return Err("If-Match requires one strong ETag");
            }
            let tag = if tag.starts_with('"') || tag.ends_with('"') {
                tag.strip_prefix('"')
                    .and_then(|v| v.strip_suffix('"'))
                    .ok_or("Invalid ETag quoting")?
            } else {
                tag
            };
            if tag.is_empty() || tag.contains(['"', ' ', '\t']) {
                return Err("Invalid ETag");
            }
            Ok(WriteCondition::Match(tag.to_owned()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, HeaderValue};

    #[test]
    fn write_headers_cannot_silently_downgrade_to_unconditional() {
        let mut headers = HeaderMap::new();
        assert_eq!(parse(&headers).unwrap(), WriteCondition::None);
        for value in ["", "W/\"v1\"", "\"unterminated", "\"v1\",\"v2\""] {
            headers.insert("if-match", HeaderValue::from_str(value).unwrap());
            assert!(parse(&headers).is_err(), "{value}");
        }
        headers.insert("if-match", HeaderValue::from_static("\"v1\""));
        assert_eq!(parse(&headers).unwrap(), WriteCondition::Match("v1".into()));
        // Only the bare `*` is the wildcard; a quoted "*" is an exact tag.
        headers.insert("if-match", HeaderValue::from_static("*"));
        assert_eq!(parse(&headers).unwrap(), WriteCondition::Exists);
        headers.insert("if-match", HeaderValue::from_static("\"*\""));
        assert_eq!(parse(&headers).unwrap(), WriteCondition::Match("*".into()));
        headers.append("if-match", HeaderValue::from_static("\"v2\""));
        assert!(parse(&headers).is_err());
        headers.clear();
        headers.insert("if-none-match", HeaderValue::from_static("*"));
        assert_eq!(parse(&headers).unwrap(), WriteCondition::Absent);
        headers.insert("if-match", HeaderValue::from_static("v1"));
        assert!(parse(&headers).is_err());
    }
}
