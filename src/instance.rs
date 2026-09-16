//! Process instance identity.
//!
//! UUID v4 unless `SPICEIO_INSTANCE_ID` pins it. Used as OTEL
//! `service.instance.id` and logged at startup so a log stream matches a
//! metrics series. Pinning is how a launchd agent keeps a stable identity
//! across restarts.

use std::sync::OnceLock;

static ID: OnceLock<String> = OnceLock::new();

unsafe extern "C" {
    /// `getentropy(2)` — up to 256 bytes, the Darwin CSPRNG.
    fn getentropy(buf: *mut u8, buflen: usize) -> i32;
    fn gethostname(name: *mut i8, namelen: usize) -> i32;
}

/// Set the process instance id. Call once at startup, before anything that
/// logs or exports. `pinned` is `SPICEIO_INSTANCE_ID` when set and non-empty.
///
/// Returns the id that will be used for the rest of the process. Subsequent
/// calls return the same value and ignore `pinned`.
pub fn init(pinned: Option<String>) -> &'static str {
    ID.get_or_init(|| resolve_id(pinned))
}

fn resolve_id(pinned: Option<String>) -> String {
    match pinned.filter(|s| !s.is_empty()) {
        Some(id) => id,
        None => generate_uuid_v4(),
    }
}

/// The instance id, or `None` if [`init`] has not run.
pub fn id() -> Option<&'static str> {
    ID.get().map(String::as_str)
}

/// The instance id, generating one if [`init`] was skipped (tests).
pub fn id_or_generate() -> &'static str {
    init(None)
}

/// `machine` dimension: `pinned` (`SPICEIO_MACHINE`) when set and non-empty,
/// else the kernel hostname, else `"unknown"`.
pub fn machine(pinned: Option<String>) -> String {
    pinned
        .filter(|s| !s.is_empty())
        .or_else(hostname)
        .unwrap_or_else(|| "unknown".into())
}

/// Kernel hostname, used as the OTEL `machine` dimension when
/// `SPICEIO_MACHINE` is unset.
pub fn hostname() -> Option<String> {
    let mut buf = [0u8; 256];
    let rc = unsafe { gethostname(buf.as_mut_ptr().cast::<i8>(), buf.len()) };
    if rc != 0 {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let s = std::str::from_utf8(&buf[..end]).ok()?.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn generate_uuid_v4() -> String {
    let mut bytes = [0u8; 16];
    fill_random(&mut bytes);
    // RFC 4122 version 4, variant 1.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(36);
    for (i, &b) in bytes.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn fill_random(buf: &mut [u8]) {
    let rc = unsafe { getentropy(buf.as_mut_ptr(), buf.len()) };
    if rc == 0 {
        return;
    }
    // getentropy failing is exceptional; mix pid + wall time so we still
    // produce a unique-enough id rather than aborting startup.
    let mut h = crate::crypto::Sha256::new();
    h.update(&std::process::id().to_le_bytes());
    h.update(
        &std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_le_bytes(),
    );
    let digest = h.finalize();
    let n = buf.len().min(digest.len());
    buf[..n].copy_from_slice(&digest[..n]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_v4_shape_and_version() {
        let id = generate_uuid_v4();
        assert_eq!(id.len(), 36, "{id}");
        let parts: Vec<&str> = id.split('-').collect();
        assert_eq!(parts.len(), 5, "{id}");
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);
        assert!(
            parts[2].starts_with('4'),
            "version nibble must be 4, got {id}"
        );
        let variant = u8::from_str_radix(&parts[3][..1], 16).unwrap();
        assert!(
            (8..12).contains(&variant),
            "variant nibble must be 8..b, got {id}"
        );
        assert!(id.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
    }

    #[test]
    fn two_generated_ids_differ() {
        // A CSPRNG collision here would be a platform bug; this guards the
        // fallback hash path from collapsing to a constant.
        assert_ne!(generate_uuid_v4(), generate_uuid_v4());
    }

    #[test]
    fn pinned_id_wins_over_generated() {
        assert_eq!(resolve_id(Some("host-a".into())), "host-a");
        assert_eq!(resolve_id(None).len(), 36);
        assert_eq!(resolve_id(Some(String::new())).len(), 36);
    }

    #[test]
    fn hostname_is_non_empty() {
        let h = hostname().expect("gethostname");
        assert!(!h.is_empty());
        assert!(!h.contains('\0'));
    }

    #[test]
    fn machine_uses_pin_else_hostname() {
        assert_eq!(machine(Some("box-1".into())), "box-1");
        let fallback = hostname().unwrap_or_else(|| "unknown".into());
        assert_eq!(machine(None), fallback);
        assert_eq!(machine(Some(String::new())), fallback);
    }
}
