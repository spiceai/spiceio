//! In-process object body cache with S3-safe revalidation.
//!
//! Entries are keyed by object key and validated by etag (size+mtime). A hit
//! is only served after a fresh open/stat shows the same etag — so a peer
//! instance's overwrite is visible (new mtime → new etag → miss). Local
//! PUT/DELETE invalidate immediately.
//!
//! Optional `immutable` mode additionally allows lookup by key alone (for
//! content-addressed stores like sccache). Default is off.

use std::collections::HashMap;
use std::sync::Mutex;

use bytes::Bytes;

/// Default max total cached body bytes (256 MiB).
pub const DEFAULT_MAX_BYTES: u64 = 256 * 1024 * 1024;

/// Default max size of a single cached object (4 MiB — covers typical sccache
/// artifacts; larger objects still stream from SMB).
pub const DEFAULT_MAX_OBJECT_BYTES: u64 = 4 * 1024 * 1024;

/// Default max number of entries.
pub const DEFAULT_MAX_ENTRIES: usize = 4096;

#[derive(Clone)]
struct Entry {
    etag: String,
    body: Bytes,
    /// Generation bump for crude LRU: higher = more recently used.
    used: u64,
}

/// Process-local GET body cache.
pub struct ObjectCache {
    inner: Mutex<Inner>,
    /// When true, `get_by_key` may return a body without etag match (caller
    /// must still have decided that is safe for the deployment).
    immutable: bool,
    max_bytes: u64,
    max_object_bytes: u64,
    max_entries: usize,
}

struct Inner {
    map: HashMap<String, Entry>,
    total_bytes: u64,
    clock: u64,
}

impl ObjectCache {
    pub fn new(immutable: bool, max_bytes: u64, max_object_bytes: u64, max_entries: usize) -> Self {
        let max_bytes = max_bytes.max(1);
        // Per-object cap cannot exceed the total budget — keeps may_fill_cache
        // / insert() invariants aligned and avoids buffering a body that
        // insert() would immediately reject.
        let max_object_bytes = max_object_bytes.max(1).min(max_bytes);
        Self {
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                total_bytes: 0,
                clock: 0,
            }),
            immutable,
            max_bytes,
            max_object_bytes,
            max_entries: max_entries.max(1),
        }
    }

    pub fn from_env() -> Self {
        let immutable = std::env::var("SPICEIO_IMMUTABLE_OBJECTS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let max_bytes = std::env::var("SPICEIO_OBJECT_CACHE_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MAX_BYTES);
        let max_object_bytes = std::env::var("SPICEIO_OBJECT_CACHE_MAX_OBJECT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MAX_OBJECT_BYTES);
        let max_entries = std::env::var("SPICEIO_OBJECT_CACHE_ENTRIES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MAX_ENTRIES);
        Self::new(immutable, max_bytes, max_object_bytes, max_entries)
    }

    pub fn immutable(&self) -> bool {
        self.immutable
    }

    pub fn max_object_bytes(&self) -> u64 {
        self.max_object_bytes
    }

    /// True if any entry exists for `key` (used to prefer open/stat revalidation
    /// over a cold compound read that would re-fetch the body).
    pub fn contains_key(&self, key: &str) -> bool {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.map.contains_key(key)
    }

    /// Lookup requiring etag match (S3-safe path after open/stat).
    pub fn get_if_etag(&self, key: &str, etag: &str) -> Option<Bytes> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // Bump clock before borrowing the entry so the mutable map borrow
        // does not overlap with the clock field write.
        g.clock = g.clock.wrapping_add(1);
        let used = g.clock;
        let e = g.map.get_mut(key)?;
        if e.etag != etag {
            return None;
        }
        e.used = used;
        Some(e.body.clone())
    }

    /// Lookup by key only — only meaningful when `immutable` is set.
    pub fn get_by_key(&self, key: &str) -> Option<(String, Bytes)> {
        if !self.immutable {
            return None;
        }
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.clock = g.clock.wrapping_add(1);
        let used = g.clock;
        let e = g.map.get_mut(key)?;
        e.used = used;
        Some((e.etag.clone(), e.body.clone()))
    }

    /// Insert or replace. No-op if body is too large for the per-object cap.
    pub fn insert(&self, key: &str, etag: &str, body: Bytes) {
        let len = body.len() as u64;
        if len > self.max_object_bytes || len > self.max_bytes {
            return;
        }
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(old) = g.map.remove(key) {
            g.total_bytes = g.total_bytes.saturating_sub(old.body.len() as u64);
        }
        // Evict until we fit.
        while g.map.len() >= self.max_entries || g.total_bytes.saturating_add(len) > self.max_bytes
        {
            if g.map.is_empty() {
                break;
            }
            // Drop least-recently used.
            let victim = g
                .map
                .iter()
                .min_by_key(|(_, e)| e.used)
                .map(|(k, _)| k.clone());
            if let Some(k) = victim {
                if let Some(old) = g.map.remove(&k) {
                    g.total_bytes = g.total_bytes.saturating_sub(old.body.len() as u64);
                }
            } else {
                break;
            }
        }
        if g.total_bytes.saturating_add(len) > self.max_bytes {
            return;
        }
        g.clock = g.clock.wrapping_add(1);
        let used = g.clock;
        g.map.insert(
            key.to_string(),
            Entry {
                etag: etag.to_string(),
                body,
                used,
            },
        );
        g.total_bytes = g.total_bytes.saturating_add(len);
    }

    /// Drop any entry for `key` (local PUT/DELETE/overwrite).
    pub fn invalidate(&self, key: &str) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(old) = g.map.remove(key) {
            g.total_bytes = g.total_bytes.saturating_sub(old.body.len() as u64);
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map
            .len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[cfg(test)]
    pub fn total_bytes(&self) -> u64 {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .total_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etag_miss_on_mismatch() {
        let c = ObjectCache::new(false, 1024, 512, 16);
        c.insert("k", "e1", Bytes::from_static(b"hello"));
        assert!(c.get_if_etag("k", "e1").is_some());
        assert!(c.get_if_etag("k", "e2").is_none());
        assert!(c.get_by_key("k").is_none()); // immutable off
    }

    #[test]
    fn immutable_allows_key_lookup() {
        let c = ObjectCache::new(true, 1024, 512, 16);
        c.insert("k", "e1", Bytes::from_static(b"hello"));
        let (e, b) = c.get_by_key("k").unwrap();
        assert_eq!(e, "e1");
        assert_eq!(&b[..], b"hello");
    }

    #[test]
    fn invalidate_drops() {
        let c = ObjectCache::new(false, 1024, 512, 16);
        c.insert("k", "e1", Bytes::from_static(b"hello"));
        c.invalidate("k");
        assert!(c.get_if_etag("k", "e1").is_none());
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn rejects_oversized_object() {
        let c = ObjectCache::new(false, 1024, 4, 16);
        c.insert("k", "e1", Bytes::from_static(b"hello")); // 5 > 4
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn clamps_per_object_cap_to_total_budget() {
        let c = ObjectCache::new(false, 8, 64, 16);
        assert_eq!(c.max_object_bytes(), 8);
        c.insert("k", "e1", Bytes::from_static(b"123456789")); // 9 > 8
        assert!(c.is_empty());
    }

    #[test]
    fn evicts_lru_under_byte_cap() {
        let c = ObjectCache::new(false, 10, 10, 16);
        c.insert("a", "e", Bytes::from_static(b"aaaaa")); // 5
        c.insert("b", "e", Bytes::from_static(b"bbbbb")); // 5 — total 10
        let _ = c.get_if_etag("a", "e"); // touch a
        c.insert("c", "e", Bytes::from_static(b"ccccc")); // need 5 — should drop b (LRU)
        assert!(c.get_if_etag("a", "e").is_some());
        assert!(c.get_if_etag("b", "e").is_none());
        assert!(c.get_if_etag("c", "e").is_some());
    }
}
