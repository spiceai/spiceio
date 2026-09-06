//! Bounded, resumable listing snapshots. First pages always walk the backend;
//! continuation pages reuse the sorted result, including during batch deletes.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::smb::ops::ObjectInfo;

const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_SNAPSHOTS: usize = 64;
const IDLE_TTL: Duration = Duration::from_secs(300);
const TOKEN_PREFIX: &str = "spiceio-list-v1:";

pub enum ListEntry {
    Object(ObjectInfo),
    Prefix(String),
}

impl ListEntry {
    pub fn key(&self) -> &str {
        match self {
            Self::Object(object) => &object.key,
            Self::Prefix(prefix) => prefix,
        }
    }
}

pub struct Snapshot {
    id: String,
    prefix: String,
    delimiter: Option<String>,
    pub entries: Vec<ListEntry>,
}

impl Snapshot {
    pub fn new(
        prefix: String,
        delimiter: Option<String>,
        objects: Vec<ObjectInfo>,
        prefixes: Vec<String>,
    ) -> Self {
        let mut entries: Vec<_> = objects
            .into_iter()
            .map(ListEntry::Object)
            .chain(prefixes.into_iter().map(ListEntry::Prefix))
            .collect();
        entries.sort_unstable_by(|a, b| a.key().cmp(b.key()));
        Self {
            id: super::headers::generate_request_id(),
            prefix,
            delimiter,
            entries,
        }
    }

    pub fn page(&self, after: &str, limit: usize) -> (&[ListEntry], bool) {
        let start = self.entries.partition_point(|entry| entry.key() <= after);
        let end = start.saturating_add(limit).min(self.entries.len());
        // max-keys=0 has no cursor to advance; do not advertise a next page.
        (
            &self.entries[start..end],
            limit > 0 && end < self.entries.len(),
        )
    }

    pub fn token(&self, last_key: &str) -> String {
        format!("{TOKEN_PREFIX}{}:{last_key}", self.id)
    }

    fn bytes(&self) -> usize {
        size_of::<Self>()
            + self.id.capacity()
            + self.prefix.capacity()
            + self.delimiter.as_ref().map_or(0, String::capacity)
            + self.entries.capacity() * size_of::<ListEntry>()
            + self
                .entries
                .iter()
                .map(|entry| match entry {
                    ListEntry::Object(object) => object.key.capacity() + object.etag.capacity(),
                    ListEntry::Prefix(prefix) => prefix.capacity(),
                })
                .sum::<usize>()
    }
}

/// The last key is embedded so an evicted/expired cursor can resume correctly
/// by walking again. Legacy versions used the raw key as their token.
pub fn decode_token(token: &str) -> (Option<&str>, &str) {
    match token
        .strip_prefix(TOKEN_PREFIX)
        .and_then(|s| s.split_once(':'))
    {
        Some((id, key)) => (Some(id), key),
        None => (None, token),
    }
}

struct Cached {
    snapshot: Arc<Snapshot>,
    touched: Instant,
    bytes: usize,
}

#[derive(Default)]
pub struct ListingCache {
    snapshots: Mutex<VecDeque<Cached>>,
}

impl ListingCache {
    /// `id=None` supports V1 markers and legacy V2 key tokens. Only requests
    /// continuing a listing call this; an initial page always sees fresh data.
    pub fn get(
        &self,
        id: Option<&str>,
        prefix: &str,
        delimiter: Option<&str>,
    ) -> Option<Arc<Snapshot>> {
        let mut snapshots = self.snapshots.lock().unwrap_or_else(|e| e.into_inner());
        snapshots.retain(|s| s.touched.elapsed() < IDLE_TTL);
        let index = snapshots.iter().rposition(|s| {
            s.snapshot.prefix == prefix
                && s.snapshot.delimiter.as_deref() == delimiter
                && id.is_none_or(|id| s.snapshot.id == id)
        })?;
        let mut cached = snapshots.remove(index)?;
        cached.touched = Instant::now();
        let snapshot = Arc::clone(&cached.snapshot);
        snapshots.push_back(cached);
        Some(snapshot)
    }

    pub fn insert(&self, snapshot: Arc<Snapshot>) {
        let bytes = snapshot.bytes();
        if bytes > MAX_BYTES {
            return;
        }
        let mut snapshots = self.snapshots.lock().unwrap_or_else(|e| e.into_inner());
        snapshots.retain(|s| s.touched.elapsed() < IDLE_TTL);
        let mut total: usize = snapshots.iter().map(|s| s.bytes).sum();
        while total + bytes > MAX_BYTES || snapshots.len() >= MAX_SNAPSHOTS {
            let Some(oldest) = snapshots.pop_front() else {
                break;
            };
            total -= oldest.bytes;
        }
        snapshots.push_back(Cached {
            snapshot,
            touched: Instant::now(),
            bytes,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(prefix: &str) -> Arc<Snapshot> {
        Arc::new(Snapshot::new(
            prefix.into(),
            Some("/".into()),
            ["z", "a"]
                .map(|key| ObjectInfo {
                    key: format!("{prefix}{key}"),
                    size: 1,
                    last_modified: 1,
                    etag: "e".into(),
                })
                .into(),
            vec![format!("{prefix}m/")],
        ))
    }

    #[test]
    fn pages_order_objects_and_prefixes_and_advance_past_deleted_markers() {
        let snapshot = snapshot("cache/");
        let (first, truncated) = snapshot.page("", 1);
        assert!(truncated);
        assert_eq!(first[0].key(), "cache/a");
        let token = snapshot.token(first[0].key());
        let (id, marker) = decode_token(&token);
        assert_eq!(id, Some(snapshot.id.as_str()));
        let (second, truncated) = snapshot.page(marker, 2);
        assert!(!truncated);
        assert_eq!(
            second.iter().map(ListEntry::key).collect::<Vec<_>>(),
            ["cache/m/", "cache/z"]
        );
        assert_eq!(snapshot.page("cache/b", 1).0[0].key(), "cache/m/");
        assert!(!snapshot.page("", 0).1);
    }

    #[test]
    fn cursors_keep_their_snapshot_when_a_fresh_listing_arrives() {
        let cache = ListingCache::default();
        let first = snapshot("cache/");
        cache.insert(Arc::clone(&first));
        cache.insert(snapshot("cache/"));
        assert!(Arc::ptr_eq(
            &first,
            &cache.get(Some(&first.id), "cache/", Some("/")).unwrap()
        ));
        assert!(cache.get(Some(&first.id), "another/", Some("/")).is_none());
        assert!(cache.get(Some(&first.id), "cache/", None).is_none());
    }

    #[test]
    fn eviction_and_expiry_leave_a_usable_resume_key() {
        let cache = ListingCache::default();
        let first = snapshot("cache/");
        let token = first.token("cache/a");
        cache.insert(Arc::clone(&first));
        for _ in 0..MAX_SNAPSHOTS {
            cache.insert(snapshot("cache/"));
        }
        assert!(cache.get(Some(&first.id), "cache/", Some("/")).is_none());
        assert_eq!(decode_token(&token).1, "cache/a");
        assert_eq!(cache.snapshots.lock().unwrap().len(), MAX_SNAPSHOTS);
        for s in cache.snapshots.lock().unwrap().iter_mut() {
            s.touched = Instant::now() - IDLE_TTL;
        }
        assert!(cache.get(None, "cache/", Some("/")).is_none());
    }
}
