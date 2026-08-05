//! Object body cache with S3-safe revalidation, over two tiers.
//!
//! Entries are keyed by object key and validated by etag (size+mtime). A hit
//! is only served after a fresh open/stat shows the same etag — so a peer
//! instance's overwrite is visible (new mtime → new etag → miss). Local
//! PUT/DELETE invalidate immediately.
//!
//! Optional `immutable` mode serves a hit by key alone, with **no SMB round
//! trip at all** — the only path in the proxy that answers a GET without
//! touching the NAS. See [`ObjectCache::get_by_key`] for when that is sound.
//!
//! # Tiers
//!
//! L1 is this process's memory, bounded by [`DEFAULT_MAX_BYTES`]. L2 is
//! [`crate::s3::spill::Spill`] — a directory on local disk shared by every
//! spiceio instance on the machine, an order of magnitude larger and still an
//! order of magnitude faster than the NAS. The `lookup_*` methods read through
//! both and promote an L2 hit into L1; `store` writes to both.
//!
//! The sync methods (`get_if_etag`, `insert`, `invalidate`, …) address L1
//! alone. They are what the tiered methods are built from, and what the unit
//! tests exercise directly.
//!
//! # Why the LRU is indexed
//!
//! Eviction used to pick its victim by scanning every entry for the minimum
//! use-generation, under the cache lock, on the insert path. That is O(n) per
//! eviction once the cache is full, which quietly caps how large the cache can
//! usefully be: at the 4096-entry default it is a 4096-entry scan per insert,
//! and raising the cache to hold a real sccache working set (tens of thousands
//! of objects) would have made a *bigger* cache *slower*. Since the cache is
//! the only mechanism measured to beat the backend's throughput ceiling, that
//! ceiling on its size was the thing worth removing. A `BTreeMap` keyed by
//! use-generation makes eviction a `pop_first` and touch an O(log n) reindex.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;

use super::spill::{DirtyEntry, Spill, SweepStats};

/// Default max total cached body bytes (8 GiB).
///
/// This is the knob that trades resident memory for backend traffic, and it is
/// the most effective one available: the cache is the only path that answers a
/// GET without touching the backend, and the backend saturates at a fixed rate
/// (~100 MiB/s measured — see `benches/baselines/`). A budget large enough to
/// hold the working set is what turns a 26× per-request win into a sustained
/// one; at 256 MiB a 294 MiB working set measured a 60% hit rate, and the
/// misses are what the throughput ceiling then applies to.
///
/// **This is up to 8 GiB of resident memory.** Eviction is O(log n), so the
/// size costs nothing in CPU, but a host that cannot spare it should lower
/// `SPICEIO_OBJECT_CACHE_BYTES`. The configured budget is logged at startup and
/// the achieved hit rate at shutdown.
pub const DEFAULT_MAX_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Fraction of the total budget any single object may occupy.
///
/// The per-object cap is not really about object size — it is about how many
/// *other* objects one admission may evict. Measured: raising the cap to 32 MiB
/// against the default 256 MiB budget dropped the hit rate from 93% to 60%,
/// because each 16 MiB artifact displaced ~28 average ones, and the small
/// objects it evicted were the overwhelming majority of requests.
///
/// So the cap is derived from the budget rather than fixed. 1/64 reproduces the
/// 4 MiB default that measured well at 256 MiB, and scales on its own when the
/// budget is sized up — a 2 GiB cache admits 32 MiB objects without the
/// pollution, because there it really is a small share.
const MAX_OBJECT_FRACTION: u64 = 64;

/// Floor for the derived per-object cap, so a very small cache still holds
/// something useful rather than rejecting every object.
const MIN_DERIVED_MAX_OBJECT: u64 = 1024 * 1024;

/// Default max size of a single cached object, given a total budget.
pub fn default_max_object_bytes(max_bytes: u64) -> u64 {
    (max_bytes / MAX_OBJECT_FRACTION).max(MIN_DERIVED_MAX_OBJECT)
}

/// Default max number of entries.
///
/// Raised with the byte budget so that *bytes* stay the binding constraint:
/// 4096 entries against an 8 GiB budget would cap the cache at 4096 objects
/// (~2 GiB at the measured mean size), quietly wasting most of it. This bounds
/// index overhead instead, which is what the entry cap is actually for.
pub const DEFAULT_MAX_ENTRIES: usize = 131_072;

#[derive(Clone)]
struct Entry {
    etag: String,
    body: Bytes,
    /// Stored so an immutable-mode hit can build the whole response without
    /// asking the backend for anything. Without it, `Last-Modified` alone
    /// would force the stat the cache exists to avoid.
    last_modified: u64,
    /// Use-generation, and this entry's key into `Inner::lru`.
    used: u64,
}

/// Everything needed to answer a GET from memory, with no backend call.
pub struct CachedObject {
    pub etag: String,
    pub last_modified: u64,
    pub body: Bytes,
}

/// GET body cache: process memory over an optional shared disk tier.
pub struct ObjectCache {
    inner: Mutex<Inner>,
    /// When true, `get_by_key` may return a body without etag match (caller
    /// must still have decided that is safe for the deployment).
    immutable: bool,
    /// L2 — the machine-wide disk spill, when configured.
    spill: Option<Arc<Spill>>,
    max_bytes: u64,
    max_object_bytes: u64,
    max_entries: usize,
    /// Served-from-memory count, and the requests that had to reach the NAS.
    /// Reported at shutdown: the cache is the main performance lever, and a
    /// deployment whose hit rate is near zero (working set larger than the
    /// budget) looks identical to one that is working, from the outside.
    hits: AtomicU64,
    misses: AtomicU64,
    hit_bytes: AtomicU64,
}

struct Inner {
    map: HashMap<String, Entry>,
    /// Use-generation → key, ordered oldest first. Kept in lockstep with
    /// `map`: every entry appears exactly once, under its `Entry::used`.
    lru: BTreeMap<u64, String>,
    total_bytes: u64,
    clock: u64,
}

impl Inner {
    /// Mark `key` as most recently used, keeping the LRU index consistent.
    fn touch(&mut self, key: &str) {
        self.clock = self.clock.wrapping_add(1);
        let used = self.clock;
        let Some(e) = self.map.get_mut(key) else {
            return;
        };
        let old = std::mem::replace(&mut e.used, used);
        self.lru.remove(&old);
        self.lru.insert(used, key.to_string());
    }

    /// Remove `key` from both halves, returning its size.
    fn remove(&mut self, key: &str) -> u64 {
        match self.map.remove(key) {
            Some(e) => {
                self.lru.remove(&e.used);
                let n = e.body.len() as u64;
                self.total_bytes = self.total_bytes.saturating_sub(n);
                n
            }
            None => 0,
        }
    }

    /// Drop the least recently used entry. Returns false when empty.
    fn evict_one(&mut self) -> bool {
        let Some((_, key)) = self.lru.pop_first() else {
            return false;
        };
        if let Some(e) = self.map.remove(&key) {
            self.total_bytes = self.total_bytes.saturating_sub(e.body.len() as u64);
        }
        true
    }
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
                lru: BTreeMap::new(),
                total_bytes: 0,
                clock: 0,
            }),
            immutable,
            spill: None,
            max_bytes,
            max_object_bytes,
            max_entries: max_entries.max(1),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            hit_bytes: AtomicU64::new(0),
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
            .unwrap_or_else(|| default_max_object_bytes(max_bytes));
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

    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Attach the shared disk tier.
    pub fn with_spill(mut self, spill: Arc<Spill>) -> Self {
        self.spill = Some(spill);
        self
    }

    pub fn spill(&self) -> Option<&Arc<Spill>> {
        self.spill.as_ref()
    }

    // ── Tiered access ───────────────────────────────────────────────────
    //
    // Spill work runs on the blocking pool: these are file reads and writes,
    // and letting one stall a runtime worker would stall unrelated requests.
    // Each call is a single blocking hop — a miss costs one failed `open`,
    // which is cheap against the backend read it is trying to avoid.

    /// Etag-validated lookup across both tiers (the S3-safe path, after a stat).
    pub async fn lookup_etag(&self, key: &str, etag: &str) -> Option<Bytes> {
        if let Some(body) = self.get_if_etag(key, etag) {
            return Some(body);
        }
        let spill = self.spill.as_ref()?;
        let entry = read_spill(spill, key).await?;
        if entry.etag != etag {
            // On disk but superseded on the backend. Drop it now rather than
            // re-reading and re-rejecting it on every future request.
            let spill = Arc::clone(spill);
            let key_owned = key.to_string();
            let _ = tokio::task::spawn_blocking(move || spill.remove(&key_owned)).await;
            return None;
        }
        self.promote(key, &entry);
        self.note_hit(entry.body.len() as u64);
        Some(entry.body)
    }

    /// Lookup by key alone across both tiers — immutable mode only.
    pub async fn lookup_key(&self, key: &str) -> Option<CachedObject> {
        if !self.immutable {
            return None;
        }
        self.lookup_any(key).await
    }

    /// Lookup by key alone, without the immutable gate.
    ///
    /// Only for a key with an acknowledged write that has not reached the
    /// backend: the cache *is* the authority for it, and revalidating would
    /// compare against an object the NAS does not have yet. Everything else
    /// must go through [`Self::lookup_etag`] or [`Self::lookup_key`].
    pub async fn lookup_pending(&self, key: &str) -> Option<CachedObject> {
        self.lookup_any(key).await
    }

    async fn lookup_any(&self, key: &str) -> Option<CachedObject> {
        if let Some(hit) = self.get_any(key) {
            self.note_hit(hit.body.len() as u64);
            return Some(hit);
        }
        let spill = self.spill.as_ref()?;
        let entry = read_spill(spill, key).await?;
        self.promote(key, &entry);
        self.note_hit(entry.body.len() as u64);
        Some(CachedObject {
            etag: entry.etag,
            last_modified: entry.last_modified,
            body: entry.body,
        })
    }

    /// True if either tier may hold `key` — used to prefer a cheap stat
    /// revalidation over a cold read that would re-fetch the body.
    pub async fn may_hold(&self, key: &str) -> bool {
        if self.contains_key(key) {
            return true;
        }
        match self.spill.as_ref() {
            Some(spill) => {
                let spill = Arc::clone(spill);
                let key = key.to_string();
                tokio::task::spawn_blocking(move || spill.contains_key(&key))
                    .await
                    .unwrap_or(false)
            }
            None => false,
        }
    }

    /// Insert into memory, and publish to the shared tier in the background.
    ///
    /// The disk write is not awaited: it is off the critical path of whatever
    /// response is being built, and a failed spill write is a missing cache
    /// entry, never a failed request. The same race L1 has always had applies —
    /// a concurrent invalidate can be overtaken by an insert already in flight
    /// — and is resolved the same way, by etag revalidation on the next read.
    pub fn store(&self, key: &str, etag: &str, last_modified: u64, body: Bytes) {
        self.insert(key, etag, last_modified, body.clone());
        let Some(spill) = self.spill.as_ref() else {
            return;
        };
        if body.len() as u64 > spill.max_object_bytes() {
            return;
        }
        let spill = Arc::clone(spill);
        let key = key.to_string();
        let etag = etag.to_string();
        tokio::task::spawn_blocking(move || {
            if let Err(e) = spill.put(&key, &etag, last_modified, &body, false) {
                crate::serr!("[spiceio] spill write failed for {key}: {e}");
            }
        });
    }

    /// Drop a stale cached copy of `key` from both tiers, keeping any
    /// journalled write.
    ///
    /// This is the invalidation a *revalidation failure* calls for — the
    /// backend says the object is gone or has changed. A dirty spill entry is
    /// not a stale copy: it is an acknowledged write the backend has not
    /// received yet, quite possibly a peer instance's, and dropping it would
    /// discard a write some client was told had succeeded.
    pub async fn invalidate_stale(&self, key: &str) {
        self.invalidate(key);
        let Some(spill) = self.spill.as_ref() else {
            return;
        };
        let spill = Arc::clone(spill);
        let key = key.to_string();
        let _ = tokio::task::spawn_blocking(move || spill.drop_clean(&key)).await;
    }

    /// Drop `key` from both tiers entirely, journalled write included.
    ///
    /// For an explicit DELETE or a wholesale replacement, where the object is
    /// genuinely going away. Awaited, unlike [`Self::store`]: a DELETE that
    /// returned 204 must not be followed by a GET that finds the body on disk.
    pub async fn forget(&self, key: &str) {
        self.invalidate(key);
        let Some(spill) = self.spill.as_ref() else {
            return;
        };
        let spill = Arc::clone(spill);
        let key = key.to_string();
        let _ = tokio::task::spawn_blocking(move || spill.remove(&key)).await;
    }

    /// Replace an entry's provisional metadata with the backend's, once an
    /// asynchronous write has landed. No-op if the entry has since been
    /// replaced — that body owns the key now, and carries its own metadata.
    pub fn retag(&self, key: &str, from_etag: &str, to_etag: &str, last_modified: u64) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(e) = g.map.get_mut(key)
            && e.etag == from_etag
        {
            e.etag = to_etag.to_string();
            e.last_modified = last_modified;
        }
    }

    /// Journal an acknowledged write to the shared tier, marked dirty. Returns
    /// the body digest, which [`Self::spill_promote`] needs to prove it is
    /// promoting the same bytes.
    pub async fn spill_put_dirty(
        &self,
        key: &str,
        etag: &str,
        last_modified: u64,
        body: &Bytes,
    ) -> Option<[u8; 32]> {
        let spill = self.spill.as_ref()?;
        if body.len() as u64 > spill.max_object_bytes() {
            return None;
        }
        let spill = Arc::clone(spill);
        let key_owned = key.to_string();
        // Journal the provisional metadata, not a placeholder: a peer instance
        // reading this pending write off the shared tier answers a GET with it.
        let etag = etag.to_string();
        let body = body.clone();
        match tokio::task::spawn_blocking(move || {
            spill
                .put(&key_owned, &etag, last_modified, &body, true)
                .map(Some)
        })
        .await
        {
            Ok(Ok(sha)) => sha,
            Ok(Err(e)) => {
                crate::serr!("[spiceio] write-back journal failed for {key}: {e}");
                None
            }
            Err(_) => None,
        }
    }

    /// Mark a journalled write clean and give it the backend's metadata.
    pub async fn spill_promote(
        &self,
        key: &str,
        sha: [u8; 32],
        etag: &str,
        last_modified: u64,
        body: &Bytes,
    ) {
        let Some(spill) = self.spill.as_ref() else {
            return;
        };
        let spill = Arc::clone(spill);
        let key_owned = key.to_string();
        let etag = etag.to_string();
        let body = body.clone();
        let res = tokio::task::spawn_blocking(move || {
            spill.promote(&key_owned, &sha, &etag, last_modified, &body)
        })
        .await;
        if let Ok(Err(e)) = res {
            crate::serr!("[spiceio] spill promote failed for {key}: {e}");
        }
    }

    /// Keys this process journalled dirty that have not reached the backend.
    /// Unlike [`Self::spill_scan_dirty`], never includes a peer's entries.
    pub fn spill_owned_dirty(&self) -> Vec<String> {
        match self.spill.as_ref() {
            Some(spill) => spill.owned_dirty_keys(),
            None => Vec::new(),
        }
    }

    /// Read one entry off the shared tier by key, whatever its state.
    pub async fn spill_read(&self, key: &str) -> Option<super::spill::SpillEntry> {
        let spill = self.spill.as_ref()?;
        read_spill(spill, key).await
    }

    /// Acknowledged writes on disk that never reached the backend.
    /// Returns `(entries ready to replay, entries skipped for being too young)`.
    pub async fn spill_scan_dirty(&self, min_age: Duration) -> (Vec<DirtyEntry>, usize) {
        let Some(spill) = self.spill.as_ref() else {
            return (Vec::new(), 0);
        };
        let spill = Arc::clone(spill);
        tokio::task::spawn_blocking(move || spill.scan_dirty(min_age))
            .await
            .unwrap_or_default()
    }

    /// Enforce the shared tier's budget.
    pub async fn spill_sweep(&self) -> Option<SweepStats> {
        let spill = Arc::clone(self.spill.as_ref()?);
        tokio::task::spawn_blocking(move || spill.sweep())
            .await
            .ok()
    }

    /// L1 lookup by key, ignoring the immutable gate.
    fn get_any(&self, key: &str) -> Option<CachedObject> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let found = g.map.get(key).map(|e| CachedObject {
            etag: e.etag.clone(),
            last_modified: e.last_modified,
            body: e.body.clone(),
        })?;
        g.touch(key);
        Some(found)
    }

    /// Pull an L2 hit into L1 so the next read skips the disk entirely.
    fn promote(&self, key: &str, entry: &super::spill::SpillEntry) {
        self.insert(key, &entry.etag, entry.last_modified, entry.body.clone());
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
        let body = match g.map.get(key) {
            Some(e) if e.etag == etag => e.body.clone(),
            _ => return None,
        };
        g.touch(key);
        drop(g);
        self.note_hit(body.len() as u64);
        Some(body)
    }

    /// Lookup by key alone, with no revalidation against the backend.
    ///
    /// Only enabled by `immutable` mode, and only sound where the key
    /// determines the content — a content-addressed store such as sccache,
    /// whose keys *are* hashes of the bytes they name. There, an entry cannot
    /// go stale: nothing can put different content under the same key, so
    /// there is nothing a revalidation could discover.
    ///
    /// What it gives up is noticing that the object was *deleted* on the
    /// backend, which for a cache is not a correctness problem — the client
    /// asked for a specific content hash and receives exactly those bytes.
    ///
    /// What it buys is the round trip. This is the only path that answers a GET
    /// without any SMB traffic, so it is also the only one that does not
    /// consume a pool slot or backend bandwidth — which matters most precisely
    /// when the backend is the bottleneck.
    pub fn get_by_key(&self, key: &str) -> Option<CachedObject> {
        if !self.immutable {
            return None;
        }
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let found = g.map.get(key).map(|e| CachedObject {
            etag: e.etag.clone(),
            last_modified: e.last_modified,
            body: e.body.clone(),
        });
        let hit = found?;
        g.touch(key);
        drop(g);
        self.note_hit(hit.body.len() as u64);
        Some(hit)
    }

    /// Count a request that had to reach the backend.
    pub fn note_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    fn note_hit(&self, bytes: u64) {
        self.hits.fetch_add(1, Ordering::Relaxed);
        self.hit_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// `(hits, misses, bytes served from memory)`.
    pub fn stats(&self) -> (u64, u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
            self.hit_bytes.load(Ordering::Relaxed),
        )
    }

    /// Insert or replace. No-op if body is too large for the per-object cap.
    pub fn insert(&self, key: &str, etag: &str, last_modified: u64, body: Bytes) {
        let len = body.len() as u64;
        if len > self.max_object_bytes || len > self.max_bytes {
            return;
        }
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.remove(key);
        // Evict until we fit. `evict_one` pops the oldest use-generation from
        // the index rather than scanning for it.
        while g.map.len() >= self.max_entries || g.total_bytes.saturating_add(len) > self.max_bytes
        {
            if !g.evict_one() {
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
                last_modified,
                used,
            },
        );
        g.lru.insert(used, key.to_string());
        g.total_bytes = g.total_bytes.saturating_add(len);
    }

    /// Drop any entry for `key` (local PUT/DELETE/overwrite).
    pub fn invalidate(&self, key: &str) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.remove(key);
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

    /// Test-only consistency check: the map and the LRU index must agree
    /// exactly, or eviction starts picking victims that are not there (leaking
    /// bytes from the accounting) or missing ones that are.
    #[cfg(test)]
    fn assert_consistent(&self) {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(g.map.len(), g.lru.len(), "map/lru size drift");
        let bytes: u64 = g.map.values().map(|e| e.body.len() as u64).sum();
        assert_eq!(bytes, g.total_bytes, "byte accounting drift");
        for (used, key) in &g.lru {
            let e = g.map.get(key).expect("lru names a missing key");
            assert_eq!(e.used, *used, "lru generation disagrees with entry");
        }
    }

    #[cfg(test)]
    pub fn total_bytes(&self) -> u64 {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .total_bytes
    }
}

/// Read one entry off the shared tier without blocking a runtime worker.
async fn read_spill(spill: &Arc<Spill>, key: &str) -> Option<super::spill::SpillEntry> {
    let spill = Arc::clone(spill);
    let key = key.to_string();
    tokio::task::spawn_blocking(move || spill.get(&key))
        .await
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Tiered behaviour (L1 over a real spill directory) ────────────

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "spiceio-cache-test-{}-{tag}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tiered(immutable: bool, dir: &TempDir) -> ObjectCache {
        let spill = Spill::open(&dir.0, "ns".into(), 1 << 20, 1 << 18).unwrap();
        ObjectCache::new(immutable, 1 << 20, 1 << 18, 64).with_spill(Arc::new(spill))
    }

    #[tokio::test]
    async fn a_spill_hit_is_promoted_into_memory() {
        // The point of the disk tier: a body evicted from RAM (or written by a
        // peer instance) is served without touching the NAS, and lands back in
        // RAM so the next read skips the disk too.
        let d = TempDir::new("promote");
        let c = tiered(false, &d);
        c.store("k", "e1", 7, Bytes::from_static(b"body"));
        // Let the background spill write land, then evict from L1 only.
        tokio::task::yield_now().await;
        for _ in 0..100 {
            if c.spill().unwrap().contains_key("k") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        c.invalidate("k");
        assert!(c.get_if_etag("k", "e1").is_none(), "still in memory");

        let hit = c.lookup_etag("k", "e1").await.expect("spill miss");
        assert_eq!(&hit[..], b"body");
        assert!(
            c.get_if_etag("k", "e1").is_some(),
            "a disk hit was not promoted into memory"
        );
    }

    #[tokio::test]
    async fn a_superseded_spill_entry_is_dropped_not_served() {
        let d = TempDir::new("stale");
        let c = tiered(false, &d);
        c.spill()
            .unwrap()
            .put("k", "old-etag", 1, b"old-body", false)
            .unwrap();
        assert!(c.lookup_etag("k", "new-etag").await.is_none());
        // Dropped on the spot, so the next read does not re-fetch and re-reject.
        assert!(!c.spill().unwrap().contains_key("k"));
    }

    #[tokio::test]
    async fn forget_clears_both_tiers() {
        // A DELETE that returned 204 must not be followed by a GET that finds
        // the body still on disk.
        let d = TempDir::new("forget");
        let c = tiered(true, &d);
        c.spill().unwrap().put("k", "e", 1, b"body", false).unwrap();
        c.insert("k", "e", 1, Bytes::from_static(b"body"));
        c.forget("k").await;
        assert!(c.lookup_key("k").await.is_none());
        assert!(!c.spill().unwrap().contains_key("k"));
    }

    #[tokio::test]
    async fn may_hold_sees_the_disk_tier() {
        let d = TempDir::new("may-hold");
        let c = tiered(false, &d);
        assert!(!c.may_hold("k").await);
        c.spill().unwrap().put("k", "e", 1, b"body", false).unwrap();
        assert!(c.may_hold("k").await);
    }

    #[tokio::test]
    async fn lookup_pending_ignores_the_immutable_gate() {
        // Pending keys are served by key in *both* modes: the cache is their
        // only authority until the write reaches the backend.
        let d = TempDir::new("pending");
        let c = tiered(false, &d);
        c.insert("k", "provisional", 1, Bytes::from_static(b"body"));
        assert!(c.lookup_key("k").await.is_none(), "immutable gate leaked");
        assert_eq!(&c.lookup_pending("k").await.unwrap().body[..], b"body");
    }

    #[test]
    fn retag_adopts_backend_metadata_only_for_the_matching_body() {
        let c = ObjectCache::new(false, 1 << 20, 1 << 18, 64);
        c.insert("k", "provisional", 1, Bytes::from_static(b"body"));
        c.retag("k", "provisional", "real", 999);
        let hit = c.get_if_etag("k", "real").expect("etag not adopted");
        assert_eq!(&hit[..], b"body");

        // A newer body owns the key now; a late flush must not stamp the old
        // write's backend metadata onto it.
        c.insert("k", "newer", 2, Bytes::from_static(b"newer-body"));
        c.retag("k", "provisional", "real", 999);
        assert!(
            c.get_if_etag("k", "real").is_none(),
            "retagged a newer body"
        );
        assert!(c.get_if_etag("k", "newer").is_some());
    }

    #[test]
    fn etag_miss_on_mismatch() {
        let c = ObjectCache::new(false, 1024, 512, 16);
        c.insert("k", "e1", 0, Bytes::from_static(b"hello"));
        assert!(c.get_if_etag("k", "e1").is_some());
        assert!(c.get_if_etag("k", "e2").is_none());
        assert!(c.get_by_key("k").is_none()); // immutable off
    }

    #[test]
    fn immutable_allows_key_lookup() {
        let c = ObjectCache::new(true, 1024, 512, 16);
        c.insert("k", "e1", 0, Bytes::from_static(b"hello"));
        let hit = c.get_by_key("k").unwrap();
        assert_eq!(hit.etag, "e1");
        assert_eq!(&hit.body[..], b"hello");
    }

    #[test]
    fn invalidate_drops() {
        let c = ObjectCache::new(false, 1024, 512, 16);
        c.insert("k", "e1", 0, Bytes::from_static(b"hello"));
        c.invalidate("k");
        assert!(c.get_if_etag("k", "e1").is_none());
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn rejects_oversized_object() {
        let c = ObjectCache::new(false, 1024, 4, 16);
        c.insert("k", "e1", 0, Bytes::from_static(b"hello")); // 5 > 4
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn default_budget_makes_bytes_the_binding_constraint() {
        // The entry cap exists to bound index overhead, not to cap the cache.
        // If it binds first the byte budget is silently unreachable.
        let mean_object = 589 * 1024u64; // measured sccache mean
        let entries_needed = DEFAULT_MAX_BYTES / mean_object;
        assert!(
            DEFAULT_MAX_ENTRIES as u64 >= entries_needed,
            "entry cap {} binds before the {} GiB byte budget ({} entries needed)",
            DEFAULT_MAX_ENTRIES,
            DEFAULT_MAX_BYTES / (1024 * 1024 * 1024),
            entries_needed
        );
    }

    #[test]
    fn derived_object_cap_scales_with_the_budget() {
        // 1/64 of the budget: reproduces the 4 MiB cap that measured well at the
        // 256 MiB default, and grows with a cache sized to a real working set
        // instead of needing a second knob turned in lockstep.
        assert_eq!(default_max_object_bytes(256 * 1024 * 1024), 4 * 1024 * 1024);
        assert_eq!(
            default_max_object_bytes(2 * 1024 * 1024 * 1024),
            32 * 1024 * 1024
        );
        // A tiny cache still admits something rather than rejecting everything.
        assert_eq!(default_max_object_bytes(1024), MIN_DERIVED_MAX_OBJECT);
    }

    #[test]
    fn one_object_cannot_evict_the_whole_cache() {
        // The property the fraction exists to guarantee, stated directly on the
        // ratio rather than via `default_max_object_bytes` (whose 1 MiB floor
        // deliberately overrides the fraction for caches too small for it to
        // mean anything). Admitting the largest permitted object must cost only
        // a small share of what is already cached.
        let budget: u64 = 64 * 1024;
        let cap = budget / MAX_OBJECT_FRACTION; // 1 KiB
        let c = ObjectCache::new(false, budget, cap, 10_000);
        let small = 256usize;
        for i in 0..(budget as usize / small) {
            c.insert(&format!("s{i}"), "e", 0, Bytes::from(vec![b'x'; small]));
        }
        let before = c.len();
        c.insert("big", "e", 0, Bytes::from(vec![b'x'; cap as usize]));
        let survived = c.len().saturating_sub(1); // exclude "big" itself
        assert!(
            survived * 20 >= before * 19,
            "one admission evicted more than 5% of the cache: {before} -> {survived}"
        );
        c.assert_consistent();
    }

    #[test]
    fn clamps_per_object_cap_to_total_budget() {
        let c = ObjectCache::new(false, 8, 64, 16);
        assert_eq!(c.max_object_bytes(), 8);
        c.insert("k", "e1", 0, Bytes::from_static(b"123456789")); // 9 > 8
        assert!(c.is_empty());
    }

    #[test]
    fn index_stays_consistent_across_the_operation_mix() {
        // The map and the LRU index are two halves of one structure; if they
        // drift, eviction picks victims that are not there and the byte
        // accounting leaks until the cache silently stops accepting inserts.
        let c = ObjectCache::new(true, 1000, 1000, 8);
        for round in 0..40 {
            let k = format!("k{}", round % 12);
            c.insert(&k, "e", 0, Bytes::from(vec![b'x'; 50 + round]));
            let _ = c.get_by_key(&k);
            let _ = c.get_if_etag(&format!("k{}", (round + 3) % 12), "e");
            if round % 5 == 0 {
                c.invalidate(&format!("k{}", (round + 1) % 12));
            }
            c.assert_consistent();
        }
    }

    #[test]
    fn reinsert_does_not_leave_a_stale_index_entry() {
        // Overwriting a key reuses it under a new generation; the old
        // generation must go, or eviction later pops a key that has already
        // been replaced and drops the live entry with it.
        let c = ObjectCache::new(false, 1000, 1000, 8);
        c.insert("k", "e1", 0, Bytes::from_static(b"aaa"));
        c.insert("k", "e2", 7, Bytes::from_static(b"bbbb"));
        c.assert_consistent();
        assert_eq!(c.len(), 1);
        assert_eq!(c.total_bytes(), 4);
        assert!(c.get_if_etag("k", "e2").is_some());
    }

    #[test]
    fn eviction_order_is_least_recently_used_at_scale() {
        // With the old linear scan this held by construction; with an index it
        // is a property of keeping the index in step, so it is worth asserting
        // on more than the three entries the original test used.
        let c = ObjectCache::new(false, 10_000, 10_000, 10);
        for i in 0..10 {
            c.insert(&format!("k{i}"), "e", 0, Bytes::from_static(b"xx"));
        }
        // Touch the five oldest so the five newest become the eviction victims.
        for i in 0..5 {
            assert!(c.get_if_etag(&format!("k{i}"), "e").is_some());
        }
        for i in 10..15 {
            c.insert(&format!("k{i}"), "e", 0, Bytes::from_static(b"xx"));
        }
        c.assert_consistent();
        for i in 0..5 {
            assert!(
                c.get_if_etag(&format!("k{i}"), "e").is_some(),
                "k{i} evicted"
            );
        }
        for i in 5..10 {
            assert!(
                c.get_if_etag(&format!("k{i}"), "e").is_none(),
                "k{i} survived"
            );
        }
    }

    #[test]
    fn stats_count_hits_and_bytes_served_from_memory() {
        let c = ObjectCache::new(true, 1000, 1000, 8);
        c.insert("k", "e", 0, Bytes::from_static(b"hello"));
        let _ = c.get_by_key("k");
        let _ = c.get_if_etag("k", "e");
        let _ = c.get_if_etag("k", "wrong-etag"); // not a hit
        c.note_miss();
        let (hits, misses, bytes) = c.stats();
        assert_eq!((hits, misses, bytes), (2, 1, 10));
    }

    #[test]
    fn evicts_lru_under_byte_cap() {
        let c = ObjectCache::new(false, 10, 10, 16);
        c.insert("a", "e", 0, Bytes::from_static(b"aaaaa")); // 5
        c.insert("b", "e", 0, Bytes::from_static(b"bbbbb")); // 5 — total 10
        let _ = c.get_if_etag("a", "e"); // touch a
        c.insert("c", "e", 0, Bytes::from_static(b"ccccc")); // need 5 — should drop b (LRU)
        assert!(c.get_if_etag("a", "e").is_some());
        assert!(c.get_if_etag("b", "e").is_none());
        assert!(c.get_if_etag("c", "e").is_some());
    }
}
