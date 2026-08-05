//! Asynchronous write-back — acknowledge a PUT from memory, reach the NAS later.
//!
//! A PutObject normally costs a full backend round trip before the client sees
//! its 200. But the proxy already holds the bytes, and the object cache is
//! authoritative for them the moment they arrive: whatever reads the object
//! next — including the client that just wrote it, which is the common case for
//! a cache like sccache — is served from memory either way. The backend write
//! is bookkeeping, and the client does not need to wait on it.
//!
//! Enabled by default (`SPICEIO_WRITE_BACK=0` opts out), PutObject inserts into
//! the cache, hands the body to this queue, and returns. A pool of flushers
//! then, per key:
//!
//! 1. publishes the body to the disk spill marked **dirty**, so a crash leaves
//!    the write recoverable and a peer instance can read it;
//! 2. writes it to the NAS;
//! 3. promotes the spill entry to clean, adopting the backend's real etag and
//!    mtime (see [`crate::s3::spill::Spill::promote`]).
//!
//! # What the client is promised
//!
//! The 200 is returned before the bytes are anywhere but this process's memory
//! — a `kill -9` between the acknowledgement and step 1 loses the write. That
//! is why `SPICEIO_WRITE_BACK=0` exists, and why this is the right default only
//! for a *cache* backend, where a lost entry costs a rebuild rather than data
//! (which is what spiceio fronts). Everything
//! after step 1 is recoverable: dirty entries are never evicted, and are
//! replayed by this instance on restart or by a peer that finds them aged.
//!
//! # What stays consistent
//!
//! Acknowledging early creates a window where the proxy's view of an object and
//! the NAS's disagree, and every operation that could observe the difference
//! consults [`WriteBack`] first:
//!
//! * **GET / HEAD** on a pending key are served from the cache without
//!   revalidating — a stat would report the *old* object, or none at all.
//! * **DELETE** cancels a queued write and waits out an in-flight one, so the
//!   flusher cannot resurrect the object after the delete lands.
//! * **LIST** overlays pending keys, which are not on the NAS to be walked.
//! * **CopyObject / UploadPartCopy** flush the source first: the server-side
//!   copy reads it on the NAS, where it may not exist yet.
//!
//! Ordering per key is total: a key is queued at most once at a time, and a
//! write that arrives while its predecessor is in flight re-queues on
//! completion rather than racing it.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::{Mutex, Notify, Semaphore};

use super::object_cache::ObjectCache;
use crate::smb::ops::ShareSession;

/// Default ceiling on un-flushed bytes. Past this the queue stops accepting
/// work and PutObject writes through synchronously, so a backend that cannot
/// keep up slows clients down instead of growing an unbounded backlog.
pub const DEFAULT_MAX_PENDING_BYTES: u64 = 1024 * 1024 * 1024;

/// Flushers per instance. Enough to keep several SMB connections busy — a
/// single flusher would serialize every write-back behind one round trip and
/// fall behind a workload the synchronous path handled fine.
pub const DEFAULT_FLUSHERS: usize = 4;

/// How long a failed flush waits before its key is retried.
const RETRY_BACKOFF: Duration = Duration::from_millis(250);

/// Share of the SMB admission budget kept clear of background flushing.
///
/// A read blocks a client; a write-back does not. Fair queueing against live
/// requests measured a read-latency spike during a write drain worse than the
/// write latency the feature removes, so flushers only take a slot while this
/// much of the budget is still free. Under sustained read load they starve, the
/// queue fills, and PutObject reverts to synchronous — the honest outcome when
/// the backend has no spare capacity.
const CLIENT_RESERVE_FRACTION: usize = 4; // keep 1/4 for clients

/// How long a flusher stands down when the pool reports overload.
///
/// Nobody is waiting on a write-back, so it is precisely the work that should
/// yield when the backend is struggling. Without this the flushers compete with
/// live requests for the same connections and turn a write burst into a *read*
/// latency spike measurably worse than the one write-back removed.
const OVERLOAD_BACKOFF: Duration = Duration::from_millis(50);

/// One acknowledged-but-unwritten object.
struct Pending {
    body: Bytes,
    /// Provisional metadata, replaced by the backend's once the write lands.
    etag: String,
    last_modified: u64,
    /// Bumped on every overwrite; how a completing flush learns it was
    /// superseded by a newer body for the same key.
    seq: u64,
    /// A flusher currently owns this key. Keeps a second one from taking it,
    /// and tells DELETE it must wait rather than cancel.
    flushing: bool,
}

/// One key checked out by a flusher.
struct Claim {
    key: String,
    body: Bytes,
    /// Provisional metadata the write was acknowledged with — the handle used
    /// to replace it with the backend's once the write lands.
    etag: String,
    last_modified: u64,
    seq: u64,
}

struct Inner {
    pending: HashMap<String, Pending>,
    /// Keys awaiting a flusher. A key appears at most once.
    queue: VecDeque<String>,
    bytes: u64,
    seq: u64,
    /// Set at shutdown — no new work is accepted, flushers exit once drained.
    closed: bool,
}

/// Queue of writes acknowledged to the client but not yet on the backend.
pub struct WriteBack {
    inner: Mutex<Inner>,
    /// Wakes an idle flusher when work arrives.
    work: Notify,
    /// Pulsed after every flush attempt, for callers waiting on a key.
    progress: Notify,
    max_bytes: u64,
    enabled: bool,
    /// Mirrors `Inner::closed` for readers that must not take the lock — the
    /// flushers check it on every pass through their backoff.
    closing: AtomicBool,
    accepted: AtomicU64,
    flushed: AtomicU64,
    rejected: AtomicU64,
    retries: AtomicU64,
}

impl WriteBack {
    pub fn new(enabled: bool, max_bytes: u64) -> Self {
        Self {
            inner: Mutex::new(Inner {
                pending: HashMap::new(),
                queue: VecDeque::new(),
                bytes: 0,
                seq: 0,
                closed: false,
            }),
            work: Notify::new(),
            progress: Notify::new(),
            max_bytes: max_bytes.max(1),
            enabled,
            closing: AtomicBool::new(false),
            accepted: AtomicU64::new(0),
            flushed: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            retries: AtomicU64::new(0),
        }
    }

    pub fn from_env() -> Self {
        // On by default. The durability trade is real (see the module docs), so
        // the opt-out is spelled the obvious ways rather than "anything that is
        // not 1" — a deployment turning this off means it.
        let enabled = match std::env::var("SPICEIO_WRITE_BACK") {
            Ok(v) => {
                !(v == "0"
                    || v.eq_ignore_ascii_case("false")
                    || v.eq_ignore_ascii_case("off")
                    || v.is_empty())
            }
            Err(_) => true,
        };
        let max_bytes = std::env::var("SPICEIO_WRITE_BACK_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MAX_PENDING_BYTES);
        Self::new(enabled, max_bytes)
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// `(accepted, flushed, rejected for backpressure, flush retries)`.
    pub fn stats(&self) -> (u64, u64, u64, u64) {
        (
            self.accepted.load(Ordering::Relaxed),
            self.flushed.load(Ordering::Relaxed),
            self.rejected.load(Ordering::Relaxed),
            self.retries.load(Ordering::Relaxed),
        )
    }

    /// Take ownership of a write, to be flushed in the background.
    ///
    /// Returns false when the caller must write through synchronously instead:
    /// write-back is off, the queue is at its byte ceiling, or shutdown has
    /// begun. The caller has the body in hand either way, so a refusal costs
    /// nothing but latency — which is exactly the backpressure intended.
    pub async fn enqueue(&self, key: &str, etag: &str, last_modified: u64, body: Bytes) -> bool {
        if !self.enabled {
            return false;
        }
        let len = body.len() as u64;
        let mut g = self.inner.lock().await;
        if g.closed {
            return false;
        }
        // Charge only the delta when replacing an entry — an overwritten body
        // is released here, not on flush.
        let displaced = g.pending.get(key).map(|p| p.body.len() as u64).unwrap_or(0);
        if g.bytes + len > self.max_bytes.saturating_add(displaced) {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        g.seq += 1;
        let seq = g.seq;
        let prev = g.pending.insert(
            key.to_string(),
            Pending {
                body,
                etag: etag.to_string(),
                last_modified,
                seq,
                flushing: false,
            },
        );
        g.bytes = g.bytes + len - displaced;
        match prev {
            // Already queued (or being flushed) — the entry now holds the new
            // body. Queueing again would let two flushers own one key; a flush
            // in flight re-queues itself on completion instead.
            Some(p) => {
                if let Some(cur) = g.pending.get_mut(key) {
                    cur.flushing = p.flushing;
                }
            }
            None => g.queue.push_back(key.to_string()),
        }
        drop(g);
        self.accepted.fetch_add(1, Ordering::Relaxed);
        self.work.notify_one();
        true
    }

    /// Metadata for a key whose write has not reached the backend, or `None`.
    ///
    /// GET and HEAD use this to decide that the cache — not a stat — is the
    /// authority for this key right now.
    pub async fn pending_meta(&self, key: &str) -> Option<(String, u64, u64)> {
        if !self.enabled {
            return None;
        }
        let g = self.inner.lock().await;
        g.pending
            .get(key)
            .map(|p| (p.etag.clone(), p.last_modified, p.body.len() as u64))
    }

    /// Every pending key, for overlaying onto a listing.
    pub async fn snapshot(&self) -> Vec<(String, String, u64, u64)> {
        if !self.enabled {
            return Vec::new();
        }
        let g = self.inner.lock().await;
        g.pending
            .iter()
            .map(|(k, p)| {
                (
                    k.clone(),
                    p.etag.clone(),
                    p.last_modified,
                    p.body.len() as u64,
                )
            })
            .collect()
    }

    /// Drop a queued write and wait out an in-flight one.
    ///
    /// Called before a DELETE (and before anything else that replaces the
    /// object wholesale). Waiting matters: cancelling a flush already in
    /// progress would let the backend write land *after* the delete and
    /// resurrect the object.
    pub async fn cancel(&self, key: &str) {
        if !self.enabled {
            return;
        }
        loop {
            // Register before observing state: a `Notified` is not listening
            // until polled, so a completion between the check below and the
            // await would otherwise be missed and this would park forever.
            let waiter = self.progress.notified();
            tokio::pin!(waiter);
            waiter.as_mut().enable();
            {
                let mut g = self.inner.lock().await;
                match g.pending.get(key) {
                    None => return,
                    Some(p) if !p.flushing => {
                        let len = p.body.len() as u64;
                        g.pending.remove(key);
                        g.bytes = g.bytes.saturating_sub(len);
                        // The key may still sit in `queue`; a flusher that pops
                        // it finds no entry and moves on.
                        return;
                    }
                    Some(_) => {}
                }
            }
            waiter.await;
        }
    }

    /// Wait until `key` has reached the backend.
    ///
    /// For operations that read the object *through* the NAS rather than
    /// through the cache — a server-side copy names a path the file server has
    /// to be able to open. Returns false on timeout.
    pub async fn flush_key(&self, key: &str, timeout: Duration) -> bool {
        if !self.enabled {
            return true;
        }
        let deadline = Instant::now() + timeout;
        loop {
            let waiter = self.progress.notified();
            tokio::pin!(waiter);
            waiter.as_mut().enable();
            {
                let g = self.inner.lock().await;
                if !g.pending.contains_key(key) {
                    return true;
                }
            }
            self.work.notify_one();
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            if tokio::time::timeout(remaining, waiter).await.is_err() {
                return false;
            }
        }
    }

    /// Journal every still-pending body to the disk spill, so an abandoned
    /// drain leaves recoverable writes instead of lost ones.
    ///
    /// Normally the flusher writes the journal entry as its first step, which
    /// means a write that no flusher has claimed yet exists only in memory.
    /// That is the acknowledged trade while running — but at shutdown there is
    /// no reason to accept it: the bodies are in hand, and a local disk write
    /// is fast enough to run through the whole queue in the time it takes to
    /// exit. Without this, "they remain in the disk spill" would be true of
    /// only the few entries a flusher happened to reach.
    ///
    /// Returns the number of bodies journalled.
    pub async fn journal_residue(&self, cache: &ObjectCache) -> usize {
        if !self.enabled {
            return 0;
        }
        let residue: Vec<(String, String, u64, Bytes)> = {
            let g = self.inner.lock().await;
            g.pending
                .iter()
                .map(|(k, p)| (k.clone(), p.etag.clone(), p.last_modified, p.body.clone()))
                .collect()
        };
        let mut written = 0;
        for (key, etag, last_modified, body) in residue {
            if cache
                .spill_put_dirty(&key, &etag, last_modified, &body)
                .await
                .is_some()
            {
                written += 1;
            }
        }
        written
    }

    /// Flush every spill entry *this* instance journalled and never promoted.
    ///
    /// The in-memory queue is not the whole story at shutdown. A body is
    /// written to the spill as the first step of its flush, so an entry can be
    /// on disk and dirty while no longer being pending — a backend write that
    /// failed after journalling, or a promote that did not land. Those are
    /// acknowledged writes with nothing scheduled to retry them until some
    /// later process happens to sweep, so a graceful stop should finish them.
    ///
    /// Only ours: a peer's dirty entry belongs to a process that is still
    /// running and will promote it itself. Taking it would duplicate its work
    /// and race its own promote.
    ///
    /// Returns `(flushed, still dirty)`.
    pub async fn drain_owned_spill(
        &self,
        share: &ShareSession,
        cache: &ObjectCache,
        deadline: Instant,
    ) -> (usize, usize) {
        let keys = cache.spill_owned_dirty();
        let (mut flushed, mut left) = (0usize, 0usize);
        for key in keys {
            if Instant::now() >= deadline {
                left += 1;
                continue;
            }
            let Some(entry) = cache.spill_read(&key).await else {
                // Evicted or deleted underneath us — nothing to publish.
                continue;
            };
            match share.put_object_atomic(&key, &entry.body).await {
                Ok(meta) => {
                    cache
                        .spill_promote(
                            &key,
                            entry.body_sha,
                            &meta.etag,
                            meta.last_modified,
                            &entry.body,
                        )
                        .await;
                    flushed += 1;
                }
                Err(e) => {
                    crate::serr!("[spiceio] shutdown flush of {key} failed: {e}");
                    left += 1;
                }
            }
        }
        (flushed, left)
    }

    /// Pending bytes and entries, for logging.
    pub async fn depth(&self) -> (u64, usize) {
        let g = self.inner.lock().await;
        (g.bytes, g.pending.len())
    }

    /// Stop accepting work and wait for the queue to drain, up to `timeout`.
    /// Returns the number of writes still unflushed — they remain in the spill
    /// as dirty entries and are replayed on the next start.
    pub async fn drain(&self, timeout: Duration) -> usize {
        if !self.enabled {
            return 0;
        }
        {
            let mut g = self.inner.lock().await;
            g.closed = true;
        }
        // Published for the flushers' backoff check, which runs outside the lock.
        self.closing.store(true, Ordering::Relaxed);
        let deadline = Instant::now() + timeout;
        loop {
            let waiter = self.progress.notified();
            tokio::pin!(waiter);
            waiter.as_mut().enable();
            {
                let g = self.inner.lock().await;
                if g.pending.is_empty() {
                    return 0;
                }
            }
            self.work.notify_waiters();
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                let g = self.inner.lock().await;
                return g.pending.len();
            }
            let _ = tokio::time::timeout(remaining, waiter).await;
        }
    }

    /// Claim the next key to flush, or `None` if the queue is empty.
    async fn claim(&self) -> Option<Claim> {
        let mut g = self.inner.lock().await;
        while let Some(key) = g.queue.pop_front() {
            // Cancelled between queueing and now (a DELETE), or superseded and
            // re-queued elsewhere — either way there is nothing to do.
            let Some(p) = g.pending.get_mut(&key) else {
                continue;
            };
            if p.flushing {
                continue;
            }
            p.flushing = true;
            return Some(Claim {
                key,
                body: p.body.clone(),
                etag: p.etag.clone(),
                last_modified: p.last_modified,
                seq: p.seq,
            });
        }
        None
    }

    /// Retire a completed flush.
    ///
    /// A newer body for the same key arrived mid-flight iff the sequence moved;
    /// that body has not been queued (the entry was already present), so
    /// re-queueing here is what keeps it from being stranded.
    async fn complete(&self, key: &str, seq: u64, ok: bool) {
        {
            let mut g = self.inner.lock().await;
            let Some(p) = g.pending.get_mut(key) else {
                drop(g);
                self.progress.notify_waiters();
                return;
            };
            p.flushing = false;
            let superseded = p.seq != seq;
            if ok && !superseded {
                let len = p.body.len() as u64;
                g.pending.remove(key);
                g.bytes = g.bytes.saturating_sub(len);
            } else {
                g.queue.push_back(key.to_string());
            }
        }
        self.progress.notify_waiters();
        self.work.notify_one();
    }

    /// Start the flusher pool. Returns the spawned tasks' handles' count for
    /// logging; the tasks own clones of everything they need and exit when the
    /// queue is closed and empty.
    pub fn spawn_flushers(
        self: &Arc<Self>,
        share: Arc<ShareSession>,
        cache: Arc<ObjectCache>,
        flushers: usize,
    ) -> usize {
        let n = flushers.max(1);
        let slots = share.admission();
        let reserve = (share.admission_limit() / CLIENT_RESERVE_FRACTION).max(1);
        for _ in 0..n {
            let wb = Arc::clone(self);
            let share = Arc::clone(&share);
            let cache = Arc::clone(&cache);
            let slots = Arc::clone(&slots);
            tokio::spawn(async move { wb.flush_loop(share, cache, slots, reserve).await });
        }
        n
    }

    async fn flush_loop(
        self: Arc<Self>,
        share: Arc<ShareSession>,
        cache: Arc<ObjectCache>,
        slots: Arc<Semaphore>,
        reserve: usize,
    ) {
        loop {
            // Register interest *before* checking, so a write enqueued between
            // the check and the wait still wakes this flusher.
            let idle = self.work.notified();
            tokio::pin!(idle);
            idle.as_mut().enable();
            // Stand down while the backend is signalling overload, or while
            // the admission budget is down to the slice held for clients: a
            // client request is waiting on its response, and this one is not.
            //
            // Both yield to the drain. Once shutdown has begun there is no
            // client left to defer to, and standing down would only spend the
            // drain's whole budget sleeping while writes the client was told
            // had succeeded sit unwritten.
            if !self.closing.load(Ordering::Relaxed)
                && (share.is_overloaded() || slots.available_permits() <= reserve)
            {
                tokio::time::sleep(OVERLOAD_BACKOFF).await;
                continue;
            }
            match self.claim().await {
                Some(c) => {
                    let ok = self.flush_one(&share, &cache, &slots, &c).await;
                    self.complete(&c.key, c.seq, ok).await;
                    if !ok {
                        self.retries.fetch_add(1, Ordering::Relaxed);
                        tokio::time::sleep(RETRY_BACKOFF).await;
                    } else {
                        self.flushed.fetch_add(1, Ordering::Relaxed);
                    }
                }
                None => {
                    {
                        let g = self.inner.lock().await;
                        if g.closed && g.pending.is_empty() {
                            return;
                        }
                    }
                    idle.await;
                }
            }
        }
    }

    /// Journal to the spill, write to the backend, then promote.
    async fn flush_one(
        &self,
        share: &ShareSession,
        cache: &ObjectCache,
        slots: &Arc<Semaphore>,
        c: &Claim,
    ) -> bool {
        // Journal first: from here on a crash is recoverable, because a dirty
        // entry is never evicted and is replayed by whoever finds it.
        let sha = cache
            .spill_put_dirty(&c.key, &c.etag, c.last_modified, &c.body)
            .await;

        // Through the same admission semaphore live requests use. A background
        // flush that skipped it would be invisible to admission control and
        // could bury the pool under work no client is waiting for.
        //
        // The only way this errors is a closed semaphore, which happens when
        // the pool is being torn down. Proceeding unmetered is then the right
        // call rather than the dangerous one: there are no client requests left
        // to protect a share of the pool for, and the alternative is abandoning
        // a write the client was already told had succeeded. `.ok()` rather
        // than a discard so the fallible acquire is visible at the call site.
        let permit = slots.clone().acquire_owned().await.ok();

        // Atomic: the client already has its 200, so a failed flush must not
        // replace a good object with a truncated one.
        let put = share.put_object_atomic(&c.key, &c.body).await;
        drop(permit);
        let meta = match put {
            Ok(m) => m,
            Err(e) => {
                crate::serr!(
                    "[spiceio] write-back flush failed for {}: {e}; will retry",
                    c.key
                );
                return false;
            }
        };

        // Adopt the backend's etag in both tiers. Skipped if the entry has
        // moved on — a newer body owns the key now, and its own flush will
        // publish the metadata that goes with it.
        cache.retag(&c.key, &c.etag, &meta.etag, meta.last_modified);
        if let Some(sha) = sha {
            cache
                .spill_promote(&c.key, sha, &meta.etag, meta.last_modified, &c.body)
                .await;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wb() -> Arc<WriteBack> {
        Arc::new(WriteBack::new(true, 1024))
    }

    #[tokio::test]
    async fn disabled_refuses_everything() {
        let w = WriteBack::new(false, 1024);
        assert!(!w.enqueue("k", "e", 1, Bytes::from_static(b"x")).await);
        assert!(w.pending_meta("k").await.is_none());
        assert!(w.snapshot().await.is_empty());
    }

    #[tokio::test]
    async fn accepts_until_the_byte_ceiling() {
        let w = WriteBack::new(true, 10);
        assert!(w.enqueue("a", "e", 1, Bytes::from_static(b"12345")).await);
        assert!(w.enqueue("b", "e", 1, Bytes::from_static(b"12345")).await);
        // Full — the caller must write through synchronously, which is the
        // backpressure a slow backend is supposed to apply to clients.
        assert!(!w.enqueue("c", "e", 1, Bytes::from_static(b"1")).await);
        let (_, _, rejected, _) = w.stats();
        assert_eq!(rejected, 1);
    }

    #[tokio::test]
    async fn overwriting_a_key_charges_only_the_delta() {
        let w = WriteBack::new(true, 10);
        assert!(
            w.enqueue("a", "e", 1, Bytes::from_static(b"12345678"))
                .await
        );
        // Replacing 8 bytes with 8 must not double-count and lock the queue.
        assert!(
            w.enqueue("a", "e", 2, Bytes::from_static(b"abcdefgh"))
                .await
        );
        let (bytes, entries) = w.depth().await;
        assert_eq!((bytes, entries), (8, 1));
        assert_eq!(w.pending_meta("a").await.unwrap().1, 2);
    }

    #[tokio::test]
    async fn a_key_is_queued_at_most_once() {
        // Two flushers must never own one key — that is what makes per-key
        // ordering total.
        let w = wb();
        w.enqueue("a", "e", 1, Bytes::from_static(b"v1")).await;
        w.enqueue("a", "e", 2, Bytes::from_static(b"v2")).await;
        w.enqueue("a", "e", 3, Bytes::from_static(b"v3")).await;
        assert!(w.claim().await.is_some());
        assert!(w.claim().await.is_none(), "same key claimed twice");
    }

    #[tokio::test]
    async fn supersede_mid_flight_requeues_the_newer_body() {
        let w = wb();
        w.enqueue("a", "e", 1, Bytes::from_static(b"v1")).await;
        let c = w.claim().await.unwrap();
        assert_eq!(&c.body[..], b"v1");
        // A second PUT lands while the first is being written.
        w.enqueue("a", "e", 2, Bytes::from_static(b"v2")).await;
        w.complete(&c.key, c.seq, true).await;
        // v2 must still be queued — dropping it would lose an acknowledged write.
        let next = w.claim().await.expect("newer body was stranded");
        assert_eq!(&next.body[..], b"v2");
    }

    #[tokio::test]
    async fn completing_a_current_flush_releases_it() {
        let w = wb();
        w.enqueue("a", "e", 1, Bytes::from_static(b"v1")).await;
        let c = w.claim().await.unwrap();
        w.complete(&c.key, c.seq, true).await;
        assert_eq!(w.depth().await, (0, 0));
        assert!(w.claim().await.is_none());
    }

    #[tokio::test]
    async fn a_failed_flush_keeps_the_body_queued() {
        let w = wb();
        w.enqueue("a", "e", 1, Bytes::from_static(b"v1")).await;
        let c = w.claim().await.unwrap();
        w.complete(&c.key, c.seq, false).await;
        assert_eq!(w.depth().await.1, 1);
        assert!(w.claim().await.is_some(), "failed write was dropped");
    }

    #[tokio::test]
    async fn cancel_removes_a_queued_write() {
        let w = wb();
        w.enqueue("a", "e", 1, Bytes::from_static(b"v1")).await;
        w.cancel("a").await;
        assert_eq!(w.depth().await, (0, 0));
        assert!(w.pending_meta("a").await.is_none());
        // The stale queue slot must not resurrect it.
        assert!(w.claim().await.is_none());
    }

    #[tokio::test]
    async fn cancel_waits_for_an_in_flight_flush() {
        // Cancelling under a flusher would let the backend write land after the
        // DELETE and bring the object back.
        let w = wb();
        w.enqueue("a", "e", 1, Bytes::from_static(b"v1")).await;
        let c = w.claim().await.unwrap();
        let w2 = Arc::clone(&w);
        let canceller = tokio::spawn(async move { w2.cancel("a").await });
        tokio::task::yield_now().await;
        assert!(
            !canceller.is_finished(),
            "cancel did not wait for the flush"
        );
        w.complete(&c.key, c.seq, true).await;
        tokio::time::timeout(Duration::from_secs(5), canceller)
            .await
            .expect("cancel never woke")
            .unwrap();
        assert!(w.pending_meta("a").await.is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cancel_wakes_even_when_the_completion_races_it() {
        // The window this guards: a `Notified` does not listen until polled, so
        // a completion landing between the canceller's state check and its
        // await is lost. On a single-threaded runtime the two are adjacent and
        // the race cannot happen — it needs real parallelism to show up.
        for i in 0..200 {
            let w = Arc::new(WriteBack::new(true, 1 << 20));
            let key = format!("k{i}");
            w.enqueue(&key, "e", 1, Bytes::from_static(b"v")).await;
            let c = w.claim().await.unwrap();
            let w_cancel = Arc::clone(&w);
            let k = key.clone();
            let canceller = tokio::spawn(async move { w_cancel.cancel(&k).await });
            let w_complete = Arc::clone(&w);
            let completer =
                tokio::spawn(async move { w_complete.complete(&c.key, c.seq, true).await });
            tokio::time::timeout(Duration::from_secs(5), async {
                completer.await.unwrap();
                canceller.await.unwrap();
            })
            .await
            .unwrap_or_else(|_| panic!("cancel parked on a missed wake-up (round {i})"));
        }
    }

    #[tokio::test]
    async fn flush_key_returns_once_the_key_is_gone() {
        let w = wb();
        w.enqueue("a", "e", 1, Bytes::from_static(b"v1")).await;
        let w2 = Arc::clone(&w);
        let waiter = tokio::spawn(async move { w2.flush_key("a", Duration::from_secs(5)).await });
        let c = w.claim().await.unwrap();
        w.complete(&c.key, c.seq, true).await;
        assert!(waiter.await.unwrap());
    }

    #[tokio::test]
    async fn flush_key_times_out_rather_than_hanging() {
        let w = wb();
        w.enqueue("a", "e", 1, Bytes::from_static(b"v1")).await;
        assert!(!w.flush_key("a", Duration::from_millis(50)).await);
        // A key that was never written is trivially flushed.
        assert!(w.flush_key("absent", Duration::from_millis(50)).await);
    }

    #[tokio::test]
    async fn snapshot_reports_pending_keys_for_listings() {
        let w = wb();
        w.enqueue("a/1", "etag-a", 11, Bytes::from_static(b"aa"))
            .await;
        w.enqueue("b/2", "etag-b", 22, Bytes::from_static(b"bbb"))
            .await;
        let mut snap = w.snapshot().await;
        snap.sort();
        assert_eq!(
            snap,
            vec![
                ("a/1".into(), "etag-a".into(), 11, 2),
                ("b/2".into(), "etag-b".into(), 22, 3),
            ]
        );
    }

    #[tokio::test]
    async fn drain_closes_the_queue_and_reports_residue() {
        let w = wb();
        w.enqueue("a", "e", 1, Bytes::from_static(b"v1")).await;
        // Nothing is flushing, so the drain can only time out — and must report
        // the write as unflushed rather than claim success.
        assert_eq!(w.drain(Duration::from_millis(50)).await, 1);
        // Closed: no new work after shutdown begins.
        assert!(!w.enqueue("b", "e", 1, Bytes::from_static(b"v2")).await);
    }

    #[tokio::test]
    async fn drain_returns_immediately_when_empty() {
        let w = wb();
        assert_eq!(w.drain(Duration::from_secs(30)).await, 0);
    }
}
