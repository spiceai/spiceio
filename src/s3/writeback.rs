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
//! Step 1 is not tied to steps 2–3. Flushers stand down from the *backend*
//! while clients are using it, and journalling is local disk, so a standing-down
//! flusher keeps doing step 1 for whatever is still memory-only (`journal_one`).
//! Bolting the journal to the front of the NAS write meant deferring the write
//! also deferred the write becoming recoverable, and under continuous client
//! traffic that window ran until the backlog hit the urgent threshold —
//! hundreds of MiB of already-acknowledged objects held in memory alone.
//!
//! # What the client is promised
//!
//! The 200 is returned before the bytes are anywhere but this process's memory.
//! They reach the disk journal shortly after — promptly, but *not* synchronously
//! with the acknowledgement — so a `kill -9` in that window still loses the
//! write. That is why `SPICEIO_WRITE_BACK=0` exists, and why this is the right
//! default only for a *cache* backend, where a lost entry costs a rebuild rather
//! than data (which is what spiceio fronts). Once journalled, a write is
//! recoverable: dirty entries are never evicted, and are replayed by this
//! instance on restart or by a peer that finds them aged.
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
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
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

/// Client SMB operations in flight past which flushers stand down.
///
/// A read blocks a client; a write-back does not, so background flushing should
/// yield whenever clients are actually using the backend. The signal has to be
/// *client demand*, not spare admission permits: admission is sized to keep
/// every connection pipelined (`pool × 8` — 128 permits at the default pool of
/// 16), while the NAS saturates at a measured concurrency of about 8. A reserve
/// expressed as a fraction of permits therefore only engaged once ~96 client
/// requests were in flight — an order of magnitude past the point where reads
/// have already started queueing behind the drain. Measured with the old
/// permit-fraction reserve: 32% of GETs in a put-then-get sweep took over 1 ms,
/// median 48 ms among them, in seconds when *no client PUT was running at all*.
///
/// Small on purpose. The backend is bandwidth-bound, not concurrency-bound, so
/// a handful of concurrent client reads is already enough to want the drain out
/// of the way.
const CLIENT_BUSY_THRESHOLD: usize = 2;

/// Fraction of the pending-byte ceiling past which flushers stop yielding.
///
/// Standing down for readers is right until the backlog is close enough to the
/// ceiling that PutObject is about to start writing through synchronously.
/// Past this point deferring costs clients *more* than it saves them: they
/// would pay the full backend write latency on the PUT and still contend with
/// the drain that eventually has to happen.
const URGENT_BACKLOG_FRACTION: u64 = 2; // half the ceiling

/// How long a flusher stands down when the backend is busy with client work.
///
/// Short, because it is a poll: the drain should resume in the gaps between
/// read bursts, and every millisecond spent sleeping past the end of a burst is
/// backend capacity nobody used. The old 50 ms was sized for the pool-overload
/// case alone, where standing down longer is harmless.
const YIELD_BACKOFF: Duration = Duration::from_millis(5);

/// How long a flusher stands down when the pool itself reports overload.
///
/// Longer than [`YIELD_BACKOFF`]: an overloaded pool means resets and poisoned
/// connections, and retrying into that quickly only adds to it.
const OVERLOAD_BACKOFF: Duration = Duration::from_millis(50);

/// How long a flusher should stand down before trying again, or `None` to
/// proceed now.
///
/// Pure, so the policy that decides whether a background write may compete with
/// client reads can be tested without a runtime, a pool, or a NAS. The caller
/// still overrides a yield when the backlog is urgent or shutdown has begun —
/// both of those cost more to evaluate, and neither depends on this decision.
///
/// Every flusher yields, with no always-on exemption. Keeping one working was
/// measured on the sustained case it was meant for — a working set past the
/// write-back ceiling, so the backlog really does reach the urgent threshold —
/// and was slightly *worse* on every metric (mixed phase at concurrency 32:
/// −7% throughput, +10% p90, +8% p99). The urgent override already stops the
/// backlog from growing untouched, so the exemption bought nothing and cost
/// exactly what any flush during a client read costs.
///
/// `waiters` inverts the policy, and must: a caller inside
/// [`WriteBack::flush_key`] is a client blocked *on the drain itself*, so
/// counting it as a reason to defer the drain deadlocks it against its own
/// prerequisite. Two concurrent CopyObjects of a not-yet-claimed pending source
/// are enough — each holds an admission slot while waiting, together they hold
/// `clients` at the threshold, and no flusher ever claims the key they are
/// waiting for. They then both wait out `PENDING_FLUSH_TIMEOUT` and answer 503.
/// Overload still wins over everything: a pool that is resetting connections
/// cannot serve the waiter either, and piling on makes it worse.
fn yield_for(overloaded: bool, clients: usize, waiters: usize) -> Option<Duration> {
    if overloaded {
        return Some(OVERLOAD_BACKOFF);
    }
    if waiters > 0 {
        return None;
    }
    if clients >= CLIENT_BUSY_THRESHOLD {
        return Some(YIELD_BACKOFF);
    }
    None
}

/// Counts one caller blocked in [`WriteBack::flush_key`] for as long as it
/// lives.
///
/// A guard rather than a bare increment/decrement pair because the future it
/// lives in is cancellable: a client that hangs up mid-wait drops it, and a
/// leaked increment would pin the drain permanently urgent — which is exactly
/// the read-latency spike the yield policy exists to prevent.
struct FlushWaiter<'a>(&'a AtomicUsize);

impl<'a> FlushWaiter<'a> {
    fn new(count: &'a AtomicUsize) -> Self {
        count.fetch_add(1, Ordering::Relaxed);
        Self(count)
    }
}

impl Drop for FlushWaiter<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

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
    /// Body digest, set once this body has been journalled to the disk spill —
    /// i.e. once a crash would leave it recoverable rather than lost. `None`
    /// means it exists only in this process's memory. Always `None` on a fresh
    /// body: an overwrite has different bytes, so the predecessor's journal
    /// entry does not vouch for it.
    sha: Option<[u8; 32]>,
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
    /// Digest of an already-journalled body, so the flush does not rewrite it.
    sha: Option<[u8; 32]>,
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
    /// Callers currently blocked in [`Self::flush_key`]. Read by the flushers
    /// without the lock; see `yield_for` for why a waiter must *raise* the
    /// drain's priority rather than lower it.
    flush_waiters: AtomicUsize,
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
            flush_waiters: AtomicUsize::new(0),
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
                // Deliberately not inherited from `prev`: these are different
                // bytes, and claiming they are already journalled would let a
                // crash lose them silently.
                sha: None,
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
        // Published for the whole wait: this caller is a client blocked on the
        // drain, so the flushers must stop treating client traffic as a reason
        // to defer it. Without this the wait is self-defeating — see
        // `yield_for`.
        let _waiting = FlushWaiter::new(&self.flush_waiters);
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
                sha: p.sha,
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
        let clients = share.client_inflight();
        for _ in 0..n {
            let wb = Arc::clone(self);
            let share = Arc::clone(&share);
            let cache = Arc::clone(&cache);
            let slots = Arc::clone(&slots);
            let clients = Arc::clone(&clients);
            tokio::spawn(async move { wb.flush_loop(share, cache, slots, clients).await });
        }
        n
    }

    /// True while the backlog is close enough to the ceiling that yielding to
    /// readers would cost clients more than it saves them.
    async fn backlog_urgent(&self) -> bool {
        let g = self.inner.lock().await;
        g.bytes >= self.max_bytes / URGENT_BACKLOG_FRACTION
    }

    /// Journal one acknowledged body that is still memory-only. Returns false
    /// when there is nothing left to journal.
    ///
    /// Run *while yielding*, not only as the first step of a flush. Yielding
    /// defers the NAS write, and journalling used to be bolted to the front of
    /// that write — so a deferred flush also deferred the moment the write
    /// became crash-recoverable, and under continuous client traffic an
    /// acknowledged object could sit in memory alone until the backlog reached
    /// the urgent threshold (512 MiB by default). Nothing about the disk spill
    /// needs the backend: it is local, and the client reads being protected are
    /// not competing for it. So the durability step keeps running when the
    /// bandwidth step stands down.
    async fn journal_one(&self, cache: &ObjectCache) -> bool {
        // Pick a victim under the lock, journal it outside — the spill write
        // goes through the blocking pool and must not hold up enqueue.
        let (key, etag, last_modified, body, seq) = {
            let g = self.inner.lock().await;
            match g
                .pending
                .iter()
                .find(|(_, p)| p.sha.is_none())
                .map(|(k, p)| {
                    (
                        k.clone(),
                        p.etag.clone(),
                        p.last_modified,
                        p.body.clone(),
                        p.seq,
                    )
                }) {
                Some(v) => v,
                None => return false,
            }
        };
        let Some(sha) = cache
            .spill_put_dirty(&key, &etag, last_modified, &body)
            .await
        else {
            // No spill configured, or the body is too large for it. Either way
            // there is nothing to record, and retrying would spin.
            return false;
        };
        let mut g = self.inner.lock().await;
        if let Some(p) = g.pending.get_mut(&key)
            && p.seq == seq
        {
            // Still the same body. A newer one would have its own `sha: None`,
            // and stamping this digest onto it would claim a journal entry that
            // holds different bytes.
            p.sha = Some(sha);
        }
        true
    }

    async fn flush_loop(
        self: Arc<Self>,
        share: Arc<ShareSession>,
        cache: Arc<ObjectCache>,
        slots: Arc<Semaphore>,
        clients: Arc<AtomicUsize>,
    ) {
        loop {
            // Register interest *before* checking, so a write enqueued between
            // the check and the wait still wakes this flusher.
            let idle = self.work.notified();
            tokio::pin!(idle);
            idle.as_mut().enable();
            // Stand down while the backend is signalling overload, or while
            // clients are using it: a client request is waiting on its
            // response, and this one is not.
            //
            // Both yield to the drain, and to a backlog near its ceiling. Once
            // shutdown has begun there is no client left to defer to, and
            // standing down would only spend the drain's whole budget sleeping
            // while writes the client was told had succeeded sit unwritten.
            //
            // `backlog_urgent` is checked last, and only when something else
            // already wants to yield, because it is the one input that costs a
            // lock to read.
            if !self.closing.load(Ordering::Relaxed)
                && let Some(backoff) = yield_for(
                    share.is_overloaded(),
                    clients.load(Ordering::Relaxed),
                    self.flush_waiters.load(Ordering::Relaxed),
                )
                && !self.backlog_urgent().await
            {
                // Standing down from the *backend*, not from durability. If any
                // acknowledged body is still memory-only, put it on disk now
                // and come back round immediately rather than sleeping through
                // a window in which a crash would lose it.
                if self.journal_one(&cache).await {
                    continue;
                }
                tokio::time::sleep(backoff).await;
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
        // entry is never evicted and is replayed by whoever finds it. Skipped
        // when `journal_one` already wrote this exact body while standing down
        // for clients — the digest is over the bytes, so a carried-over one
        // names the same entry.
        let sha = match c.sha {
            Some(sha) => Some(sha),
            None => {
                cache
                    .spill_put_dirty(&c.key, &c.etag, c.last_modified, &c.body)
                    .await
            }
        };

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

    // ── Who gets the backend when both want it ───────────────────────

    #[test]
    fn an_idle_backend_lets_flushers_run() {
        assert_eq!(yield_for(false, 0, 0), None);
        assert_eq!(yield_for(false, CLIENT_BUSY_THRESHOLD - 1, 0), None);
    }

    #[test]
    fn flushers_yield_to_client_traffic() {
        // The regression this exists for: the previous policy compared spare
        // *admission permits* (pool × 8) against a quarter of them, so it did
        // not engage until ~72 concurrent client requests — long past the
        // measured ~8 at which the NAS saturates. A handful of clients has to
        // be enough, or the drain queues in front of client reads.
        assert_eq!(
            yield_for(false, CLIENT_BUSY_THRESHOLD, 0),
            Some(YIELD_BACKOFF)
        );
        assert_eq!(yield_for(false, 64, 0), Some(YIELD_BACKOFF));
    }

    #[test]
    fn a_caller_waiting_on_the_drain_is_not_a_reason_to_defer_it() {
        // The deadlock this closes: CopyObject holds an admission slot while
        // awaiting `flush_key`, so waiters are *also* counted as clients. Two
        // concurrent copies of a not-yet-claimed pending source would then hold
        // `clients` at the threshold and stall the flusher they are both
        // blocked on, until each timed out into a 503.
        assert_eq!(yield_for(false, 64, 1), None);
        assert_eq!(yield_for(false, CLIENT_BUSY_THRESHOLD, 2), None);
    }

    #[test]
    fn an_overloaded_pool_stands_down_longer() {
        // Resets and poisoned connections are not a queue to push through, and
        // retrying into one quickly only adds to it — not even for a waiter,
        // who cannot be served by a pool in that state either.
        assert_eq!(yield_for(true, 0, 0), Some(OVERLOAD_BACKOFF));
        assert_eq!(yield_for(true, 0, 4), Some(OVERLOAD_BACKOFF));
        assert!(OVERLOAD_BACKOFF > YIELD_BACKOFF);
    }

    #[tokio::test]
    async fn a_cancelled_waiter_does_not_pin_the_drain_urgent() {
        // `flush_key` lives in a cancellable future — a client that hangs up
        // drops it mid-wait. A leaked waiter count would make the flushers
        // defer to nobody forever, which is the read-latency spike the yield
        // policy exists to prevent.
        let w = wb();
        w.enqueue("a", "e", 1, Bytes::from_static(b"v1")).await;
        {
            let fut = w.flush_key("a", Duration::from_secs(30));
            tokio::pin!(fut);
            // Poll once so the wait is actually entered, then drop it.
            assert!(
                tokio::time::timeout(Duration::from_millis(50), &mut fut)
                    .await
                    .is_err()
            );
        }
        assert_eq!(w.flush_waiters.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn journalling_does_not_wait_for_a_flusher_to_stop_yielding() {
        // Durability must not be coupled to backend bandwidth. Yielding defers
        // the NAS write; it must not also defer the moment an acknowledged
        // write becomes crash-recoverable, or a busy proxy keeps hundreds of
        // MiB of already-200'd objects in memory alone.
        let dir = std::env::temp_dir().join(format!("spiceio-wb-journal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let spill = super::super::spill::Spill::open(&dir, "ns".into(), 1 << 20, 1 << 18).unwrap();
        let cache = ObjectCache::new(false, 1 << 20, 1 << 18, 64).with_spill(Arc::new(spill));

        let w = WriteBack::new(true, 1 << 20);
        w.enqueue("a", "e", 1, Bytes::from_static(b"body-a")).await;
        assert!(w.journal_one(&cache).await, "nothing was journalled");
        assert!(
            cache.spill().unwrap().contains_key("a"),
            "acknowledged body never reached the disk journal"
        );
        // Idempotent: the digest is recorded, so a second pass finds no work
        // rather than rewriting the same body forever.
        assert!(!w.journal_one(&cache).await);

        // An overwrite is different bytes, so it must be journalled again
        // rather than inheriting its predecessor's digest.
        w.enqueue("a", "e", 2, Bytes::from_static(b"body-a2")).await;
        assert!(
            w.journal_one(&cache).await,
            "overwrite was not re-journalled"
        );

        // And the flush reuses that digest instead of writing it a third time.
        let c = w.claim().await.unwrap();
        assert!(
            c.sha.is_some(),
            "flush did not inherit the journalled digest"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_backlog_near_the_ceiling_is_urgent() {
        // Past this point deferring costs clients more than it saves them:
        // PutObject is about to start writing through synchronously.
        let w = WriteBack::new(true, 100);
        assert!(!w.backlog_urgent().await);
        w.enqueue("a", "e", 1, Bytes::from(vec![b'x'; 49])).await;
        assert!(!w.backlog_urgent().await);
        w.enqueue("b", "e", 1, Bytes::from(vec![b'x'; 1])).await;
        assert!(w.backlog_urgent().await, "half the ceiling is urgent");
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
