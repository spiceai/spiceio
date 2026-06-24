//! SMB connection pool — multiple authenticated TCP connections to the same
//! server, round-robin dispatched. Eliminates the single-connection mutex
//! bottleneck under concurrent S3 requests.

use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use super::client::{SmbClient, SmbConfig};

/// Backoff schedule for transient connect failures (TCP/negotiate/auth).
/// A shared NAS under load can flake one connect while the rest succeed —
/// retry handles that without taking down startup.
const CONNECT_RETRY_BACKOFF: &[Duration] = &[
    Duration::from_millis(250),
    Duration::from_millis(750),
    Duration::from_millis(2000),
];

/// Hard cap on a single connect attempt (TCP + SMB negotiate + auth). A NAS at
/// its session limit often completes the TCP handshake but then stalls the SMB
/// session-setup; without this cap that stall burns the per-op read timeout
/// (tens of seconds) before a retry can run, blowing the caller's startup
/// budget. Kept short so the `CONNECT_RETRY_BACKOFF` retries actually get to run
/// (4 attempts + backoff stays well under a typical ~60s startup budget).
const CONNECT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(8);

/// Generic retry-with-backoff helper. Runs `op` until it succeeds, sleeping
/// the corresponding `backoff` interval between failures. After `backoff.len()`
/// retries (i.e. `backoff.len() + 1` total attempts), returns the final error.
///
/// Each failed attempt is logged with its error (and a final give-up notice on
/// the last attempt), so a flaky or saturated server is visible in the log
/// without `op` needing to log internally.
async fn retry_with_backoff<T, F, Fut>(
    label: &str,
    backoff: &[Duration],
    mut op: F,
) -> io::Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    let max_attempts = backoff.len() + 1;
    let mut last_err: Option<io::Error> = None;
    for attempt in 1..=max_attempts {
        match op().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                if attempt < max_attempts {
                    let delay = backoff[attempt - 1];
                    let next = attempt + 1;
                    crate::slog!(
                        "[spiceio] {label} attempt {attempt}/{max_attempts} failed: {e}; retrying (attempt {next}) in {}ms",
                        delay.as_millis()
                    );
                    tokio::time::sleep(delay).await;
                } else {
                    crate::serr!("[spiceio] {label} failed after {max_attempts} attempts: {e}");
                }
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::other(format!("{label} failed without error"))))
}

async fn connect_with_retry(config: SmbConfig) -> io::Result<Arc<SmbClient>> {
    retry_with_backoff("smb connect", CONNECT_RETRY_BACKOFF, || {
        let cfg = config.clone();
        async move {
            // Cap the whole attempt (TCP + negotiate + auth). A saturated NAS
            // completes TCP but stalls the SMB handshake; without this cap that
            // stall would burn the per-op read timeout before a retry can run.
            match tokio::time::timeout(CONNECT_ATTEMPT_TIMEOUT, SmbClient::connect(cfg)).await {
                Ok(res) => res,
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "connect exceeded {}s — TCP reachable but the SMB handshake stalled (NAS overloaded or at its session limit?)",
                        CONNECT_ATTEMPT_TIMEOUT.as_secs()
                    ),
                )),
            }
        }
    })
    .await
}

/// One pool connection: an authenticated session and its tree-connect id for
/// the share. Both are replaced together when the slot is healed.
struct Slot {
    client: Arc<SmbClient>,
    tree_id: u32,
}

/// A pool of authenticated SMB connections to the same server.
///
/// Requests are distributed across connections via round-robin. Each connection
/// is an independently authenticated SMB session with its own TCP stream, so
/// concurrent operations don't serialize on a single mutex.
pub struct SmbPool {
    /// Swappable slots — a poisoned connection is replaced in place by `heal`.
    /// The vec length is the historical max; `n` tracks the current active count
    /// which can be reduced at runtime.
    slots: RwLock<Vec<Slot>>,
    /// Current number of active connections in the pool (round-robin target).
    /// Starts at the configured size but is dynamically reduced (by truncating
    /// slots) if the server reports capacity limits such as too many sessions.
    n: AtomicUsize,
    next: AtomicUsize,
    /// Config for reconnecting a poisoned slot.
    config: SmbConfig,
    /// Share name, set by `connect_share`, needed to re-tree-connect on heal.
    share: OnceLock<String>,
    /// Cached from the first connection's negotiate response.
    pub max_read_size: u32,
    pub max_write_size: u32,
    pub compound_max_read_size: u32,
    pub compound_max_write_size: u32,
    /// Adaptive streaming-write *in-flight bytes* — the per-flush byte budget.
    /// Starts at `INFLIGHT_MAX` and shrinks toward `IO_FLOOR` when the server
    /// resets a write (it can't sustain that burst), then grows back on each
    /// healer tick once it recovers. The chunk size is `min(max_write_size,
    /// write_inflight)` and the flush issues `write_inflight / chunk` writes —
    /// so as this shrinks, the burst shrinks first, then (below the negotiated
    /// max) the individual write size, down to a single 64 KB write.
    write_inflight: AtomicU32,
    /// Adaptive streaming-read in-flight bytes — same scheme for the GET path
    /// (`min(max_read_size, read_inflight)` chunk, `read_inflight / chunk` reads
    /// per batch).
    read_inflight: AtomicU32,
    /// Set whenever a reset backs off an I/O size; gates `grow_io` so recovery
    /// only re-probes a larger size after a full healer interval with no reset.
    /// Without this the healer could grow the size back mid-retry-burst, making
    /// a client's retry hit a too-large chunk that resets again.
    reset_since_grow: AtomicBool,
    /// Serializes connection healing so a burst of concurrent retries triggers
    /// one reconnect pass, not N competing ones that pile reconnect load onto an
    /// already-struggling server (a retry storm). The per-slot `is_poisoned`
    /// check inside `heal` lets callers that queue behind a heal skip the slots
    /// it already restored.
    heal_lock: tokio::sync::Mutex<()>,
}

/// Floor for the adaptive streaming in-flight size — one conservative op the
/// server handles even under heavy load (the same size the compound small-file
/// path uses successfully). At this floor a streaming transfer issues a single
/// 64 KB write/read at a time (no pipelining) — maximally gentle.
const IO_FLOOR: u32 = 65536;

/// Ceiling for the adaptive in-flight size — the per-flush / per-read-batch byte
/// budget on a healthy server. Far above the sub-ms-RTT bandwidth-delay product,
/// so single-stream throughput saturates; the chunk size (capped separately at
/// the negotiated max) determines how many ops make up the batch.
const INFLIGHT_MAX: u32 = 4 * 1024 * 1024;

/// Multiplicative decrease: halve `cur`, never below the floor (and never above
/// `cur`). Pure for testability.
fn io_after_reset(cur: u32) -> u32 {
    (cur / 2).max(IO_FLOOR).min(cur)
}

/// Multiplicative increase: double `cur`, capped at `max` (and never below
/// `cur`). Pure for testability.
fn io_after_grow(cur: u32, max: u32) -> u32 {
    cur.saturating_mul(2).min(max).max(cur)
}

impl SmbPool {
    /// Connect `n` authenticated sessions to the SMB server.
    ///
    /// All connections negotiate independently and authenticate with the same
    /// credentials. The pool uses the negotiated sizes from the first connection.
    pub async fn connect(config: SmbConfig, requested_n: usize) -> io::Result<Arc<Self>> {
        let requested_n = requested_n.max(1);
        let mut clients = Vec::with_capacity(requested_n);

        // First connection — establishes negotiated parameters
        let first = connect_with_retry(config.clone()).await?;
        let max_read_size = first.max_read_size;
        let max_write_size = first.max_write_size;
        let compound_max_read_size = first.compound_max_read_size;
        let compound_max_write_size = first.compound_max_write_size;
        clients.push(first);
        let mut actual_n = 1;

        // Additional connections in parallel. If the server reports a capacity
        // limit (too many sessions, request not accepted, etc.) we stop adding
        // more and dynamically reduce the pool size rather than failing or
        // retrying the same limit forever.
        if requested_n > 1 {
            let mut joins = Vec::with_capacity(requested_n - 1);
            for _ in 1..requested_n {
                let cfg = config.clone();
                joins.push(tokio::spawn(async move { connect_with_retry(cfg).await }));
            }
            let mut pending = joins.into_iter();
            let mut fatal: Option<io::Error> = None;
            for join in pending.by_ref() {
                match join.await {
                    Ok(Ok(client)) => {
                        clients.push(client);
                        actual_n += 1;
                    }
                    Ok(Err(e)) => {
                        // Server at capacity → stop adding and use what we have.
                        // Any other failure is fatal for the whole connect.
                        if super::client::is_capacity_error(&e) {
                            crate::slog!(
                                "[spiceio] smb server at capacity, using only {actual_n} of {requested_n} requested connections"
                            );
                        } else {
                            fatal = Some(e);
                        }
                        break;
                    }
                    Err(e) => {
                        fatal = Some(io::Error::other(format!("spawn failed: {e}")));
                        break;
                    }
                }
            }
            // Abort the connections we decided not to use: dropping a JoinHandle
            // detaches the task, which would keep opening SMB sessions in the
            // background against an already-capacity-limited server.
            for join in pending {
                join.abort();
            }
            if let Some(e) = fatal {
                return Err(e);
            }
            crate::slog!("[spiceio] smb pool: {actual_n} connections ready");
        }

        let slots: Vec<Slot> = clients
            .into_iter()
            .map(|client| Slot { client, tree_id: 0 })
            .collect();
        let pool_n = slots.len();

        Ok(Arc::new(Self {
            slots: RwLock::new(slots),
            n: AtomicUsize::new(pool_n),
            next: AtomicUsize::new(0),
            config,
            share: OnceLock::new(),
            max_read_size,
            max_write_size,
            compound_max_read_size,
            compound_max_write_size,
            write_inflight: AtomicU32::new(INFLIGHT_MAX),
            read_inflight: AtomicU32::new(INFLIGHT_MAX),
            reset_since_grow: AtomicBool::new(false),
            heal_lock: tokio::sync::Mutex::new(()),
        }))
    }

    /// Current adaptive streaming-write in-flight bytes (per-flush budget).
    pub fn write_inflight(&self) -> u32 {
        self.write_inflight.load(Ordering::Relaxed)
    }

    /// Current adaptive streaming-read in-flight bytes (per-batch budget).
    pub fn read_inflight(&self) -> u32 {
        self.read_inflight.load(Ordering::Relaxed)
    }

    /// Per-write chunk size: the negotiated max, but no larger than the current
    /// in-flight budget (so below the max the writes shrink too). Always ≥ 1.
    pub fn write_chunk_size(&self) -> u32 {
        self.max_write_size.min(self.write_inflight()).max(1)
    }

    /// Per-read chunk size — analogous to `write_chunk_size`.
    pub fn read_chunk_size(&self) -> u32 {
        self.max_read_size.min(self.read_inflight()).max(1)
    }

    /// Note that the server reset/dropped a connection on a write — halve the
    /// write in-flight budget (down to `IO_FLOOR`) so the next attempt uses a
    /// smaller burst (and, below the negotiated max, a smaller write). No-op once
    /// already at the floor.
    pub fn note_write_reset(&self) {
        self.reset_since_grow.store(true, Ordering::Relaxed);
        let cur = self.write_inflight.load(Ordering::Relaxed);
        let next = io_after_reset(cur);
        if next != cur {
            self.write_inflight.store(next, Ordering::Relaxed);
            crate::slog!(
                "[spiceio] write in-flight backed off to {}K after reset",
                next / 1024
            );
        }
    }

    /// Note that the server reset/dropped a connection on a read — halve the read
    /// in-flight budget (down to `IO_FLOOR`). No-op once at the floor.
    pub fn note_read_reset(&self) {
        self.reset_since_grow.store(true, Ordering::Relaxed);
        let cur = self.read_inflight.load(Ordering::Relaxed);
        let next = io_after_reset(cur);
        if next != cur {
            self.read_inflight.store(next, Ordering::Relaxed);
            crate::slog!(
                "[spiceio] read in-flight backed off to {}K after reset",
                next / 1024
            );
        }
    }

    /// Step both adaptive I/O sizes back up toward their maxes (×2) — called each
    /// healer tick. Only re-probes a larger size after a full interval with *no*
    /// reset, so recovery never inflates the size into an active overload (which
    /// would make a client's in-flight retries hit a too-large chunk).
    fn grow_io(&self) {
        // Cooldown: if any reset happened since the last tick, skip growing this
        // round and clear the flag so a quiet interval next time lets us re-probe.
        if self.reset_since_grow.swap(false, Ordering::Relaxed) {
            return;
        }
        let w = self.write_inflight.load(Ordering::Relaxed);
        let wn = io_after_grow(w, INFLIGHT_MAX);
        if wn != w {
            self.write_inflight.store(wn, Ordering::Relaxed);
            crate::slog!("[spiceio] write in-flight recovered to {}K", wn / 1024);
        }
        let r = self.read_inflight.load(Ordering::Relaxed);
        let rn = io_after_grow(r, INFLIGHT_MAX);
        if rn != r {
            self.read_inflight.store(rn, Ordering::Relaxed);
            crate::slog!("[spiceio] read in-flight recovered to {}K", rn / 1024);
        }
    }

    /// Tree-connect every slot to `share` and remember the share name so a
    /// healed (reconnected) slot can be re-tree-connected.
    pub async fn connect_share(&self, share: &str) -> io::Result<()> {
        let clients: Vec<Arc<SmbClient>> = {
            let guard = self.slots.read().unwrap();
            let cur = self.n.load(Ordering::Relaxed).min(guard.len());
            guard[..cur].iter().map(|s| s.client.clone()).collect()
        };
        for (idx, client) in clients.iter().enumerate() {
            let tree_id = client.tree_connect(share).await?;
            let mut guard = self.slots.write().unwrap();
            if idx < guard.len() {
                guard[idx].tree_id = tree_id;
            }
        }
        let _ = self.share.set(share.to_string());
        Ok(())
    }

    /// Pick the next healthy connection via round-robin, skipping poisoned ones.
    /// Returns an owned `Arc` and its tree id. Falls back to a poisoned slot if
    /// all (current active) are poisoned — the I/O fails fast and `heal` reconnects it.
    pub fn pick(&self) -> (Arc<SmbClient>, u32) {
        let slots = self.slots.read().unwrap();
        let mut current_n = self.n.load(Ordering::Relaxed).min(slots.len());
        if current_n == 0 {
            // Degenerate case (should not happen after successful connect).
            if slots.is_empty() {
                panic!("smb pool is empty");
            }
            current_n = 1;
        }
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        for i in 0..current_n {
            let idx = (start + i) % current_n;
            if !slots[idx].client.is_poisoned() {
                return (slots[idx].client.clone(), slots[idx].tree_id);
            }
        }
        // All (current) poisoned — return a round-robin pick; the I/O will fail fast.
        let idx = start % current_n;
        (slots[idx].client.clone(), slots[idx].tree_id)
    }

    /// Pick a connection, preferring a healthy one. `pick` already skips
    /// poisoned slots, so the common case (one connection dropped, the rest
    /// healthy) costs nothing; only when every connection is down do we pay for
    /// a heal and a brief pause before re-picking. If the whole pool is still
    /// poisoned after that (the heal could not reconnect), this falls back to a
    /// poisoned connection — the caller's op then fails fast and retries.
    pub async fn pick_live(&self) -> (Arc<SmbClient>, u32) {
        let (client, tree_id) = self.pick();
        if client.is_poisoned() {
            self.heal().await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            return self.pick();
        }
        (client, tree_id)
    }

    /// Back the active pool off by one connection (truncating the last slot).
    /// Called when a heal reconnect hits a server capacity limit: the server
    /// can't sustain the current count, so we reduce by one — based on the
    /// current size, NOT the failing slot index, which could discard most of a
    /// healthy pool. Repeated capacity errors shrink it further, one at a time.
    /// Keeps at least one slot (a poisoned last slot is retried on the next
    /// heal; restart with a lower SPICEIO_SMB_CONNECTIONS for a hard low limit).
    fn shrink_by_one(&self) {
        let mut slots = self.slots.write().unwrap();
        let old = self.n.load(Ordering::Relaxed);
        if old <= 1 {
            return;
        }
        let new_size = (old - 1).min(slots.len());
        slots.truncate(new_size);
        self.n.store(new_size, Ordering::Relaxed);
        crate::slog!(
            "[spiceio] smb pool reduced from {} to {} connections due to server capacity limit",
            old,
            new_size
        );
    }

    /// Reconnect any poisoned slots and re-tree-connect them to the share.
    /// Best-effort: a slot whose reconnect fails stays poisoned and is retried
    /// on the next pass. Without this the pool degrades monotonically — every
    /// timeout would permanently remove a connection until the proxy is wedged.
    /// If a reconnect fails specifically due to server capacity (too many
    /// sessions etc.), we shrink the pool instead of keeping a poisoned slot.
    pub async fn heal(&self) {
        let Some(share) = self.share.get() else {
            return;
        };
        // Coalesce concurrent heals: serialize the reconnect pass so a burst of
        // retrying requests doesn't fan out into competing reconnect storms.
        // Callers that queue behind a heal find the slots it restored already
        // healthy (the `is_poisoned` check) and skip them.
        {
            let _guard = self.heal_lock.lock().await;
            let current_n = self.n.load(Ordering::Relaxed);
            for idx in 0..current_n {
                // Re-check current size in case a prior capacity shrink happened.
                let cur = self.n.load(Ordering::Relaxed);
                if idx >= cur {
                    break;
                }
                let poisoned = self
                    .slots
                    .read()
                    .unwrap()
                    .get(idx)
                    .is_some_and(|s| s.client.is_poisoned());
                if !poisoned {
                    continue;
                }
                match connect_with_retry(self.config.clone()).await {
                    Ok(client) => match client.tree_connect(share).await {
                        Ok(tree_id) => {
                            // Guard the write in case size changed.
                            let mut guard = self.slots.write().unwrap();
                            if idx < guard.len() {
                                guard[idx] = Slot { client, tree_id };
                            }
                            crate::slog!("[spiceio] healed poisoned smb connection (slot {idx})");
                        }
                        Err(e) => {
                            if super::client::is_capacity_error(&e) {
                                self.shrink_by_one();
                                crate::slog!(
                                    "[spiceio] heal tree-connect hit server capacity, reduced pool (slot {idx})"
                                );
                                break;
                            } else {
                                crate::serr!("[spiceio] heal tree-connect failed (slot {idx}): {e}")
                            }
                        }
                    },
                    Err(e) => {
                        if super::client::is_capacity_error(&e) {
                            self.shrink_by_one();
                            crate::slog!(
                                "[spiceio] heal reconnect hit server capacity, reduced pool (slot {idx})"
                            );
                            break;
                        } else {
                            crate::serr!("[spiceio] heal reconnect failed (slot {idx}): {e}")
                        }
                    }
                }
            }
        }
        // Re-probe larger I/O sizes now the server has had a moment to recover
        // (AIMD: multiplicative decrease on reset, gradual increase here).
        self.grow_io();
    }

    /// Current number of (active) connections in the pool. May be smaller than
    /// originally requested if the server indicated capacity limits.
    pub fn size(&self) -> usize {
        self.n.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;
    use tokio::time::Instant;

    #[test]
    fn adaptive_io_aimd() {
        let max = INFLIGHT_MAX; // 4 MiB in-flight ceiling
        // Decrease halves toward the floor, never below it.
        assert_eq!(io_after_reset(INFLIGHT_MAX), 2 * 1024 * 1024);
        assert_eq!(io_after_reset(128 * 1024), 64 * 1024);
        assert_eq!(io_after_reset(64 * 1024), 64 * 1024); // at floor, stays
        // Increase doubles toward the max, never above it.
        assert_eq!(io_after_grow(64 * 1024, max), 128 * 1024);
        assert_eq!(io_after_grow(2 * 1024 * 1024, max), max);
        assert_eq!(io_after_grow(max, max), max); // at max, stays
        // A full back-off (4 MiB → 64 KiB, ~6 halvings) then recovery
        // round-trips between floor and max.
        let mut io = max;
        let mut steps = 0;
        while io > IO_FLOOR {
            io = io_after_reset(io);
            steps += 1;
        }
        assert_eq!(io, IO_FLOOR);
        assert_eq!(steps, 6); // 4M→2M→1M→512K→256K→128K→64K
        while io < max {
            io = io_after_grow(io, max);
        }
        assert_eq!(io, max);
    }

    fn make_io_err(msg: &str) -> io::Error {
        io::Error::other(msg.to_string())
    }

    #[tokio::test]
    async fn retry_succeeds_on_first_attempt() {
        let calls = AtomicU32::new(0);
        let backoff = &[Duration::from_millis(10), Duration::from_millis(20)];
        let r: io::Result<u32> = retry_with_backoff("test", backoff, || {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Ok::<u32, io::Error>(42) }
        })
        .await;
        assert!(matches!(r, Ok(42)));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn retry_succeeds_after_transient_failures() {
        let calls = AtomicU32::new(0);
        let backoff = &[Duration::from_millis(1), Duration::from_millis(1)];
        let r: io::Result<&'static str> = retry_with_backoff("test", backoff, || {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if n < 2 {
                    Err(make_io_err("flake"))
                } else {
                    Ok("ok")
                }
            }
        })
        .await;
        assert!(matches!(r, Ok("ok")));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn retry_exhausts_attempts_and_returns_last_error() {
        let calls = AtomicU32::new(0);
        let backoff = &[
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_millis(1),
        ];
        let r: io::Result<u32> = retry_with_backoff("test", backoff, || {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            async move { Err::<u32, _>(make_io_err(&format!("err{n}"))) }
        })
        .await;
        let err = r.unwrap_err();
        // backoff.len() + 1 = 4 total attempts; last failure is err3
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        assert!(err.to_string().contains("err3"), "got: {err}");
    }

    #[tokio::test]
    async fn retry_empty_backoff_runs_exactly_once() {
        let calls = AtomicU32::new(0);
        let backoff: &[Duration] = &[];
        let r: io::Result<u32> = retry_with_backoff("test", backoff, || {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Err::<u32, _>(make_io_err("once")) }
        })
        .await;
        assert!(r.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn retry_honors_backoff_schedule_total_delay() {
        // Sum of backoff entries is the floor on elapsed time when all attempts fail.
        let backoff = &[Duration::from_millis(40), Duration::from_millis(60)];
        let expected_floor = backoff.iter().sum::<Duration>();
        let start = Instant::now();
        let r: io::Result<u32> = retry_with_backoff("test", backoff, || async {
            Err::<u32, _>(make_io_err("nope"))
        })
        .await;
        let elapsed = start.elapsed();
        assert!(r.is_err());
        assert!(
            elapsed >= expected_floor,
            "elapsed {elapsed:?} < floor {expected_floor:?}"
        );
    }

    #[test]
    fn connect_backoff_schedule_is_monotonic_nondecreasing() {
        let mut prev = Duration::ZERO;
        for d in CONNECT_RETRY_BACKOFF {
            assert!(*d >= prev, "backoff schedule must be nondecreasing");
            prev = *d;
        }
        assert!(!CONNECT_RETRY_BACKOFF.is_empty());
    }
}
