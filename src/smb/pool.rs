//! SMB connection pool — multiple authenticated TCP connections to the same
//! server, round-robin dispatched. Eliminates the single-connection mutex
//! bottleneck under concurrent S3 requests.

use std::future::Future;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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

/// Generic retry-with-backoff helper. Runs `op` until it succeeds, sleeping
/// the corresponding `backoff` interval between failures. After `backoff.len()`
/// retries (i.e. `backoff.len() + 1` total attempts), returns the final error.
///
/// `op` is responsible for logging the error detail on each failed attempt;
/// this helper only emits a short retry notice ("retrying in Nms") so the
/// log isn't doubled up under flaky conditions.
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
                        "[spiceio] {label} retrying (attempt {next}/{max_attempts}) in {}ms",
                        delay.as_millis()
                    );
                    tokio::time::sleep(delay).await;
                }
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::other(format!("{label} failed without error"))))
}

async fn connect_with_retry(config: SmbConfig) -> io::Result<Arc<SmbClient>> {
    retry_with_backoff("smb connect", CONNECT_RETRY_BACKOFF, || {
        SmbClient::connect(config.clone())
    })
    .await
}

/// A pool of authenticated SMB connections to the same server.
///
/// Requests are distributed across connections via round-robin. Each connection
/// is an independently authenticated SMB session with its own TCP stream, so
/// concurrent operations don't serialize on a single mutex.
pub struct SmbPool {
    clients: Vec<Arc<SmbClient>>,
    next: AtomicUsize,
    /// Cached from the first connection's negotiate response.
    pub max_read_size: u32,
    pub max_write_size: u32,
    pub compound_max_read_size: u32,
    pub compound_max_write_size: u32,
}

impl SmbPool {
    /// Connect `n` authenticated sessions to the SMB server.
    ///
    /// All connections negotiate independently and authenticate with the same
    /// credentials. The pool uses the negotiated sizes from the first connection.
    pub async fn connect(config: SmbConfig, n: usize) -> io::Result<Arc<Self>> {
        let n = n.max(1);
        let mut clients = Vec::with_capacity(n);

        // First connection — establishes negotiated parameters
        let first = connect_with_retry(config.clone()).await?;
        let max_read_size = first.max_read_size;
        let max_write_size = first.max_write_size;
        let compound_max_read_size = first.compound_max_read_size;
        let compound_max_write_size = first.compound_max_write_size;
        clients.push(first);

        // Additional connections in parallel
        if n > 1 {
            let mut joins = Vec::with_capacity(n - 1);
            for _ in 1..n {
                let cfg = config.clone();
                joins.push(tokio::spawn(async move { connect_with_retry(cfg).await }));
            }
            for join in joins {
                let client = join
                    .await
                    .map_err(|e| io::Error::other(format!("spawn failed: {e}")))??;
                clients.push(client);
            }
            crate::slog!("[spiceio] smb pool: {n} connections ready");
        }

        Ok(Arc::new(Self {
            clients,
            next: AtomicUsize::new(0),
            max_read_size,
            max_write_size,
            compound_max_read_size,
            compound_max_write_size,
        }))
    }

    /// Pick the next healthy connection via round-robin, skipping poisoned ones.
    /// Falls back to a poisoned connection if all are poisoned (error will
    /// surface on the first I/O attempt).
    pub fn get(&self) -> &Arc<SmbClient> {
        let n = self.clients.len();
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        for i in 0..n {
            let idx = (start + i) % n;
            if !self.clients[idx].is_poisoned() {
                return &self.clients[idx];
            }
        }
        // All poisoned — return round-robin pick; caller gets BrokenPipe on I/O
        &self.clients[start % n]
    }

    /// Get the next round-robin index (and advance the counter), preferring
    /// healthy connections.
    pub fn next_index(&self) -> usize {
        let n = self.clients.len();
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        for i in 0..n {
            let idx = (start + i) % n;
            if !self.clients[idx].is_poisoned() {
                return idx;
            }
        }
        start % n
    }

    /// Access a specific connection by index.
    pub fn client(&self, idx: usize) -> &Arc<SmbClient> {
        &self.clients[idx]
    }

    /// Access all connections (for tree-connect setup).
    pub fn clients(&self) -> &[Arc<SmbClient>] {
        &self.clients
    }

    /// Number of connections in the pool.
    pub fn size(&self) -> usize {
        self.clients.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;
    use tokio::time::Instant;

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
