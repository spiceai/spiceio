//! SMB connection pool — multiple authenticated TCP connections to the same
//! server, round-robin dispatched. Eliminates the single-connection mutex
//! bottleneck under concurrent S3 requests.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::client::{SmbClient, SmbConfig};

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
        let first = SmbClient::connect(config.clone()).await?;
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
                joins.push(tokio::spawn(async move { SmbClient::connect(cfg).await }));
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

    /// Pick the next connection via round-robin.
    pub fn get(&self) -> &Arc<SmbClient> {
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.clients.len();
        &self.clients[idx]
    }

    /// Get the next round-robin index (and advance the counter).
    pub fn next_index(&self) -> usize {
        self.next.fetch_add(1, Ordering::Relaxed)
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
