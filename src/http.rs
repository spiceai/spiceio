//! HTTP front end for the S3 listener: the accept loop and its tuning.
//!
//! The loop lives here rather than inline in `main` so that the behaviors it
//! encodes — the header-read timeout, `TCP_NODELAY`, the accept backoff, and
//! the bounded graceful drain — are exercised by `tests/http_frontend.rs`
//! exactly as the server runs them. A test that rebuilt the sequence itself
//! would keep passing while the real loop regressed.

use std::collections::HashSet;
use std::convert::Infallible;
use std::error::Error as StdError;
use std::future::Future;
use std::net::IpAddr;
use std::time::Duration;

use hyper::body::{Body, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use tokio::net::{TcpListener, TcpStream};

/// Tuning for the S3 listener. `Default` is what the server runs with; tests
/// shorten the timeouts so the same code paths can be driven in milliseconds
/// instead of minutes.
#[derive(Debug, Clone, Copy)]
pub struct ServeConfig {
    /// How long a connection may go without producing complete request headers
    /// before it is dropped. hyper arms this timer as soon as it starts waiting
    /// for a request, so it doubles as the idle keep-alive bound: it is what
    /// reclaims sockets from clients that vanished without a FIN (a crashed
    /// host, a yanked cable) instead of letting them accumulate forever, and it
    /// caps how long a slow-loris client can hold a task.
    ///
    /// Deliberately well above any common client's idle-reuse window: a server
    /// that closes an idle connection the client still believes is usable
    /// creates a retry race, and a non-idempotent request (PUT/POST) losing
    /// that race is a user-visible failure.
    pub header_read_timeout: Duration,
    /// Pause after a failed `accept()` so descriptor exhaustion cannot spin the
    /// accept loop at 100% CPU (which would starve the tasks that free them).
    pub accept_error_backoff: Duration,
    /// How long shutdown waits for in-flight requests to finish before exiting
    /// anyway. Long enough for a large streaming transfer to wrap up, bounded
    /// so a wedged connection cannot keep the process alive indefinitely.
    pub shutdown_grace: Duration,
}

impl Default for ServeConfig {
    fn default() -> Self {
        Self {
            header_read_timeout: Duration::from_secs(120),
            accept_error_backoff: Duration::from_millis(50),
            shutdown_grace: Duration::from_secs(30),
        }
    }
}

/// Build the connection server used for every accepted socket.
///
/// HTTP/1.1 only, deliberately. Every S3 client that matters (the AWS CLI and
/// SDKs, sccache, curl) speaks HTTP/1.1 to a plain-HTTP endpoint — h2 is
/// negotiated over TLS, which this proxy does not terminate — so the
/// protocol-sniffing `auto` server would only add the whole HTTP/2 stack to
/// the binary for a code path no client takes. It would also *weaken* the
/// header timeout: sniffing has to read the first bytes before it can hand off
/// to the HTTP/1 connection, so a client that connects and then says nothing
/// at all — the exact slow-loris/dead-peer case this timeout exists for — is
/// never covered by it. Serving HTTP/1 directly arms the timeout from the
/// first byte.
pub fn connection_builder(header_read_timeout: Duration) -> http1::Builder {
    let mut builder = http1::Builder::new();
    builder
        // Required for `header_read_timeout` to take effect — and hyper
        // panics when the timeout is set without it.
        .timer(TokioTimer::new())
        .header_read_timeout(header_read_timeout);
    builder
}

/// Apply per-connection socket options to an accepted stream.
///
/// Nagle off: S3 responses are small and latency-sensitive (HEAD, small GET,
/// the many metadata round trips a client makes per object). Coalescing them
/// against delayed ACKs adds tens of milliseconds per request for no benefit.
pub fn configure_socket(stream: &TcpStream) {
    if let Err(e) = stream.set_nodelay(true) {
        serr!("[spiceio] could not set TCP_NODELAY: {e}");
    }
}

/// Accept and serve connections until `shutdown` resolves, then drain.
///
/// `handler` is invoked once per request; it is cloned per connection, so it
/// should be cheap to clone (an `Arc` capture).
///
/// On shutdown the listener is dropped first — no new connections — and
/// in-flight requests are given `shutdown_grace` to finish. Cutting them off
/// instead would truncate client transfers and abandon partially written
/// temporary files.
pub async fn serve<F, Fut, B>(
    listener: TcpListener,
    config: ServeConfig,
    shutdown: impl Future<Output = ()>,
    handler: F,
) where
    F: Fn(Request<Incoming>) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Response<B>> + Send + 'static,
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    let builder = connection_builder(config.header_read_timeout);
    let graceful = GracefulShutdown::new();
    // spiceio has no client authentication, so the accept log is the only
    // record of who reached it. Logging every connection would drown the log
    // (an sccache build opens hundreds), so log each distinct peer once.
    //
    // Capped: on a trusted LAN the set is small, but nothing stops a peer from
    // arriving with fresh source addresses, and an unbounded set would then be
    // a slow memory leak driven by remote input. Past the cap the proxy stops
    // tracking and stops logging new peers rather than growing.
    const MAX_TRACKED_PEERS: usize = 1024;
    let mut seen_peers: HashSet<IpAddr> = HashSet::new();
    let mut shutdown = std::pin::pin!(shutdown);

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer_addr) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        serr!("[spiceio] accept error: {e}");
                        tokio::time::sleep(config.accept_error_backoff).await;
                        continue;
                    }
                };
                configure_socket(&stream);
                if seen_peers.len() < MAX_TRACKED_PEERS && seen_peers.insert(peer_addr.ip()) {
                    slog!("[spiceio] first connection from {}", peer_addr.ip());
                }

                let handler = handler.clone();
                let service = service_fn(move |req: Request<Incoming>| {
                    let handler = handler.clone();
                    async move { Ok::<_, Infallible>(handler(req).await) }
                });

                // `watch` enrolls the connection in the drain set.
                let conn = graceful.watch(builder.serve_connection(TokioIo::new(stream), service));
                tokio::spawn(async move {
                    if let Err(e) = conn.await {
                        // A client hanging up, and an idle connection reaped by
                        // the header-read timeout, are both routine — logging
                        // them would bury real errors under per-connection
                        // noise. `is_timeout` is hyper's own predicate for the
                        // latter; matching its Display text would silently stop
                        // working the day hyper rewords the message.
                        if !e.is_timeout() && !e.to_string().contains("connection reset") {
                            serr!("[spiceio] connection error from {peer_addr}: {e}");
                        }
                    }
                });
            }
            () = &mut shutdown => break,
        }
    }

    drop(listener);
    tokio::select! {
        () = graceful.shutdown() => slog!("[spiceio] all connections drained"),
        () = tokio::time::sleep(config.shutdown_grace) => serr!(
            "[spiceio] shutdown grace period ({}s) elapsed with connections still open",
            config.shutdown_grace.as_secs()
        ),
    }
}
