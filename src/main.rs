//! spiceio — S3-compatible API proxy to SMB 3.1.1 file shares (macOS 26).

use hyper::Request;
use hyper::body::Incoming;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal;

use spiceio::crash;
use spiceio::http;
use spiceio::log;
use spiceio::s3;
use spiceio::serr;
use spiceio::slog;
use spiceio::smb;

use s3::multipart::MultipartStore;
use s3::router::AppState;
use smb::client::SmbConfig;
use smb::ops::ShareSession;
use smb::pool::SmbPool;

/// Runtime configuration parsed from environment variables.
struct Config {
    /// Address to bind the HTTP server to
    bind_addr: SocketAddr,
    /// SMB server hostname or IP
    smb_server: String,
    /// SMB port (default 445)
    smb_port: u16,
    /// SMB username
    smb_username: String,
    /// SMB password
    smb_password: String,
    /// SMB domain (default empty)
    smb_domain: String,
    /// SMB share name
    smb_share: String,
    /// S3 bucket name (virtual, maps to the share)
    bucket_name: String,
    /// AWS region to advertise
    region: String,
    /// Number of SMB TCP connections in the pool (default 8)
    smb_connections: usize,
    /// Max I/O size for standalone read/write operations (default 256KB)
    smb_max_io: u32,
    /// TTL after which an abandoned multipart upload is reaped
    multipart_ttl_secs: u64,
    /// Age below which startup cleanup leaves a WAL temp / upload dir alone
    cleanup_grace_secs: u64,
}

/// Exit nonzero after draining the async logger. The log writer thread dies
/// with the process, so an `exit()` immediately after `serr!`/`slog!` would
/// drop the just-queued line (the channel is non-blocking and drains on its
/// own thread). Flushing first guarantees the message reaches stderr and the
/// log file — important for one-line startup/config errors.
fn flush_and_exit(code: i32) -> ! {
    log::flush(Duration::from_millis(500));
    std::process::exit(code);
}

/// Read a required env var, exiting with a clean config error (not a panic /
/// crash report) when missing or empty.
fn require_env(name: &str) -> String {
    match env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => {
            serr!("[spiceio] {name} is required");
            flush_and_exit(1);
        }
    }
}

/// Parse an optional env var, warning (instead of silently defaulting) when a
/// value is present but unparsable — a misconfiguration worth surfacing.
fn parse_env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    match env::var(name) {
        Ok(raw) => match raw.parse() {
            Ok(v) => v,
            Err(_) => {
                serr!("[spiceio] {name}={raw} is not valid; using default");
                default
            }
        },
        Err(_) => default,
    }
}

impl Config {
    fn from_env() -> Self {
        Self {
            bind_addr: {
                let raw = env::var("SPICEIO_BIND").unwrap_or_else(|_| "0.0.0.0:8333".into());
                match raw.parse() {
                    Ok(addr) => addr,
                    Err(_) => {
                        serr!("[spiceio] SPICEIO_BIND is not a valid socket address: {raw}");
                        flush_and_exit(1);
                    }
                }
            },
            smb_server: require_env("SPICEIO_SMB_SERVER"),
            smb_port: parse_env_or("SPICEIO_SMB_PORT", 445),
            smb_username: require_env("SPICEIO_SMB_USER"),
            smb_password: require_env("SPICEIO_SMB_PASS"),
            smb_domain: env::var("SPICEIO_SMB_DOMAIN").unwrap_or_default(),
            smb_share: require_env("SPICEIO_SMB_SHARE"),
            bucket_name: env::var("SPICEIO_BUCKET").unwrap_or_else(|_| {
                env::var("SPICEIO_SMB_SHARE").unwrap_or_else(|_| "data".into())
            }),
            region: env::var("SPICEIO_REGION").unwrap_or_else(|_| "us-east-1".into()),
            smb_connections: parse_env_or("SPICEIO_SMB_CONNECTIONS", default_pool_size()),
            smb_max_io: parse_env_or("SPICEIO_SMB_MAX_IO", 0),
            multipart_ttl_secs: parse_env_or("SPICEIO_MULTIPART_TTL_SECS", 86_400u64),
            cleanup_grace_secs: parse_env_or(
                "SPICEIO_CLEANUP_GRACE_SECS",
                smb::ops::DEFAULT_CLEANUP_GRACE_SECS,
            ),
        }
    }
}

/// Default SMB connection-pool size, scaled with CPU cores so concurrent S3
/// requests (e.g. a parallel `cargo`/sccache build) fan out across connections
/// instead of queuing on one connection's stream lock. Floored at 4 (enough
/// fan-out on small machines), capped at 12 to bound concurrent SMB session
/// load on the server; override with `SPICEIO_SMB_CONNECTIONS`.
fn default_pool_size() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(4, 12)
}

#[tokio::main]
async fn main() {
    if env::args().any(|a| a == "--version" || a == "-V") {
        println!("spiceio {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    // Treat an empty SPICEIO_LOG_FILE as unset: CI and the test scripts may
    // forward the variable unconditionally (`SPICEIO_LOG_FILE="${VAR:-}"`), and
    // opening the path "" would otherwise fail and exit at startup.
    let log_file = env::var("SPICEIO_LOG_FILE").ok().filter(|s| !s.is_empty());
    log::init(log_file.as_deref());
    // Crash reporting (panic hook + fatal-signal handlers) — as early as
    // possible so every later failure leaves a report on stderr + log file.
    crash::install(log_file.as_deref());

    // Hidden: `--crash-test <panic|segv|abort>` deliberately crashes through
    // the real pipeline so the reporting path itself is testable end-to-end.
    {
        let args: Vec<String> = env::args().collect();
        if let Some(i) = args.iter().position(|a| a == "--crash-test") {
            let mode = args.get(i + 1).map(String::as_str).unwrap_or("panic");
            crash::crash_test(mode);
        }
    }

    slog!(
        "[spiceio] v{} starting (pid {})",
        env!("CARGO_PKG_VERSION"),
        std::process::id()
    );

    let config = Config::from_env();

    // Bind TCP listener early (before SMB setup). If the port is taken,
    // auto-increment until an available port is found.
    let (listener, bind_addr) = {
        let mut addr = config.bind_addr;
        let start_port = addr.port();
        loop {
            match TcpListener::bind(addr).await {
                Ok(l) => break (l, addr),
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                    let next = match addr.port().checked_add(1) {
                        Some(n) if n - start_port <= 100 => n,
                        _ => {
                            serr!("no available port in range {start_port}–{}", addr.port());
                            flush_and_exit(1);
                        }
                    };
                    addr.set_port(next);
                }
                Err(e) => {
                    serr!("failed to bind TCP listener: {e}");
                    flush_and_exit(1);
                }
            }
        }
    };

    slog!(
        "[spiceio] connecting to smb://****@{}:{}/{} ({}x)",
        config.smb_server,
        config.smb_port,
        config.smb_share,
        config.smb_connections,
    );

    // Flush the startup lines to disk before the (possibly slow) SMB connect: on
    // an overloaded NAS the connect can block, and these lines are the
    // breadcrumb that shows where startup stalled. Without this the async log
    // buffer holds them and a hung startup leaves an empty log to diagnose from.
    log::flush(Duration::from_millis(200));

    // Connect SMB connection pool
    let smb_config = SmbConfig {
        server: config.smb_server.clone(),
        port: config.smb_port,
        username: config.smb_username.clone(),
        password: config.smb_password.clone(),
        domain: config.smb_domain.clone(),
        workstation: "SPICEIO".into(),
        max_io_size: config.smb_max_io,
    };

    // Startup connection failures are operational errors, not crashes —
    // report them cleanly (server, share, cause) and exit nonzero.
    let pool = match SmbPool::connect(smb_config, config.smb_connections).await {
        Ok(p) => p,
        Err(e) => {
            serr!(
                "[spiceio] failed to connect to SMB server {}:{}: {e}",
                config.smb_server,
                config.smb_port
            );
            flush_and_exit(1);
        }
    };

    let share =
        match ShareSession::connect(pool, &config.smb_share, config.cleanup_grace_secs).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                serr!(
                    "[spiceio] failed to connect to SMB share '{}': {e}",
                    config.smb_share
                );
                flush_and_exit(1);
            }
        };

    // Clean up orphaned WAL temp files and stale multipart upload dirs from
    // prior crashes (the in-memory upload map does not survive a restart).
    share.cleanup_previous_runs().await;

    let state = Arc::new(AppState {
        share,
        bucket: config.bucket_name.clone(),
        region: config.region.clone(),
        multipart: MultipartStore::new(),
    });

    slog!("[spiceio] listening on http://{bind_addr}");
    slog!(
        "[spiceio] bucket: {} region: {}",
        config.bucket_name,
        config.region
    );

    // Background pool healer — reconnect SMB connections poisoned by a
    // transient outage so the pool recovers instead of degrading to a wedge,
    // and probe idle connections so a session dropped during a quiet period is
    // found (and healed) here rather than by the next client request.
    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                state.share.heal().await;
                state.share.keepalive();
            }
        });
    }

    // Background reaper — abort multipart uploads abandoned past the TTL,
    // freeing their in-memory entry and temp files.
    {
        let state = Arc::clone(&state);
        let ttl = config.multipart_ttl_secs;
        // The heartbeat below is what keeps a live upload's marker looking
        // recent, so its cadence must stay comfortably inside the cleanup
        // grace period — otherwise lowering `SPICEIO_CLEANUP_GRACE_SECS`
        // would silently reinstate the very bug the grace exists to prevent.
        // Deriving it from the grace makes the two impossible to drift apart.
        let reaper_interval = Duration::from_secs((config.cleanup_grace_secs / 3).clamp(30, 300));
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(reaper_interval).await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let expired = state.multipart.reap_expired(now, ttl).await;
                for upload in &expired {
                    for part in upload.parts.values() {
                        state.share.delete_temp(&part.temp_path).await;
                    }
                    // Delete the initiate-time marker file too — without this
                    // the directory is never empty and remove_dir fails, so
                    // reaped upload dirs would pile up until the next restart.
                    state
                        .share
                        .delete_temp(&MultipartStore::marker_path(&upload.upload_id))
                        .await;
                    state
                        .share
                        .remove_dir(&MultipartStore::temp_dir(&upload.upload_id))
                        .await;
                }
                if !expired.is_empty() {
                    slog!(
                        "[spiceio] reaped {} abandoned multipart upload(s)",
                        expired.len()
                    );
                }

                // Heartbeat the uploads that survived: refreshing each marker
                // keeps its directory looking recent, which is how another
                // spiceio instance's startup cleanup tells "a live process
                // owns this upload" from "leftovers of a crashed run" — even
                // when a client goes quiet between parts. Touches run
                // concurrently: they are independent, and serializing them
                // would put N round trips back-to-back on connections the
                // client requests are also using.
                // Bounded fan-out: enough to overlap the round trips, not so
                // much that a share with thousands of live uploads floods the
                // pool the client requests are also using.
                const MARKER_TOUCH_CONCURRENCY: usize = 8;
                let live = state.multipart.upload_ids().await;
                for batch in live.chunks(MARKER_TOUCH_CONCURRENCY) {
                    let mut set = tokio::task::JoinSet::new();
                    for id in batch {
                        let state = Arc::clone(&state);
                        let path = MultipartStore::marker_path(id);
                        set.spawn(async move {
                            let _ = state.share.write_temp(&path, b"").await;
                        });
                    }
                    while set.join_next().await.is_some() {}
                }
            }
        });
    }

    // SIGTERM (the standard service-manager stop signal) triggers the same
    // graceful shutdown as Ctrl-C. Registration failing is exceptional; fall
    // back to a never-resolving future so SIGINT still works.
    let shutdown = async {
        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate()).ok();
        let term = async {
            match sigterm.as_mut() {
                Some(s) => {
                    s.recv().await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            _ = signal::ctrl_c() => slog!("\n[spiceio] shutting down (SIGINT)"),
            () = term => slog!("[spiceio] shutting down (SIGTERM)"),
        }
    };

    // Serve until a stop signal arrives, then drain in-flight requests.
    http::serve(
        listener,
        http::ServeConfig::default(),
        shutdown,
        move |req: Request<Incoming>| {
            let state = Arc::clone(&state);
            async move { s3::router::handle_request(req, &state).await }
        },
    )
    .await;

    // Push the final log lines (including the shutdown notice) to disk before
    // the process exits and takes the writer thread with it.
    log::flush(Duration::from_millis(500));
}
