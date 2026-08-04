//! spiceio — S3-compatible API proxy to SMB 3.1.1 file shares (macOS 26).

use hyper::Request;
use hyper::body::Incoming;
use std::env;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::Semaphore;

use spiceio::crash;
use spiceio::http;
use spiceio::log;
use spiceio::s3;
use spiceio::serr;
use spiceio::slog;
use spiceio::smb;

use s3::multipart::MultipartStore;
use s3::object_cache::ObjectCache;
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

/// One attempt to stand up the SMB pool + share session + startup cleanup.
/// Failures are returned to the caller for retry — they must not take the
/// HTTP listener down.
async fn connect_share(
    smb_config: SmbConfig,
    smb_connections: usize,
    smb_share: &str,
    cleanup_grace_secs: u64,
    bucket_name: String,
    region: String,
) -> Result<Arc<AppState>, std::io::Error> {
    let pool = SmbPool::connect(smb_config, smb_connections).await?;
    let admission = pool.admission_limit();
    let share = ShareSession::connect(pool, smb_share, cleanup_grace_secs).await?;
    let share = Arc::new(share);
    // Clean up orphaned WAL temps / stale multipart dirs from prior crashes
    // (the in-memory upload map does not survive a restart).
    share.cleanup_previous_runs().await;
    let object_cache = Arc::new(ObjectCache::from_env());
    slog!("[spiceio] admission limit {admission} concurrent SMB ops (pool×work-depth)");
    if object_cache.immutable() {
        slog!(
            "[spiceio] object cache: immutable-keys mode on, max_object={}B",
            object_cache.max_object_bytes()
        );
    } else {
        slog!(
            "[spiceio] object cache: etag-validated, max_object={}B",
            object_cache.max_object_bytes()
        );
    }
    Ok(Arc::new(AppState {
        share,
        bucket: bucket_name,
        region,
        multipart: MultipartStore::new(),
        smb_slots: Arc::new(Semaphore::new(admission)),
        object_cache,
    }))
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

    // Gate for the HTTP handler: None while the SMB pool is still connecting,
    // Some(state) once the share is live. Serving TCP *before* SMB is ready is
    // what keeps sccache (and other S3 clients) from seeing "Connection
    // refused" during a slow NAS connect — they get a 503 SlowDown they can
    // retry instead of a hard TCP error that aborts server startup.
    let ready: Arc<RwLock<Option<Arc<AppState>>>> = Arc::new(RwLock::new(None));

    slog!("[spiceio] accepting connections on http://{bind_addr} (connecting to SMB…)");
    slog!(
        "[spiceio] connecting to smb://****@{}:{}/{} ({}x)",
        config.smb_server,
        config.smb_port,
        config.smb_share,
        config.smb_connections,
    );
    // Flush so the setup action / CI can see the bind address immediately,
    // even if the NAS connect stalls for a long time.
    log::flush(Duration::from_millis(200));

    // Connect SMB in the background with unbounded retry. A flaky or rebooting
    // NAS must not take the HTTP listener down — that is the connection-refused
    // failure mode sccache hits when spiceio exits (or has not yet bound).
    {
        let ready = Arc::clone(&ready);
        let smb_config = SmbConfig {
            server: config.smb_server.clone(),
            port: config.smb_port,
            username: config.smb_username.clone(),
            password: config.smb_password.clone(),
            domain: config.smb_domain.clone(),
            workstation: "SPICEIO".into(),
            max_io_size: config.smb_max_io,
        };
        let smb_server = config.smb_server.clone();
        let smb_port = config.smb_port;
        let smb_share = config.smb_share.clone();
        let smb_connections = config.smb_connections;
        let cleanup_grace_secs = config.cleanup_grace_secs;
        let multipart_ttl_secs = config.multipart_ttl_secs;
        let bucket_name = config.bucket_name.clone();
        let region = config.region.clone();
        let bind_addr_log = bind_addr;

        tokio::spawn(async move {
            let mut delay = Duration::from_secs(1);
            let state = loop {
                match connect_share(
                    smb_config.clone(),
                    smb_connections,
                    &smb_share,
                    cleanup_grace_secs,
                    bucket_name.clone(),
                    region.clone(),
                )
                .await
                {
                    Ok(state) => break state,
                    Err(e) => {
                        slog!(
                            "[spiceio] SMB not ready ({}:{} / {}): {e}; retrying in {}s",
                            smb_server,
                            smb_port,
                            smb_share,
                            delay.as_secs()
                        );
                        log::flush(Duration::from_millis(100));
                        tokio::time::sleep(delay).await;
                        delay = (delay * 2).min(Duration::from_secs(30));
                    }
                }
            };

            // Background pool healer — reconnect poisoned connections and probe
            // idle ones so a session dropped during a quiet period is found
            // here rather than by the next client request.
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

            // Background reaper — abort multipart uploads abandoned past the TTL.
            {
                let state = Arc::clone(&state);
                let ttl = multipart_ttl_secs;
                let reaper_interval = Duration::from_secs((cleanup_grace_secs / 3).clamp(30, 300));
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

            // Publish readiness. The setup action greps for "ready, listening"
            // (not merely "accepting connections") before pointing sccache at us.
            *ready.write().unwrap_or_else(|e| e.into_inner()) = Some(state);
            slog!("[spiceio] ready, listening on http://{bind_addr_log}");
            slog!("[spiceio] bucket: {bucket_name} region: {region}");
            log::flush(Duration::from_millis(200));
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
    // Requests that arrive before SMB is ready get 503 SlowDown + Retry-After
    // rather than a TCP refuse — sccache treats temporary storage errors as
    // retryable, but a connection refusal fails server startup hard.
    http::serve(
        listener,
        http::ServeConfig::default(),
        shutdown,
        move |req: Request<Incoming>| {
            let ready = Arc::clone(&ready);
            async move {
                let state = ready.read().unwrap_or_else(|e| e.into_inner()).clone();
                match state {
                    Some(state) => s3::router::handle_request(req, &state).await,
                    None => s3::router::service_unavailable(
                        "spiceio is still connecting to the SMB backend; please retry.",
                    ),
                }
            }
        },
    )
    .await;

    // Push the final log lines (including the shutdown notice) to disk before
    // the process exits and takes the writer thread with it.
    log::flush(Duration::from_millis(500));
}
