//! spiceio — S3-compatible API proxy to SMB 3.1.1 file shares (macOS 26).

use hyper::body::Incoming;
use hyper::{Request, Response};
use std::env;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::signal;

use spiceio::access_log;
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
use s3::spill::{self, Spill};
use s3::writeback::WriteBack;
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
    /// Number of SMB TCP connections in the pool (see `default_pool_size`)
    smb_connections: usize,
    /// Max I/O size for standalone read/write operations (default 256KB)
    smb_max_io: u32,
    /// TTL after which an abandoned multipart upload is reaped
    multipart_ttl_secs: u64,
    /// Age below which startup cleanup leaves a WAL temp / upload dir alone
    cleanup_grace_secs: u64,
    /// Machine-wide disk spill directory, or None when disabled
    spill_dir: Option<String>,
    /// Disk budget for the whole spill directory, shared by every instance
    spill_bytes: u64,
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
            // On by default: a read cache on local disk changes no semantics,
            // only how often the NAS is asked. `off` (or empty) opts out.
            spill_dir: match env::var("SPICEIO_SPILL_DIR") {
                Ok(v) if v.is_empty() || v.eq_ignore_ascii_case("off") => None,
                Ok(v) => Some(v),
                Err(_) => Some(spill::DEFAULT_DIR.to_string()),
            },
            spill_bytes: parse_env_or("SPICEIO_SPILL_BYTES", spill::DEFAULT_MAX_BYTES),
        }
    }
}

/// Time allowed at shutdown for acknowledged writes to reach the NAS. Matched
/// to the HTTP drain grace: a stop that waits for in-flight *requests* should
/// wait as long for writes it has already told clients succeeded.
const WRITE_BACK_DRAIN: Duration = Duration::from_secs(30);

/// Default SMB connection-pool size: **two per CPU, clamped to 8–32**.
/// Override with `SPICEIO_SMB_CONNECTIONS`.
///
/// Connections are not a CPU resource — they are how the proxy hides NAS
/// round-trip latency and avoids head-of-line blocking. A connection owns its
/// stream for a whole round trip, so a one-round-trip HEAD behind a
/// multi-megabyte pipelined batch waits for it, and the only cure is another
/// connection. Scaling off core count is a proxy for offered concurrency, which
/// is why it is *two* per core rather than one: an `-j16` build keeps well over
/// 16 requests outstanding.
///
/// Sizing is a latency decision, not a throughput one. Backend *bandwidth* is
/// flat at ~100 MiB/s from 32 concurrent writes upward, and a pool sweep at
/// fixed concurrency measured no throughput gain past 12 connections while GET
/// p50 kept falling (123 ms at 4 → 83 ms at 12 → 48 ms at 24 → 28 ms at 48).
/// Re-measured on the mixed sccache-shaped phase, 3 interleaved reps, 16 vs 32:
/// p90 fell 52% at concurrency 32 and 36% at 64, and the run-to-run spread
/// tightened markedly (p90 reps 3.7/10.3/13.6 ms at 16 versus 4.3/3.8/4.9 ms at
/// 32) — the wider pool is both faster and steadier. Cost is one extra second
/// of startup (0.7 s → 1.4 s to authenticate the pool) and more concurrent SMB
/// sessions on the server, which is why it is still capped.
fn default_pool_size() -> usize {
    pool_size_for(
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4),
    )
}

/// The sizing rule itself, split out so it can be checked at core counts this
/// host does not have — the floor and the ceiling are the parts worth testing,
/// and neither is reachable on a 16-core machine.
fn pool_size_for(cpus: usize) -> usize {
    cpus.saturating_mul(2).clamp(8, 32)
}

/// One attempt to stand up the SMB pool + share session + startup cleanup.
/// Failures are returned to the caller for retry — they must not take the
/// HTTP listener down.
#[allow(clippy::too_many_arguments)]
async fn connect_share(
    smb_config: SmbConfig,
    smb_connections: usize,
    smb_share: &str,
    cleanup_grace_secs: u64,
    bucket_name: String,
    region: String,
    spill_dir: Option<String>,
    spill_bytes: u64,
) -> Result<Arc<AppState>, std::io::Error> {
    let pool = SmbPool::connect(smb_config.clone(), smb_connections).await?;
    let admission = pool.admission_limit();
    // Shared with the pool so capacity shrinks reduce available permits.
    let smb_slots = pool.admission();
    let share = ShareSession::connect(pool, smb_share, cleanup_grace_secs).await?;
    let share = Arc::new(share);
    // Clean up orphaned WAL temps / stale multipart dirs from prior crashes
    // (the in-memory upload map does not survive a restart).
    share.cleanup_previous_runs().await;

    let mut object_cache = ObjectCache::from_env();
    slog!("[spiceio] admission limit {admission} concurrent SMB ops (pool×work-depth)");
    slog!(
        "[spiceio] object cache: {} MiB budget, max_object={} MiB, {} entries, {}",
        object_cache.max_bytes() / (1024 * 1024),
        object_cache.max_object_bytes() / (1024 * 1024),
        object_cache.max_entries(),
        if object_cache.immutable() {
            "immutable keys (hits served with no backend round trip)"
        } else {
            "etag-revalidated (one stat per hit)"
        }
    );

    // L2: the machine-wide disk tier. Namespaced by backend identity so
    // instances fronting *different* shares can share one directory without
    // ever serving each other's objects.
    if let Some(dir) = spill_dir.as_deref() {
        let namespace = format!("{}:{}/{}", smb_config.server, smb_config.port, smb_share);
        let max_object = s3::object_cache::default_max_object_bytes(spill_bytes);
        match Spill::open(
            std::path::Path::new(dir),
            namespace,
            spill_bytes,
            max_object,
        ) {
            Ok(s) => {
                slog!(
                    "[spiceio] disk spill: {dir} ({} GiB budget, max_object={} MiB, shared machine-wide)",
                    spill_bytes / (1024 * 1024 * 1024),
                    max_object / (1024 * 1024),
                );
                object_cache = object_cache.with_spill(Arc::new(s));
            }
            // A cache tier that cannot be opened is a missing optimization, not
            // a reason to refuse to serve.
            Err(e) => serr!("[spiceio] disk spill disabled: cannot use {dir}: {e}"),
        }
    }
    let object_cache = Arc::new(object_cache);

    let writeback = Arc::new(WriteBack::from_env());
    if writeback.enabled() {
        let flushers = writeback.spawn_flushers(
            Arc::clone(&share),
            Arc::clone(&object_cache),
            s3::writeback::DEFAULT_FLUSHERS,
        );
        slog!(
            "[spiceio] write-back: on ({} MiB queue, {flushers} flushers) — PUT is \
             acknowledged from memory before the NAS write (SPICEIO_WRITE_BACK=0 to disable)",
            writeback.max_bytes() / (1024 * 1024),
        );
        if object_cache.spill().is_none() {
            serr!(
                "[spiceio] write-back is on without a disk spill: an acknowledged \
                 write that has not flushed is lost if this process dies"
            );
        }
    }

    Ok(Arc::new(AppState {
        client_inflight: share.client_inflight(),
        share,
        bucket: bucket_name,
        region,
        multipart: MultipartStore::new(),
        listings: Default::default(),
        smb_slots,
        object_cache,
        writeback,
    }))
}

/// Register a terminating signal for graceful shutdown.
///
/// Returns `None` if the kernel refuses the registration, which is exceptional
/// but must not be fatal: one signal failing to register should leave the others
/// working rather than abort startup. It is logged because the consequence is
/// invisible until someone tries to stop the process and has to reach for
/// SIGKILL — which is exactly the case the drain exists to avoid.
fn register_signal(kind: signal::unix::SignalKind, name: &str) -> Option<signal::unix::Signal> {
    match signal::unix::signal(kind) {
        Ok(s) => Some(s),
        Err(e) => {
            serr!(
                "[spiceio] could not install a {name} handler: {e}; \
                 that signal will terminate without draining"
            );
            None
        }
    }
}

/// Wait for the next delivery of a registered signal.
///
/// An unregistered one parks forever instead of resolving, so it simply never
/// wins its `select!` arm — the alternative, resolving immediately, would spin
/// the shutdown listener at full tilt.
async fn next_signal(sig: &mut Option<signal::unix::Signal>) {
    match sig {
        Some(s) => {
            s.recv().await;
        }
        None => std::future::pending().await,
    }
}

/// Interval between spill sweeps, chosen from how full the last one found the
/// directory. A cache with room to spare does not need a tree walk every
/// minute; one near its budget does.
fn sweep_interval(stats: &spill::SweepStats) -> Duration {
    if stats.skipped {
        // Another instance is sweeping — check back on its cadence, not ours.
        return Duration::from_secs(120);
    }
    let used = stats.bytes as f64 / (stats.effective_budget.max(1)) as f64;
    match used {
        u if u > 0.9 => Duration::from_secs(30),
        u if u > 0.5 => Duration::from_secs(120),
        _ => Duration::from_secs(300),
    }
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

    // Opt-in per-request metrics side channel. Off unless SPICEIO_ACCESS_LOG
    // names a file; the benchmark scripts turn it on to attribute latency to
    // spiceio versus the client and the network.
    let access_log_path = env::var("SPICEIO_ACCESS_LOG")
        .ok()
        .filter(|s| !s.is_empty());
    if access_log::init(access_log_path.as_deref())
        && let Some(p) = access_log_path.as_deref()
    {
        slog!(
            "[spiceio] access log: {p} \
             (t_ms method status req_bytes resp_bytes head_us total_us path)"
        );
    }

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

    // Gate for the HTTP handler: empty while the SMB pool is still connecting,
    // published once the share is live. `OnceLock` is a one-shot publish — no
    // per-request lock after readiness. Serving TCP *before* SMB is ready is
    // what keeps sccache (and other S3 clients) from seeing "Connection
    // refused" during a slow NAS connect — they get a 503 SlowDown they can
    // retry instead of a hard TCP error that aborts server startup.
    let ready: Arc<OnceLock<Arc<AppState>>> = Arc::new(OnceLock::new());

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
        let spill_dir = config.spill_dir.clone();
        let spill_bytes = config.spill_bytes;
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
                    spill_dir.clone(),
                    spill_bytes,
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

            // Background spill maintenance — enforce the machine-wide disk
            // budget, and recover acknowledged writes that never reached the
            // NAS. The dirty scan covers this instance's own writes after a
            // restart *and* a crashed peer's: an unflushed body exists only on
            // this disk, so whichever instance finds it has to publish it.
            if state.object_cache.spill().is_some() {
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    // Long enough that a flush in progress on a live peer is
                    // not duplicated; short enough that a crashed peer's writes
                    // do not sit unwritten for long.
                    const DIRTY_MIN_AGE: Duration = Duration::from_secs(60);
                    // Startup recovery uses a much shorter age than the steady
                    // state: everything this process finds before it has written
                    // anything of its own was stranded by a previous run, and
                    // waiting out the full age would leave a crash unrecovered
                    // for minutes. Not zero, because a live peer's genuinely
                    // in-flight entry is milliseconds old and is not ours to
                    // duplicate.
                    const STARTUP_MIN_AGE: Duration = Duration::from_secs(5);
                    let mut min_age = STARTUP_MIN_AGE;
                    let mut delay = Duration::ZERO;
                    loop {
                        tokio::time::sleep(delay).await;

                        // Entries this instance journalled are already spoken
                        // for — its own flushers promote them, and its shutdown
                        // drains them. Replaying those would duplicate work that
                        // is in progress; the scan is for *orphans*.
                        let owned: std::collections::HashSet<String> =
                            state.object_cache.spill_owned_dirty().into_iter().collect();
                        let (dirty, young) = state.object_cache.spill_scan_dirty(min_age).await;
                        let dirty: Vec<_> = dirty
                            .into_iter()
                            .filter(|d| !owned.contains(&d.key))
                            .collect();
                        if !dirty.is_empty() {
                            slog!(
                                "[spiceio] replaying {} unflushed write(s) from the disk spill",
                                dirty.len()
                            );
                            for d in dirty {
                                let Ok(_mutation) = state.writeback.begin_mutation(&d.key).await
                                else {
                                    continue;
                                };
                                if state.writeback.pending_meta(&d.key).await.is_some()
                                    || state.object_cache.spill_owns_dirty(&d.key)
                                {
                                    continue;
                                }
                                let Some(entry) = state.object_cache.spill_load_dirty(&d).await
                                else {
                                    continue;
                                };
                                // Re-enqueue when write-back is on; otherwise
                                // write straight through. Either way the spill
                                // entry is promoted (or left dirty to retry) by
                                // the same code path a live write uses.
                                let queued = state
                                    .writeback
                                    .enqueue(
                                        &d.key,
                                        &entry.etag,
                                        entry.last_modified,
                                        entry.body.clone(),
                                    )
                                    .await;
                                if queued {
                                    continue;
                                }
                                let Ok(_permit) = state.smb_slots.clone().acquire_owned().await
                                else {
                                    break;
                                };
                                match state.share.put_object_atomic(&d.key, &entry.body).await {
                                    Ok(meta) => {
                                        state
                                            .object_cache
                                            .spill_promote(
                                                &d.key,
                                                entry.body_sha,
                                                &meta.etag,
                                                meta.last_modified,
                                                &entry.body,
                                            )
                                            .await;
                                    }
                                    Err(e) => serr!(
                                        "[spiceio] replay of {} (stranded {}s) failed: {e}; \
                                         will retry",
                                        d.key,
                                        d.age_secs
                                    ),
                                }
                            }
                        }

                        let stats = state.object_cache.spill_sweep().await.unwrap_or_default();

                        // Still recovering: entries skipped only for being young
                        // are the freshest stranded writes there are, so come
                        // back the moment they have aged rather than at the
                        // sweep cadence. Once a pass finds none, this instance
                        // has recovered what a previous run left and can switch
                        // to the polite steady-state age.
                        if min_age == STARTUP_MIN_AGE && young > 0 {
                            delay = STARTUP_MIN_AGE;
                            continue;
                        }
                        min_age = DIRTY_MIN_AGE;
                        if stats.evicted_entries > 0 {
                            slog!(
                                "[spiceio] disk spill: evicted {} entries ({:.1} GiB); \
                                 {} entries / {:.1} GiB resident of {:.1} GiB budget",
                                stats.evicted_entries,
                                stats.evicted_bytes as f64 / 1_073_741_824.0,
                                stats.entries,
                                stats.bytes as f64 / 1_073_741_824.0,
                                stats.effective_budget as f64 / 1_073_741_824.0,
                            );
                        }
                        delay = sweep_interval(&stats);
                    }
                });
            }

            // Publish readiness. The setup action greps for "ready, listening"
            // (not merely "accepting connections") before pointing sccache at us.
            // OnceLock::set is one-shot; ignore a racing second set.
            let _ = ready.set(state);
            slog!("[spiceio] ready, listening on http://{bind_addr_log}");
            slog!("[spiceio] bucket: {bucket_name} region: {region}");
            log::flush(Duration::from_millis(200));
        });
    }

    // Every signal whose default disposition would terminate the process
    // triggers the same graceful shutdown.
    //
    // Which signals, and why all of them: write-back means this process can be
    // holding writes it has already answered 200 for. Any *uncaught* terminating
    // signal drops the ones that have not reached the spill journal yet. SIGTERM
    // is the obvious one (plain `kill`, `launchctl bootout`, a container stop),
    // but it is not the only way an operator ends a process:
    //
    // * **SIGHUP** — `kill -HUP`, and what the kernel sends when a controlling
    //   terminal goes away. Uncaught, it kills instantly; anyone running spiceio
    //   from a shell that then closes would silently lose acknowledged writes.
    // * **SIGQUIT** — `kill -QUIT`. Normally "terminate and dump core", but
    //   `crash::install` does not report on SIGQUIT, so catching it costs no
    //   diagnostic we would otherwise produce and buys the drain.
    // * **SIGINT** — Ctrl-C.
    //
    // SIGKILL cannot be caught, by design; that case is covered instead by the
    // dirty spill journal, which the next start (or a peer instance) replays.
    //
    // The listener is a long-lived task rather than a future the server
    // consumes, because shutdown does not end when the HTTP server returns:
    // acknowledged writes are drained after it, which can take tens of seconds
    // against a slow NAS. An operator who signals again during that means
    // "stop now", and a future that had already been consumed by the first
    // signal could not hear them — the process would appear wedged, and the
    // only way out would be SIGKILL, which is precisely the outcome the drain
    // exists to avoid. A second signal of *any* of these kinds counts.
    //
    // `notify_one` rather than `notify_waiters`: it leaves a permit when
    // nobody is listening yet, so a signal arriving in the gap before the
    // server first polls `shutdown` still stops the process.
    let stop = Arc::new(tokio::sync::Notify::new());
    let stop_again = Arc::new(tokio::sync::Notify::new());
    {
        let stop = Arc::clone(&stop);
        let stop_again = Arc::clone(&stop_again);
        tokio::spawn(async move {
            use signal::unix::SignalKind;
            // A registration that fails must not take the others down with it,
            // so each is independently optional and a missing one simply never
            // fires (see `next_signal`). Logged rather than silent: losing a
            // stop signal turns a graceful shutdown into a SIGKILL later.
            let mut sigint = register_signal(SignalKind::interrupt(), "SIGINT");
            let mut sigterm = register_signal(SignalKind::terminate(), "SIGTERM");
            let mut sighup = register_signal(SignalKind::hangup(), "SIGHUP");
            let mut sigquit = register_signal(SignalKind::quit(), "SIGQUIT");
            let mut count = 0u32;
            loop {
                let name = tokio::select! {
                    () = next_signal(&mut sigint) => "SIGINT",
                    () = next_signal(&mut sigterm) => "SIGTERM",
                    () = next_signal(&mut sighup) => "SIGHUP",
                    () = next_signal(&mut sigquit) => "SIGQUIT",
                };
                count += 1;
                if count == 1 {
                    slog!("[spiceio] shutting down ({name})");
                    stop.notify_one();
                } else {
                    slog!("[spiceio] {name} again — stopping without finishing the drain");
                    stop_again.notify_one();
                }
            }
        });
    }
    let shutdown = {
        let stop = Arc::clone(&stop);
        async move { stop.notified().await }
    };

    // Serve until a stop signal arrives, then drain in-flight requests.
    // Requests that arrive before SMB is ready get 503 SlowDown + Retry-After
    // rather than a TCP refuse — sccache treats temporary storage errors as
    // retryable, but a connection refusal fails server startup hard.
    // Kept out of the handler closure, which takes ownership of `ready`, so the
    // shutdown summary below can still read the cache counters.
    let ready_for_stats = Arc::clone(&ready);

    http::serve(
        listener,
        http::ServeConfig::default(),
        shutdown,
        move |req: Request<Incoming>| {
            let ready = Arc::clone(&ready);
            async move {
                // `begin` returns None (and costs one atomic load) unless the
                // access log is on; `finish` then hands the body straight back.
                let observed = access_log::begin(&req);
                let response = match ready.get() {
                    Some(state) => s3::router::handle_request(req, state).await,
                    None => s3::router::service_unavailable(
                        "spiceio is still connecting to the SMB backend; please retry.",
                    ),
                };
                let (parts, body) = response.into_parts();
                let body = access_log::finish(observed, parts.status, body);
                Response::from_parts(parts, body)
            }
        },
    )
    .await;

    // Drain acknowledged writes before exiting. The client already has its 200
    // for each of these, so this is the last chance to honour it in-process;
    // whatever is left is a dirty spill entry the next start replays.
    if let Some(state) = ready_for_stats.get()
        && state.writeback.enabled()
    {
        let deadline = Instant::now() + WRITE_BACK_DRAIN;
        let (pending_bytes, pending) = state.writeback.depth().await;
        if pending > 0 {
            slog!(
                "[spiceio] flushing {pending} acknowledged write(s) ({:.1} MiB) to the NAS…",
                pending_bytes as f64 / 1_048_576.0,
            );
        }
        // Interruptible: a second stop signal abandons the drain rather than
        // making the operator wait out the cap (or reach for SIGKILL).
        //
        // `forced` is latched rather than re-awaited below, because the signal
        // delivers a single permit: a second `notified()` would find none and
        // wait, so the operator who asked to stop now would still sit through
        // the next phase.
        let mut forced = false;
        let residue = tokio::select! {
            left = state.writeback.drain(WRITE_BACK_DRAIN) => left,
            _ = stop_again.notified() => {
                forced = true;
                state.writeback.depth().await.1
            }
        };
        if residue > 0 {
            // Make the claim true before making it: most of these have not been
            // journalled yet, because that is the flusher's first step and no
            // flusher reached them.
            let saved = state.writeback.journal_residue(&state.object_cache).await;
            serr!(
                "[spiceio] {residue} write(s) did not reach the NAS before shutdown; \
                 {saved} are held in the disk spill and replayed on the next start"
            );
            if saved < residue {
                serr!(
                    "[spiceio] {} write(s) were acknowledged but are lost — no disk spill \
                     to hold them (set SPICEIO_SPILL_DIR, or SPICEIO_WRITE_BACK=0)",
                    residue - saved
                );
            }
        }

        // The queue is not the whole picture. A body reaches the spill as the
        // first step of its flush, so an entry can be dirty on disk while no
        // longer pending — a backend write that failed after journalling, or a
        // promote that did not land. Nothing retries those until some later
        // process sweeps, so finish them here.
        //
        // Strictly the ones *this* instance wrote: a peer's dirty entry belongs
        // to a process that is still running and will promote it itself.
        let (flushed, stuck) = if forced {
            (0, state.object_cache.spill_owned_dirty().len())
        } else {
            tokio::select! {
                r = state
                    .writeback
                    .drain_owned_spill(&state.share, &state.object_cache, deadline) => r,
                _ = stop_again.notified() => (0, state.object_cache.spill_owned_dirty().len()),
            }
        };
        if flushed > 0 {
            slog!("[spiceio] flushed {flushed} journalled write(s) left on disk");
        }
        if stuck > 0 {
            serr!(
                "[spiceio] {stuck} journalled write(s) remain on disk; \
                 they are replayed on the next start"
            );
        }
    }

    // The body cache is the only mechanism that serves a GET without touching
    // the NAS, so its hit rate is the single most useful number for explaining
    // a deployment's throughput. A cache whose working set does not fit looks
    // exactly like one that is working, from the outside.
    if let Some(state) = ready_for_stats.get() {
        let (hits, misses, hit_bytes) = state.object_cache.stats();
        let total = hits + misses;
        if total > 0 {
            slog!(
                "[spiceio] object cache: {hits} hit / {misses} miss ({:.1}% hit rate), \
                 {:.1} MiB served from memory",
                100.0 * hits as f64 / total as f64,
                hit_bytes as f64 / 1_048_576.0,
            );
        }
        if let Some(spill) = state.object_cache.spill() {
            let (hits, misses, hit_bytes, writes) = spill.stats();
            if hits + misses > 0 {
                slog!(
                    "[spiceio] disk spill: {hits} hit / {misses} miss ({:.1}% hit rate), \
                     {:.1} MiB served from disk, {writes} entries written",
                    100.0 * hits as f64 / (hits + misses) as f64,
                    hit_bytes as f64 / 1_048_576.0,
                );
            }
        }
        if state.writeback.enabled() {
            let (accepted, flushed, rejected, retries) = state.writeback.stats();
            // `accepted - flushed` is not loss: a key overwritten before its
            // flush starts is coalesced into one backend write, which is a win
            // worth reporting rather than an imbalance worth wondering about.
            // Anything genuinely unflushed was reported by the drain above.
            let (_, unflushed) = state.writeback.depth().await;
            let coalesced = accepted.saturating_sub(flushed + unflushed as u64);
            slog!(
                "[spiceio] write-back: {accepted} acknowledged, {flushed} written to the NAS, \
                 {coalesced} coalesced by a later write to the same key, \
                 {rejected} fell back to synchronous (queue full), {retries} flush retries"
            );
        }
    }

    // Push the final log lines (including the shutdown notice) to disk before
    // the process exits and takes the writer thread with it.
    access_log::flush(Duration::from_millis(500));
    log::flush(Duration::from_millis(500));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pool_stays_within_its_bounds_on_this_host() {
        // The bounds are the point: connections cost SMB sessions on the
        // server, and a machine's core count is only a proxy for how much
        // request concurrency it will offer.
        let n = default_pool_size();
        assert!((8..=32).contains(&n), "pool {n} outside 8..=32");
    }

    #[test]
    fn pool_size_is_two_per_core_between_a_floor_and_a_ceiling() {
        // Two per core, because a connection owns its stream for a whole round
        // trip and an `-j16` build keeps well over 16 requests outstanding.
        assert_eq!(pool_size_for(8), 16);
        assert_eq!(pool_size_for(16), 32);
        // Floor: one connection per core on a 2-core box would put a whole
        // build behind two streams.
        assert_eq!(pool_size_for(1), 8);
        assert_eq!(pool_size_for(2), 8);
        // Ceiling: past this the pool buys no measured latency and costs the
        // server sessions.
        assert_eq!(pool_size_for(64), 32);
        // A pathological core count must clamp, not wrap.
        assert_eq!(pool_size_for(usize::MAX), 32);
    }
}
