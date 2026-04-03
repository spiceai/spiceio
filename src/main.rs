//! spiceio — S3-compatible API proxy to SMB 3.1.1 file shares (macOS 26).

use hyper::Request;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use std::convert::Infallible;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;

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
    /// Max I/O size for standalone read/write operations (default 1MB)
    smb_max_io: u32,
}

impl Config {
    fn from_env() -> Self {
        Self {
            bind_addr: env::var("SPICEIO_BIND")
                .unwrap_or_else(|_| "0.0.0.0:8333".into())
                .parse()
                .expect("SPICEIO_BIND must be a valid socket address"),
            smb_server: env::var("SPICEIO_SMB_SERVER").expect("SPICEIO_SMB_SERVER is required"),
            smb_port: env::var("SPICEIO_SMB_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(445),
            smb_username: env::var("SPICEIO_SMB_USER").expect("SPICEIO_SMB_USER is required"),
            smb_password: env::var("SPICEIO_SMB_PASS").expect("SPICEIO_SMB_PASS is required"),
            smb_domain: env::var("SPICEIO_SMB_DOMAIN").unwrap_or_default(),
            smb_share: env::var("SPICEIO_SMB_SHARE").expect("SPICEIO_SMB_SHARE is required"),
            bucket_name: env::var("SPICEIO_BUCKET").unwrap_or_else(|_| {
                env::var("SPICEIO_SMB_SHARE").unwrap_or_else(|_| "data".into())
            }),
            region: env::var("SPICEIO_REGION").unwrap_or_else(|_| "us-east-1".into()),
            smb_connections: env::var("SPICEIO_SMB_CONNECTIONS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8),
            smb_max_io: env::var("SPICEIO_SMB_MAX_IO")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
        }
    }
}

#[tokio::main]
async fn main() {
    if env::args().any(|a| a == "--version" || a == "-V") {
        println!("spiceio {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    log::init(env::var("SPICEIO_LOG_FILE").ok().as_deref());

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
                            std::process::exit(1);
                        }
                    };
                    addr.set_port(next);
                }
                Err(e) => {
                    serr!("failed to bind TCP listener: {e}");
                    std::process::exit(1);
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

    let pool = SmbPool::connect(smb_config, config.smb_connections)
        .await
        .expect("failed to connect to SMB server");

    let share = Arc::new(
        ShareSession::connect(pool, &config.smb_share)
            .await
            .expect("failed to connect to SMB share"),
    );

    // Clean up orphaned WAL temp files from prior crashes
    share.cleanup_wal().await;

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

    // Accept loop
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer_addr) = match accepted {
                    Ok(v) => {
                        slog!("[spiceio] client connected: {}", v.1);
                        v
                    }
                    Err(e) => {
                        serr!("[spiceio] accept error: {e}");
                        continue;
                    }
                };

                let state = Arc::clone(&state);

                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                        let state = Arc::clone(&state);
                        async move {
                            let resp = s3::router::handle_request(req, &state).await;
                            Ok::<_, Infallible>(resp)
                        }
                    });

                    if let Err(e) = ConnBuilder::new(hyper_util::rt::TokioExecutor::new())
                        .serve_connection(io, service)
                        .await
                        && !e.to_string().contains("connection reset") {
                            serr!("[spiceio] connection error from {peer_addr}: {e}");
                        }
                });
            }
            _ = signal::ctrl_c() => {
                slog!("\n[spiceio] shutting down");
                break;
            }
        }
    }
}
