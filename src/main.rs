//! spiceio — S3-compatible API proxy to SMB 3.1.1 file shares (macOS 26).

mod crypto;
mod s3;
mod smb;

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

use s3::multipart::MultipartStore;
use s3::router::AppState;
use smb::client::SmbConfig;
use smb::ops::ShareSession;

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
        }
    }
}

#[tokio::main]
async fn main() {
    let config = Config::from_env();

    eprintln!(
        "[spiceio] connecting to smb://{}@{}:{}/{}",
        config.smb_username, config.smb_server, config.smb_port, config.smb_share
    );

    // Connect to SMB server
    let smb_config = SmbConfig {
        server: config.smb_server.clone(),
        port: config.smb_port,
        username: config.smb_username.clone(),
        password: config.smb_password.clone(),
        domain: config.smb_domain.clone(),
        workstation: "SPICEIO".into(),
    };

    let client = smb::SmbClient::connect(smb_config)
        .await
        .expect("failed to connect to SMB server");

    let share = Arc::new(
        ShareSession::connect(client, &config.smb_share)
            .await
            .expect("failed to connect to SMB share"),
    );

    let state = Arc::new(AppState {
        share,
        bucket: config.bucket_name.clone(),
        region: config.region.clone(),
        multipart: MultipartStore::new(),
    });

    let bind_addr = config.bind_addr;

    // Bind TCP listener
    let listener = TcpListener::bind(bind_addr)
        .await
        .expect("failed to bind TCP listener");

    eprintln!("[spiceio] listening on http://{bind_addr}");
    eprintln!(
        "[spiceio] bucket: {} region: {}",
        config.bucket_name, config.region
    );

    // Accept loop
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer_addr) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("[spiceio] accept error: {e}");
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
                            eprintln!("[spiceio] connection error from {peer_addr}: {e}");
                        }
                });
            }
            _ = signal::ctrl_c() => {
                eprintln!("\n[spiceio] shutting down");
                break;
            }
        }
    }
}
