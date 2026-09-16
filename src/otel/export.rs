//! OTLP/gRPC push client for a Spice Cloud app (or any OTEL MetricsService).
//!
//! Spice Cloud apps ingest on the same gRPC server as Flight, authenticated
//! with `x-api-key`. This client speaks HTTP/2 directly (h2c or TLS+ALPN h2)
//! so the proxy does not take on tonic/prost.

use std::time::Duration;

use bytes::Bytes;
use http::Request;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpStream;

use super::metrics::Snapshot;
use super::proto::{self, GRPC_PATH, Resource};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const EXPORT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub tls: bool,
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    /// Parse an exporter target.
    ///
    /// Accepted forms:
    /// - Spice Cloud app: `spicehq/spiceio` or `https://spice.ai/spicehq/spiceio`
    ///   → regional Flight host (`https://{region}-prod-aws-flight.spiceai.io`)
    /// - gRPC URL: `https://host`, `http://host:50051`, `grpc+tls://host:443`
    /// - bare `host:port` (insecure, local Spice)
    pub fn parse(raw: &str, region: &str) -> Result<Self, String> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err("empty endpoint".into());
        }
        if is_cloud_app(raw) {
            let region = if region.is_empty() {
                "us-east-1"
            } else {
                region
            };
            return Ok(Self {
                tls: true,
                host: format!("{region}-prod-aws-flight.spiceai.io"),
                port: 443,
            });
        }
        let (tls, rest) = if let Some(r) = raw.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = raw.strip_prefix("grpc+tls://") {
            (true, r)
        } else if let Some(r) = raw.strip_prefix("http://") {
            (false, r)
        } else if let Some(r) = raw.strip_prefix("grpc://") {
            (false, r)
        } else {
            (false, raw)
        };
        let rest = rest.split('/').next().unwrap_or(rest);
        let (host, port) = split_host_port(rest, if tls { 443 } else { 50051 })?;
        if host.is_empty() {
            return Err("endpoint has no host".into());
        }
        Ok(Self { tls, host, port })
    }

    fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// `org/app` or `https://spice.ai/org/app`. The names themselves are not
/// forwarded: Cloud ingest is the regional Flight host, not an app path.
fn is_cloud_app(raw: &str) -> bool {
    let path = raw
        .strip_prefix("https://spice.ai/")
        .or_else(|| raw.strip_prefix("http://spice.ai/"))
        .unwrap_or(raw)
        .trim_matches('/');
    if path.contains("://") || path.contains(':') {
        return false;
    }
    let mut parts = path.split('/');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(org), Some(app), None) => is_name(org) && is_name(app),
        _ => false,
    }
}

fn is_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn split_host_port(rest: &str, default_port: u16) -> Result<(String, u16), String> {
    if let Some(rest) = rest.strip_prefix('[') {
        // [ipv6]:port
        let close = rest
            .find(']')
            .ok_or_else(|| "invalid IPv6 endpoint".to_string())?;
        let host = rest[..close].to_string();
        let after = &rest[close + 1..];
        let port = if let Some(p) = after.strip_prefix(':') {
            p.parse::<u16>().map_err(|_| format!("invalid port {p}"))?
        } else if after.is_empty() {
            default_port
        } else {
            return Err("invalid IPv6 endpoint".into());
        };
        return Ok((host, port));
    }
    if let Some((host, port)) = rest.rsplit_once(':')
        && !host.is_empty()
        && port.chars().all(|c| c.is_ascii_digit())
    {
        let port = port
            .parse::<u16>()
            .map_err(|_| format!("invalid port {port}"))?;
        return Ok((host.to_string(), port));
    }
    Ok((rest.to_string(), default_port))
}

pub struct Client {
    endpoint: Endpoint,
    api_key: Option<String>,
    sender: Option<http2::SendRequest<Full<Bytes>>>,
}

impl Client {
    pub fn new(endpoint: Endpoint, api_key: Option<String>) -> Self {
        Self {
            endpoint,
            api_key,
            sender: None,
        }
    }

    pub async fn export(&mut self, resource: &Resource, snap: &Snapshot) -> Result<(), String> {
        let msg = proto::encode(resource, snap);
        let frame = proto::grpc_frame(&msg);
        match tokio::time::timeout(EXPORT_TIMEOUT, self.send(Bytes::from(frame))).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(_) => {
                self.sender = None;
                Err("export timed out".into())
            }
        }
    }

    async fn send(&mut self, body: Bytes) -> Result<(), String> {
        if self.sender.is_none() {
            self.connect().await?;
        }
        match self.send_ready(body.clone()).await {
            Ok(()) => Ok(()),
            Err(e) => {
                self.sender = None;
                self.connect().await?;
                self.send_ready(body)
                    .await
                    .map_err(|retry| format!("{e}; reconnect: {retry}"))
            }
        }
    }

    async fn send_ready(&mut self, body: Bytes) -> Result<(), String> {
        let sender = self
            .sender
            .as_mut()
            .ok_or_else(|| "not connected".to_string())?;
        sender
            .ready()
            .await
            .map_err(|e| format!("http2 not ready: {e}"))?;
        let mut req = Request::builder()
            .method("POST")
            .uri(GRPC_PATH)
            .header("host", self.endpoint.authority())
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .header(
                "user-agent",
                format!("spiceio/{}", env!("CARGO_PKG_VERSION")),
            )
            .header("grpc-timeout", "15000m"); // gRPC "Nm" = N milliseconds
        if let Some(key) = &self.api_key {
            req = req.header("x-api-key", key.as_str());
        }
        let req = req
            .body(Full::new(body))
            .map_err(|e| format!("build request: {e}"))?;
        let res = sender
            .send_request(req)
            .await
            .map_err(|e| format!("send: {e}"))?;
        read_grpc_status(res).await
    }

    async fn connect(&mut self) -> Result<(), String> {
        let addr = (self.endpoint.host.as_str(), self.endpoint.port);
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| {
                format!(
                    "connect {}:{} timed out",
                    self.endpoint.host, self.endpoint.port
                )
            })?
            .map_err(|e| format!("connect {}:{}: {e}", self.endpoint.host, self.endpoint.port))?;
        let _ = tcp.set_nodelay(true);
        if self.endpoint.tls {
            let connector = native_tls::TlsConnector::builder()
                .request_alpns(&["h2"])
                .build()
                .map_err(|e| format!("tls connector: {e}"))?;
            let connector = tokio_native_tls::TlsConnector::from(connector);
            let tls =
                tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(&self.endpoint.host, tcp))
                    .await
                    .map_err(|_| "tls handshake timed out".to_string())?
                    .map_err(|e| format!("tls handshake: {e}"))?;
            self.handshake(tls).await
        } else {
            self.handshake(tcp).await
        }
    }

    async fn handshake<T>(&mut self, io: T) -> Result<(), String>
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (sender, conn) = http2::Builder::new(TokioExecutor::new())
            .handshake::<_, Full<Bytes>>(TokioIo::new(io))
            .await
            .map_err(|e| format!("http2 handshake: {e}"))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        self.sender = Some(sender);
        Ok(())
    }
}

fn grpc_field<'a>(
    trailers: Option<&'a http::HeaderMap>,
    headers: &'a http::HeaderMap,
    name: &'static str,
) -> Option<&'a str> {
    trailers
        .and_then(|t| t.get(name))
        .or_else(|| headers.get(name))
        .and_then(|v| v.to_str().ok())
}

async fn read_grpc_status(res: http::Response<Incoming>) -> Result<(), String> {
    let status = res.status();
    let (parts, body) = res.into_parts();
    let collected = body
        .collect()
        .await
        .map_err(|e| format!("read response: {e}"))?;
    let trailers = collected.trailers();
    interpret_grpc_status(
        status,
        grpc_field(trailers, &parts.headers, "grpc-status"),
        grpc_field(trailers, &parts.headers, "grpc-message").unwrap_or(""),
    )
}

/// HTTP 200 from a proxy is not a gRPC OK. Only an explicit `grpc-status: 0`
/// (headers or trailers) counts as a successful export; anything else restores
/// the interval for retry.
fn interpret_grpc_status(
    http_status: http::StatusCode,
    grpc_status: Option<&str>,
    grpc_message: &str,
) -> Result<(), String> {
    match grpc_status {
        Some("0") => Ok(()),
        Some(code) => Err(format!("grpc-status {code}: {grpc_message}")),
        None => Err(format!("HTTP {http_status} (no grpc-status)")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloud_app_path_resolves_to_regional_flight() {
        let e = Endpoint::parse("spicehq/spiceio", "us-east-1").unwrap();
        assert!(e.tls);
        assert_eq!(e.host, "us-east-1-prod-aws-flight.spiceai.io");
        assert_eq!(e.port, 443);
        let e = Endpoint::parse("https://spice.ai/spicehq/spiceio", "eu-central-1").unwrap();
        assert_eq!(e.host, "eu-central-1-prod-aws-flight.spiceai.io");
        let e = Endpoint::parse("http://spice.ai/spicehq/spiceio", "us-west-2").unwrap();
        assert_eq!(e.host, "us-west-2-prod-aws-flight.spiceai.io");
        let e = Endpoint::parse("spicehq/spiceio", "").unwrap();
        assert_eq!(e.host, "us-east-1-prod-aws-flight.spiceai.io");
    }

    #[test]
    fn grpc_urls() {
        let e = Endpoint::parse("http://127.0.0.1:50051", "").unwrap();
        assert!(!e.tls);
        assert_eq!(e.host, "127.0.0.1");
        assert_eq!(e.port, 50051);
        let e = Endpoint::parse("https://flight.example.com", "").unwrap();
        assert!(e.tls);
        assert_eq!(e.port, 443);
        let e = Endpoint::parse("grpc+tls://flight.example.com", "").unwrap();
        assert!(e.tls);
        assert_eq!(e.port, 443);
        let e = Endpoint::parse("grpc://127.0.0.1:4317", "").unwrap();
        assert!(!e.tls);
        assert_eq!(e.host, "127.0.0.1");
        assert_eq!(e.port, 4317);
        let e = Endpoint::parse("localhost:4317", "").unwrap();
        assert!(!e.tls);
        assert_eq!(e.port, 4317);
        // A raw gRPC URL is not an org/app pair, even with a path.
        let e = Endpoint::parse("https://flight.example.com:443/v1", "").unwrap();
        assert_eq!(e.host, "flight.example.com");
        assert_eq!(e.port, 443);
    }

    #[test]
    fn rejects_empty() {
        assert!(Endpoint::parse("", "").is_err());
        assert!(Endpoint::parse("   ", "").is_err());
    }

    #[test]
    fn ipv6_authority_stays_bracketed() {
        let e = Endpoint::parse("http://[::1]:4317", "").unwrap();
        assert_eq!(e.host, "::1");
        assert_eq!(e.port, 4317);
        assert_eq!(e.authority(), "[::1]:4317");
        let e = Endpoint::parse("[2001:db8::1]:443", "").unwrap();
        assert_eq!(e.host, "2001:db8::1");
        assert_eq!(e.authority(), "[2001:db8::1]:443");
        let e = Endpoint::parse("https://[::1]", "").unwrap();
        assert_eq!(e.port, 443);
        assert_eq!(e.authority(), "[::1]:443");
        let e = Endpoint::parse("http://127.0.0.1:50051", "").unwrap();
        assert_eq!(e.authority(), "127.0.0.1:50051");
    }

    #[test]
    fn missing_grpc_status_is_an_error_even_on_http_200() {
        assert_eq!(
            interpret_grpc_status(http::StatusCode::OK, None, "").unwrap_err(),
            "HTTP 200 OK (no grpc-status)"
        );
        assert!(interpret_grpc_status(http::StatusCode::OK, Some("0"), "").is_ok());
        assert_eq!(
            interpret_grpc_status(http::StatusCode::OK, Some("13"), "rejected").unwrap_err(),
            "grpc-status 13: rejected"
        );
        assert!(
            interpret_grpc_status(http::StatusCode::BAD_GATEWAY, None, "")
                .unwrap_err()
                .contains("no grpc-status")
        );
    }
}
