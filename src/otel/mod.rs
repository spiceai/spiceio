//! OTLP metrics exporter — push performance metrics to a Spice Cloud app.
//!
//! Off unless `SPICEIO_OTEL_ENDPOINT` is set. When off the request path pays
//! one relaxed atomic load, matching the access log. When on, a background
//! task snapshots request histograms and runtime gauges and pushes them over
//! OTLP/gRPC (`MetricsService/Export`) — the ingest Spice Cloud apps expose
//! on their Flight port.
//!
//! Every data point is labeled with `machine` (the hostname) and
//! `service.instance.id` so two proxies, or two hosts, are distinguishable
//! in the same app.

mod export;
mod metrics;
mod proto;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

use crate::s3::router::AppState;

use export::{Client, Endpoint};
use metrics::{Registry, RuntimeGauges};
use proto::Resource;

static ENABLED: AtomicBool = AtomicBool::new(false);
static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
static STOP: OnceLock<Arc<Notify>> = OnceLock::new();

fn lock_registry() -> Option<MutexGuard<'static, Registry>> {
    REGISTRY.get()?.lock().ok()
}

/// Exporter configuration, parsed from the environment in `main`.
pub struct Config {
    /// Spice Cloud app (`spicehq/spiceio`, `https://spice.ai/spicehq/spiceio`)
    /// or a raw OTLP/gRPC URL.
    pub endpoint: String,
    pub api_key: Option<String>,
    /// Region used when `endpoint` is an org/app pair. Default `us-east-1`.
    pub region: String,
    pub interval: Duration,
    pub share: String,
    /// Optional override for the `machine` dimension. Default: kernel hostname.
    pub machine: Option<String>,
}

pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Record one completed request. No-op when the exporter is off.
pub fn record_request(
    method: &str,
    status: u16,
    req_bytes: u64,
    resp_bytes: u64,
    head_us: u64,
    total_us: u64,
) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let Some(mut g) = lock_registry() else { return };
    g.record(method, status, req_bytes, resp_bytes, head_us, total_us);
}

/// Start the exporter. Failures to parse the endpoint disable it; they must
/// not keep the proxy from serving. The push loop runs until [`shutdown`].
pub fn start(config: Config, ready: Arc<OnceLock<Arc<AppState>>>) -> Result<String, String> {
    let endpoint = Endpoint::parse(&config.endpoint, &config.region)?;
    let resource = Resource {
        service_name: "spiceio".into(),
        service_version: env!("CARGO_PKG_VERSION").into(),
        instance_id: crate::instance::id_or_generate().to_string(),
        machine: crate::instance::machine(config.machine),
        share: config.share,
    };
    let target = format!(
        "{}://{}:{}",
        if endpoint.tls { "https" } else { "http" },
        endpoint.host,
        endpoint.port
    );
    let desc = format!("{target} machine={}", resource.machine);
    let _ = REGISTRY.set(Mutex::new(Registry::new()));
    let stop = STOP.get_or_init(|| Arc::new(Notify::new()));
    let stop = Arc::clone(stop);
    ENABLED.store(true, Ordering::Relaxed);

    let api_key = config.api_key;
    let interval = config.interval.max(Duration::from_secs(1));
    tokio::spawn(async move {
        let mut client = Client::new(endpoint, api_key);
        let mut last_err_log: Option<Instant> = None;
        loop {
            tokio::select! {
                () = tokio::time::sleep(interval) => {}
                () = stop.notified() => {
                    let _ = push_once(&mut client, &resource, &ready).await;
                    break;
                }
            }
            if let Err(e) = push_once(&mut client, &resource, &ready).await
                && last_err_log.is_none_or(|t| t.elapsed() >= Duration::from_secs(60))
            {
                crate::serr!("[spiceio] OTEL export to {target} failed: {e}");
                last_err_log = Some(Instant::now());
            }
        }
    });

    Ok(desc)
}

/// One last push, then stop the loop. Bounded so a wedged Cloud app cannot
/// hold up shutdown.
pub async fn shutdown(timeout: Duration) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    ENABLED.store(false, Ordering::Relaxed);
    if let Some(stop) = STOP.get() {
        stop.notify_waiters();
        // Give the task a moment to flush; we do not join it, because a
        // hung export is exactly what `timeout` exists to bound and the
        // process is exiting anyway.
        tokio::time::sleep(timeout.min(Duration::from_secs(2))).await;
    }
}

async fn push_once(
    client: &mut Client,
    resource: &Resource,
    ready: &OnceLock<Arc<AppState>>,
) -> Result<(), String> {
    let gauges = match ready.get() {
        Some(state) => runtime_gauges(state).await,
        None => RuntimeGauges::default(),
    };
    let snap = {
        let Some(mut g) = lock_registry() else {
            return Ok(());
        };
        g.snapshot(gauges)
    };
    match client.export(resource, &snap).await {
        Ok(()) => Ok(()),
        Err(e) => {
            if let Some(mut g) = lock_registry() {
                g.restore(snap);
            }
            Err(e)
        }
    }
}

async fn runtime_gauges(state: &AppState) -> RuntimeGauges {
    let (cache_hits, cache_misses, cache_hit_bytes) = state.object_cache.stats();
    let (spill_hits, spill_misses, spill_hit_bytes) = match state.object_cache.spill() {
        Some(s) => {
            let (h, m, b, _) = s.stats();
            (Some(h), Some(m), Some(b))
        }
        None => (None, None, None),
    };
    let (writeback_pending, writeback_pending_bytes, writeback_accepted, writeback_flushed) =
        if state.writeback.enabled() {
            let (bytes, n) = state.writeback.depth().await;
            let (accepted, flushed, _, _) = state.writeback.stats();
            (Some(n as u64), Some(bytes), Some(accepted), Some(flushed))
        } else {
            (None, None, None, None)
        };
    RuntimeGauges {
        cache_hits,
        cache_misses,
        cache_hit_bytes,
        cache_bytes: state.object_cache.total_bytes(),
        cache_entries: state.object_cache.len() as u64,
        spill_hits,
        spill_misses,
        spill_hit_bytes,
        writeback_pending,
        writeback_pending_bytes,
        writeback_accepted,
        writeback_flushed,
        smb_inflight: state.client_inflight.load(Ordering::Relaxed) as u64,
        uptime: Duration::ZERO,
    }
}

#[cfg(test)]
mod tests {
    use super::proto;
    use super::*;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use std::convert::Infallible;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn pushes_otlp_grpc_to_an_h2c_collector() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let rec = Arc::clone(&received);
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let rec = Arc::clone(&rec);
            let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                let rec = Arc::clone(&rec);
                async move {
                    assert_eq!(req.uri().path(), proto::GRPC_PATH);
                    let body = req.into_body().collect().await.unwrap().to_bytes();
                    *rec.lock().unwrap() = body.to_vec();
                    let mut res = Response::new(Full::new(Bytes::from(proto::grpc_frame(&[]))));
                    res.headers_mut()
                        .insert("grpc-status", http::HeaderValue::from_static("0"));
                    res.headers_mut().insert(
                        "content-type",
                        http::HeaderValue::from_static("application/grpc"),
                    );
                    Ok::<_, Infallible>(res)
                }
            });
            let _ = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                .await;
        });

        let mut registry = Registry::new();
        registry.record("GET", 200, 0, 64, 120, 180);
        let snap = registry.snapshot(RuntimeGauges {
            cache_hits: 3,
            ..RuntimeGauges::default()
        });
        let resource = Resource {
            service_name: "spiceio".into(),
            service_version: "test".into(),
            instance_id: "inst-test".into(),
            machine: "test-host".into(),
            share: "files".into(),
        };
        let mut client = Client::new(
            Endpoint {
                tls: false,
                host: addr.ip().to_string(),
                port: addr.port(),
            },
            None,
        );
        client.export(&resource, &snap).await.expect("export");

        let frame = received.lock().unwrap().clone();
        let msg = proto::unframe(&frame).expect("grpc frame");
        let text = String::from_utf8_lossy(msg);
        assert!(text.contains("spiceio_http_requests"), "{text:?}");
        assert!(text.contains("test-host"), "machine dimension missing");
        assert!(text.contains("inst-test"), "instance id missing");
        assert!(text.contains("spiceio_cache_hits"), "{text:?}");
    }

    /// Talks to the real Spice Cloud Flight endpoint for `spicehq/spiceio`.
    /// Ignored in CI: depends on the public Cloud Flight listener. A
    /// `grpc-status` from the server (including unauthenticated) means the
    /// OTLP/gRPC client works; TLS/HTTP2 failures fail the test. Set
    /// `SPICEIO_OTEL_API_KEY` to exercise ingest.
    #[tokio::test]
    #[ignore = "live Spice Cloud; run with --ignored"]
    async fn live_push_spicehq_spiceio() {
        let region = std::env::var("SPICEIO_OTEL_REGION")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "us-west-2".into());
        let endpoint = Endpoint::parse("spicehq/spiceio", &region).unwrap();
        let api_key = std::env::var("SPICEIO_OTEL_API_KEY")
            .ok()
            .filter(|s| !s.is_empty());
        let mut registry = Registry::new();
        registry.record("GET", 200, 0, 8, 50, 80);
        let snap = registry.snapshot(RuntimeGauges::default());
        let resource = Resource {
            service_name: "spiceio".into(),
            service_version: env!("CARGO_PKG_VERSION").into(),
            instance_id: "live-test".into(),
            machine: crate::instance::machine(None),
            share: "live-test".into(),
        };
        let mut client = Client::new(endpoint, api_key.clone());
        match client.export(&resource, &snap).await {
            Ok(()) => {}
            // The API key is valid; Cloud still refuses writes while the
            // runtime is starting or updating. That is app lifecycle, not a
            // client bug.
            Err(e)
                if api_key.is_some()
                    && (e.contains("not ready")
                        || e.contains("not%20ready")
                        || e.contains("grpc-status 14")) => {}
            Err(e) if api_key.is_some() => {
                panic!("Spice Cloud rejected an authenticated export: {e}");
            }
            Err(e) => {
                // Unauthenticated is the Cloud app answering; a TLS/HTTP2
                // failure is a client bug. "reconnect" in the retry path is
                // not a connect() failure.
                assert!(
                    e.contains("grpc-status"),
                    "OTLP/gRPC transport to Spice Cloud failed: {e}"
                );
            }
        }
    }
}
