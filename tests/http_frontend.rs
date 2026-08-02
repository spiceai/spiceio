//! Integration tests for `spiceio::http::serve` — the real accept loop, over
//! real TCP sockets, without needing an SMB server.
//!
//! These cover the behaviors the proxy depends on and that are otherwise only
//! observable in production:
//!
//! 1. serving a request at all — `header_read_timeout` panics at serve time if
//!    its timer is missing, and with `panic = "abort"` that kills the process
//!    on the first connection;
//! 2. the timeout actually firing, so idle and half-dead sockets are reclaimed;
//! 3. graceful shutdown draining an in-flight request instead of cutting it,
//!    and the loop returning once it has.

use std::time::Duration;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, Response};
use spiceio::http::{ServeConfig, serve};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, oneshot};

/// Short enough to test in-band; the server itself uses minutes.
const TEST_HEADER_TIMEOUT: Duration = Duration::from_millis(300);
const READ_LIMIT: usize = 64 * 1024;

fn test_config() -> ServeConfig {
    ServeConfig {
        header_read_timeout: TEST_HEADER_TIMEOUT,
        ..ServeConfig::default()
    }
}

/// Read from the socket until it closes or `READ_LIMIT` bytes arrive.
async fn read_to_end(stream: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 1024];
    while out.len() < READ_LIMIT {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
    out
}

#[tokio::test]
async fn serves_a_request() {
    // Regression guard: `header_read_timeout` without a timer panics inside
    // hyper when the connection is served — which under `panic = "abort"`
    // would abort the proxy on its very first client.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop_tx, stop_rx) = oneshot::channel();

    let server = tokio::spawn(async move {
        serve(
            listener,
            test_config(),
            async {
                let _ = stop_rx.await;
            },
            |_req: Request<hyper::body::Incoming>| async {
                Response::new(Full::new(Bytes::from_static(b"hello")))
            },
        )
        .await;
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(b"GET /bucket/key HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let resp = tokio::time::timeout(Duration::from_secs(5), read_to_end(&mut client))
        .await
        .expect("server did not answer");
    let text = String::from_utf8_lossy(&resp);
    assert!(text.starts_with("HTTP/1.1 200 OK"), "got: {text}");
    assert!(text.ends_with("hello"), "got: {text}");

    let _ = stop_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("serve did not return after shutdown")
        .unwrap();
}

#[tokio::test]
async fn header_read_timeout_closes_a_silent_connection() {
    // A client that connects and never sends headers (slow loris, or a host
    // that vanished without a FIN) must not hold the connection forever.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop_tx, stop_rx) = oneshot::channel();

    let server = tokio::spawn(async move {
        serve(
            listener,
            test_config(),
            async {
                let _ = stop_rx.await;
            },
            |_req: Request<hyper::body::Incoming>| async {
                Response::new(Full::new(Bytes::from_static(b"hello")))
            },
        )
        .await;
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    // Send nothing at all, then wait for the server to hang up.
    let closed = tokio::time::timeout(TEST_HEADER_TIMEOUT * 10, read_to_end(&mut client))
        .await
        .expect("connection was not closed by the header-read timeout");
    assert!(
        closed.is_empty(),
        "expected a bare close, got: {}",
        String::from_utf8_lossy(&closed)
    );

    let _ = stop_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
}

#[tokio::test]
async fn graceful_shutdown_drains_an_in_flight_request() {
    // Shutdown must let a request that is already being served finish — for
    // the real proxy that is the difference between a completed PutObject and
    // a truncated transfer plus an abandoned WAL temp.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop_tx, stop_rx) = oneshot::channel();
    // The handler signals when it has begun, so shutdown is provably
    // mid-request rather than racing the request into the handler.
    let started = std::sync::Arc::new(Notify::new());
    let handler_started = std::sync::Arc::clone(&started);

    let server = tokio::spawn(async move {
        serve(
            listener,
            test_config(),
            async {
                let _ = stop_rx.await;
            },
            move |_req: Request<hyper::body::Incoming>| {
                let started = std::sync::Arc::clone(&handler_started);
                async move {
                    started.notify_one();
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    Response::new(Full::new(Bytes::from_static(b"drained")))
                }
            },
        )
        .await;
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    started.notified().await;
    let _ = stop_tx.send(());

    let resp = tokio::time::timeout(Duration::from_secs(5), read_to_end(&mut client))
        .await
        .expect("in-flight request was cut off by shutdown");
    let text = String::from_utf8_lossy(&resp);
    assert!(text.starts_with("HTTP/1.1 200 OK"), "got: {text}");
    assert!(text.ends_with("drained"), "got: {text}");

    // The loop must return once the drain completes, not hang.
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("serve did not return after draining")
        .unwrap();
}
