//! Opt-in per-request access log — the server-side half of the performance
//! picture.
//!
//! A client-side benchmark can only report end-to-end latency, which lumps
//! together HTTP framing, spiceio's own work, and the SMB round trips it makes.
//! When the question is "why is sccache slow through this proxy", the useful
//! split is *how long spiceio held the request* versus everything else, broken
//! down by operation and object size. That is what this records.
//!
//! Enabled by `SPICEIO_ACCESS_LOG=<path>`. When unset the request path pays one
//! relaxed atomic load per request and the body wrapper is a straight
//! delegation, so it costs nothing in production.
//!
//! Output is one TSV line per request, written by a dedicated thread behind a
//! bounded channel (the same never-block-the-proxy discipline as [`crate::log`]).
//! Lines are dropped rather than queued when the channel fills, and the drop
//! count is reported at shutdown so a truncated log is never mistaken for a
//! quiet one.
//!
//! ```text
//! #t_ms  method  status  req_bytes  resp_bytes  head_us  total_us  path
//! 1754331…  GET  200  0  65536  1204  1839  /sccache/us-east-1/…
//! ```
//!
//! `head_us` is the time until the response head was ready — for GetObject that
//! is the SMB open plus first read. `total_us` additionally covers streaming the
//! body out. The gap between them is the streaming cost; for a HEAD or a 404
//! they are effectively equal.

use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::pin::Pin;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::task::{Context, Poll};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bytes::Buf;
use http::{Request, StatusCode};
use http_body::{Body, Frame};

/// Lines buffered before the writer thread starts dropping them. Sized for a
/// full sccache stampede (hundreds of in-flight requests, thousands per second)
/// so a normal run never drops.
const CHANNEL_CAP: usize = 65_536;

/// Bytes buffered before a `write` syscall.
const BUF_CAP: usize = 256 * 1024;

/// Checked on every request, so it must stay cheaper than a channel probe.
static ENABLED: AtomicBool = AtomicBool::new(false);
static TX: OnceLock<mpsc::SyncSender<Msg>> = OnceLock::new();
static DROPPED: AtomicU64 = AtomicU64::new(0);

enum Msg {
    Line(String),
    Flush(mpsc::SyncSender<()>),
}

/// Start the access log if `path` is set and non-empty. Returns whether it is
/// on. A path that cannot be opened is reported and treated as "off" — a
/// diagnostic side channel must never keep the proxy from starting.
pub fn init(path: Option<&str>) -> bool {
    let Some(path) = path.filter(|p| !p.is_empty()) else {
        return false;
    };

    let file = match OpenOptions::new().create(true).append(true).open(path) {
        Ok(f) => f,
        Err(e) => {
            serr!("[spiceio] could not open SPICEIO_ACCESS_LOG {path}: {e}; continuing without it");
            return false;
        }
    };

    let (tx, rx) = mpsc::sync_channel::<Msg>(CHANNEL_CAP);
    let spawned = std::thread::Builder::new()
        .name("spiceio-access".into())
        .spawn(move || writer_loop(rx, file))
        .is_ok();
    if !spawned {
        serr!("[spiceio] could not spawn access-log thread; continuing without it");
        return false;
    }

    if TX.set(tx).is_err() {
        return ENABLED.load(Ordering::Relaxed);
    }
    ENABLED.store(true, Ordering::Relaxed);
    send(Msg::Line(
        "#t_ms\tmethod\tstatus\treq_bytes\tresp_bytes\thead_us\ttotal_us\tpath".into(),
    ));
    true
}

/// Drain and flush the queue, then report any dropped lines. Call at shutdown —
/// without it the writer thread dies with the process holding buffered lines.
pub fn flush(timeout: std::time::Duration) {
    let Some(tx) = TX.get() else { return };
    let (ack_tx, ack_rx) = mpsc::sync_channel::<()>(1);
    if tx.try_send(Msg::Flush(ack_tx)).is_ok() {
        let _ = ack_rx.recv_timeout(timeout);
    }
    let dropped = DROPPED.load(Ordering::Relaxed);
    if dropped > 0 {
        serr!("[spiceio] access log dropped {dropped} line(s) — queue full under load");
    }
}

fn send(msg: Msg) {
    let Some(tx) = TX.get() else { return };
    if tx.try_send(msg).is_err() {
        DROPPED.fetch_add(1, Ordering::Relaxed);
    }
}

/// Batches writes: one `flush` per drained burst rather than per line, so a
/// request-per-line log does not turn into a syscall-per-request log.
fn writer_loop(rx: mpsc::Receiver<Msg>, file: std::fs::File) {
    let mut w = BufWriter::with_capacity(BUF_CAP, file);
    let mut acks: Vec<mpsc::SyncSender<()>> = Vec::new();
    let handle = |msg: Msg,
                  w: &mut BufWriter<std::fs::File>,
                  acks: &mut Vec<mpsc::SyncSender<()>>| match msg {
        Msg::Line(line) => {
            let _ = w.write_all(line.as_bytes());
            let _ = w.write_all(b"\n");
        }
        Msg::Flush(ack) => acks.push(ack),
    };
    while let Ok(msg) = rx.recv() {
        handle(msg, &mut w, &mut acks);
        while let Ok(msg) = rx.try_recv() {
            handle(msg, &mut w, &mut acks);
        }
        let _ = w.flush();
        for ack in acks.drain(..) {
            let _ = ack.send(());
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Snapshot of a request in flight, taken before the router consumes it.
pub struct Pending {
    start: Instant,
    t_ms: u64,
    method: Box<str>,
    path: Box<str>,
    req_bytes: u64,
}

/// Snapshot an incoming request, or `None` when the access log is off.
///
/// Takes the method, path and declared request length before `handle_request`
/// consumes the request — none of it is recoverable from the response.
pub fn begin<B>(req: &Request<B>) -> Option<Pending> {
    if !ENABLED.load(Ordering::Relaxed) {
        return None;
    }
    let req_bytes = req
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    Some(Pending {
        start: Instant::now(),
        t_ms: now_ms(),
        method: req.method().as_str().into(),
        path: req.uri().path().into(),
        req_bytes,
    })
}

/// Attach the pending snapshot to the response body so the record is written
/// when the body finishes (or is dropped), not when the head is produced.
///
/// Returns the body unchanged — wrapped in a no-op `Metered` — when the access
/// log is off.
pub fn finish<B>(pending: Option<Pending>, status: StatusCode, body: B) -> Metered<B> {
    let entry = pending.map(|p| {
        let head_us = p.start.elapsed().as_micros() as u64;
        Entry {
            start: p.start,
            t_ms: p.t_ms,
            method: p.method,
            path: p.path,
            status: status.as_u16(),
            req_bytes: p.req_bytes,
            resp_bytes: 0,
            head_us,
        }
    });
    Metered { inner: body, entry }
}

struct Entry {
    start: Instant,
    t_ms: u64,
    method: Box<str>,
    path: Box<str>,
    status: u16,
    req_bytes: u64,
    resp_bytes: u64,
    head_us: u64,
}

impl Entry {
    fn emit(self) {
        let total_us = self.start.elapsed().as_micros() as u64;
        send(Msg::Line(format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.t_ms,
            self.method,
            self.status,
            self.req_bytes,
            self.resp_bytes,
            self.head_us,
            total_us,
            self.path,
        )));
    }
}

/// Response body that counts the bytes it yields and writes one access-log line
/// when the response completes.
///
/// The line is emitted from `Drop` as well as from end-of-stream, so a transfer
/// the client abandons mid-body is still recorded (with the bytes it actually
/// received) instead of vanishing from the log.
pub struct Metered<B> {
    inner: B,
    entry: Option<Entry>,
}

impl<B> Drop for Metered<B> {
    fn drop(&mut self) {
        if let Some(entry) = self.entry.take() {
            entry.emit();
        }
    }
}

impl<B> Body for Metered<B>
where
    B: Body + Unpin,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_frame(cx);
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(entry) = this.entry.as_mut()
                    && let Some(data) = frame.data_ref()
                {
                    entry.resp_bytes += data.remaining() as u64;
                }
            }
            // End of stream, or an error that aborts it: either way the
            // response is over. Record now rather than waiting for the drop so
            // the timing excludes however long hyper holds the body afterwards.
            Poll::Ready(None) | Poll::Ready(Some(Err(_))) => {
                if let Some(entry) = this.entry.take() {
                    entry.emit();
                }
            }
            Poll::Pending => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

/// Whether the access log is recording. Exposed for callers that want to skip
/// building a snapshot they would immediately throw away.
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::BodyExt;

    #[test]
    fn disabled_wrapper_passes_body_through() {
        // With the log off, `begin` yields nothing and `finish` must not change
        // what the client sees.
        let req = Request::builder().uri("/b/k").body(()).unwrap();
        assert!(begin(&req).is_none());

        let body = http_body_util::Full::new(Bytes::from_static(b"hello"));
        let metered = finish(None, StatusCode::OK, body);
        let collected = block_on(metered.collect());
        assert_eq!(collected.unwrap().to_bytes(), Bytes::from_static(b"hello"));
    }

    #[test]
    fn counts_bytes_across_frames() {
        // Byte accounting is what turns the log into a throughput measurement,
        // so verify it sums frames rather than trusting the size hint.
        let entry = Entry {
            start: Instant::now(),
            t_ms: 0,
            method: "GET".into(),
            path: "/b/k".into(),
            status: 200,
            req_bytes: 0,
            resp_bytes: 0,
            head_us: 0,
        };
        let body = http_body_util::Full::new(Bytes::from_static(b"0123456789"));
        let mut metered = Metered {
            inner: body,
            entry: Some(entry),
        };
        let _ = block_on(std::future::poll_fn(|cx| {
            Pin::new(&mut metered).poll_frame(cx)
        }));
        assert_eq!(metered.entry.as_ref().map(|e| e.resp_bytes), Some(10));
    }

    /// Minimal block-on so the body tests need no async runtime. Both bodies
    /// under test are ready immediately, so a no-op waker is enough.
    fn block_on<F: Future>(fut: F) -> F::Output {
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut fut = Box::pin(fut);
        loop {
            if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
                return out;
            }
        }
    }
}
