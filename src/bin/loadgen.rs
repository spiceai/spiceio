//! `spiceio-loadgen` — sccache-shaped HTTP load generator.
//!
//! Built only with `--features loadgen`, so it never lands in a release build.
//!
//! # Why not curl
//!
//! The bench this replaces fanned out one `curl` per request. That measures the
//! wrong thing twice over: every request paid a fresh TCP handshake, and the
//! fork/exec cost of a process per request capped offered load well below what
//! the proxy can serve. sccache does neither — it drives a small pool of
//! **persistent, keep-alive** connections and reuses them for thousands of
//! requests. A bench that does not reuse connections cannot see the costs
//! sccache actually pays, and cannot push spiceio hard enough to find its knee.
//!
//! So this speaks HTTP/1.1 directly over `tokio::net::TcpStream`: no new
//! dependencies (the same discipline the SMB client follows), persistent
//! connections, and full control of the timestamps — which is what makes
//! per-phase latency percentiles trustworthy.
//!
//! # What it measures
//!
//! Per operation class (`GET-hit`, `GET-miss`, `PUT`, `HEAD-hit`, `HEAD-miss`,
//! `DELETE`), and per size class within a phase:
//!
//! * throughput — ops/s and MiB/s over the phase wall clock
//! * latency — mean/p50/p90/p99/p99.9/max, from request write to last body byte
//! * time to first byte — the same percentiles, isolating the response-head
//!   path (SMB open + first read) from the streaming path
//! * outcomes — status-code histogram, connection errors, timeouts
//!
//! Results print as a table and, with `--json <path>`, as one JSON document per
//! run so a baseline can be diffed against a later change.
//!
//! # Usage
//!
//! ```text
//! spiceio-loadgen --endpoint http://127.0.0.1:18390 --bucket sccache \
//!     --prefix bench-1 --concurrency 64 --objects 512 --phase put,get,head-miss,mixed
//! ```

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

// ── Configuration ───────────────────────────────────────────────────────────

/// One size class in the synthetic working set.
#[derive(Clone, Copy, Debug)]
struct SizeClass {
    bytes: usize,
    /// Relative share of objects in this class.
    weight: u32,
}

/// Object-size mix approximating a real sccache cache.
///
/// Measured shape: the vast majority of cached rustc outputs are tens to a few
/// hundred KiB, with a long tail of multi-MiB objects from large crates. The
/// tail matters disproportionately because it is where streaming (rather than
/// per-request overhead) dominates, so it is represented even though it is rare.
const SIZE_MIX: &[SizeClass] = &[
    SizeClass {
        bytes: 4 * 1024,
        weight: 12,
    },
    SizeClass {
        bytes: 16 * 1024,
        weight: 20,
    },
    SizeClass {
        bytes: 64 * 1024,
        weight: 26,
    },
    SizeClass {
        bytes: 256 * 1024,
        weight: 22,
    },
    SizeClass {
        bytes: 1024 * 1024,
        weight: 14,
    },
    SizeClass {
        bytes: 4 * 1024 * 1024,
        weight: 5,
    },
    SizeClass {
        bytes: 16 * 1024 * 1024,
        weight: 1,
    },
];

struct Config {
    endpoint: String,
    host_header: String,
    addr: String,
    bucket: String,
    prefix: String,
    concurrency: usize,
    /// Size of the key space — how many distinct objects the phase touches.
    objects: usize,
    /// Requests issued per phase. Kept separate from `objects` so a concurrency
    /// sweep can hold the working set fixed while giving every worker enough
    /// requests to reach steady state; a phase of `concurrency` requests would
    /// measure ramp-up, not throughput.
    ops: usize,
    phases: Vec<String>,
    json_path: Option<String>,
    timeout: Duration,
    label: String,
    /// Repeat each read phase this many times; the reported figures come from
    /// the last repetition, so a cold first pass does not colour the result.
    warmup: usize,
}

fn usage() -> ! {
    eprintln!(
        "spiceio-loadgen — sccache-shaped HTTP load generator

  --endpoint URL     spiceio base URL (default http://127.0.0.1:18390)
  --bucket NAME      bucket (default sccache-bench)
  --prefix NAME      key prefix for this run (default loadgen)
  --concurrency N    in-flight requests, one persistent connection each (default 64)
  --objects N        distinct keys in the working set (default 512)
  --ops N            requests per phase (default: max(objects, concurrency*20))
  --phase LIST       comma-separated: put,get,head-hit,head-miss,get-miss,mixed,delete
                     (default put,get,head-hit,head-miss,mixed)
  --warmup N         repetitions of each read phase; last one is reported (default 1)
  --timeout SECS     per-request timeout (default 60)
  --label TEXT       free-form label recorded in the JSON output
  --json PATH        write machine-readable results here
"
    );
    std::process::exit(2)
}

fn parse_args() -> Config {
    let mut cfg = Config {
        endpoint: "http://127.0.0.1:18390".into(),
        host_header: String::new(),
        addr: String::new(),
        bucket: "sccache-bench".into(),
        prefix: "loadgen".into(),
        concurrency: 64,
        objects: 512,
        ops: 0,
        phases: vec![
            "put".into(),
            "get".into(),
            "head-hit".into(),
            "head-miss".into(),
            "mixed".into(),
        ],
        json_path: None,
        timeout: Duration::from_secs(60),
        label: String::new(),
        warmup: 1,
    };

    let args: Vec<String> = std::env::args().skip(1).collect();
    /// Consume the value that follows a flag, or exit with usage.
    fn value(args: &[String], i: &mut usize) -> String {
        *i += 1;
        args.get(*i).cloned().unwrap_or_else(|| usage())
    }
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--endpoint" => cfg.endpoint = value(&args, &mut i),
            "--bucket" => cfg.bucket = value(&args, &mut i),
            "--prefix" => cfg.prefix = value(&args, &mut i),
            "--concurrency" => {
                cfg.concurrency = value(&args, &mut i).parse().unwrap_or_else(|_| usage());
            }
            "--objects" => cfg.objects = value(&args, &mut i).parse().unwrap_or_else(|_| usage()),
            "--ops" => cfg.ops = value(&args, &mut i).parse().unwrap_or_else(|_| usage()),
            "--warmup" => cfg.warmup = value(&args, &mut i).parse().unwrap_or_else(|_| usage()),
            "--timeout" => {
                let secs = value(&args, &mut i).parse().unwrap_or_else(|_| usage());
                cfg.timeout = Duration::from_secs(secs);
            }
            "--label" => cfg.label = value(&args, &mut i),
            "--json" => cfg.json_path = Some(value(&args, &mut i)),
            "--phase" => {
                cfg.phases = value(&args, &mut i)
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect();
            }
            "-h" | "--help" => usage(),
            other => {
                eprintln!("unknown argument: {other}");
                usage()
            }
        }
        i += 1;
    }

    let hostport = cfg
        .endpoint
        .strip_prefix("http://")
        .unwrap_or(&cfg.endpoint)
        .trim_end_matches('/')
        .to_string();
    cfg.host_header.clone_from(&hostport);
    cfg.addr = if hostport.contains(':') {
        hostport
    } else {
        format!("{hostport}:80")
    };
    cfg.concurrency = cfg.concurrency.max(1);
    cfg.objects = cfg.objects.max(1);
    if cfg.ops == 0 {
        cfg.ops = cfg.objects.max(cfg.concurrency * 20);
    }
    cfg
}

// ── Latency accounting ──────────────────────────────────────────────────────

/// Latency samples for one operation class.
///
/// Percentiles come from the full sorted sample set rather than a fixed-bucket
/// histogram: a run is at most a few hundred thousand requests, so exact ranks
/// cost a sort and remove any question about bucket-boundary error at p99.9 —
/// which is precisely the number a tail-latency investigation turns on.
#[derive(Default)]
struct Samples {
    total_us: Vec<u64>,
    ttfb_us: Vec<u64>,
    bytes: u64,
    ops: u64,
    statuses: BTreeMap<u16, u64>,
    errors: BTreeMap<String, u64>,
}

impl Samples {
    fn merge(&mut self, other: Samples) {
        self.total_us.extend(other.total_us);
        self.ttfb_us.extend(other.ttfb_us);
        self.bytes += other.bytes;
        self.ops += other.ops;
        for (k, v) in other.statuses {
            *self.statuses.entry(k).or_insert(0) += v;
        }
        for (k, v) in other.errors {
            *self.errors.entry(k).or_insert(0) += v;
        }
    }

    fn error_count(&self) -> u64 {
        self.errors.values().sum()
    }
}

/// Exact rank percentile over a sorted slice, in microseconds.
fn pct(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    // Nearest-rank: the smallest sample at or above the requested share.
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

fn mean(v: &[u64]) -> u64 {
    if v.is_empty() {
        return 0;
    }
    (v.iter().sum::<u64>() as f64 / v.len() as f64) as u64
}

struct PhaseResult {
    name: String,
    concurrency: usize,
    wall: Duration,
    samples: Samples,
    total_sorted: Vec<u64>,
    ttfb_sorted: Vec<u64>,
}

impl PhaseResult {
    fn new(name: String, concurrency: usize, wall: Duration, mut samples: Samples) -> Self {
        let mut total_sorted = std::mem::take(&mut samples.total_us);
        let mut ttfb_sorted = std::mem::take(&mut samples.ttfb_us);
        total_sorted.sort_unstable();
        ttfb_sorted.sort_unstable();
        Self {
            name,
            concurrency,
            wall,
            samples,
            total_sorted,
            ttfb_sorted,
        }
    }

    fn ops_per_sec(&self) -> f64 {
        let secs = self.wall.as_secs_f64();
        if secs <= 0.0 {
            0.0
        } else {
            self.samples.ops as f64 / secs
        }
    }

    fn mib_per_sec(&self) -> f64 {
        let secs = self.wall.as_secs_f64();
        if secs <= 0.0 {
            0.0
        } else {
            self.samples.bytes as f64 / 1_048_576.0 / secs
        }
    }
}

// ── Minimal HTTP/1.1 client over a persistent connection ────────────────────

/// One keep-alive connection. Reconnects transparently if the peer closes it,
/// which is what a real client library does and what keeps a slow-path
/// connection reset from being scored as a request failure.
struct Conn {
    stream: Option<BufReader<TcpStream>>,
    addr: String,
    host: String,
}

struct Reply {
    status: u16,
    body_len: u64,
    ttfb: Duration,
}

impl Conn {
    fn new(addr: String, host: String) -> Self {
        Self {
            stream: None,
            addr,
            host,
        }
    }

    async fn ensure(&mut self) -> std::io::Result<&mut BufReader<TcpStream>> {
        if self.stream.is_none() {
            let s = TcpStream::connect(&self.addr).await?;
            s.set_nodelay(true)?;
            self.stream = Some(BufReader::with_capacity(64 * 1024, s));
        }
        Ok(self.stream.as_mut().expect("just set"))
    }

    fn drop_conn(&mut self) {
        self.stream = None;
    }

    /// Issue one request and read the full response.
    ///
    /// `body` is sent with an explicit `Content-Length` (never chunked) because
    /// that is what sccache's S3 client does for a cache write.
    async fn request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> std::io::Result<Reply> {
        // One retry: a connection the server reaped between requests is a
        // property of keep-alive, not a failure of the request.
        for attempt in 0..2 {
            match self.try_request(method, path, body).await {
                Ok(reply) => return Ok(reply),
                Err(e) => {
                    self.drop_conn();
                    if attempt == 1 {
                        return Err(e);
                    }
                }
            }
        }
        unreachable!("loop returns on both attempts")
    }

    async fn try_request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> std::io::Result<Reply> {
        let host = self.host.clone();
        let stream = self.ensure().await?;

        let mut head = String::with_capacity(160);
        let _ = write!(head, "{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
        head.push_str("Connection: keep-alive\r\n");
        // sccache signs with SigV4; spiceio does not verify, but sending the
        // header keeps the request shape (and header parsing cost) honest.
        head.push_str("x-amz-content-sha256: UNSIGNED-PAYLOAD\r\n");
        let _ = write!(
            head,
            "Content-Length: {}\r\n\r\n",
            body.map_or(0, <[u8]>::len)
        );

        let started = Instant::now();
        // A server that rejects a request can answer and close before the body
        // has finished uploading, which surfaces to the writer as EPIPE or
        // ECONNRESET. Reporting that as a connection error would hide the
        // status the server actually sent — the single most useful fact about
        // the failure — so hold the write error and try to read the reply
        // anyway. Only if nothing readable arrives is the write error returned.
        let write_result = async {
            stream.get_mut().write_all(head.as_bytes()).await?;
            if let Some(b) = body
                && !b.is_empty()
            {
                stream.get_mut().write_all(b).await?;
            }
            stream.get_mut().flush().await
        }
        .await;
        let mut write_err = write_result.err();

        // ── Response head ──
        let mut status = 0u16;
        let mut content_length: Option<u64> = None;
        let mut chunked = false;
        let mut close = false;
        let mut line = String::new();
        let mut first = true;
        let ttfb;
        loop {
            line.clear();
            let n = match read_line(stream, &mut line).await {
                Ok(n) => n,
                // Nothing readable either — the write error is the real cause.
                Err(e) => return Err(write_err.take().unwrap_or(e)),
            };
            if n == 0 {
                return Err(write_err.take().unwrap_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "connection closed mid-header",
                    )
                }));
            }
            let trimmed = line.trim_end();
            if first {
                first = false;
                status = trimmed
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("bad status line: {trimmed}"),
                        )
                    })?;
                continue;
            }
            if trimmed.is_empty() {
                ttfb = started.elapsed();
                break;
            }
            let Some((name, value)) = trimmed.split_once(':') else {
                continue;
            };
            let value = value.trim();
            match name.to_ascii_lowercase().as_str() {
                "content-length" => content_length = value.parse().ok(),
                "transfer-encoding" if value.eq_ignore_ascii_case("chunked") => chunked = true,
                "connection" if value.eq_ignore_ascii_case("close") => close = true,
                _ => {}
            }
        }

        // ── Response body ──
        // HEAD never carries one; 204/304 likewise.
        let body_len = if method == "HEAD" || status == 204 || status == 304 {
            0
        } else if chunked {
            read_chunked(stream).await?
        } else if let Some(len) = content_length {
            discard(stream, len).await?;
            len
        } else if close {
            // Length delimited by EOF.
            let mut sink = [0u8; 32 * 1024];
            let mut total = 0u64;
            loop {
                let n = stream.read(&mut sink).await?;
                if n == 0 {
                    break;
                }
                total += n as u64;
            }
            total
        } else {
            0
        };

        // An early response that raced the body upload leaves the connection in
        // an indeterminate state — the peer stopped reading partway through a
        // request it never framed. Reusing it would desynchronise the stream, so
        // retire it even though a status was recovered.
        if close || write_err.is_some() {
            self.drop_conn();
        }
        Ok(Reply {
            status,
            body_len,
            ttfb,
        })
    }
}

async fn read_line(stream: &mut BufReader<TcpStream>, out: &mut String) -> std::io::Result<usize> {
    let mut byte = [0u8; 1];
    let mut n = 0;
    loop {
        let got = stream.read(&mut byte).await?;
        if got == 0 {
            return Ok(n);
        }
        n += 1;
        out.push(byte[0] as char);
        if byte[0] == b'\n' {
            return Ok(n);
        }
        if n > 8192 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "header line too long",
            ));
        }
    }
}

async fn discard(stream: &mut BufReader<TcpStream>, mut len: u64) -> std::io::Result<()> {
    let mut sink = [0u8; 64 * 1024];
    while len > 0 {
        let want = len.min(sink.len() as u64) as usize;
        let n = stream.read(&mut sink[..want]).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed mid-body",
            ));
        }
        len -= n as u64;
    }
    Ok(())
}

async fn read_chunked(stream: &mut BufReader<TcpStream>) -> std::io::Result<u64> {
    let mut total = 0u64;
    let mut line = String::new();
    loop {
        line.clear();
        read_line(stream, &mut line).await?;
        let size_hex = line.trim_end().split(';').next().unwrap_or("").trim();
        let size = u64::from_str_radix(size_hex, 16).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("bad chunk size: {size_hex:?}"),
            )
        })?;
        if size == 0 {
            // Trailer section, terminated by a blank line.
            loop {
                line.clear();
                let n = read_line(stream, &mut line).await?;
                if n == 0 || line.trim_end().is_empty() {
                    break;
                }
            }
            return Ok(total);
        }
        discard(stream, size).await?;
        total += size;
        line.clear();
        read_line(stream, &mut line).await?; // CRLF after chunk data
    }
}

// ── Workload ────────────────────────────────────────────────────────────────

/// Deterministic key layout: a handful of stable parent directories holding
/// many leaves, which is the shape sccache produces under a key prefix and the
/// shape that exercises spiceio's directory handling.
fn key_for(prefix: &str, i: usize) -> String {
    format!("{prefix}/{:02x}/{:08x}", i % 256, i)
}

/// Size class for object `i`, drawn from the weighted mix.
fn size_for(i: usize) -> usize {
    let total: u32 = SIZE_MIX.iter().map(|c| c.weight).sum();
    // A cheap integer hash so neighbouring keys do not land in the same class —
    // consecutive same-size objects would let the NAS read cache flatter the
    // result.
    let h = (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let mut pick = ((h >> 32) % u64::from(total)) as u32;
    for class in SIZE_MIX {
        if pick < class.weight {
            return class.bytes;
        }
        pick -= class.weight;
    }
    SIZE_MIX[0].bytes
}

/// What one worker does for request number `n` of a phase.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Op {
    Put,
    Get,
    GetMiss,
    HeadHit,
    HeadMiss,
    Delete,
    /// Weighted blend approximating a live sccache fleet.
    Mixed,
}

impl Op {
    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "put" => Op::Put,
            "get" => Op::Get,
            "get-miss" => Op::GetMiss,
            "head-hit" => Op::HeadHit,
            "head-miss" => Op::HeadMiss,
            "delete" => Op::Delete,
            "mixed" => Op::Mixed,
            _ => return None,
        })
    }

    /// Read phases are repeated for warmup; write phases are not (a repeated
    /// PUT of the same key measures overwrite, not first write).
    fn is_read(self) -> bool {
        matches!(self, Op::Get | Op::GetMiss | Op::HeadHit | Op::HeadMiss)
    }

    /// Whether `status` means the operation actually did what it was asked to.
    ///
    /// This is what separates a load generator from a traffic generator, and it
    /// is not optional. Without it a proxy that answers *every* PUT with 404
    /// posts perfect throughput and zero errors: the response parsed, the
    /// connection stayed up, so nothing looks wrong. The defect this bench
    /// exists to catch — PutObject answered `NoSuchKey`, the object silently
    /// never stored — is precisely the shape that a transport-only error count
    /// cannot see.
    ///
    /// Deliberately strict per operation rather than one global allowlist: 404
    /// is the *correct* answer for a miss probe and a *failure* for a write or
    /// a hit, so a shared allowlist that permits 404 everywhere would re-hide
    /// exactly the case this exists for.
    fn accepts(self, status: u16) -> bool {
        match self {
            Op::Put => status == 200,
            Op::Get | Op::HeadHit => status == 200,
            Op::GetMiss | Op::HeadMiss => status == 404,
            // DeleteObject is idempotent in S3 — 204 whether or not the key was
            // there — and cleanup passes run over keys that may already be gone.
            Op::Delete => status == 204 || status == 404,
            Op::Mixed => unreachable!("resolved to a concrete op before classification"),
        }
    }

    /// Short name used in the error breakdown, so a failure reads
    /// `GET-hit status 404` rather than an anonymous count.
    fn label(self) -> &'static str {
        match self {
            Op::Put => "PUT",
            Op::Get => "GET-hit",
            Op::GetMiss => "GET-miss",
            Op::HeadHit => "HEAD-hit",
            Op::HeadMiss => "HEAD-miss",
            Op::Delete => "DELETE",
            Op::Mixed => "mixed",
        }
    }
}

/// Resolve the mixed blend for request `i`.
///
/// 70% GET hit / 20% GET miss / 10% PUT: a warm sccache fleet is
/// overwhelmingly reads, with misses (404s) from compile units nobody has
/// built yet and writes trailing behind them.
fn mixed_op(i: usize) -> Op {
    match i % 10 {
        0..=6 => Op::Get,
        7..=8 => Op::GetMiss,
        _ => Op::Put,
    }
}

struct Workload {
    cfg: Arc<Config>,
    payloads: Arc<BTreeMap<usize, Arc<Vec<u8>>>>,
}

impl Workload {
    /// Issue one request, returning the *resolved* op alongside the reply — the
    /// mixed phase picks a different op per request, and the caller cannot
    /// judge the status without knowing which one ran.
    async fn one(&self, conn: &mut Conn, op: Op, i: usize) -> std::io::Result<(Op, Reply, u64)> {
        let cfg = &self.cfg;
        let op = if op == Op::Mixed { mixed_op(i) } else { op };
        let idx = i % cfg.objects;
        match op {
            Op::Put => {
                let size = size_for(idx);
                let payload = self.payloads.get(&size).expect("payload for size class");
                let path = format!("/{}/{}", cfg.bucket, key_for(&cfg.prefix, idx));
                let r = conn.request("PUT", &path, Some(payload)).await?;
                Ok((op, r, size as u64))
            }
            Op::Get => {
                let path = format!("/{}/{}", cfg.bucket, key_for(&cfg.prefix, idx));
                let r = conn.request("GET", &path, None).await?;
                let n = r.body_len;
                Ok((op, r, n))
            }
            Op::GetMiss => {
                let path = format!("/{}/{}-absent/{:08x}", cfg.bucket, cfg.prefix, i);
                let r = conn.request("GET", &path, None).await?;
                Ok((op, r, 0))
            }
            Op::HeadHit => {
                let path = format!("/{}/{}", cfg.bucket, key_for(&cfg.prefix, idx));
                let r = conn.request("HEAD", &path, None).await?;
                Ok((op, r, 0))
            }
            Op::HeadMiss => {
                let path = format!("/{}/{}-absent/{:08x}", cfg.bucket, cfg.prefix, i);
                let r = conn.request("HEAD", &path, None).await?;
                Ok((op, r, 0))
            }
            Op::Delete => {
                let path = format!("/{}/{}", cfg.bucket, key_for(&cfg.prefix, idx));
                let r = conn.request("DELETE", &path, None).await?;
                Ok((op, r, 0))
            }
            Op::Mixed => unreachable!("resolved above"),
        }
    }
}

/// Run `total` operations across `concurrency` persistent connections.
///
/// Closed-loop: each worker issues its next request as soon as the previous one
/// completes, so offered concurrency stays pinned at `concurrency` and the
/// measured latency is what a client with that many in-flight requests sees.
/// An open-loop generator would instead queue work the proxy cannot absorb and
/// report latencies dominated by that queue.
async fn run_phase(work: Arc<Workload>, op: Op, total: usize, label: &str) -> PhaseResult {
    let cfg = Arc::clone(&work.cfg);
    let next = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(cfg.concurrency);
    let started = Instant::now();

    for _ in 0..cfg.concurrency {
        let work = Arc::clone(&work);
        let cfg = Arc::clone(&cfg);
        let next = Arc::clone(&next);
        handles.push(tokio::spawn(async move {
            let mut conn = Conn::new(cfg.addr.clone(), cfg.host_header.clone());
            let mut s = Samples::default();
            loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= total {
                    break;
                }
                let t0 = Instant::now();
                match tokio::time::timeout(cfg.timeout, work.one(&mut conn, op, i)).await {
                    Ok(Ok((resolved, reply, bytes))) => {
                        // Record the status either way — the breakdown is how a
                        // reader sees *what* the proxy answered.
                        *s.statuses.entry(reply.status).or_insert(0) += 1;
                        if resolved.accepts(reply.status) {
                            s.total_us.push(t0.elapsed().as_micros() as u64);
                            s.ttfb_us.push(reply.ttfb.as_micros() as u64);
                            s.bytes += bytes.max(reply.body_len);
                            s.ops += 1;
                        } else {
                            // A wrong-status response is a failed operation, not
                            // a slow one: counting it in ops/bytes would credit
                            // the proxy with throughput for work it did not do,
                            // and its latency would flatter the percentiles
                            // (rejections are fast).
                            *s.errors
                                .entry(format!("{} status {}", resolved.label(), reply.status))
                                .or_insert(0) += 1;
                            // The connection is fine — the server answered. Only
                            // transport failures below justify dropping it.
                        }
                    }
                    Ok(Err(e)) => {
                        *s.errors.entry(e.kind().to_string()).or_insert(0) += 1;
                        conn.drop_conn();
                    }
                    Err(_) => {
                        *s.errors.entry("timeout".into()).or_insert(0) += 1;
                        conn.drop_conn();
                    }
                }
            }
            s
        }));
    }

    let mut samples = Samples::default();
    for h in handles {
        if let Ok(s) = h.await {
            samples.merge(s);
        }
    }
    PhaseResult::new(
        label.to_string(),
        cfg.concurrency,
        started.elapsed(),
        samples,
    )
}

// ── Reporting ───────────────────────────────────────────────────────────────

fn fmt_us(us: u64) -> String {
    if us >= 10_000 {
        format!("{:.1}ms", us as f64 / 1000.0)
    } else if us >= 1_000 {
        format!("{:.2}ms", us as f64 / 1000.0)
    } else {
        format!("{us}us")
    }
}

fn print_header() {
    println!(
        "\n{:<14} {:>6} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9} {:>7}",
        "phase", "ops", "ops/s", "MiB/s", "mean", "p50", "p90", "p99", "p99.9", "err"
    );
    println!("{}", "─".repeat(106));
}

fn print_phase(r: &PhaseResult) {
    println!(
        "{:<14} {:>6} {:>9.1} {:>9.1} {:>9} {:>9} {:>9} {:>9} {:>9} {:>7}",
        r.name,
        r.samples.ops,
        r.ops_per_sec(),
        r.mib_per_sec(),
        fmt_us(mean(&r.total_sorted)),
        fmt_us(pct(&r.total_sorted, 50.0)),
        fmt_us(pct(&r.total_sorted, 90.0)),
        fmt_us(pct(&r.total_sorted, 99.0)),
        fmt_us(pct(&r.total_sorted, 99.9)),
        r.samples.error_count(),
    );
    // TTFB only tells you something new when a body follows it.
    if r.samples.bytes > 0 {
        println!(
            "{:<14} {:>6} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9} {:>7}",
            "  └ ttfb",
            "",
            "",
            "",
            fmt_us(mean(&r.ttfb_sorted)),
            fmt_us(pct(&r.ttfb_sorted, 50.0)),
            fmt_us(pct(&r.ttfb_sorted, 90.0)),
            fmt_us(pct(&r.ttfb_sorted, 99.0)),
            fmt_us(pct(&r.ttfb_sorted, 99.9)),
            "",
        );
    }
    // Always show what the proxy answered. There is deliberately no "expected"
    // allowlist here: which statuses are acceptable depends on the operation
    // (404 is right for a miss probe and wrong for a write), and that judgement
    // lives in `Op::accepts`, which has already turned any mismatch into an
    // entry in `errors` below.
    let seen: Vec<String> = r
        .samples
        .statuses
        .iter()
        .map(|(code, n)| format!("{code}×{n}"))
        .collect();
    if seen.len() > 1 {
        println!("  └ status: {}", seen.join(" "));
    }
    if !r.samples.errors.is_empty() {
        let errs: Vec<String> = r
            .samples
            .errors
            .iter()
            .map(|(k, n)| format!("{k}×{n}"))
            .collect();
        println!("  └ errors: {}", errs.join(" "));
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn write_json(cfg: &Config, results: &[PhaseResult], path: &str) {
    let mut out = String::new();
    out.push_str("{\n");
    let _ = write!(
        out,
        "  \"label\": \"{}\",\n  \"endpoint\": \"{}\",\n  \"bucket\": \"{}\",\n  \
         \"concurrency\": {},\n  \"objects\": {},\n  \"ops_per_phase\": {},\n  \"phases\": [\n",
        json_escape(&cfg.label),
        json_escape(&cfg.endpoint),
        json_escape(&cfg.bucket),
        cfg.concurrency,
        cfg.objects,
        cfg.ops
    );
    for (i, r) in results.iter().enumerate() {
        let statuses: Vec<String> = r
            .samples
            .statuses
            .iter()
            .map(|(c, n)| format!("\"{c}\": {n}"))
            .collect();
        let errors: Vec<String> = r
            .samples
            .errors
            .iter()
            .map(|(k, n)| format!("\"{}\": {}", json_escape(k), n))
            .collect();
        let _ = write!(
            out,
            "    {{\n      \"phase\": \"{}\",\n      \"concurrency\": {},\n      \
             \"ops\": {},\n      \"bytes\": {},\n      \"wall_ms\": {},\n      \
             \"ops_per_sec\": {:.2},\n      \"mib_per_sec\": {:.2},\n      \
             \"latency_us\": {{\"mean\": {}, \"p50\": {}, \"p90\": {}, \"p99\": {}, \
             \"p999\": {}, \"max\": {}}},\n      \
             \"ttfb_us\": {{\"mean\": {}, \"p50\": {}, \"p90\": {}, \"p99\": {}, \
             \"p999\": {}, \"max\": {}}},\n      \
             \"statuses\": {{{}}},\n      \"errors\": {{{}}}\n    }}{}\n",
            json_escape(&r.name),
            r.concurrency,
            r.samples.ops,
            r.samples.bytes,
            r.wall.as_millis(),
            r.ops_per_sec(),
            r.mib_per_sec(),
            mean(&r.total_sorted),
            pct(&r.total_sorted, 50.0),
            pct(&r.total_sorted, 90.0),
            pct(&r.total_sorted, 99.0),
            pct(&r.total_sorted, 99.9),
            r.total_sorted.last().copied().unwrap_or(0),
            mean(&r.ttfb_sorted),
            pct(&r.ttfb_sorted, 50.0),
            pct(&r.ttfb_sorted, 90.0),
            pct(&r.ttfb_sorted, 99.0),
            pct(&r.ttfb_sorted, 99.9),
            r.ttfb_sorted.last().copied().unwrap_or(0),
            statuses.join(", "),
            errors.join(", "),
            if i + 1 == results.len() { "" } else { "," }
        );
    }
    out.push_str("  ]\n}\n");
    if let Err(e) = std::fs::write(path, out) {
        eprintln!("[loadgen] could not write {path}: {e}");
    }
}

// ── Entry point ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cfg = Arc::new(parse_args());

    // One shared buffer per size class — the payload contents are irrelevant to
    // what is being measured, and regenerating them per request would put
    // allocator noise in the latency samples.
    let mut payloads = BTreeMap::new();
    for class in SIZE_MIX {
        payloads.insert(class.bytes, Arc::new(vec![0xABu8; class.bytes]));
    }
    let work = Arc::new(Workload {
        cfg: Arc::clone(&cfg),
        payloads: Arc::new(payloads),
    });

    println!(
        "[loadgen] {} → {}/{}  concurrency={} objects={} ops/phase={} prefix={}",
        if cfg.label.is_empty() {
            "run".into()
        } else {
            cfg.label.clone()
        },
        cfg.endpoint,
        cfg.bucket,
        cfg.concurrency,
        cfg.objects,
        cfg.ops,
        cfg.prefix
    );

    // The connection pool is shared across phases via fresh workers each time;
    // a short settle keeps a phase from inheriting the previous one's backlog.
    let mut results: Vec<PhaseResult> = Vec::new();
    print_header();

    for phase in &cfg.phases {
        let Some(op) = Op::parse(phase) else {
            eprintln!("[loadgen] unknown phase {phase:?}, skipping");
            continue;
        };
        let reps = if op.is_read() { cfg.warmup.max(1) } else { 1 };
        let mut last = None;
        for rep in 0..reps {
            let r = run_phase(Arc::clone(&work), op, cfg.ops, phase).await;
            if rep + 1 < reps {
                // Warmup repetitions are discarded, not averaged: their point is
                // to leave the caches (spiceio's, the NAS's) in the state a
                // steady-state client would find them in.
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            last = Some(r);
        }
        if let Some(r) = last {
            print_phase(&r);
            results.push(r);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let total_err: u64 = results.iter().map(|r| r.samples.error_count()).sum();
    println!(
        "\n[loadgen] done — {} phase(s), {total_err} error(s)",
        results.len()
    );

    if let Some(path) = cfg.json_path.as_deref() {
        write_json(&cfg, &results, path);
        println!("[loadgen] wrote {path}");
    }

    if total_err > 0 {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_write_answered_404_is_a_failure() {
        // The regression this bench exists to catch. spiceio answered 40 of
        // 1203 PutObjects with 404 NoSuchKey during a real sccache build; the
        // objects were never stored and the next build recompiled them. If
        // `accepts` tolerated 404 here, the load burst would report perfect
        // throughput and zero errors through exactly that failure.
        assert!(!Op::Put.accepts(404));
        assert!(Op::Put.accepts(200));
    }

    #[test]
    fn a_hit_answered_404_is_a_failure_but_a_miss_probe_needs_it() {
        // 404 cannot be judged globally: it is the correct answer for one of
        // these and a silent data-loss signal for the other. A single shared
        // allowlist — which is what this replaced — collapses the distinction.
        assert!(!Op::Get.accepts(404));
        assert!(!Op::HeadHit.accepts(404));
        assert!(Op::GetMiss.accepts(404));
        assert!(Op::HeadMiss.accepts(404));
        // ...and a miss probe that suddenly returns a body is equally wrong.
        assert!(!Op::GetMiss.accepts(200));
        assert!(!Op::HeadMiss.accepts(200));
    }

    #[test]
    fn server_errors_never_pass_for_any_operation() {
        // 503 is what the write path now returns instead of 404 for a missing
        // destination path. It must not become the new invisible failure.
        for op in [
            Op::Put,
            Op::Get,
            Op::GetMiss,
            Op::HeadHit,
            Op::HeadMiss,
            Op::Delete,
        ] {
            for status in [500, 502, 503, 504, 403, 400] {
                assert!(!op.accepts(status), "{} accepted {status}", op.label());
            }
        }
    }

    #[test]
    fn delete_tolerates_an_already_absent_key() {
        // DeleteObject is idempotent in S3, and cleanup passes run over keys a
        // previous phase may already have removed.
        assert!(Op::Delete.accepts(204));
        assert!(Op::Delete.accepts(404));
        assert!(!Op::Delete.accepts(500));
    }

    #[test]
    fn every_phase_name_round_trips() {
        // A typo in a phase list should be rejected, not silently skipped into
        // a run that measures nothing.
        for name in [
            "put",
            "get",
            "get-miss",
            "head-hit",
            "head-miss",
            "delete",
            "mixed",
        ] {
            assert!(Op::parse(name).is_some(), "{name}");
        }
        assert!(Op::parse("gett").is_none());
    }

    #[test]
    fn mixed_resolves_only_to_classifiable_ops() {
        // `accepts` panics on Op::Mixed by construction, so the blend must
        // never yield it — otherwise a mixed phase panics mid-run.
        for i in 0..100 {
            let op = mixed_op(i);
            assert_ne!(op, Op::Mixed);
            let _ = op.accepts(200);
        }
    }

    #[test]
    fn percentiles_use_nearest_rank() {
        // The server-side summary in bench-sccache.sh reimplements this to
        // compare both sides of the same request; they have to agree.
        let v = vec![10u64, 20, 30, 40];
        assert_eq!(pct(&v, 50.0), 20);
        assert_eq!(pct(&v, 90.0), 40);
        assert_eq!(pct(&v, 100.0), 40);
        assert_eq!(pct(&[], 50.0), 0);
        assert_eq!(pct(&[7], 99.9), 7);
    }

    #[test]
    fn size_mix_covers_every_class_and_stays_deterministic() {
        // Payloads are pre-generated per class; a size outside the mix would
        // panic on lookup. Determinism keeps runs comparable.
        let sizes: std::collections::BTreeSet<usize> = (0..5000).map(size_for).collect();
        for class in SIZE_MIX {
            assert!(sizes.contains(&class.bytes), "{} unused", class.bytes);
        }
        assert_eq!(size_for(42), size_for(42));
    }
}
