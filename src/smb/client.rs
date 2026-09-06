//! SMB2 client — manages TCP connections and speaks the protocol.

use bytes::Buf;
use std::io::{self, IoSlice};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use bytes::{BufMut, Bytes, BytesMut};

/// Timeout for a single SMB response read. Prevents indefinite mutex hold when
/// the SMB server is slow or unresponsive under heavy load.
const SMB_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout for a socket write. There is no OS-level write timeout, so a server
/// that stops draining its receive window under heavy concurrent write load
/// would otherwise block `write_all` forever (hanging the request). On timeout
/// we poison the connection — the pool healer reconnects it.
const SMB_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout for the initial TCP handshake to the SMB server. Without this,
/// a server that drops SYNs leaves the OS waiting ~75-90s, which stalls
/// pool initialization past any sensible CI window. Kept short; the whole
/// connect (TCP + handshake) is additionally capped by the pool's per-attempt
/// timeout so a stalled SMB session-setup fails fast and retries.
const SMB_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

fn validate_reply(header: &Header, message_id: u64, command: u16) -> io::Result<()> {
    if header.message_id != message_id || header.command != command {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unexpected SMB reply: id={} command={}, expected id={message_id} command={command}",
                header.message_id, header.command
            ),
        ));
    }
    Ok(())
}

use super::auth;
use super::protocol::*;

/// Configuration for connecting to an SMB server.
#[derive(Debug, Clone)]
pub struct SmbConfig {
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub domain: String,
    pub workstation: String,
    /// Cap for standalone read/write I/O (0 = use DEFAULT_MAX_IO).
    pub max_io_size: u32,
}

impl SmbConfig {
    pub fn share_path(&self, share: &str) -> String {
        format!("\\\\{}\\{}", self.server, share)
    }
}

/// Floor for the QUERY_DIRECTORY response buffer, and what is used before the
/// negotiate response is known. Matches the value used before the buffer was
/// derived from the transact size.
const QUERY_DIR_BUFFER_FLOOR: u32 = 65536;

/// Cap on the QUERY_DIRECTORY response buffer. A directory listing is
/// round-trip bound — every response costs a full RTT to the NAS — so a bigger
/// buffer directly cuts the round trips a large listing needs (1 MiB is 16x
/// fewer than the old fixed 64 KiB). Capped rather than taking the server's
/// full transact size (often 8 MiB) because the buffer is also the credit
/// charge: 1 MiB costs 16 credits, 8 MiB would cost 128 and would starve the
/// concurrent read/write pipelines sharing the connection. The server returns
/// only the bytes it actually has, so this costs nothing on small directories.
const QUERY_DIR_BUFFER_MAX: u32 = 1024 * 1024;

/// Effective QUERY_DIRECTORY buffer for a negotiated transact size. A server
/// reporting zero clamps up to the floor, same as any undersized value.
fn query_dir_buffer(neg_max_transact: u32) -> u32 {
    neg_max_transact.clamp(QUERY_DIR_BUFFER_FLOOR, QUERY_DIR_BUFFER_MAX)
}

/// Default I/O cap for standalone (non-compound) read/write operations.
///
/// 256 KB is the measured sweet spot for streaming throughput: on a 10G link a
/// single-stream PutObject rises from ~31 MiB/s at 64 KB to ~744 MiB/s at
/// 256 KB. The WAL writer bounds its in-flight burst with the adaptive flush
/// budget (`write_inflight`), which backs off on resets, so this cap sets the
/// per-write size rather than how much is buffered at once. 256 KB stays well
/// within what essentially every SMB server handles, and small files keep using
/// the 64 KB compound cap (so per-op latency is unchanged). Override via
/// `SPICEIO_SMB_MAX_IO`; the effective size is always clamped to the server's
/// negotiated maximum.
const DEFAULT_MAX_IO: u32 = 262144;

/// An authenticated SMB2 session.
pub struct SmbClient {
    stream: Mutex<TcpStream>,
    message_id: AtomicU64,
    session_id: u64,
    config: SmbConfig,
    /// Effective max read size for standalone (non-compound) reads.
    pub max_read_size: u32,
    /// Effective max write size for standalone (non-compound) writes.
    pub max_write_size: u32,
    /// Capped max for compound operations (64KB — some NAS servers reject
    /// larger payloads inside compound requests).
    pub compound_max_read_size: u32,
    pub compound_max_write_size: u32,
    /// Largest QUERY_DIRECTORY response we will ask the server for, derived
    /// from the negotiated transact size (see `QUERY_DIR_BUFFER_MAX`).
    query_dir_buffer: u32,
    /// 16-byte client GUID
    client_guid: [u8; 16],
    /// SMB 3.1.1 signing key (derived after auth)
    signing_key: Option<[u8; 16]>,
    /// Set on read timeout — connection framing is desynchronized.
    poisoned: AtomicBool,
    /// SMB2 credit balance: credits granted by the server (the
    /// `CreditResponse` field of every response, banked by `harvest_credits`)
    /// minus credits consumed by requests (each request costs
    /// `credit_charge`, consumed by `alloc_ids` in lockstep with its
    /// MessageId range). Sending more in-flight charge than the balance
    /// violates the server's sequence window — servers disconnect — so the
    /// pipelined paths clamp their batches to it and the single-op paths
    /// split oversized I/O. Signed: a compliant server always leaves the
    /// client ≥ 1 credit, but we permit a one-request overdraft on a
    /// non-compliant grant rather than wedging (see `affordable_count`).
    credits: AtomicI64,
    /// One-shot flag so the first credit-limited batch on this connection is
    /// logged (visibility) without per-batch log spam.
    credit_clamp_logged: AtomicBool,
    /// Operations currently holding or waiting for the stream lock. Every
    /// request/response round trip owns the stream for its whole duration, so
    /// this is the connection's queue depth: `SmbPool::pick` steers new work
    /// to the shallowest connection instead of round-robining into one that a
    /// multi-megabyte pipelined batch is already sitting on.
    inflight: AtomicUsize,
    /// Monotonic milliseconds (since process start) of the last completed
    /// round trip, used to decide when a connection is idle enough to be
    /// worth an ECHO keepalive.
    last_active_ms: AtomicU64,
    /// Cleared if the server answers a keepalive ECHO with an error status, so
    /// a server that dislikes the probe is asked once rather than every idle
    /// interval for the life of the connection.
    echoes_ok: AtomicBool,
}

/// Process-start reference for `now_ms` — a monotonic clock immune to wall-clock
/// jumps (NTP steps, DST), which a keepalive deadline must not follow.
static START: OnceLock<Instant> = OnceLock::new();

/// Milliseconds since process start, saturating at `u64::MAX` (~584M years).
fn now_ms() -> u64 {
    START
        .get_or_init(Instant::now)
        .elapsed()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

/// Exclusive access to a connection's stream, with the connection's queue
/// depth counted for as long as it is held.
///
/// Binding the two together is the point: every operation owns the stream for
/// a whole round trip, and `SmbPool::pick` dispatches on that depth. Counting
/// at each call site instead would mean the next stream-holding operation
/// someone adds compiles, runs, and silently under-reports its connection's
/// load — a dispatch skew under load, not a test failure.
///
/// `Drop` releases the slot on every path, including an early `?` return and a
/// caller future dropped mid-await (a disconnected HTTP client), and re-stamps
/// the activity clock so idleness is measured from when the round trip
/// *finished*.
struct StreamGuard<'a> {
    client: &'a SmbClient,
    stream: tokio::sync::MutexGuard<'a, TcpStream>,
    complete: bool,
}

/// Holds the in-flight count for an operation that is still waiting for the
/// stream lock, so a cancelled caller cannot leak it. Defused (`client` set to
/// `None`) once the lock is acquired and `StreamGuard` takes over.
struct PendingIo<'a> {
    client: Option<&'a SmbClient>,
}

impl Drop for PendingIo<'_> {
    fn drop(&mut self) {
        if let Some(client) = self.client {
            client.inflight.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl std::ops::Deref for StreamGuard<'_> {
    type Target = TcpStream;
    fn deref(&self) -> &TcpStream {
        &self.stream
    }
}

impl std::ops::DerefMut for StreamGuard<'_> {
    fn deref_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }
}

impl Drop for StreamGuard<'_> {
    fn drop(&mut self) {
        // A dropped future cannot run the caller's error handler. Never let an
        // unread reply (or partially written frame) reach the next operation.
        if !self.complete {
            self.client.poisoned.store(true, Ordering::Relaxed);
        }
        self.client.inflight.fetch_sub(1, Ordering::Relaxed);
        self.client
            .last_active_ms
            .store(now_ms(), Ordering::Relaxed);
    }
}

impl SmbClient {
    /// Connect to the SMB server and authenticate.
    pub async fn connect(config: SmbConfig) -> io::Result<Arc<Self>> {
        let addr = format!("{}:{}", config.server, config.port);
        let stream =
            match tokio::time::timeout(SMB_CONNECT_TIMEOUT, TcpStream::connect(&addr)).await {
                Ok(Ok(s)) => {
                    crate::slog!("[spiceio] smb tcp connected: {addr}");
                    s
                }
                Ok(Err(e)) => {
                    // Return a contextual error without logging here: the pool's
                    // retry loop (`retry_with_backoff`) is the single source of
                    // per-attempt connect logging, so logging here would double it.
                    return Err(io::Error::new(
                        e.kind(),
                        format!("smb tcp connect failed: {addr}: {e}"),
                    ));
                }
                Err(_) => {
                    // Contextual error, no logging here (see the reset arm above).
                    let msg = format!(
                        "smb tcp connect timed out after {}s: {addr}",
                        SMB_CONNECT_TIMEOUT.as_secs()
                    );
                    return Err(io::Error::new(io::ErrorKind::TimedOut, msg));
                }
            };
        stream.set_nodelay(true)?;

        // Socket tuning: 4 MB send/receive buffers for large read/write
        // throughput, plus TCP keepalive so the OS surfaces a peer that
        // vanished without a FIN (NAS power-cut, cable pull, NAT eviction).
        // Without keepalive such a half-open connection looks healthy until a
        // request stalls on it for the full SMB read timeout; with it, the
        // socket errors out and the pool healer reconnects. Best-effort — a
        // failed setsockopt only forgoes the tuning, so results are ignored.
        {
            use std::os::fd::AsRawFd;

            unsafe extern "C" {
                fn setsockopt(
                    socket: i32,
                    level: i32,
                    option_name: i32,
                    option_value: *const u8,
                    option_len: u32,
                ) -> i32;
            }

            const SOL_SOCKET: i32 = 0xffff;
            const SO_SNDBUF: i32 = 0x1001;
            const SO_RCVBUF: i32 = 0x1002;
            const SO_KEEPALIVE: i32 = 0x0008;
            const IPPROTO_TCP: i32 = 6;
            // macOS names: TCP_KEEPALIVE is the idle time before the first
            // probe; TCP_KEEPINTVL/TCP_KEEPCNT pace and bound the retries.
            const TCP_KEEPALIVE: i32 = 0x10;
            const TCP_KEEPINTVL: i32 = 0x101;
            const TCP_KEEPCNT: i32 = 0x102;

            let fd = stream.as_raw_fd();
            let len = size_of::<i32>() as u32;
            let set = |level: i32, name: i32, value: i32| {
                let ptr = std::ptr::from_ref(&value).cast();
                // SAFETY: `fd` is an open socket owned by `stream` for the
                // duration of this call, and `ptr`/`len` describe the `i32`
                // every one of these options expects.
                unsafe { setsockopt(fd, level, name, ptr, len) };
            };
            set(SOL_SOCKET, SO_SNDBUF, 4 * 1024 * 1024);
            set(SOL_SOCKET, SO_RCVBUF, 4 * 1024 * 1024);
            set(SOL_SOCKET, SO_KEEPALIVE, 1);
            // ~30s idle, then 3 probes 10s apart: a dead peer is detected in
            // about a minute, well inside the pool's healer cadence.
            set(IPPROTO_TCP, TCP_KEEPALIVE, 30);
            set(IPPROTO_TCP, TCP_KEEPINTVL, 10);
            set(IPPROTO_TCP, TCP_KEEPCNT, 3);
        }

        let mut client_guid = [0u8; 16];
        unsafe extern "C" {
            fn arc4random_buf(buf: *mut u8, nbytes: usize);
        }
        unsafe {
            arc4random_buf(client_guid.as_mut_ptr(), 16);
        }

        // Use a temporary non-Arc client for the handshake, then wrap in Arc.
        let mut client = Self {
            stream: Mutex::new(stream),
            message_id: AtomicU64::new(0),
            session_id: 0,
            config,
            max_read_size: 65536,
            max_write_size: 65536,
            compound_max_read_size: 65536,
            compound_max_write_size: 65536,
            query_dir_buffer: QUERY_DIR_BUFFER_FLOOR,
            client_guid,
            signing_key: None,
            poisoned: AtomicBool::new(false),
            // One credit to spend on the negotiate request; every response
            // from then on replenishes the balance via `harvest_credits`.
            credits: AtomicI64::new(1),
            credit_clamp_logged: AtomicBool::new(false),
            inflight: AtomicUsize::new(0),
            last_active_ms: AtomicU64::new(now_ms()),
            echoes_ok: AtomicBool::new(true),
        };

        client.negotiate_and_auth().await?;
        Ok(Arc::new(client))
    }

    /// Whether this connection has been poisoned by a timeout.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Relaxed)
    }

    /// Operations currently queued on this connection's stream — the load
    /// signal `SmbPool::pick` dispatches on.
    pub fn inflight(&self) -> usize {
        self.inflight.load(Ordering::Relaxed)
    }

    /// How long since this connection last completed a round trip.
    pub fn idle(&self) -> Duration {
        Duration::from_millis(now_ms().saturating_sub(self.last_active_ms.load(Ordering::Relaxed)))
    }

    /// Take exclusive use of the stream for one operation, counting it against
    /// this connection's queue depth until the guard drops. This is the only
    /// way to reach the stream, so the accounting cannot be skipped.
    async fn lock_stream(&self) -> io::Result<StreamGuard<'_>> {
        // Counted before the await: an operation waiting for the lock is load
        // on this connection, and `pick` should steer new work elsewhere.
        //
        // That leaves a window where the count is owned by neither guard — if
        // the caller is dropped while waiting for the lock (an HTTP client
        // disconnecting mid-request), `StreamGuard` is never built and the
        // increment would leak, permanently inflating this connection's
        // apparent load and, since keepalive only probes at depth zero,
        // silently disabling its liveness probe. `PendingIo` owns the count
        // across the await and hands it over only once the lock is held.
        self.inflight.fetch_add(1, Ordering::Relaxed);
        let mut pending = PendingIo { client: Some(self) };
        let stream = self.stream.lock().await;
        if self.is_poisoned() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "SMB connection poisoned",
            ));
        }
        pending.client = None; // handed off to StreamGuard below
        Ok(StreamGuard {
            client: self,
            stream,
            complete: false,
        })
    }

    fn next_message_id(&self) -> u64 {
        self.alloc_ids(1)
    }

    /// Allocate a MessageId range spanning `total_charge` sequence numbers AND
    /// atomically consume the same amount from the credit balance, for callers
    /// that charge a *fixed* amount (single write, compound chains, handshake).
    /// Charges and MessageIds advance together, so "balance ≥ 0" means "every
    /// allocated MessageId lies within the server-granted sequence window".
    fn alloc_ids(&self, total_charge: u64) -> u64 {
        self.credits
            .fetch_sub(total_charge as i64, Ordering::AcqRel);
        self.message_id.fetch_add(total_charge, Ordering::Relaxed)
    }

    /// Advance the MessageId window by `total_charge` *without* touching the
    /// credit balance — for callers that already reserved their credits via
    /// `reserve_*` (the variable-size pipelined / single-IO paths). Splitting
    /// reservation from MessageId allocation lets reservation be a single
    /// atomic CAS (see `reserve_request_count`).
    fn alloc_msg_ids(&self, total_charge: u64) -> u64 {
        self.message_id.fetch_add(total_charge, Ordering::Relaxed)
    }

    /// Atomically reserve credits for up to `want` requests of `charge` credits
    /// each, returning how many were granted. A single CAS makes the
    /// affordability check and the debit one indivisible step, so concurrent
    /// callers cannot both observe the same balance and each commit a full
    /// batch — which would put far more in-flight charge on the wire than the
    /// server granted and trip its sequence window. Always grants ≥ 1 when
    /// `want ≥ 1` (the bounded per-request overdraft: a compliant server keeps
    /// the balance ≥ 1, so the floor only bites on a fresh or stingy
    /// connection and merely prevents a stuck transfer). Reservations are
    /// conservative — held from here until the response replenishes the
    /// balance via `harvest_credits` — which errs on the safe side of the grant.
    fn reserve_request_count(&self, charge: u16, want: usize) -> usize {
        if want == 0 {
            return 0;
        }
        let per = i64::from(charge.max(1));
        let mut bal = self.credits.load(Ordering::Relaxed);
        loop {
            let n = affordable_count(bal, charge, want);
            let cost = n as i64 * per;
            match self.credits.compare_exchange_weak(
                bal,
                bal - cost,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return n,
                Err(actual) => bal = actual,
            }
        }
    }

    /// Atomically reserve credits for the longest prefix of `chunks` that fits
    /// the balance (always ≥ 1 chunk — same bounded overdraft as
    /// `reserve_request_count`), returning `(chunk_count, total_charge)`. CAS
    /// for the same race-freedom reason as the read path.
    fn reserve_chunk_prefix(&self, chunks: &[&[u8]]) -> (usize, u64) {
        if chunks.is_empty() {
            return (0, 0);
        }
        let mut bal = self.credits.load(Ordering::Relaxed);
        loop {
            let (take, total) = affordable_prefix(bal, chunks);
            match self.credits.compare_exchange_weak(
                bal,
                bal - total as i64,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return (take, total),
                Err(actual) => bal = actual,
            }
        }
    }

    /// Atomically reserve credits for a single read/write of up to `length`
    /// bytes, returning the granted length (clamped to the balance, floored at
    /// one credit's worth). CAS so a concurrent op can't reserve the same
    /// credits.
    fn reserve_io_len(&self, length: u32) -> u32 {
        let mut bal = self.credits.load(Ordering::Relaxed);
        loop {
            let len = length.min(credit_affordable_bytes(bal));
            let cost = i64::from(credit_charge_for(len));
            match self.credits.compare_exchange_weak(
                bal,
                bal - cost,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return len,
                Err(actual) => bal = actual,
            }
        }
    }

    /// Bank the credits granted by a response. Every response — including
    /// STATUS_PENDING interims and each message of a compound chain — carries
    /// a `CreditResponse` grant that replenishes the connection's balance.
    fn harvest_credits(&self, hdr: &Header) {
        self.credits
            .fetch_add(i64::from(hdr.credits), Ordering::AcqRel);
    }

    /// Log the first credit-limited batch on this connection — expected on a
    /// fresh connection (grants accumulate as responses arrive) but worth one
    /// line of visibility, without per-batch spam.
    fn note_credit_clamp(&self, want: usize, got: usize) {
        if got < want && !self.credit_clamp_logged.swap(true, Ordering::Relaxed) {
            crate::slog!(
                "[spiceio] smb credit window limited a batch to {got} of {want} request(s); batches grow as grants arrive"
            );
        }
    }

    /// Read exactly `buf.len()` bytes from the stream with a timeout.
    ///
    /// On timeout the stream framing is desynchronized, so we poison the
    /// connection (all future operations fail fast) and drop the underlying
    /// socket to fully close both halves.
    async fn read_exact_timeout(&self, stream: &mut TcpStream, buf: &mut [u8]) -> io::Result<()> {
        if self.poisoned.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "SMB connection poisoned by an earlier transport error",
            ));
        }
        match tokio::time::timeout(SMB_READ_TIMEOUT, stream.read_exact(buf)).await {
            Ok(result) => result.map(|_| ()),
            Err(_) => {
                self.poisoned.store(true, Ordering::Relaxed);
                // Drop the socket to fully close both halves.
                let _ = stream.shutdown().await;
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "SMB server read timed out; connection poisoned",
                ))
            }
        }
    }

    /// Read one SMB2 frame (NetBIOS length + payload) without zero-filling the
    /// payload buffer. `BytesMut::with_capacity` leaves capacity uninit;
    /// `read_buf` fills it. On a 256 KiB pipelined read that saves a full
    /// payload memset per response — free bandwidth the NAS can use instead.
    ///
    /// Timeout / EOF poison the connection the same way `read_exact_timeout`
    /// does: the frame is incomplete, so the stream cannot be reused.
    async fn read_frame(&self, stream: &mut TcpStream) -> io::Result<Bytes> {
        if self.poisoned.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "SMB connection poisoned by an earlier transport error",
            ));
        }
        let mut len_buf = [0u8; 4];
        self.read_exact_timeout(stream, &mut len_buf).await?;
        let msg_len = u32::from_be_bytes(len_buf) as usize;
        if !(SMB2_HEADER_SIZE..=16 * 1024 * 1024).contains(&msg_len) {
            crate::serr!("[spiceio] smb invalid message length: {msg_len}");
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid SMB2 message length: {msg_len}"),
            ));
        }
        let mut msg = BytesMut::with_capacity(msg_len);
        while msg.len() < msg_len {
            if self.poisoned.load(Ordering::Relaxed) {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "SMB connection poisoned by an earlier transport error",
                ));
            }
            match tokio::time::timeout(SMB_READ_TIMEOUT, stream.read_buf(&mut msg)).await {
                Ok(Ok(0)) => {
                    self.poisoned.store(true, Ordering::Relaxed);
                    let _ = stream.shutdown().await;
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "SMB connection closed mid-frame",
                    ));
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    self.poisoned.store(true, Ordering::Relaxed);
                    let _ = stream.shutdown().await;
                    return Err(e);
                }
                Err(_) => {
                    self.poisoned.store(true, Ordering::Relaxed);
                    let _ = stream.shutdown().await;
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "SMB server read timed out; connection poisoned",
                    ));
                }
            }
        }
        // `read_buf` cannot overshoot `capacity`, which we set to `msg_len`.
        Ok(msg.freeze())
    }

    /// Write all of `buf` to the stream with a timeout. A server that stops
    /// draining its receive window under heavy concurrent write load would
    /// otherwise block `write_all` indefinitely (there is no OS write timeout),
    /// hanging the request. On timeout we poison the connection and drop the
    /// socket, mirroring the read path; the pool healer reconnects it.
    async fn write_all_timeout(&self, stream: &mut TcpStream, buf: &[u8]) -> io::Result<()> {
        if self.poisoned.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "SMB connection poisoned by an earlier transport error",
            ));
        }
        match tokio::time::timeout(SMB_WRITE_TIMEOUT, stream.write_all(buf)).await {
            Ok(result) => result,
            Err(_) => {
                self.poisoned.store(true, Ordering::Relaxed);
                let _ = stream.shutdown().await;
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "SMB server write timed out; connection poisoned",
                ))
            }
        }
    }

    /// Vectored write of all slices with the same timeout/poison policy as
    /// `write_all_timeout`. Used by pipelined WRITE so payload bytes stay in
    /// their original buffers (header || data per packet) instead of being
    /// memcpy'd into one contiguous frame.
    async fn write_vectored_all_timeout(
        &self,
        stream: &mut TcpStream,
        mut bufs: &mut [IoSlice<'_>],
    ) -> io::Result<()> {
        if self.poisoned.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "SMB connection poisoned by an earlier transport error",
            ));
        }
        while !bufs.is_empty() {
            // Skip leading empty slices so a zero-byte write is never issued.
            if bufs[0].is_empty() {
                bufs = &mut bufs[1..];
                continue;
            }
            match tokio::time::timeout(SMB_WRITE_TIMEOUT, stream.write_vectored(bufs)).await {
                Ok(Ok(0)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "SMB socket write returned 0 bytes",
                    ));
                }
                Ok(Ok(n)) => {
                    IoSlice::advance_slices(&mut bufs, n);
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    self.poisoned.store(true, Ordering::Relaxed);
                    let _ = stream.shutdown().await;
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "SMB server write timed out; connection poisoned",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Mark the connection poisoned and best-effort shut the socket down. A
    /// failed transport/framing/pipelined/compound op can leave unread responses
    /// queued in the stream; closing the socket lets the server release the
    /// session promptly and ensures the leftover bytes can never be misread as a
    /// later reply (the poisoned flag already blocks reuse until the pool heals).
    async fn poison(&self) {
        self.poisoned.store(true, Ordering::Relaxed);
        let _ = self.stream.lock().await.shutdown().await;
    }

    /// Send a packet and receive the response header plus a zero-copy view of
    /// its body. The whole response lives in the single buffer it was read
    /// into — a 256 KiB read costs one allocation and no payload memcpy.
    ///
    /// The handshake needs the full message (header included) for the preauth
    /// integrity hash; it calls `send_recv_inner` directly and slices the body
    /// off itself, since one is a view of the other.
    async fn send_recv(&self, packet: &[u8]) -> io::Result<(Header, Bytes)> {
        let (header, msg) = self.send_recv_inner(packet).await?;
        Ok((header, msg.slice(SMB2_HEADER_SIZE..)))
    }

    /// Send a packet and receive the full response message (header + body).
    async fn send_recv_inner(&self, packet: &[u8]) -> io::Result<(Header, Bytes)> {
        // Poison on any transport/framing error so the connection is never
        // reused with a desynchronized stream (a partial/leftover frame would
        // otherwise be misread as the next operation's reply).
        let r = self.send_recv_io(packet).await;
        if r.is_err() {
            self.poison().await;
        }
        r
    }

    async fn send_recv_io(&self, packet: &[u8]) -> io::Result<(Header, Bytes)> {
        let expected = Header::decode(packet.get(4..).unwrap_or_default())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid SMB request"))?;
        let mut stream = self.lock_stream().await?;

        // Sign the packet if we have a signing key. We need a writable buffer
        // to sign in-place; `BytesMut::from(&[u8])` is one alloc + one copy
        // (same cost as the previous `to_vec`, but expressed as a typed buffer
        // that mirrors what the pipelined paths do).
        if let Some(ref key) = self.signing_key {
            let mut signed = BytesMut::from(packet);
            sign_packet(&mut signed, key);
            self.write_all_timeout(&mut stream, &signed).await?;
        } else {
            self.write_all_timeout(&mut stream, packet).await?;
        }
        stream.flush().await?;

        // Read responses, looping past STATUS_PENDING interim responses
        loop {
            let msg = self.read_frame(&mut stream).await?;

            let header = Header::decode(&msg).ok_or_else(|| {
                crate::serr!("[spiceio] smb invalid header");
                io::Error::new(io::ErrorKind::InvalidData, "invalid SMB2 header")
            })?;
            validate_reply(&header, expected.message_id, expected.command)?;
            self.harvest_credits(&header);

            // STATUS_PENDING (0x00000103): server is still processing, wait for real response
            if header.status == 0x0000_0103 {
                continue;
            }

            stream.complete = true;
            return Ok((header, msg));
        }
    }

    /// Perform negotiate + session setup (NTLM auth) with signing key derivation.
    async fn negotiate_and_auth(&mut self) -> io::Result<()> {
        // Preauth integrity hash — tracks all handshake messages for key derivation
        let mut preauth_hash = [0u8; 64];

        // ── Step 1: Negotiate ──
        let msg_id = self.next_message_id();
        let hdr = Header::new(Command::Negotiate, msg_id);
        let packet = build_request(&hdr, |buf| {
            encode_negotiate_request(buf, &self.client_guid);
        });

        // Hash the negotiate request (SMB2 message, skip 4-byte NetBIOS header)
        update_preauth_hash(&mut preauth_hash, &packet[4..]);

        let (resp_hdr, resp_raw) = self.send_recv_inner(&packet).await?;
        let resp_body = resp_raw.slice(SMB2_HEADER_SIZE..);
        if NtStatus::from_u32(resp_hdr.status).is_error() {
            // A negotiate NTSTATUS failure is a protocol-level rejection over an
            // already-established TCP connection (e.g. unsupported dialect),
            // typically permanent — surface it as InvalidData, not
            // ConnectionRefused, which the S3 layer treats as a retryable 503.
            // ConnectionRefused is reserved for an actual TCP connect refusal.
            return Err(handshake_error(
                "negotiate",
                resp_hdr.status,
                io::ErrorKind::InvalidData,
            ));
        }

        // Hash the negotiate response
        update_preauth_hash(&mut preauth_hash, &resp_raw);

        let neg_resp = decode_negotiate_response(&resp_body).ok_or_else(|| {
            crate::serr!("[spiceio] smb invalid negotiate response");
            io::Error::new(io::ErrorKind::InvalidData, "invalid negotiate response")
        })?;
        // We only offer (and can only sign for) SMB 3.1.1 — its signing key is
        // derived from the preauth integrity hash, which earlier dialects do
        // not use. A server answering with anything else is misbehaving;
        // continuing would fail with signature errors on every request.
        if neg_resp.dialect_revision != DIALECT_SMB3_1_1 {
            crate::serr!(
                "[spiceio] smb server negotiated unsupported dialect 0x{:04X} (require 3.1.1)",
                neg_resp.dialect_revision
            );
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "server negotiated unsupported SMB dialect 0x{:04X} (require 3.1.1)",
                    neg_resp.dialect_revision
                ),
            ));
        }
        let io_cap = if self.config.max_io_size > 0 {
            self.config.max_io_size
        } else {
            DEFAULT_MAX_IO
        };
        crate::slog!(
            "[spiceio] negotiated SMB 0x{:04X}, server_max={}K io_cap={}K",
            neg_resp.dialect_revision,
            neg_resp.max_read_size / 1024,
            io_cap / 1024,
        );

        // ── Step 2: Session Setup (NTLM Negotiate) ──
        let ntlm_negotiate = auth::build_negotiate_message();
        let spnego_negotiate = auth::wrap_spnego_negotiate(&ntlm_negotiate);

        let msg_id = self.next_message_id();
        let mut hdr = Header::new(Command::SessionSetup, msg_id);
        let packet = build_request(&hdr, |buf| {
            encode_session_setup_request(buf, &spnego_negotiate);
        });

        // Hash session setup request 1
        update_preauth_hash(&mut preauth_hash, &packet[4..]);

        let (resp_hdr, resp_raw) = self.send_recv_inner(&packet).await?;
        let resp_body = resp_raw.slice(SMB2_HEADER_SIZE..);

        // The first session-setup leg should return MORE_PROCESSING_REQUIRED
        // carrying the NTLM challenge. The session is allocated on this leg, so a
        // server at capacity refuses *here* — classify any other error status
        // (commonly server capacity) as a typed, retryable error instead of
        // failing to parse a challenge out of an error body (which surfaced as a
        // hard InvalidData 500 and stopped the pool from shrinking).
        let status1 = NtStatus::from_u32(resp_hdr.status);
        if status1.is_error() && status1 != NtStatus::MoreProcessingRequired {
            return Err(handshake_error(
                "session setup",
                resp_hdr.status,
                io::ErrorKind::PermissionDenied,
            ));
        }

        // Hash session setup response 1
        update_preauth_hash(&mut preauth_hash, &resp_raw);

        let sess_resp = decode_session_setup_response(&resp_hdr, &resp_body).ok_or_else(|| {
            crate::serr!("[spiceio] smb invalid session setup response");
            io::Error::new(io::ErrorKind::InvalidData, "invalid session setup response")
        })?;

        // Parse NTLM challenge from SPNEGO wrapper
        let challenge_data = auth::unwrap_spnego(&sess_resp.security_buffer);
        let challenge = auth::parse_challenge_message(challenge_data).ok_or_else(|| {
            crate::serr!("[spiceio] smb invalid NTLM challenge");
            io::Error::new(io::ErrorKind::InvalidData, "invalid NTLM challenge")
        })?;

        // ── Step 3: Session Setup (NTLM Auth) ──
        let (ntlm_auth, session_base_key) = auth::build_authenticate_message(
            &challenge,
            &self.config.username,
            &self.config.password,
            &self.config.domain,
            &self.config.workstation,
        );
        let spnego_auth = auth::wrap_spnego_auth(&ntlm_auth);

        let msg_id = self.next_message_id();
        hdr = Header::new(Command::SessionSetup, msg_id);
        hdr.session_id = sess_resp.session_id;
        let packet = build_request(&hdr, |buf| {
            encode_session_setup_request(buf, &spnego_auth);
        });

        // Hash session setup request 2 (this is the final hash for key derivation)
        update_preauth_hash(&mut preauth_hash, &packet[4..]);

        let (resp_hdr, _) = self.send_recv(&packet).await?;
        if NtStatus::from_u32(resp_hdr.status).is_error() {
            return Err(handshake_error(
                "session setup",
                resp_hdr.status,
                io::ErrorKind::PermissionDenied,
            ));
        }

        // Derive the signing key
        let signing_key = auth::derive_signing_key(&session_base_key, &preauth_hash);
        crate::slog!("[spiceio] authenticated, signing key derived");

        self.session_id = resp_hdr.session_id;
        let io_cap = if self.config.max_io_size > 0 {
            self.config.max_io_size
        } else {
            DEFAULT_MAX_IO
        };
        let sizes = effective_io_sizes(
            neg_resp.max_read_size,
            neg_resp.max_write_size,
            neg_resp.max_transact_size,
            io_cap,
            |name, value| {
                crate::serr!(
                    "[spiceio] smb negotiated {name}={value} — substituting io_cap={io_cap}"
                );
            },
        );
        self.max_read_size = sizes.max_read;
        self.max_write_size = sizes.max_write;
        self.compound_max_read_size = sizes.compound_max_read;
        self.compound_max_write_size = sizes.compound_max_write;
        self.query_dir_buffer = query_dir_buffer(neg_resp.max_transact_size);
        self.signing_key = Some(signing_key);
        Ok(())
    }

    /// Connect to a share (Tree Connect).
    pub async fn tree_connect(&self, share: &str) -> io::Result<u32> {
        let path = self.config.share_path(share);
        let msg_id = self.next_message_id();
        let mut hdr = Header::new(Command::TreeConnect, msg_id);
        hdr.session_id = self.session_id;

        let packet = build_request(&hdr, |buf| {
            encode_tree_connect_request(buf, &path);
        });

        let (resp_hdr, _resp_body) = self.send_recv(&packet).await?;
        if NtStatus::from_u32(resp_hdr.status).is_error() {
            return Err(handshake_error(
                &format!("tree connect to '{share}'"),
                resp_hdr.status,
                io::ErrorKind::NotFound,
            ));
        }

        crate::slog!(
            "[spiceio] smb tree connected: \\\\{}\\{}",
            self.config.server,
            share
        );
        Ok(resp_hdr.tree_id)
    }

    /// Send an SMB2 ECHO and wait for the reply — the protocol's keepalive.
    ///
    /// Used by the pool to probe connections that have gone idle: an SMB
    /// session dropped while idle (server timeout, NAS reboot, NAT/firewall
    /// eviction) is otherwise invisible until a client request lands on it and
    /// fails. A completed round trip proves the connection still carries
    /// traffic; a transport failure poisons it (via `send_recv`) so the healer
    /// reconnects it *before* a request arrives.
    ///
    /// The reply's *status* is classified rather than ignored, because the
    /// whole point of probing is to learn that a session died:
    ///
    /// * A session-invalidating status means the server has forgotten this
    ///   session — exactly the condition the probe exists to catch. Poison the
    ///   connection so the healer replaces it; every request that lands here
    ///   would otherwise fail forever.
    /// * A not-supported status means the server dislikes ECHO but is fine.
    ///   Stop probing this connection rather than repeating the complaint
    ///   every interval.
    /// * Anything else: the frame round-tripped, which proves liveness. Log it
    ///   and keep probing.
    pub async fn echo(&self) -> io::Result<()> {
        let msg_id = self.next_message_id();
        let mut hdr = Header::new(Command::Echo, msg_id);
        hdr.session_id = self.session_id;

        let packet = build_request(&hdr, encode_echo_request);
        let (resp_hdr, _) = self.send_recv(&packet).await?;
        let status = resp_hdr.status;
        if is_session_invalid_status(status) {
            self.poison().await;
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                format!("smb session is no longer valid (echo returned 0x{status:08X})"),
            ));
        }
        if is_echo_unsupported_status(status) {
            self.echoes_ok.store(false, Ordering::Relaxed);
            crate::slog!(
                "[spiceio] smb server does not support keepalive echo (0x{status:08X}); disabling it for this connection"
            );
        } else if NtStatus::from_u32(status).is_error() {
            crate::slog!("[spiceio] smb echo answered with status 0x{status:08X}");
        }
        Ok(())
    }

    /// Whether keepalive probes are still worth sending on this connection —
    /// false once the server has rejected one.
    pub fn echoes_ok(&self) -> bool {
        self.echoes_ok.load(Ordering::Relaxed)
    }

    /// Fetch the 24-byte resume key that identifies an open file to the server
    /// as a server-side copy *source*.
    pub async fn request_resume_key(
        &self,
        tree_id: u32,
        file_id: &[u8; 16],
    ) -> io::Result<[u8; 24]> {
        // 32 bytes of output is the documented response size; one credit.
        const RESUME_KEY_OUTPUT: u32 = 32;
        let msg_id = self.alloc_ids(1);
        let mut hdr = Header::new(Command::Ioctl, msg_id);
        hdr.session_id = self.session_id;
        hdr.tree_id = tree_id;

        let packet = build_request(&hdr, |buf| {
            encode_ioctl_request(
                buf,
                FSCTL_SRV_REQUEST_RESUME_KEY,
                file_id,
                &[],
                RESUME_KEY_OUTPUT,
            );
        });

        let (resp_hdr, resp_body) = self.send_recv(&packet).await?;
        if NtStatus::from_u32(resp_hdr.status).is_error() {
            return Err(ioctl_error("resume key", resp_hdr.status));
        }
        // A reply we cannot parse is reported as unsupported rather than a hard
        // error: the caller then streams the copy, which is always correct.
        // Failing instead would turn a server quirk into a broken CopyObject.
        decode_ioctl_output(&resp_body)
            .and_then(decode_resume_key)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "server returned an unparseable resume key",
                )
            })
    }

    /// Ask the server to copy `chunks` from the resume-key'd source into
    /// `dst_file_id`, without the data crossing this connection.
    ///
    /// A server that does not implement copychunk answers with a
    /// not-supported status, which surfaces as `Unsupported` so the caller can
    /// fall back to streaming. `STATUS_INVALID_PARAMETER` is special-cased by
    /// MS-SMB2: the response body then carries the server's chunk limits
    /// rather than a result, so it is reported as `InvalidInput` with those
    /// limits in the message.
    pub async fn copychunk(
        &self,
        tree_id: u32,
        dst_file_id: &[u8; 16],
        resume_key: &[u8; 24],
        chunks: &[CopyChunk],
    ) -> io::Result<CopyChunkResponse> {
        // The response is a 12-byte SRV_COPYCHUNK_RESPONSE; one credit covers
        // it, but the *request* carries the chunk list, so charge for that.
        const COPYCHUNK_OUTPUT: u32 = 64;
        let mut input = BytesMut::with_capacity(32 + chunks.len() * 24);
        encode_copychunk_input(&mut input, resume_key, chunks);

        let msg_id = self.alloc_ids(1);
        let mut hdr = Header::new(Command::Ioctl, msg_id);
        hdr.session_id = self.session_id;
        hdr.tree_id = tree_id;

        let packet = build_request(&hdr, |buf| {
            encode_ioctl_request(
                buf,
                FSCTL_SRV_COPYCHUNK_WRITE,
                dst_file_id,
                &input,
                COPYCHUNK_OUTPUT,
            );
        });

        let (resp_hdr, resp_body) = self.send_recv(&packet).await?;
        if NtStatus::from_u32(resp_hdr.status).is_error() {
            // On STATUS_INVALID_PARAMETER the payload is the server's limits.
            if resp_hdr.status == 0xC000_000D
                && let Some(limits) =
                    decode_ioctl_output(&resp_body).and_then(decode_copychunk_response)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "copychunk limits exceeded: max {} chunks, {} bytes/chunk, {} bytes total",
                        limits.chunks_written,
                        limits.chunk_bytes_written,
                        limits.total_bytes_written
                    ),
                ));
            }
            return Err(ioctl_error("copychunk", resp_hdr.status));
        }
        decode_ioctl_output(&resp_body)
            .and_then(decode_copychunk_response)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "server returned an unparseable copychunk response",
                )
            })
    }

    /// Open a file or directory.
    pub async fn create(
        &self,
        tree_id: u32,
        path: &str,
        desired_access: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
    ) -> io::Result<CreateResponse> {
        let msg_id = self.next_message_id();
        let mut hdr = Header::new(Command::Create, msg_id);
        hdr.session_id = self.session_id;
        hdr.tree_id = tree_id;

        let packet = build_request(&hdr, |buf| {
            encode_create_request(
                buf,
                path,
                desired_access,
                share_access,
                create_disposition,
                create_options,
            );
        });

        let (resp_hdr, resp_body) = self.send_recv(&packet).await?;
        let status = NtStatus::from_u32(resp_hdr.status);
        if status.is_error() {
            return Err(smb_status_to_io_error(resp_hdr.status, path));
        }

        decode_create_response(&resp_body).ok_or_else(|| {
            // Status was "success" but the body is unusable — almost always a
            // desynced stream after a prior mid-response disconnect (or a
            // server that returned an empty success). Log enough to tell those
            // apart from a real codec bug.
            crate::serr!(
                "[spiceio] smb invalid create response: {path} status=0x{:08X} body_len={}",
                resp_hdr.status,
                resp_body.len()
            );
            io::Error::new(io::ErrorKind::InvalidData, "invalid create response")
        })
    }

    /// Close a file handle and return the file's final attributes.
    ///
    /// SMB2 CLOSE can carry the post-close size and timestamp
    /// (`SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB`), so a caller that needs them right
    /// after writing gets them for free instead of paying a separate stat
    /// round trip. Servers may decline to fill them in, in which case the
    /// fields come back zero and the caller should stat.
    pub async fn close_query(&self, tree_id: u32, file_id: &[u8; 16]) -> io::Result<CloseResponse> {
        let msg_id = self.next_message_id();
        let mut hdr = Header::new(Command::Close, msg_id);
        hdr.session_id = self.session_id;
        hdr.tree_id = tree_id;

        let packet = build_request(&hdr, |buf| {
            encode_close_request_ex(buf, file_id, true);
        });

        let (resp_hdr, resp_body) = self.send_recv(&packet).await?;
        if NtStatus::from_u32(resp_hdr.status).is_error() {
            crate::serr!("[spiceio] smb close failed: 0x{:08X}", resp_hdr.status);
            return Err(io::Error::other(format!(
                "close failed: 0x{:08X}",
                resp_hdr.status
            )));
        }
        Ok(decode_close_response(&resp_body).unwrap_or(CloseResponse {
            last_write_time: 0,
            file_size: 0,
        }))
    }

    /// Close a file handle.
    pub async fn close(&self, tree_id: u32, file_id: &[u8; 16]) -> io::Result<()> {
        let msg_id = self.next_message_id();
        let mut hdr = Header::new(Command::Close, msg_id);
        hdr.session_id = self.session_id;
        hdr.tree_id = tree_id;

        let packet = build_request(&hdr, |buf| {
            encode_close_request(buf, file_id);
        });

        let (resp_hdr, _) = self.send_recv(&packet).await?;
        let status = NtStatus::from_u32(resp_hdr.status);
        if status.is_error() {
            crate::serr!("[spiceio] smb close failed: 0x{:08X}", resp_hdr.status);
            return Err(io::Error::other(format!(
                "close failed: 0x{:08X}",
                resp_hdr.status
            )));
        }
        Ok(())
    }

    /// Read from an open file. May return fewer bytes than requested (EOF, a
    /// short server read, or credit-window clamping) — callers advance by the
    /// returned length and loop.
    pub async fn read(
        &self,
        tree_id: u32,
        file_id: &[u8; 16],
        offset: u64,
        length: u32,
    ) -> io::Result<Bytes> {
        // Atomically reserve credits for (and clamp to) this read, so a
        // multi-credit read never exceeds the granted sequence window even
        // under concurrent callers (floor: one credit's worth).
        let length = self.reserve_io_len(length);
        // Multi-credit commands (payload > 64 KiB) consume `credit_charge`
        // sequence numbers; the credits are already reserved, so just advance
        // the MessageId window by the charge.
        let msg_id = self.alloc_msg_ids(credit_charge_for(length) as u64);
        let mut hdr = Header::new(Command::Read, msg_id).with_credit_charge(length);
        hdr.session_id = self.session_id;
        hdr.tree_id = tree_id;

        let packet = build_request(&hdr, |buf| {
            encode_read_request(buf, file_id, offset, length, 0);
        });

        let (resp_hdr, resp_body) = self.send_recv(&packet).await?;
        let status = NtStatus::from_u32(resp_hdr.status);
        if status == NtStatus::EndOfFile {
            return Ok(Bytes::new());
        }
        if status.is_error() {
            crate::serr!("[spiceio] smb read failed: 0x{:08X}", resp_hdr.status);
            return Err(io::Error::other(format!(
                "read failed: 0x{:08X}",
                resp_hdr.status
            )));
        }

        decode_read_response_bytes(&resp_body).ok_or_else(|| {
            crate::serr!("[spiceio] smb invalid read response");
            io::Error::new(io::ErrorKind::InvalidData, "invalid read response")
        })
    }

    /// Pipelined read: send `count` read requests, then receive all responses.
    ///
    /// Holds the stream lock for the entire batch, eliminating per-request
    /// round-trip latency. Returns chunks in offset order. Stops early on EOF.
    ///
    /// Coalesces all request packets into a single contiguous buffer and signs
    /// each in-place — one allocation, one `write_all` syscall for the whole
    /// batch of request headers (only the responses carry bulk data).
    ///
    /// Responses may arrive out of order (SMB2 does not guarantee response
    /// ordering). Each response is matched to its request slot via message_id.
    /// `remaining` is how many bytes the caller still wants *in total* from
    /// this offset, which becomes the server's read-ahead hint — sized from the
    /// transfer rather than the batch, so the hint does not reset to "nothing
    /// follows" at every batch boundary.
    pub async fn pipelined_read(
        &self,
        tree_id: u32,
        file_id: &[u8; 16],
        start_offset: u64,
        chunk_size: u32,
        count: usize,
        remaining: u64,
    ) -> io::Result<Vec<Bytes>> {
        // Poison on any error: a batch leaves unread responses in the socket on
        // an early return, so the connection must not be reused.
        let r = self
            .pipelined_read_io(tree_id, file_id, start_offset, chunk_size, count, remaining)
            .await;
        if r.is_err() {
            self.poison().await;
        }
        r
    }

    async fn pipelined_read_io(
        &self,
        tree_id: u32,
        file_id: &[u8; 16],
        start_offset: u64,
        chunk_size: u32,
        count: usize,
        remaining: u64,
    ) -> io::Result<Vec<Bytes>> {
        if count == 0 || remaining == 0 {
            return Ok(Vec::new());
        }
        // Defensive guard: a zero `chunk_size` would panic later on
        // `remaining.div_ceil(chunk_size as u64)` in callers, and would
        // make this function issue `count` duplicate reads at the same
        // offset. Callers are expected to have validated already, but
        // we treat this as a hard error rather than UB.
        if chunk_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pipelined_read called with chunk_size = 0",
            ));
        }

        // Multi-credit reads consume `credit_charge` sequence numbers each, so
        // the MessageId window advances by count * charge and requests are
        // spaced by `charge`. A response maps to its slot via that stride.
        //
        // Clamp the batch to the credit balance: a batch whose total charge
        // exceeds the server's grants violates the sequence window (servers
        // disconnect under exactly the heavy load where it matters). Callers
        // loop on the returned chunks, so a shortened batch simply means the
        // next batch resumes from the new offset with a replenished balance.
        let chunk_size = chunk_size.min(remaining.min(u64::from(u32::MAX)) as u32);
        let count = count.min(remaining.div_ceil(u64::from(chunk_size)) as usize);
        let charge = credit_charge_for(chunk_size) as u64;
        let want = count;
        let count = self.reserve_request_count(charge as u16, count);
        self.note_credit_clamp(want, count);
        let lengths: Vec<u32> = (0..count)
            .map(|i| {
                (remaining - i as u64 * u64::from(chunk_size)).min(u64::from(chunk_size)) as u32
            })
            .collect();
        // Only the last request can be short. Return its excess reservation
        // and advance MessageIds by the charge actually sent on the wire.
        let refund = charge - u64::from(credit_charge_for(lengths[count - 1]));
        self.credits.fetch_add(refund as i64, Ordering::AcqRel);
        let base_msg_id = self.alloc_msg_ids(count as u64 * charge - refund);

        // Each request: 4 (NetBIOS length) + SMB2_HEADER_SIZE (64) + 49
        // (read request fixed part incl. 1-byte buffer pad).
        const READ_REQUEST_FIXED: usize = 49;
        let per_packet = 4 + SMB2_HEADER_SIZE + READ_REQUEST_FIXED;
        let mut buf = BytesMut::with_capacity(per_packet * count);
        let mut packet_starts: Vec<usize> = Vec::with_capacity(count + 1);

        for (i, &length) in lengths.iter().enumerate() {
            packet_starts.push(buf.len());
            let offset = start_offset + (i as u64) * (chunk_size as u64);
            // Tell the server how much the caller still wants after this
            // request, so it can read ahead instead of waiting for the next one.
            let consumed = (i as u64 + 1).saturating_mul(u64::from(chunk_size));
            let remaining_after =
                u32::try_from(remaining.saturating_sub(consumed)).unwrap_or(u32::MAX);
            let msg_id = base_msg_id + i as u64 * charge;
            let mut hdr = Header::new(Command::Read, msg_id).with_credit_charge(length);
            hdr.session_id = self.session_id;
            hdr.tree_id = tree_id;

            let packet_smb_total = SMB2_HEADER_SIZE + READ_REQUEST_FIXED;
            buf.put_u32((packet_smb_total as u32) & 0x00FF_FFFF);
            hdr.encode(&mut buf);
            encode_read_request(&mut buf, file_id, offset, length, remaining_after);
        }
        packet_starts.push(buf.len());

        if let Some(ref key) = self.signing_key {
            for i in 0..count {
                let start = packet_starts[i];
                let end = packet_starts[i + 1];
                sign_packet(&mut buf[start..end], key);
            }
        }

        let mut stream = self.lock_stream().await?;
        self.write_all_timeout(&mut stream, &buf).await?;
        stream.flush().await?;

        // Receive responses into ordered slots (handles out-of-order delivery).
        let mut slots: Vec<Option<Bytes>> = (0..count).map(|_| None).collect();
        let mut received = 0usize;
        let mut eof_after = count; // trim to this length on EOF

        while received < count {
            // Non-zeroing frame read: capacity is uninit until the socket fills
            // it, so a 256 KiB × 16 pipeline no longer pays 4 MiB of memset.
            let msg = self.read_frame(&mut stream).await?;

            let header = Header::decode(&msg)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid SMB2 header"))?;
            self.harvest_credits(&header);

            let delta = header.message_id.wrapping_sub(base_msg_id);
            if delta % charge != 0 || (delta / charge) as usize >= count {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "unexpected message_id {} (base={}, count={}, charge={})",
                        header.message_id, base_msg_id, count, charge
                    ),
                ));
            }
            let slot = (delta / charge) as usize;
            validate_reply(
                &header,
                base_msg_id + slot as u64 * charge,
                Command::Read as u16,
            )?;
            if header.status == 0x0000_0103 {
                continue;
            }
            if slots[slot].is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate SMB read reply",
                ));
            }

            let status = NtStatus::from_u32(header.status);
            if status == NtStatus::EndOfFile {
                // This slot and all later slots are past EOF
                eof_after = eof_after.min(slot);
                slots[slot] = Some(Bytes::new());
                received += 1;
                continue;
            }
            if status.is_error() {
                return Err(io::Error::other(format!(
                    "pipelined read failed: 0x{:08X}",
                    header.status
                )));
            }

            // Zero-copy: the frame is already `Bytes`; the decoder slices the
            // payload out without a body memcpy.
            let data = decode_read_response_from_msg(msg).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid read response")
            })?;
            if data.len() > lengths[slot] as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SMB read exceeds requested length",
                ));
            }
            if data.len() < lengths[slot] as usize {
                // Later reads start after a gap. Drain them, but let the
                // caller resume at the end of this contiguous prefix.
                eof_after = eof_after.min(slot + 1);
            }
            slots[slot] = Some(data);
            received += 1;
        }

        stream.complete = true;
        // Collect in order, stopping at EOF or the first short read.
        Ok(slots
            .into_iter()
            .take(eof_after)
            .map(|s| s.unwrap_or_default())
            .collect())
    }

    /// Write all of `data` to an open file. Returns `data.len()` on success —
    /// short server writes and credit-window clamping are handled internally
    /// by resuming from the acknowledged count, so a success never leaves a
    /// silent gap (callers track offsets by the data they passed).
    pub async fn write(
        &self,
        tree_id: u32,
        file_id: &[u8; 16],
        offset: u64,
        data: &[u8],
    ) -> io::Result<u32> {
        let mut sent = 0usize;
        while sent < data.len() {
            // Atomically reserve credits for (and clamp) each sub-write, so it
            // never exceeds the granted window under concurrent callers (floor:
            // one credit). `write_once` then only advances the MessageId window.
            let want = (data.len() - sent).min(u32::MAX as usize) as u32;
            let take = self.reserve_io_len(want) as usize;
            let written = self
                .write_once(
                    tree_id,
                    file_id,
                    offset + sent as u64,
                    &data[sent..sent + take],
                )
                .await?;
            if written == 0 {
                // A "success" that wrote nothing would loop forever.
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "SMB write reported 0 bytes written",
                ));
            }
            sent += written as usize;
        }
        Ok(data.len() as u32)
    }

    /// Send one WRITE request (no splitting). Returns the server-acknowledged
    /// byte count, which may be short.
    async fn write_once(
        &self,
        tree_id: u32,
        file_id: &[u8; 16],
        offset: u64,
        data: &[u8],
    ) -> io::Result<u32> {
        // Credits were reserved by the caller (`write`) via `reserve_io_len`;
        // just advance the MessageId window by this request's charge.
        let msg_id = self.alloc_msg_ids(credit_charge_for(data.len() as u32) as u64);
        let mut hdr = Header::new(Command::Write, msg_id).with_credit_charge(data.len() as u32);
        hdr.session_id = self.session_id;
        hdr.tree_id = tree_id;

        let packet = build_request(&hdr, |buf| {
            encode_write_request(buf, file_id, offset, data);
        });

        let (resp_hdr, resp_body) = self.send_recv(&packet).await?;
        // Check raw status: high two bits indicate severity
        // 0x00 = success, 0x40 = info, 0x80 = warning, 0xC0 = error
        if resp_hdr.status & 0xC000_0000 == 0xC000_0000 {
            crate::serr!(
                "[spiceio] smb write failed: 0x{:08X} offset={} len={}",
                resp_hdr.status,
                offset,
                data.len()
            );
            return Err(io::Error::other(format!(
                "write failed: status=0x{:08X} offset={} len={}",
                resp_hdr.status,
                offset,
                data.len()
            )));
        }

        decode_write_response(&resp_body)
            .filter(|&n| n as usize <= data.len())
            .ok_or_else(|| {
                crate::serr!("[spiceio] smb invalid write response");
                io::Error::new(io::ErrorKind::InvalidData, "invalid write response")
            })
    }

    /// Pipelined write: send `chunks` write requests in a batch, then receive
    /// all responses. Holds the stream lock for the entire batch, eliminating
    /// per-request round-trip latency. Returns the contiguous prefix written;
    /// callers retry the suffix after a short response, including later slots.
    ///
    /// Headers are packed into one small buffer and signed with multi-slice
    /// CMAC over `header || payload`; the payload is writev'd from the caller's
    /// slices (no data memcpy into the frame). Responses may arrive out of
    /// order; each is matched by message_id.
    pub async fn pipelined_write(
        &self,
        tree_id: u32,
        file_id: &[u8; 16],
        start_offset: u64,
        chunks: &[&[u8]],
    ) -> io::Result<u64> {
        // Poison on any error: an early return leaves unread write responses in
        // the socket, so the connection must not be reused.
        let r = self
            .pipelined_write_io(tree_id, file_id, start_offset, chunks)
            .await;
        if r.is_err() {
            self.poison().await;
        }
        r
    }

    async fn pipelined_write_io(
        &self,
        tree_id: u32,
        file_id: &[u8; 16],
        start_offset: u64,
        chunks: &[&[u8]],
    ) -> io::Result<u64> {
        if chunks.is_empty() {
            return Ok(0);
        }

        // Multi-credit writes consume `credit_charge` sequence numbers each;
        // advance the window by the total charge and space each request by its
        // own charge (chunks may differ in size, e.g. a short final chunk).
        //
        // Clamp the batch to the longest chunk prefix whose total charge fits
        // the credit balance (always at least one chunk) — more in-flight
        // charge than the server granted violates the sequence window.
        // Callers advance by the returned byte count and re-send the
        // remainder, so a shortened batch self-heals on the next window.
        let (take, total_charge) = self.reserve_chunk_prefix(chunks);
        self.note_credit_clamp(chunks.len(), take);
        let chunks = &chunks[..take];
        let n = chunks.len();
        let base_msg_id = self.alloc_msg_ids(total_charge);

        // Header-only framing: 4 (NetBIOS) + SMB2_HEADER_SIZE (64) + 48
        // (write request fixed part). Payload rides as a separate IoSlice.
        const WRITE_REQUEST_FIXED: usize = 48;
        const HEADER_LEN: usize = 4 + SMB2_HEADER_SIZE + WRITE_REQUEST_FIXED;
        let mut headers = BytesMut::with_capacity(HEADER_LEN * n);
        let mut header_starts: Vec<usize> = Vec::with_capacity(n + 1);

        let mut offset = start_offset;
        let mut cum_charge = 0u64;
        let mut message_ids = Vec::with_capacity(n);
        for chunk in chunks.iter() {
            header_starts.push(headers.len());
            let msg_id = base_msg_id + cum_charge;
            message_ids.push(msg_id);
            cum_charge += credit_charge_for(chunk.len() as u32) as u64;
            let mut hdr =
                Header::new(Command::Write, msg_id).with_credit_charge(chunk.len() as u32);
            hdr.session_id = self.session_id;
            hdr.tree_id = tree_id;

            let packet_smb_total = SMB2_HEADER_SIZE + WRITE_REQUEST_FIXED + chunk.len();
            headers.put_u32((packet_smb_total as u32) & 0x00FF_FFFF);
            hdr.encode(&mut headers);
            encode_write_request_header(&mut headers, file_id, offset, chunk.len() as u32);
            offset += chunk.len() as u64;
        }
        header_starts.push(headers.len());

        // Sign each packet as header||payload without copying the payload.
        if let Some(ref key) = self.signing_key {
            for i in 0..n {
                let start = header_starts[i];
                let end = header_starts[i + 1];
                sign_packet_parts(&mut headers[start..end], chunks[i], key);
            }
        }

        // writev: [hdr0, data0, hdr1, data1, ...]
        let mut slices: Vec<IoSlice<'_>> = Vec::with_capacity(n * 2);
        for i in 0..n {
            let start = header_starts[i];
            let end = header_starts[i + 1];
            slices.push(IoSlice::new(&headers[start..end]));
            slices.push(IoSlice::new(chunks[i]));
        }

        let mut stream = self.lock_stream().await?;
        self.write_vectored_all_timeout(&mut stream, &mut slices)
            .await?;
        stream.flush().await?;

        // Receive all responses (handles out-of-order delivery)
        let mut counts = vec![None; n];
        let mut received = 0usize;
        while received < n {
            let msg = self.read_frame(&mut stream).await?;

            let header = Header::decode(&msg)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid SMB2 header"))?;
            self.harvest_credits(&header);

            let slot = message_ids.binary_search(&header.message_id).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "unexpected SMB write MessageId")
            })?;
            validate_reply(&header, message_ids[slot], Command::Write as u16)?;

            if header.status == 0x0000_0103 {
                continue;
            }
            if counts[slot].is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate SMB write reply",
                ));
            }

            if header.status & 0xC000_0000 == 0xC000_0000 {
                return Err(io::Error::other(format!(
                    "pipelined write failed: 0x{:08X}",
                    header.status
                )));
            }

            let body = &msg[SMB2_HEADER_SIZE..];
            let written = decode_write_response(body).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid write response")
            })?;
            if written as usize > chunks[slot].len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SMB write exceeds requested length",
                ));
            }
            counts[slot] = Some(written);
            received += 1;
        }

        stream.complete = true;
        let mut contiguous = 0;
        for (count, chunk) in counts.into_iter().zip(chunks) {
            let written = count.expect("every response was received");
            contiguous += u64::from(written);
            if written as usize != chunk.len() {
                break;
            }
        }
        Ok(contiguous)
    }

    /// Rename a file using SET_INFO with FileRenameInformation.
    pub async fn rename(
        &self,
        tree_id: u32,
        file_id: &[u8; 16],
        new_path: &str,
        replace_if_exists: bool,
    ) -> io::Result<()> {
        let msg_id = self.next_message_id();
        let mut hdr = Header::new(Command::SetInfo, msg_id);
        hdr.session_id = self.session_id;
        hdr.tree_id = tree_id;

        let packet = build_request(&hdr, |buf| {
            encode_set_info_rename(buf, file_id, new_path, replace_if_exists);
        });

        let (resp_hdr, _) = self.send_recv(&packet).await?;
        if resp_hdr.status & 0xC000_0000 == 0xC000_0000 {
            crate::serr!(
                "[spiceio] smb rename failed: 0x{:08X} -> {}",
                resp_hdr.status,
                new_path
            );
            return Err(io::Error::other(format!(
                "rename failed: status=0x{:08X} -> {}",
                resp_hdr.status, new_path
            )));
        }
        Ok(())
    }

    /// List directory contents.
    ///
    /// Pages the QUERY_DIRECTORY conversation under one stream lock. After each
    /// non-final page the next request is written *before* the current page is
    /// parsed, so parse CPU overlaps with the server's next-page RTT on wide
    /// directories (1 MiB pages).
    pub async fn query_directory(
        &self,
        tree_id: u32,
        file_id: &[u8; 16],
        pattern: &str,
    ) -> io::Result<Vec<DirectoryEntry>> {
        // Transport/framing errors poison; NTSTATUS protocol errors do not
        // (the stream is still synchronized — we consumed the response).
        match self.query_directory_io(tree_id, file_id, pattern).await {
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::BrokenPipe
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::InvalidData
                ) =>
            {
                self.poison().await;
                Err(e)
            }
            other => other,
        }
    }

    async fn query_directory_io(
        &self,
        tree_id: u32,
        file_id: &[u8; 16],
        pattern: &str,
    ) -> io::Result<Vec<DirectoryEntry>> {
        let mut all_entries = Vec::new();
        let mut stream = self.lock_stream().await?;

        // Helper: allocate credits + build a signed packet.
        let build_packet = |this: &Self, restart: bool| -> (u64, BytesMut) {
            let out_len = this.reserve_io_len(this.query_dir_buffer);
            let charge = credit_charge_for(out_len);
            let msg_id = this.alloc_msg_ids(charge as u64);
            let mut hdr = Header::new(Command::QueryDirectory, msg_id).with_credit_charge(out_len);
            hdr.session_id = this.session_id;
            hdr.tree_id = tree_id;
            let mut packet = build_request(&hdr, |buf| {
                encode_query_directory_request(
                    buf,
                    file_id,
                    pattern,
                    FILE_ID_BOTH_DIRECTORY_INFORMATION,
                    restart,
                    out_len,
                );
            });
            if let Some(ref key) = this.signing_key {
                sign_packet(&mut packet, key);
            }
            (msg_id, packet)
        };

        // Send the first page (restart = true).
        let mut expected_id;
        {
            let (id, packet) = build_packet(self, true);
            expected_id = id;
            self.write_all_timeout(&mut stream, &packet).await?;
            stream.flush().await?;
        }

        loop {
            // Read response (skip STATUS_PENDING interim replies).
            let (resp_hdr, msg) = loop {
                let msg = self.read_frame(&mut stream).await?;
                let header = Header::decode(&msg).ok_or_else(|| {
                    crate::serr!("[spiceio] smb invalid header");
                    io::Error::new(io::ErrorKind::InvalidData, "invalid SMB2 header")
                })?;
                validate_reply(&header, expected_id, Command::QueryDirectory as u16)?;
                self.harvest_credits(&header);
                if header.status == 0x0000_0103 {
                    continue;
                }
                break (header, msg);
            };
            let status = NtStatus::from_u32(resp_hdr.status);

            if status == NtStatus::NoMoreFiles {
                break;
            }
            if status.is_error() {
                stream.complete = true;
                crate::serr!(
                    "[spiceio] smb query directory failed: 0x{:08X}",
                    resp_hdr.status
                );
                return Err(io::Error::other(format!(
                    "query directory failed: 0x{:08X}",
                    resp_hdr.status
                )));
            }

            // Prefetch: write the next page request before parsing this one so
            // the server is already working while we walk entries. The final
            // STATUS_NO_MORE_FILES response is expected and cheap.
            {
                let (id, packet) = build_packet(self, false);
                expected_id = id;
                self.write_all_timeout(&mut stream, &packet).await?;
                stream.flush().await?;
            }

            let resp_body = &msg[SMB2_HEADER_SIZE..];
            if resp_body.len() >= 9 {
                let buf_offset = (&resp_body[2..4] as &[u8]).get_u16_le() as usize;
                let buf_length = (&resp_body[4..8] as &[u8]).get_u32_le() as usize;
                let start = buf_offset.saturating_sub(SMB2_HEADER_SIZE);
                let end = (start + buf_length).min(resp_body.len());
                if start < end {
                    let entries = parse_directory_entries(&resp_body[start..end]);
                    all_entries.extend(entries);
                }
            }
        }

        stream.complete = true;
        Ok(all_entries)
    }

    // ── Compound operations (multiple SMB ops in one round trip) ────────

    /// Send a compound request and parse the compound response.
    ///
    /// Caller sets `SMB2_FLAGS_RELATED` on related-chain requests.
    /// This method handles `NextCommand` offsets, signing, and framing.
    async fn send_compound(
        &self,
        requests: Vec<(Header, BytesMut)>,
    ) -> io::Result<Vec<(Header, Bytes)>> {
        // Poison on any transport/framing error so a desynchronized compound
        // stream is never reused.
        let r = self.send_compound_io(requests).await;
        if r.is_err() {
            self.poison().await;
        }
        r
    }

    async fn send_compound_io(
        &self,
        requests: Vec<(Header, BytesMut)>,
    ) -> io::Result<Vec<(Header, Bytes)>> {
        let n = requests.len();
        let expected: Vec<_> = requests
            .iter()
            .map(|(h, _)| (h.message_id, h.command))
            .collect();

        // Padded message sizes (8-byte aligned except last).
        let sizes: Vec<usize> = requests
            .iter()
            .enumerate()
            .map(|(i, (_, body))| {
                let raw = SMB2_HEADER_SIZE + body.len();
                if i < n - 1 {
                    raw + (8 - raw % 8) % 8
                } else {
                    raw
                }
            })
            .collect();

        let total: usize = sizes.iter().sum();
        let mut buf = BytesMut::with_capacity(4 + total);
        buf.put_u32((total as u32) & 0x00FF_FFFF); // NetBIOS length (big-endian, masked to 24 bits)

        for (i, (mut header, body)) in requests.into_iter().enumerate() {
            let body_len = body.len();
            header.next_command = if i < n - 1 { sizes[i] as u32 } else { 0 };

            let msg_start = buf.len();
            header.encode(&mut buf);
            buf.put_slice(&body);

            // Pad to 8-byte alignment
            let pad = sizes[i] - SMB2_HEADER_SIZE - body_len;
            if pad > 0 {
                buf.extend_from_slice(&[0u8; 7][..pad]);
            }

            // Sign this message
            if let Some(ref key) = self.signing_key {
                sign_message(&mut buf[msg_start..msg_start + sizes[i]], key);
            }
        }

        // Send and receive under the stream lock
        let mut stream = self.lock_stream().await?;
        self.write_all_timeout(&mut stream, &buf).await?;
        stream.flush().await?;

        // Read response frames, skipping STATUS_PENDING interim responses
        loop {
            let msg = self.read_frame(&mut stream).await?;

            // Single STATUS_PENDING interim — skip, but bank its credit grant
            if let Some(h) = Header::decode(&msg)
                && h.status == 0x0000_0103
                && h.next_command == 0
            {
                if !expected.contains(&(h.message_id, h.command)) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected pending compound reply",
                    ));
                }
                self.harvest_credits(&h);
                continue;
            }

            // Each message of the compound chain carries its own grant.
            let responses = parse_compound_response(&msg);
            if responses.is_empty() || responses.len() > expected.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid compound response count",
                ));
            }
            for ((h, _), &(id, command)) in responses.iter().zip(&expected) {
                validate_reply(h, id, command)?;
                self.harvest_credits(h);
            }
            stream.complete = true;
            return Ok(responses);
        }
    }

    /// Compound Create + Close (1 round trip). Returns create and close
    /// metadata. Used for head_object and delete_object.
    pub async fn create_close(
        &self,
        tree_id: u32,
        path: &str,
        desired_access: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
    ) -> io::Result<(CreateResponse, CloseResponse)> {
        // Compound ops are ≤ 64 KiB (effective_io_sizes clamps the compound
        // caps), so every chained request charges exactly 1 credit and the
        // MessageId stride equals the message count.
        let base = self.alloc_ids(2);

        let mut h1 = Header::new(Command::Create, base);
        h1.session_id = self.session_id;
        h1.tree_id = tree_id;
        let mut b1 = BytesMut::with_capacity(128);
        encode_create_request(
            &mut b1,
            path,
            desired_access,
            share_access,
            create_disposition,
            create_options,
        );

        let mut h2 = Header::new(Command::Close, base + 1);
        h2.session_id = self.session_id;
        h2.tree_id = tree_id;
        h2.flags |= SMB2_FLAGS_RELATED;
        let mut b2 = BytesMut::with_capacity(32);
        encode_close_request_ex(&mut b2, &SENTINEL_FILE_ID, true);

        let resp = self.send_compound(vec![(h1, b1), (h2, b2)]).await?;
        if resp.len() < 2 {
            return Err(compound_too_short(path, &resp, 2));
        }

        if NtStatus::from_u32(resp[0].0.status).is_error() {
            return Err(smb_status_to_io_error(resp[0].0.status, path));
        }
        let cr = decode_create_response(&resp[0].1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid create response"))?;
        if NtStatus::from_u32(resp[1].0.status).is_error() {
            crate::serr!(
                "[spiceio] smb compound close failed: 0x{:08X}",
                resp[1].0.status
            );
        }
        let cl = decode_close_response(&resp[1].1).unwrap_or(CloseResponse {
            last_write_time: cr.last_write_time,
            file_size: cr.file_size,
        });

        Ok((cr, cl))
    }

    /// Compound Create + Read + Close (1 round trip). For small-file reads.
    pub async fn create_read_close(
        &self,
        tree_id: u32,
        path: &str,
        max_read: u32,
    ) -> io::Result<(CreateResponse, Bytes)> {
        // Compound reads are capped at 64 KiB (charge 1), so the three chained
        // messages charge 3 credits and stride 3 MessageIds.
        let base = self.alloc_ids(3);

        let mut h1 = Header::new(Command::Create, base);
        h1.session_id = self.session_id;
        h1.tree_id = tree_id;
        let mut b1 = BytesMut::with_capacity(128);
        encode_create_request(
            &mut b1,
            path,
            DesiredAccess::GenericRead as u32,
            ShareAccess::All as u32,
            CreateDisposition::Open as u32,
            CreateOptions::NonDirectoryFile as u32,
        );

        let mut h2 = Header::new(Command::Read, base + 1).with_credit_charge(max_read);
        h2.session_id = self.session_id;
        h2.tree_id = tree_id;
        h2.flags |= SMB2_FLAGS_RELATED;
        let mut b2 = BytesMut::with_capacity(64);
        encode_read_request(&mut b2, &SENTINEL_FILE_ID, 0, max_read, 0);

        let mut h3 = Header::new(Command::Close, base + 2);
        h3.session_id = self.session_id;
        h3.tree_id = tree_id;
        h3.flags |= SMB2_FLAGS_RELATED;
        let mut b3 = BytesMut::with_capacity(32);
        encode_close_request(&mut b3, &SENTINEL_FILE_ID);

        let resp = self
            .send_compound(vec![(h1, b1), (h2, b2), (h3, b3)])
            .await?;
        if resp.len() < 3 {
            return Err(compound_too_short(path, &resp, 3));
        }

        if NtStatus::from_u32(resp[0].0.status).is_error() {
            return Err(smb_status_to_io_error(resp[0].0.status, path));
        }
        let cr = decode_create_response(&resp[0].1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid create response"))?;

        let data = if NtStatus::from_u32(resp[1].0.status) == NtStatus::EndOfFile {
            Bytes::new()
        } else if NtStatus::from_u32(resp[1].0.status).is_error() {
            return Err(io::Error::other(format!(
                "read failed: 0x{:08X}",
                resp[1].0.status
            )));
        } else {
            decode_read_response_bytes(&resp[1].1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid read response")
            })?
        };

        Ok((cr, data))
    }

    /// Compound Create + Write + Close (1 round trip). For small-file writes.
    /// Returns the Close response with post-query metadata.
    pub async fn create_write_close(
        &self,
        tree_id: u32,
        path: &str,
        data: &[u8],
    ) -> io::Result<CloseResponse> {
        // Compound writes are capped at 64 KiB (charge 1), so the three
        // chained messages charge 3 credits and stride 3 MessageIds.
        let base = self.alloc_ids(3);

        let mut h1 = Header::new(Command::Create, base);
        h1.session_id = self.session_id;
        h1.tree_id = tree_id;
        let mut b1 = BytesMut::with_capacity(128);
        encode_create_request(
            &mut b1,
            path,
            DesiredAccess::GenericWrite as u32,
            ShareAccess::Read as u32,
            CreateDisposition::OverwriteIf as u32,
            CreateOptions::NonDirectoryFile as u32,
        );

        let mut h2 = Header::new(Command::Write, base + 1).with_credit_charge(data.len() as u32);
        h2.session_id = self.session_id;
        h2.tree_id = tree_id;
        h2.flags |= SMB2_FLAGS_RELATED;
        let mut b2 = BytesMut::with_capacity(64 + data.len());
        encode_write_request(&mut b2, &SENTINEL_FILE_ID, 0, data);

        let mut h3 = Header::new(Command::Close, base + 2);
        h3.session_id = self.session_id;
        h3.tree_id = tree_id;
        h3.flags |= SMB2_FLAGS_RELATED;
        let mut b3 = BytesMut::with_capacity(32);
        encode_close_request_ex(&mut b3, &SENTINEL_FILE_ID, true);

        let resp = self
            .send_compound(vec![(h1, b1), (h2, b2), (h3, b3)])
            .await?;
        if resp.len() < 3 {
            return Err(compound_too_short(path, &resp, 3));
        }

        if NtStatus::from_u32(resp[0].0.status).is_error() {
            return Err(smb_status_to_io_error(resp[0].0.status, path));
        }
        if resp[1].0.status & 0xC000_0000 == 0xC000_0000 {
            return Err(io::Error::other(format!(
                "write failed: 0x{:08X}",
                resp[1].0.status
            )));
        }
        // A success status with a short count would silently truncate the
        // object while PutObject reports 200 — verify every byte landed.
        let written = decode_write_response(&resp[1].1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid write response"))?;
        if written as usize != data.len() {
            return Err(io::Error::other(format!(
                "compound write short: {written} of {} bytes for {path}",
                data.len()
            )));
        }

        Ok(decode_close_response(&resp[2].1).unwrap_or(CloseResponse {
            last_write_time: 0,
            file_size: data.len() as u64,
        }))
    }

    /// Compound batch of Create+Close pairs for directory creation (1 round trip).
    /// Each pair forms a related chain; different pairs are unrelated.
    pub async fn ensure_dirs(&self, tree_id: u32, dirs: &[String]) -> io::Result<()> {
        if dirs.is_empty() {
            return Ok(());
        }

        let count = dirs.len() * 2;
        // Create/Close pairs charge 1 credit each.
        let base = self.alloc_ids(count as u64);
        let mut requests = Vec::with_capacity(count);

        for (i, dir) in dirs.iter().enumerate() {
            // Create (unrelated — starts new chain)
            let mut h1 = Header::new(Command::Create, base + (i as u64) * 2);
            h1.session_id = self.session_id;
            h1.tree_id = tree_id;
            let mut b1 = BytesMut::with_capacity(128);
            encode_create_request(
                &mut b1,
                dir,
                DesiredAccess::ReadAttributes as u32,
                ShareAccess::All as u32,
                CreateDisposition::OpenIf as u32,
                CreateOptions::DirectoryFile as u32,
            );
            requests.push((h1, b1));

            // Close (related — sentinel file ID from preceding Create)
            let mut h2 = Header::new(Command::Close, base + (i as u64) * 2 + 1);
            h2.session_id = self.session_id;
            h2.tree_id = tree_id;
            h2.flags |= SMB2_FLAGS_RELATED;
            let mut b2 = BytesMut::with_capacity(32);
            encode_close_request(&mut b2, &SENTINEL_FILE_ID);
            requests.push((h2, b2));
        }

        let responses = self.send_compound(requests).await?;
        ensure_dirs_outcome(dirs, &responses, count)
    }
}

/// Effective per-connection I/O sizes derived from the SMB negotiate
/// response, with any zero fields substituted by the configured `io_cap`.
///
/// Returning a struct (rather than a tuple) makes the relationship between
/// `max_read`/`compound_max_read` self-documenting.
pub(crate) struct EffectiveIoSizes {
    pub max_read: u32,
    pub max_write: u32,
    pub compound_max_read: u32,
    pub compound_max_write: u32,
}

/// Compute the effective I/O sizes for a session given the server's
/// negotiate response and our configured cap. Any zero negotiated field
/// is substituted with `io_cap` (and `on_zero` is invoked so the caller
/// can log it). The result is then capped to `min(value, transact, io_cap)`
/// for standalone I/O and further to 64 KiB for compound operations.
///
/// Extracted as a free function so its zero-handling is unit-testable
/// without needing a real SMB connection.
pub(crate) fn effective_io_sizes(
    neg_max_read: u32,
    neg_max_write: u32,
    neg_max_transact: u32,
    io_cap: u32,
    mut on_zero: impl FnMut(&'static str, u32),
) -> EffectiveIoSizes {
    let nonzero = |name: &'static str, v: u32, on_zero: &mut dyn FnMut(&'static str, u32)| {
        if v == 0 {
            on_zero(name, v);
            io_cap
        } else {
            v
        }
    };
    // A single SMB2 message must fit the 24-bit NetBIOS length frame the
    // transport writes (`len & 0x00FF_FFFF`). An `SPICEIO_SMB_MAX_IO` above
    // ~16 MiB would silently truncate the frame length and desynchronize the
    // stream — clamp well below the limit (headroom for headers).
    const MAX_WIRE_IO: u32 = 0x00F0_0000; // 15 MiB
    let read = nonzero("max_read_size", neg_max_read, &mut on_zero);
    let write = nonzero("max_write_size", neg_max_write, &mut on_zero);
    let transact = nonzero("max_transact_size", neg_max_transact, &mut on_zero);
    // Cap standalone I/O by: min(server_advertised, max_transact, configured_cap).
    // Many NAS servers advertise multi-MB limits but fail at much smaller sizes.
    let max_read = read.min(transact).min(io_cap).min(MAX_WIRE_IO);
    let max_write = write.min(transact).min(io_cap).min(MAX_WIRE_IO);
    // Cap at 64KB for compound requests — some NAS servers reject larger
    // payloads inside compound (chained) operations.
    EffectiveIoSizes {
        max_read,
        max_write,
        compound_max_read: max_read.min(65536),
        compound_max_write: max_write.min(65536),
    }
}

/// Decide the outcome of an `ensure_dirs` compound chain.
///
/// Two failure modes, and the order they are checked in is the whole point.
///
/// A server that aborts a related chain on its first failure returns only that
/// one response. Judging the chain by its *length* first would turn a precise
/// `OBJECT_PATH_NOT_FOUND` or `ACCESS_DENIED` into a generic framing error —
/// the exact loss [`compound_too_short`] exists to prevent — and the write-path
/// recovery that keys on `NotFound` would never fire, while a permission
/// failure would stop being a 403. So inspect the statuses that arrived first
/// and report the real one, against the directory it belongs to.
///
/// Only once every response that arrived is a success does a short chain mean
/// what its length says: the server stopped early for some other reason. That
/// still cannot be `Ok`. The caller records every directory in `dirs` as
/// existing and skips creating them for the rest of the process, so returning
/// success here would cache directories that were never created, and every
/// later write beneath one of them would fail having skipped the single
/// operation that would have fixed it.
///
/// Extracted as a free function so both orderings are unit-testable without a
/// live SMB connection.
fn ensure_dirs_outcome(
    dirs: &[String],
    responses: &[(Header, Bytes)],
    expected: usize,
) -> io::Result<()> {
    // Create responses are the even indices; the odd ones are their Closes.
    for i in (0..responses.len()).step_by(2) {
        if NtStatus::from_u32(responses[i].0.status).is_error() {
            let path = dirs.get(i / 2).map_or("", String::as_str);
            return Err(smb_status_to_io_error(responses[i].0.status, path));
        }
    }

    if responses.len() != expected {
        // Name the first directory we could not confirm — that is the one the
        // caller must not cache.
        let unverified = dirs.get(responses.len() / 2).map_or("", String::as_str);
        return Err(compound_too_short(unverified, responses, expected));
    }

    Ok(())
}

/// Map a short compound chain to a useful error.
///
/// Servers that abort a related chain on the first error often return only
/// that first response (`NextCommand = 0`). Treating that as a generic
/// "too short" loses the NTSTATUS (sharing violation, path not found, …) and
/// makes overload look like a framing bug. Prefer the first error status when
/// present; only then fall back to InvalidData.
fn compound_too_short(path: &str, resp: &[(Header, Bytes)], expected: usize) -> io::Error {
    if let Some((hdr, _)) = resp.first() {
        if NtStatus::from_u32(hdr.status).is_error() {
            return smb_status_to_io_error(hdr.status, path);
        }
        crate::serr!(
            "[spiceio] compound response too short for {path}: got {} of {expected} \
             (first status=0x{:08X})",
            resp.len(),
            hdr.status
        );
    } else {
        crate::serr!(
            "[spiceio] compound response too short for {path}: empty (expected {expected})"
        );
    }
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "compound response too short: got {} of {expected}",
            resp.len()
        ),
    )
}

// ── SMB2 credit-window arithmetic (pure, unit-tested) ───────────────────────

/// How many requests of `charge` credits each a batch may send within the
/// current credit `balance`, capped at `want`. Always at least one (when any
/// were requested): a compliant server never leaves the client below one
/// credit, so a zero/negative balance means either a fresh connection whose
/// window is still growing or a non-compliant grant — a bounded one-request
/// overdraft recovers both, whereas sending nothing would wedge the transfer.
fn affordable_count(balance: i64, charge: u16, want: usize) -> usize {
    if want == 0 {
        return 0;
    }
    let per = i64::from(charge.max(1));
    usize::try_from((balance / per).max(1))
        .unwrap_or(1)
        .min(want)
}

/// Longest prefix of `chunks` whose total credit charge fits `balance`
/// (always at least one chunk — see `affordable_count` for the overdraft
/// rationale). Returns `(chunk_count, total_charge)`.
fn affordable_prefix(balance: i64, chunks: &[&[u8]]) -> (usize, u64) {
    let budget = balance.max(0) as u64;
    let mut take = 0usize;
    let mut total = 0u64;
    for c in chunks {
        let ch = u64::from(credit_charge_for(c.len() as u32));
        if take > 0 && total + ch > budget {
            break;
        }
        take += 1;
        total += ch;
    }
    (take, total)
}

/// Bytes a single read/write request may carry within `balance` credits
/// (floor: one credit = 64 KiB — the bounded single-request overdraft).
fn credit_affordable_bytes(balance: i64) -> u32 {
    u32::try_from(balance.max(1).saturating_mul(65536)).unwrap_or(u32::MAX)
}

/// Sign an SMB2 packet in-place. `packet` includes the 4-byte NetBIOS header.
/// Sets the SMB2_FLAGS_SIGNED bit and computes AES-128-CMAC over the SMB2 message.
fn sign_packet(packet: &mut [u8], key: &[u8; 16]) {
    sign_packet_parts(packet, &[], key);
}

/// Sign an SMB2 packet whose payload is a separate slice (WRITE path).
/// `header` is NetBIOS + SMB2 header + fixed request body; `payload` is the
/// data that logically follows it on the wire. CMAC is over the concatenated
/// SMB2 message (header without NetBIOS || payload).
fn sign_packet_parts(header: &mut [u8], payload: &[u8], key: &[u8; 16]) {
    use crate::crypto;

    const NETBIOS_HEADER: usize = 4;
    const FLAGS_OFFSET: usize = NETBIOS_HEADER + 16; // Flags field at header offset 16
    const SIGNATURE_OFFSET: usize = NETBIOS_HEADER + 48; // Signature at header offset 48

    // Set SMB2_FLAGS_SIGNED (0x00000008)
    let flags = u32::from_le_bytes(header[FLAGS_OFFSET..FLAGS_OFFSET + 4].try_into().unwrap());
    header[FLAGS_OFFSET..FLAGS_OFFSET + 4].copy_from_slice(&(flags | 0x0000_0008).to_le_bytes());

    // Zero the signature field
    header[SIGNATURE_OFFSET..SIGNATURE_OFFSET + 16].fill(0);

    // Compute AES-128-CMAC over the SMB2 message (skip NetBIOS header) + payload.
    let smb2_hdr = &header[NETBIOS_HEADER..];
    let signature = if payload.is_empty() {
        crypto::aes128_cmac(key, smb2_hdr)
    } else {
        crypto::aes128_cmac_parts(key, &[smb2_hdr, payload])
    };

    // Write the signature
    header[SIGNATURE_OFFSET..SIGNATURE_OFFSET + 16].copy_from_slice(&signature);
}

/// Update preauth integrity hash: hash = SHA-512(hash || message_bytes).
fn update_preauth_hash(hash: &mut [u8; 64], message: &[u8]) {
    use crate::crypto;
    let mut input = Vec::with_capacity(64 + message.len());
    input.extend_from_slice(hash);
    input.extend_from_slice(message);
    *hash = crypto::sha512(&input);
}

fn smb_status_to_io_error(status: u32, path: &str) -> io::Error {
    // Map raw status codes directly to avoid losing info through NtStatus enum.
    // We deliberately do NOT log for mapped statuses — many of these are
    // expected (NotFound on HEAD probes, SharingViolation during cleanup) and
    // the typed `io::ErrorKind` is enough for callers to handle them. Only the
    // fallback arm (truly unknown statuses) includes the raw hex code in the
    // error string and logs at error level.
    match status {
        0xC000_000F // STATUS_NO_SUCH_FILE
        | 0xC000_0034 // STATUS_OBJECT_NAME_NOT_FOUND
        | 0xC000_003A // STATUS_OBJECT_PATH_NOT_FOUND
        | 0xC000_0033 // STATUS_OBJECT_NAME_INVALID
        // The S3 namespace has no directories: a key that resolves to an SMB
        // directory (GET dir-as-key), a path whose intermediate component is a
        // file, or a file mid-deletion is "no such key", not a 500.
        | 0xC000_00BA // STATUS_FILE_IS_A_DIRECTORY
        | 0xC000_0103 // STATUS_NOT_A_DIRECTORY
        | 0xC000_0056 // STATUS_DELETE_PENDING
        => io::Error::new(io::ErrorKind::NotFound, format!("not found: {path}")),

        0xC000_0022 => io::Error::new( // STATUS_ACCESS_DENIED
            io::ErrorKind::PermissionDenied,
            format!("access denied: {path}"),
        ),

        0xC000_0035 => io::Error::new( // STATUS_OBJECT_NAME_COLLISION
            io::ErrorKind::AlreadyExists,
            format!("already exists: {path}"),
        ),

        0xC000_0043 => io::Error::new( // STATUS_SHARING_VIOLATION
            io::ErrorKind::ResourceBusy,
            format!("sharing violation: {path}"),
        ),

        // Server capacity / limit statuses all map to retryable ResourceBusy.
        // Classified via `is_server_capacity_status` (the single source of truth
        // for these codes) so there is no third hand-maintained list here; the
        // NtStatus name in the message says which limit was hit.
        s if is_server_capacity_status(s) => io::Error::new(
            io::ErrorKind::ResourceBusy,
            format!("server at capacity ({:?}): {path}", NtStatus::from_u32(s)),
        ),

        _ => {
            crate::serr!("[spiceio] smb error 0x{status:08X}: {path}");
            io::Error::other(format!("SMB error 0x{status:08X} for {path}"))
        }
    }
}

/// Classify an IOCTL failure. A server that does not implement the FSCTL says
/// so with one of a small set of statuses; those become `Unsupported` so the
/// caller falls back to its own implementation rather than failing the
/// request. Everything else keeps its usual mapping.
fn ioctl_error(what: &str, status: u32) -> io::Error {
    if is_echo_unsupported_status(status) || status == 0xC000_00CB
    /* STATUS_INVALID_DEVICE_STATE */
    {
        return io::Error::new(
            io::ErrorKind::Unsupported,
            format!("{what} not supported by this server (0x{status:08X})"),
        );
    }
    smb_status_to_io_error(status, what)
}

/// True for NTSTATUS values meaning the server no longer recognizes this
/// session or tree, so every subsequent request on the connection will fail
/// until it is re-established. Treated as a dead connection (poison + heal),
/// not as a per-request error — an expired session that merely logged would
/// leave the pool slot failing indefinitely.
fn is_session_invalid_status(status: u32) -> bool {
    matches!(
        status,
        0xC000_0203 // STATUS_USER_SESSION_DELETED
        | 0xC000_035C // STATUS_NETWORK_SESSION_EXPIRED
        | 0xC000_020C // STATUS_CONNECTION_DISCONNECTED
        | 0xC000_00C9 // STATUS_NETWORK_NAME_DELETED (tree is gone)
    )
}

/// True for NTSTATUS values meaning the server understood the ECHO but does
/// not implement it. The connection is healthy; only the probe is pointless,
/// so it is switched off for that connection.
fn is_echo_unsupported_status(status: u32) -> bool {
    matches!(
        status,
        0xC000_0002 // STATUS_NOT_IMPLEMENTED
        | 0xC000_00BB // STATUS_NOT_SUPPORTED
        | 0xC000_0010 // STATUS_INVALID_DEVICE_REQUEST
    )
}

/// True for NTSTATUS values that indicate the SMB server has hit a connection,
/// session, or resource limit and is refusing new sessions/connections.
/// These surface as ResourceBusy (mapped to 503 SlowDown by the S3 layer)
/// so clients retry, and the pool healer / connect backoff treat them as
/// transient.
pub(crate) fn is_server_capacity_status(status: u32) -> bool {
    matches!(
        NtStatus::from_u32(status),
        NtStatus::InsufficientResources
            | NtStatus::TooManySessions
            | NtStatus::RequestNotAccepted
            | NtStatus::SharingPaused
            | NtStatus::RemoteSessionLimit
    )
}

/// Returns whether the given error indicates the SMB server rejected a new
/// connection or session due to a capacity limit (too many sessions,
/// insufficient resources, request not accepted, etc.). Used by the pool to
/// shrink itself instead of failing or retrying the same limit forever.
///
/// At the connect / tree-connect layer the *only* source of `ResourceBusy` is a
/// server-capacity NTSTATUS — no file operations run there, so a sharing
/// violation (the other `ResourceBusy` producer) can't occur. The typed kind is
/// therefore a reliable single signal, so we don't re-parse the message text
/// (which would be a fourth copy of the capacity-code list to keep in sync).
/// `handshake_error` and `is_server_capacity_status` uphold the invariant:
/// capacity statuses map to `ResourceBusy`, everything else does not.
pub(crate) fn is_capacity_error(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::ResourceBusy
}

/// Build the `io::Error` for a failed SMB handshake step (negotiate, session
/// setup, tree connect). Server-capacity statuses become retryable
/// `ResourceBusy` and are logged quietly — they are expected back-pressure, not
/// bugs, and the pool shrinks / retries on them. `STATUS_ACCESS_DENIED` maps to
/// `PermissionDenied`; every other status uses `fallback`. Non-capacity errors
/// are logged at error level. `context` names the step for the log/message.
fn handshake_error(context: &str, status: u32, fallback: io::ErrorKind) -> io::Error {
    if is_server_capacity_status(status) {
        crate::slog!("[spiceio] smb {context} rejected by server capacity: 0x{status:08X}");
        return io::Error::new(
            io::ErrorKind::ResourceBusy,
            format!("{context} rejected by server capacity: status=0x{status:08X}"),
        );
    }
    crate::serr!("[spiceio] smb {context} failed: 0x{status:08X}");
    // STATUS_ACCESS_DENIED is an auth/ACL failure at any step — surface it as
    // PermissionDenied rather than the step's generic fallback (e.g. tree
    // connect's NotFound), so it is not misreported as a missing share.
    let kind = if NtStatus::from_u32(status) == NtStatus::AccessDenied {
        io::ErrorKind::PermissionDenied
    } else {
        fallback
    };
    io::Error::new(kind, format!("{context} failed: status=0x{status:08X}"))
}

/// Sign a single SMB2 message in-place (no NetBIOS header prefix).
/// Used for compound requests where each message is signed individually.
fn sign_message(msg: &mut [u8], key: &[u8; 16]) {
    use crate::crypto;
    const FLAGS_OFFSET: usize = 16;
    const SIGNATURE_OFFSET: usize = 48;

    let flags = u32::from_le_bytes(msg[FLAGS_OFFSET..FLAGS_OFFSET + 4].try_into().unwrap());
    msg[FLAGS_OFFSET..FLAGS_OFFSET + 4].copy_from_slice(&(flags | 0x0000_0008).to_le_bytes());

    msg[SIGNATURE_OFFSET..SIGNATURE_OFFSET + 16].fill(0);

    let signature = crypto::aes128_cmac(key, msg);
    msg[SIGNATURE_OFFSET..SIGNATURE_OFFSET + 16].copy_from_slice(&signature);
}

// Test fixture: bypass the handshake to exercise transport over loopback.
#[cfg(test)]
impl SmbClient {
    pub(crate) fn test_from_stream(stream: TcpStream) -> Arc<Self> {
        Arc::new(Self {
            stream: Mutex::new(stream),
            message_id: AtomicU64::new(0),
            session_id: 1,
            config: crate::test_support::config(),
            max_read_size: 65536,
            max_write_size: 65536,
            compound_max_read_size: 65536,
            compound_max_write_size: 65536,
            query_dir_buffer: QUERY_DIR_BUFFER_FLOOR,
            client_guid: [0; 16],
            signing_key: None,
            poisoned: AtomicBool::new(false),
            credits: AtomicI64::new(256),
            credit_clamp_logged: AtomicBool::new(false),
            inflight: AtomicUsize::new(0),
            last_active_ms: AtomicU64::new(now_ms()),
            echoes_ok: AtomicBool::new(true),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ensure_dirs_outcome ─────────────────────────────────────────────────

    /// Build a Create/Close response pair chain with the given Create statuses.
    fn dir_chain(create_statuses: &[u32]) -> Vec<(Header, Bytes)> {
        let mut out = Vec::new();
        for (i, st) in create_statuses.iter().enumerate() {
            let mut create = Header::new(Command::Create, i as u64 * 2);
            create.status = *st;
            out.push((create, Bytes::new()));
            let close = Header::new(Command::Close, i as u64 * 2 + 1);
            out.push((close, Bytes::new()));
        }
        out
    }

    fn dirs(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("d{i}")).collect()
    }

    #[test]
    fn ensure_dirs_outcome_accepts_a_complete_successful_chain() {
        let d = dirs(3);
        let resp = dir_chain(&[0, 0, 0]);
        assert!(ensure_dirs_outcome(&d, &resp, 6).is_ok());
    }

    #[test]
    fn ensure_dirs_outcome_keeps_the_status_when_the_chain_is_cut_short_by_it() {
        // The failure mode that matters: the server aborted the chain on the
        // first failed Create, so only that response came back. The precise
        // NTSTATUS must survive — the write-path recovery keys on NotFound, and
        // judging by length first would erase it into a framing error.
        let d = dirs(4);
        let resp = dir_chain(&[0xC000_003A]); // STATUS_OBJECT_PATH_NOT_FOUND
        let err = ensure_dirs_outcome(&d, &resp, 8).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(err.to_string().contains("d0"), "names the dir: {err}");
    }

    #[test]
    fn ensure_dirs_outcome_keeps_access_denied_on_a_short_chain() {
        // Same ordering requirement, different consequence: this one has to
        // stay a 403 rather than becoming a retryable framing error.
        let d = dirs(4);
        let resp = dir_chain(&[0xC000_0022]); // STATUS_ACCESS_DENIED
        let err = ensure_dirs_outcome(&d, &resp, 8).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn ensure_dirs_outcome_reports_the_failing_dir_not_the_first_one() {
        // A mid-chain failure must be attributed to its own directory, or the
        // caller evicts the wrong cache entry.
        let d = dirs(3);
        let resp = dir_chain(&[0, 0xC000_003A, 0]);
        let err = ensure_dirs_outcome(&d, &resp, 6).unwrap_err();
        assert!(err.to_string().contains("d1"), "names the dir: {err}");
    }

    #[test]
    fn ensure_dirs_outcome_rejects_a_short_all_success_chain() {
        // Every response that arrived succeeded, but not all arrived. Returning
        // Ok would let the caller cache `d2`/`d3` as created when the server
        // never created them, and every later write beneath them would fail
        // having skipped the create that would have fixed it.
        let d = dirs(4);
        let resp = dir_chain(&[0, 0]);
        let err = ensure_dirs_outcome(&d, &resp, 8).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn ensure_dirs_outcome_rejects_an_empty_chain() {
        let d = dirs(2);
        let err = ensure_dirs_outcome(&d, &[], 4).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    fn assert_kind_and_path(err: &io::Error, kind: io::ErrorKind, needle: &str) {
        assert_eq!(err.kind(), kind, "wrong kind for {err}");
        let s = err.to_string();
        assert!(s.contains(needle), "expected {needle:?} in {s:?}");
    }

    #[test]
    fn maps_no_such_file_to_not_found() {
        let e = smb_status_to_io_error(0xC000_000F, "a\\b");
        assert_kind_and_path(&e, io::ErrorKind::NotFound, "a\\b");
    }

    #[test]
    fn maps_object_name_not_found_to_not_found() {
        let e = smb_status_to_io_error(0xC000_0034, "missing.txt");
        assert_kind_and_path(&e, io::ErrorKind::NotFound, "missing.txt");
    }

    #[test]
    fn maps_object_path_not_found_to_not_found() {
        let e = smb_status_to_io_error(0xC000_003A, "dir\\file");
        assert_kind_and_path(&e, io::ErrorKind::NotFound, "dir\\file");
    }

    #[test]
    fn maps_object_name_invalid_to_not_found() {
        let e = smb_status_to_io_error(0xC000_0033, "bad?name");
        assert_kind_and_path(&e, io::ErrorKind::NotFound, "bad?name");
    }

    #[test]
    fn maps_access_denied_to_permission_denied() {
        let e = smb_status_to_io_error(0xC000_0022, "secret");
        assert_kind_and_path(&e, io::ErrorKind::PermissionDenied, "secret");
    }

    #[test]
    fn maps_name_collision_to_already_exists() {
        let e = smb_status_to_io_error(0xC000_0035, "dup");
        assert_kind_and_path(&e, io::ErrorKind::AlreadyExists, "dup");
    }

    #[test]
    fn maps_sharing_violation_to_resource_busy() {
        let e = smb_status_to_io_error(0xC000_0043, ".spiceio-wal\\01-0000");
        assert_kind_and_path(&e, io::ErrorKind::ResourceBusy, ".spiceio-wal\\01-0000");
    }

    #[test]
    fn maps_insufficient_resources_to_resource_busy() {
        let e = smb_status_to_io_error(0xC000009A, "conn");
        assert_kind_and_path(&e, io::ErrorKind::ResourceBusy, "InsufficientResources");
    }

    #[test]
    fn maps_too_many_sessions_to_resource_busy() {
        let e = smb_status_to_io_error(0xC00000CE, "srv");
        assert_kind_and_path(&e, io::ErrorKind::ResourceBusy, "TooManySessions");
    }

    #[test]
    fn maps_request_not_accepted_to_resource_busy() {
        let e = smb_status_to_io_error(0xC00000D0, "share");
        assert_kind_and_path(&e, io::ErrorKind::ResourceBusy, "RequestNotAccepted");
    }

    #[test]
    fn is_server_capacity_status_recognizes_common_limit_codes() {
        assert!(is_server_capacity_status(0xC000009A));
        assert!(is_server_capacity_status(0xC00000CE));
        assert!(is_server_capacity_status(0xC00000D0));
        assert!(is_server_capacity_status(0xC00000CF));
        assert!(is_server_capacity_status(0xC0000196));
        assert!(!is_server_capacity_status(0xC000000F)); // no such file
        assert!(!is_server_capacity_status(0));
    }

    #[test]
    fn handshake_error_classifies_capacity_as_retryable_resource_busy() {
        // A capacity rejection at any handshake step — including the first
        // session-setup leg — must be retryable ResourceBusy, not the fallback,
        // so the pool shrinks instead of hard-failing.
        let e = handshake_error("session setup", 0xC00000CE, io::ErrorKind::PermissionDenied);
        assert_eq!(e.kind(), io::ErrorKind::ResourceBusy);
        assert!(e.to_string().contains("0xC00000CE"), "expected hex in {e}");
    }

    #[test]
    fn handshake_error_uses_fallback_for_non_capacity() {
        // 0xC000000D (STATUS_INVALID_PARAMETER): not capacity, not access-denied.
        let e = handshake_error("negotiate", 0xC000000D, io::ErrorKind::ConnectionRefused);
        assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused);
        assert!(e.to_string().contains("0xC000000D"), "expected hex in {e}");
    }

    #[test]
    fn handshake_error_maps_access_denied_to_permission_denied() {
        // tree_connect's fallback is NotFound, but ACCESS_DENIED must surface as
        // PermissionDenied — not a misleading "share not found".
        let e = handshake_error(
            "tree connect to 'share'",
            0xC0000022,
            io::ErrorKind::NotFound,
        );
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert!(e.to_string().contains("0xC0000022"), "expected hex in {e}");
    }

    #[test]
    fn is_capacity_error_true_only_for_resource_busy() {
        // The pool relies on this to decide whether to shrink. Capacity statuses
        // map to ResourceBusy (via handshake_error / smb_status_to_io_error);
        // auth / not-found / refused / timeout must NOT trigger a shrink.
        assert!(is_capacity_error(&handshake_error(
            "session setup",
            0xC00000D0,
            io::ErrorKind::PermissionDenied,
        )));
        assert!(is_capacity_error(&smb_status_to_io_error(0xC000009A, "x")));
        assert!(!is_capacity_error(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            "auth failed",
        )));
        assert!(!is_capacity_error(&io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "refused",
        )));
        assert!(!is_capacity_error(&io::Error::from(
            io::ErrorKind::TimedOut
        )));
    }

    #[test]
    fn unknown_status_falls_back_to_other_and_includes_hex() {
        let e = smb_status_to_io_error(0xC000_00BB, "x");
        assert_eq!(e.kind(), io::ErrorKind::Other);
        let s = e.to_string();
        assert!(s.contains("0xC00000BB"), "expected hex in: {s}");
        assert!(s.contains("x"), "expected path in: {s}");
    }

    #[test]
    fn success_status_zero_falls_through_to_other() {
        // STATUS_SUCCESS is not really an error, but the mapper must never panic.
        let e = smb_status_to_io_error(0x0000_0000, "ok");
        assert_eq!(e.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn error_path_is_preserved_verbatim() {
        // Path containing backslashes, dots, and the WAL prefix must round-trip.
        let path = ".spiceio-wal\\01778725545751751000-0000";
        let e = smb_status_to_io_error(0xC000_0043, path);
        assert!(e.to_string().contains(path));
    }

    // ── credit-window arithmetic ────────────────────────────────────────────

    #[test]
    fn affordable_count_clamps_to_balance() {
        // Plenty of balance: full batch.
        assert_eq!(affordable_count(256, 1, 64), 64);
        assert_eq!(affordable_count(256, 4, 64), 64);
        // Partial balance: batch shrinks (whole requests only).
        assert_eq!(affordable_count(16, 4, 64), 4);
        assert_eq!(affordable_count(15, 4, 64), 3);
        // Tight/zero/negative balance: floor at one request (the bounded
        // overdraft) so a transfer can always make progress.
        assert_eq!(affordable_count(3, 4, 64), 1);
        assert_eq!(affordable_count(0, 1, 64), 1);
        assert_eq!(affordable_count(-8, 4, 64), 1);
        // Never exceeds the requested count; zero requests stay zero.
        assert_eq!(affordable_count(1_000_000, 1, 7), 7);
        assert_eq!(affordable_count(256, 1, 0), 0);
        // Charge 0 is treated as 1, never a division by zero.
        assert_eq!(affordable_count(8, 0, 64), 8);
    }

    #[test]
    fn affordable_prefix_takes_what_fits() {
        let a = vec![0u8; 65536]; // charge 1
        let b = vec![0u8; 131072]; // charge 2
        let c = vec![0u8; 1]; // charge 1
        let chunks: Vec<&[u8]> = vec![&a, &b, &c];
        // Everything fits.
        assert_eq!(affordable_prefix(16, &chunks), (3, 4));
        // Exactly the first two (1 + 2 = 3 credits).
        assert_eq!(affordable_prefix(3, &chunks), (2, 3));
        // Only the first.
        assert_eq!(affordable_prefix(1, &chunks), (1, 1));
        // Zero/negative balance still sends one chunk (bounded overdraft).
        assert_eq!(affordable_prefix(0, &chunks), (1, 1));
        assert_eq!(affordable_prefix(-5, &chunks), (1, 1));
        // Empty input.
        let empty: Vec<&[u8]> = Vec::new();
        assert_eq!(affordable_prefix(100, &empty), (0, 0));
    }

    #[test]
    fn credit_affordable_bytes_floors_and_saturates() {
        assert_eq!(credit_affordable_bytes(0), 65536); // floor: one credit
        assert_eq!(credit_affordable_bytes(-3), 65536);
        assert_eq!(credit_affordable_bytes(4), 4 * 65536);
        assert_eq!(credit_affordable_bytes(i64::MAX / 2), u32::MAX); // saturates
    }

    // ── effective_io_sizes ──────────────────────────────────────────────────

    fn no_op_logger() -> impl FnMut(&'static str, u32) {
        |_name, _value| {}
    }

    #[test]
    fn effective_io_sizes_typical_negotiate() {
        // Server advertises 1 MiB, transact 1 MiB; configured cap 64 KiB
        // (the default). Result: 64 KiB everywhere, compound also 64 KiB.
        let s = effective_io_sizes(1_048_576, 1_048_576, 1_048_576, 65536, no_op_logger());
        assert_eq!(s.max_read, 65536);
        assert_eq!(s.max_write, 65536);
        assert_eq!(s.compound_max_read, 65536);
        assert_eq!(s.compound_max_write, 65536);
    }

    #[test]
    fn effective_io_sizes_compound_cap_at_64k_when_max_higher() {
        // io_cap raised to 1 MiB so the standalone path opens up; compound
        // must still cap at 64 KiB.
        let s = effective_io_sizes(1_048_576, 1_048_576, 1_048_576, 1_048_576, no_op_logger());
        assert_eq!(s.max_read, 1_048_576);
        assert_eq!(s.max_write, 1_048_576);
        assert_eq!(s.compound_max_read, 65536);
        assert_eq!(s.compound_max_write, 65536);
    }

    #[test]
    fn effective_io_sizes_floors_zero_max_read() {
        // The core regression test: a server returning max_read_size = 0
        // must not propagate as a 0 chunk size to callers.
        let mut zero_calls: Vec<&'static str> = Vec::new();
        let s = effective_io_sizes(0, 1_048_576, 1_048_576, 65536, |name, _v| {
            zero_calls.push(name);
        });
        assert_eq!(s.max_read, 65536);
        assert_eq!(s.max_write, 65536);
        assert_eq!(zero_calls, vec!["max_read_size"]);
    }

    #[test]
    fn effective_io_sizes_floors_zero_max_write() {
        let mut zero_calls: Vec<&'static str> = Vec::new();
        let s = effective_io_sizes(1_048_576, 0, 1_048_576, 65536, |name, _v| {
            zero_calls.push(name);
        });
        assert_eq!(s.max_read, 65536);
        assert_eq!(s.max_write, 65536);
        assert_eq!(zero_calls, vec!["max_write_size"]);
    }

    #[test]
    fn effective_io_sizes_floors_zero_transact() {
        let mut zero_calls: Vec<&'static str> = Vec::new();
        let s = effective_io_sizes(1_048_576, 1_048_576, 0, 65536, |name, _v| {
            zero_calls.push(name);
        });
        assert_eq!(s.max_read, 65536);
        assert_eq!(s.max_write, 65536);
        assert_eq!(zero_calls, vec!["max_transact_size"]);
    }

    #[test]
    fn effective_io_sizes_floors_all_zeros() {
        // All three zero — every callback fires, and we end up at io_cap.
        let mut zero_calls: Vec<&'static str> = Vec::new();
        let s = effective_io_sizes(0, 0, 0, 65536, |name, _v| zero_calls.push(name));
        assert_eq!(s.max_read, 65536);
        assert_eq!(s.max_write, 65536);
        assert_eq!(s.compound_max_read, 65536);
        assert_eq!(s.compound_max_write, 65536);
        assert_eq!(
            zero_calls,
            vec!["max_read_size", "max_write_size", "max_transact_size"]
        );
    }

    #[test]
    fn effective_io_sizes_transact_clamps_read_and_write() {
        // Server advertises 1 MiB read/write but only 64 KiB transact —
        // the smaller transact dominates the min().
        let s = effective_io_sizes(1_048_576, 1_048_576, 65536, 1_048_576, no_op_logger());
        assert_eq!(s.max_read, 65536);
        assert_eq!(s.max_write, 65536);
    }
}
