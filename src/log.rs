//! Non-blocking logger backed by a dedicated OS thread.
//!
//! Design: a bounded `mpsc::sync_channel` feeds a background thread that owns
//! the console streams (and, when configured, the log file). The hot path
//! (`emit` / `emit_err`) does a single `try_send` — if the channel is full the
//! message is silently dropped, so logging *never blocks the proxy*, even when
//! stdout/stderr is piped to a slow or stalled reader.
//!
//! Two entry points: `emit` (stdout) and `emit_err` (stderr). Both prepend an
//! ISO-8601 timestamp. Before `init` runs (or if the channel cannot be set up)
//! they fall back to a direct synchronous write so early-startup logs are never
//! lost.

use std::fmt;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::sync::OnceLock;
use std::sync::mpsc;

/// Channel capacity — number of formatted log lines buffered before drops.
const CHANNEL_CAP: usize = 4096;

/// BufWriter capacity — bytes buffered before a syscall write.
const BUF_CAP: usize = 64 * 1024;

/// A queued log line and which console stream it targets, or a flush request.
enum LogMsg {
    Stdout(String),
    Stderr(String),
    /// Flush the file buffer and acknowledge — used at shutdown so the final
    /// lines are on disk before the process exits.
    Flush(mpsc::SyncSender<()>),
}

static LOG_TX: OnceLock<mpsc::SyncSender<LogMsg>> = OnceLock::new();

/// Initialise logging. Call once at startup. Spawns the background writer
/// thread that owns stdout/stderr and, if `path` is `Some`, the log file too.
/// All console output is routed through this thread so the request path never
/// blocks on a stalled console pipe.
pub fn init(path: Option<&str>) {
    let file = path.map(|p| {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .unwrap_or_else(|e| {
                // Config error, not a crash — report cleanly and exit.
                eprintln!("[spiceio] failed to open log file {p}: {e}");
                std::process::exit(1);
            })
    });

    let (tx, rx) = mpsc::sync_channel::<LogMsg>(CHANNEL_CAP);

    let spawned = std::thread::Builder::new()
        .name("spiceio-log".into())
        .spawn(move || writer_loop(rx, file))
        .is_ok();

    if spawned {
        LOG_TX.set(tx).ok();
    }
}

/// Background writer — drains the channel, fans out to the console stream and
/// optional log file, and flushes in batches.
fn writer_loop(rx: mpsc::Receiver<LogMsg>, file: Option<std::fs::File>) {
    let mut fw = file.map(|f| BufWriter::with_capacity(BUF_CAP, f));
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();

    let handle = |msg: LogMsg,
                  fw: &mut Option<BufWriter<std::fs::File>>,
                  acks: &mut Vec<mpsc::SyncSender<()>>| {
        let line = match &msg {
            LogMsg::Stdout(s) | LogMsg::Stderr(s) => s.as_str(),
            LogMsg::Flush(ack) => {
                acks.push(ack.clone());
                return;
            }
        };
        match &msg {
            LogMsg::Stdout(_) => {
                let mut o = stdout.lock();
                let _ = writeln!(o, "{line}");
            }
            LogMsg::Stderr(_) => {
                let mut e = stderr.lock();
                let _ = writeln!(e, "{line}");
            }
            LogMsg::Flush(_) => unreachable!(),
        }
        if let Some(w) = fw.as_mut() {
            let _ = w.write_all(line.as_bytes());
            let _ = w.write_all(b"\n");
        }
    };

    let mut acks: Vec<mpsc::SyncSender<()>> = Vec::new();
    while let Ok(msg) = rx.recv() {
        handle(msg, &mut fw, &mut acks);
        // Drain any queued messages before issuing the syscall flush.
        while let Ok(msg) = rx.try_recv() {
            handle(msg, &mut fw, &mut acks);
        }
        if let Some(w) = fw.as_mut() {
            let _ = w.flush();
        }
        // Acknowledge flush requests only after the file hit the OS.
        for ack in acks.drain(..) {
            let _ = ack.send(());
        }
    }
}

/// Block until all log lines queued so far are flushed (file included), or the
/// timeout elapses. Call at graceful shutdown — without it the writer thread
/// dies with the process and the final buffered lines are lost.
///
/// Honors `timeout` as an overall deadline split across two waits: blocking to
/// *enqueue* the flush request (the channel may be momentarily full under heavy
/// logging — exactly when the final lines matter most, so `try_send` would drop
/// them) and then waiting for the writer's ack within the remaining budget. If
/// the request can't be enqueued before the deadline, it gives up rather than
/// hang.
pub fn flush(timeout: std::time::Duration) {
    let Some(tx) = LOG_TX.get() else { return };
    let deadline = std::time::Instant::now() + timeout;
    let (ack_tx, ack_rx) = mpsc::sync_channel::<()>(1);
    // Enqueue the flush request, retrying within the deadline if the channel is
    // momentarily full (heavy logging — exactly when the final lines matter, so
    // a single non-blocking `try_send` would drop them). `try_send` hands the
    // message back on `Full`, so reuse it. `send_timeout` would be simpler but
    // is unstable on stable Rust.
    let mut msg = LogMsg::Flush(ack_tx);
    loop {
        match tx.try_send(msg) {
            Ok(()) => break,
            Err(mpsc::TrySendError::Full(returned)) => {
                if std::time::Instant::now() >= deadline {
                    return; // couldn't enqueue before the deadline — give up
                }
                std::thread::sleep(std::time::Duration::from_millis(2));
                msg = returned;
            }
            Err(mpsc::TrySendError::Disconnected(_)) => return,
        }
    }
    // The flush is processed after every line queued before it, so the ack
    // means the writer has drained and flushed them. Wait out the remaining
    // budget for it.
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    let _ = ack_rx.recv_timeout(remaining);
}

/// Format a timestamp from `gettimeofday` into a fixed 24-byte ISO-8601 UTC
/// string: `2026-04-02T16:09:34.123Z`. Uses a stack buffer — no allocation.
fn timestamp(buf: &mut [u8; 24]) {
    #[repr(C)]
    struct Timeval {
        tv_sec: i64,
        tv_usec: i32,
    }

    unsafe extern "C" {
        fn gettimeofday(tp: *mut Timeval, tzp: *const std::ffi::c_void) -> i32;
    }

    let mut tv = Timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    unsafe {
        gettimeofday(&mut tv, std::ptr::null());
    }

    let secs = tv.tv_sec as u64;
    let millis = (tv.tv_usec / 1000) as u64;

    // Civil time from Unix epoch (Howard Hinnant algorithm)
    let days = secs / 86400;
    let rem = secs % 86400;
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    let h = rem / 3600;
    let min = (rem % 3600) / 60;
    let s = rem % 60;

    // Write directly: "YYYY-MM-DDThh:mm:ss.mmmZ"
    buf[0] = b'0' + ((y / 1000) % 10) as u8;
    buf[1] = b'0' + ((y / 100) % 10) as u8;
    buf[2] = b'0' + ((y / 10) % 10) as u8;
    buf[3] = b'0' + (y % 10) as u8;
    buf[4] = b'-';
    buf[5] = b'0' + ((m / 10) % 10) as u8;
    buf[6] = b'0' + (m % 10) as u8;
    buf[7] = b'-';
    buf[8] = b'0' + ((d / 10) % 10) as u8;
    buf[9] = b'0' + (d % 10) as u8;
    buf[10] = b'T';
    buf[11] = b'0' + ((h / 10) % 10) as u8;
    buf[12] = b'0' + (h % 10) as u8;
    buf[13] = b':';
    buf[14] = b'0' + ((min / 10) % 10) as u8;
    buf[15] = b'0' + (min % 10) as u8;
    buf[16] = b':';
    buf[17] = b'0' + ((s / 10) % 10) as u8;
    buf[18] = b'0' + (s % 10) as u8;
    buf[19] = b'.';
    buf[20] = b'0' + ((millis / 100) % 10) as u8;
    buf[21] = b'0' + ((millis / 10) % 10) as u8;
    buf[22] = b'0' + (millis % 10) as u8;
    buf[23] = b'Z';
}

/// Write a formatted message to **stdout** (and the log file when configured),
/// routed through the background thread so it never blocks the caller.
#[inline]
pub fn emit(args: fmt::Arguments<'_>) {
    let mut ts = [0u8; 24];
    timestamp(&mut ts);
    let ts = unsafe { std::str::from_utf8_unchecked(&ts) };
    let line = format!("{ts} {args}");
    if let Some(tx) = LOG_TX.get() {
        // Drop on full — logging must never stall request handling.
        let _ = tx.try_send(LogMsg::Stdout(line));
    } else {
        // Pre-init fallback (startup only).
        println!("{line}");
    }
}

/// Write a formatted message to **stderr** (and the log file when configured),
/// routed through the background thread so it never blocks the caller.
#[inline]
pub fn emit_err(args: fmt::Arguments<'_>) {
    let mut ts = [0u8; 24];
    timestamp(&mut ts);
    let ts = unsafe { std::str::from_utf8_unchecked(&ts) };
    let line = format!("{ts} {args}");
    if let Some(tx) = LOG_TX.get() {
        let _ = tx.try_send(LogMsg::Stderr(line));
    } else {
        eprintln!("{line}");
    }
}
