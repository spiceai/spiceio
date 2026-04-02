//! Non-blocking file logger backed by a dedicated OS thread.
//!
//! Design: a bounded `mpsc::sync_channel` feeds a background thread that owns
//! the file descriptor and writes through a 64 KB `BufWriter`. The hot path
//! (`emit` / `emit_err`) does a single `try_send` — if the channel is full
//! the message is silently dropped, so logging never blocks the proxy.
//!
//! Two entry points: `emit` (stdout) and `emit_err` (stderr). Both prepend
//! an ISO-8601 timestamp and write to the log file when configured. When no
//! log file is configured only the console stream is written (zero overhead
//! from the file path — no channel, no allocation, no thread).

use std::fmt;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::sync::OnceLock;
use std::sync::mpsc;

/// Channel capacity — number of formatted log lines buffered before drops.
const CHANNEL_CAP: usize = 4096;

/// BufWriter capacity — bytes buffered before a syscall write.
const BUF_CAP: usize = 64 * 1024;

static FILE_TX: OnceLock<mpsc::SyncSender<String>> = OnceLock::new();

/// Initialise file logging.  Call once at startup.
/// If `path` is `None`, only console logging is active (the default).
pub fn init(path: Option<&str>) {
    let Some(p) = path else { return };

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(p)
        .unwrap_or_else(|e| panic!("[spiceio] failed to open log file {p}: {e}"));

    let (tx, rx) = mpsc::sync_channel::<String>(CHANNEL_CAP);

    std::thread::Builder::new()
        .name("spiceio-log".into())
        .spawn(move || writer_loop(rx, file))
        .expect("[spiceio] failed to spawn log thread");

    FILE_TX.set(tx).ok();
}

/// Background writer — drains the channel and flushes in batches.
fn writer_loop(rx: mpsc::Receiver<String>, file: std::fs::File) {
    let mut w = BufWriter::with_capacity(BUF_CAP, file);
    while let Ok(line) = rx.recv() {
        let _ = w.write_all(line.as_bytes());
        let _ = w.write_all(b"\n");
        // Drain any queued messages before issuing the syscall flush.
        while let Ok(line) = rx.try_recv() {
            let _ = w.write_all(line.as_bytes());
            let _ = w.write_all(b"\n");
        }
        let _ = w.flush();
    }
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

/// Write a formatted message to **stdout** and (if configured) to the log file.
#[inline]
pub fn emit(args: fmt::Arguments<'_>) {
    let mut ts = [0u8; 24];
    timestamp(&mut ts);
    let ts = unsafe { std::str::from_utf8_unchecked(&ts) };
    println!("{ts} {args}");
    if let Some(tx) = FILE_TX.get() {
        let _ = tx.try_send(format!("{ts} {args}"));
    }
}

/// Write a formatted message to **stderr** and (if configured) to the log file.
#[inline]
pub fn emit_err(args: fmt::Arguments<'_>) {
    let mut ts = [0u8; 24];
    timestamp(&mut ts);
    let ts = unsafe { std::str::from_utf8_unchecked(&ts) };
    eprintln!("{ts} {args}");
    if let Some(tx) = FILE_TX.get() {
        let _ = tx.try_send(format!("{ts} {args}"));
    }
}
