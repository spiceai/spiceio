//! Crash reporting — panic hook and fatal-signal handler.
//!
//! Guarantees that when spiceio dies abnormally it leaves a diagnosable
//! report on stderr (and, when `SPICEIO_LOG_FILE` is configured, appended to
//! the log file) before the process exits:
//!
//! - **Panics** (including `panic = "abort"` release builds): the hook runs
//!   before the abort and writes version, pid, uptime, thread, the panic
//!   message *with source location* (always present, even in stripped
//!   binaries), and a captured backtrace.
//! - **Fatal signals** (`SIGSEGV`/`SIGBUS`/`SIGILL`/`SIGFPE`/`SIGTRAP`/
//!   `SIGABRT` — e.g. a fault inside FFI code): an async-signal-safe handler
//!   writes the signal, fault address, register state, and a frame-pointer
//!   backtrace, then re-raises with the default disposition so the OS crash
//!   reporter and exit status still behave normally.
//!
//! Release binaries are stripped for size/perf, so in-process symbolication
//! is not available there. Every report therefore includes the image load
//! address and ASLR slide; raw frame addresses can be symbolized offline
//! against the build's dSYM (produced by the release profile):
//!
//! ```text
//! atos -o target/release/spiceio.dSYM/Contents/Resources/DWARF/spiceio \
//!      -l <image base> <frame addresses…>
//! ```
//!
//! The signal path uses only async-signal-safe operations (`write(2)`,
//! `sigaction(2)`, `raise(2)`, stack buffers — no allocation, no locks). The
//! handler restores the default disposition *first*, so a nested fault while
//! reporting terminates the process instead of looping.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};

// ── libc / libSystem FFI ────────────────────────────────────────────────────

#[repr(C)]
struct Sigaction {
    /// `union __sigaction_u` — handler or sigaction fn pointer.
    sa_sigaction: usize,
    /// `sigset_t` is `u32` on macOS.
    sa_mask: u32,
    sa_flags: i32,
}

const SA_ONSTACK: i32 = 0x0001;
const SA_SIGINFO: i32 = 0x0040;
const SIG_DFL: usize = 0;

/// `CLOCK_MONOTONIC` from macOS `<time.h>`.
const CLOCK_MONOTONIC: i32 = 6;

/// `struct timespec` (64-bit macOS): `time_t tv_sec; long tv_nsec`.
#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

unsafe extern "C" {
    fn sigaction(signum: i32, act: *const Sigaction, oldact: *mut Sigaction) -> i32;
    fn raise(signum: i32) -> i32;
    fn write(fd: i32, buf: *const u8, count: usize) -> isize;
    /// POSIX-guaranteed async-signal-safe; used for uptime in the handler.
    fn clock_gettime(clk_id: i32, tp: *mut Timespec) -> i32;
    /// ASLR slide of image `index` (0 = main executable).
    fn _dyld_get_image_vmaddr_slide(index: u32) -> isize;
    /// Mach header address of image `index` (0 = main executable).
    fn _dyld_get_image_header(index: u32) -> usize;
}

/// Fatal signals we report on. (name, number) — macOS signal numbers.
const FATAL_SIGNALS: &[(&str, i32)] = &[
    ("SIGILL", 4),
    ("SIGTRAP", 5),
    ("SIGABRT", 6),
    ("SIGFPE", 8),
    ("SIGBUS", 10),
    ("SIGSEGV", 11),
];

// ── Shared crash-report state ───────────────────────────────────────────────

/// Pre-opened `O_APPEND` fd for the log file, used by both the panic hook and
/// the signal handler (a signal handler cannot safely open files).
static CRASH_FD: AtomicI32 = AtomicI32::new(-1);
/// Set by the panic hook so the subsequent `SIGABRT` (from `panic = "abort"`)
/// does not produce a second, redundant report.
static PANIC_REPORTED: AtomicBool = AtomicBool::new(false);
/// Re-entrancy guard for the signal handler.
static IN_SIGNAL_HANDLER: AtomicBool = AtomicBool::new(false);
/// Process start time as monotonic seconds (`clock_gettime(CLOCK_MONOTONIC)`),
/// for uptime in reports. Stored as a raw second count — not `Instant` — so the
/// fatal-signal handler can recompute uptime with only async-signal-safe calls
/// (`clock_gettime` + an atomic load), never `Instant::elapsed()`.
static STARTED_SECS: AtomicU64 = AtomicU64::new(0);
/// Main-image load address and ASLR slide, captured at install time (the dyld
/// calls are not async-signal-safe, so they must not run in the handler).
static IMAGE_BASE: OnceLock<usize> = OnceLock::new();
static IMAGE_SLIDE: OnceLock<isize> = OnceLock::new();

/// Install the panic hook and fatal-signal handlers. Call once at startup,
/// after logging is initialised. `log_path` mirrors `SPICEIO_LOG_FILE`; when
/// set, crash reports are appended there as well as to stderr.
pub fn install(log_path: Option<&str>) {
    STARTED_SECS.store(monotonic_secs(), Ordering::SeqCst);
    IMAGE_BASE.set(unsafe { _dyld_get_image_header(0) }).ok();
    IMAGE_SLIDE
        .set(unsafe { _dyld_get_image_vmaddr_slide(0) })
        .ok();

    if let Some(path) = log_path
        && let Ok(file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
    {
        use std::os::fd::IntoRawFd;
        CRASH_FD.store(file.into_raw_fd(), Ordering::SeqCst);
    }

    std::panic::set_hook(Box::new(panic_hook));

    for &(_, sig) in FATAL_SIGNALS {
        let act = Sigaction {
            sa_sigaction: fatal_signal_handler as *const () as usize,
            sa_mask: 0,
            // SA_ONSTACK: run on the sigaltstack Rust installs per thread, so
            // stack-overflow SIGSEGVs are reportable too.
            sa_flags: SA_SIGINFO | SA_ONSTACK,
        };
        // SAFETY: `act` is a valid sigaction for the lifetime of the call and
        // the handler is async-signal-safe by construction.
        unsafe {
            sigaction(sig, &act, std::ptr::null_mut());
        }
    }
}

/// Monotonic seconds via `clock_gettime(CLOCK_MONOTONIC)`. Async-signal-safe
/// (POSIX lists `clock_gettime`), so it is callable from the fatal-signal
/// handler — unlike `Instant::elapsed()`, whose macOS backend is not on the
/// async-signal-safe list. Returns 0 if the clock read fails.
fn monotonic_secs() -> u64 {
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, exclusively-borrowed out-param for the call.
    if unsafe { clock_gettime(CLOCK_MONOTONIC, &mut ts) } != 0 {
        return 0;
    }
    ts.tv_sec.max(0) as u64
}

fn uptime_secs() -> u64 {
    monotonic_secs().saturating_sub(STARTED_SECS.load(Ordering::Relaxed))
}

/// Write a crash report to stderr and (when configured) the log file.
/// Writes via raw `write(2)` to fd 2 rather than `std::io::stderr().lock()`:
/// a panic that fires while another thread (e.g. the log writer) holds the
/// Rust stderr lock would otherwise deadlock the hook and produce no report.
/// This also matches the fatal-signal path, which must avoid locks entirely.
/// Never routed through the async logger, whose buffered lines would be lost
/// when the process aborts.
fn crash_write(bytes: &[u8]) {
    write_fd(2, bytes);
    write_fd(CRASH_FD.load(Ordering::SeqCst), bytes);
}

/// `write(2)` loop, usable from a signal handler (no locks, no allocation).
fn write_fd(fd: i32, mut bytes: &[u8]) {
    if fd < 0 {
        return;
    }
    while !bytes.is_empty() {
        // SAFETY: `bytes` is a valid readable buffer of the given length.
        let n = unsafe { write(fd, bytes.as_ptr(), bytes.len()) };
        if n <= 0 {
            return;
        }
        bytes = &bytes[n as usize..];
    }
}

// ── Panic hook ──────────────────────────────────────────────────────────────

fn panic_hook(info: &std::panic::PanicHookInfo<'_>) {
    PANIC_REPORTED.store(true, Ordering::SeqCst);

    let payload = info.payload();
    let msg = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("<non-string panic payload>");
    let location = info
        .location()
        .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
        .unwrap_or_else(|| "<unknown location>".into());
    let thread = std::thread::current();
    let thread_name = thread.name().unwrap_or("<unnamed>");
    // force_capture: independent of RUST_BACKTRACE so production crashes are
    // never reported without a trace. In stripped builds frames show as raw
    // addresses — symbolize offline with the dSYM and the base printed below.
    let backtrace = std::backtrace::Backtrace::force_capture();
    let base = IMAGE_BASE.get().copied().unwrap_or(0);
    let slide = IMAGE_SLIDE.get().copied().unwrap_or(0);

    let report = format!(
        "\n=== spiceio crash report (panic) ===\n\
         version : {version} (pid {pid}, uptime {uptime}s)\n\
         thread  : {thread_name}\n\
         panicked at {location}:\n  {msg}\n\
         image   : base 0x{base:x} slide 0x{slide:x} \
         (symbolize: atos -o spiceio.dSYM/... -l 0x{base:x} <addr>)\n\
         backtrace:\n{backtrace}\n\
         === end crash report ===\n",
        version = env!("CARGO_PKG_VERSION"),
        pid = std::process::id(),
        uptime = uptime_secs(),
    );
    crash_write(report.as_bytes());
}

// ── Fatal-signal handler (async-signal-safe) ───────────────────────────────

/// Fixed-size, no-allocation line buffer for signal-handler formatting.
struct SigBuf {
    buf: [u8; 256],
    len: usize,
}

impl SigBuf {
    fn new() -> Self {
        Self {
            buf: [0; 256],
            len: 0,
        }
    }

    fn push(&mut self, s: &str) -> &mut Self {
        for &b in s.as_bytes() {
            if self.len < self.buf.len() {
                self.buf[self.len] = b;
                self.len += 1;
            }
        }
        self
    }

    fn push_hex(&mut self, v: u64) -> &mut Self {
        self.push("0x");
        let mut started = false;
        for i in (0..16).rev() {
            let digit = ((v >> (i * 4)) & 0xF) as usize;
            if digit != 0 || started || i == 0 {
                started = true;
                self.push(unsafe {
                    // SAFETY: single ASCII hex digit.
                    std::str::from_utf8_unchecked(&b"0123456789abcdef"[digit..digit + 1])
                });
            }
        }
        self
    }

    fn push_dec(&mut self, v: u64) -> &mut Self {
        let mut tmp = [0u8; 20];
        let mut i = tmp.len();
        let mut v = v;
        loop {
            i -= 1;
            tmp[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        // SAFETY: ASCII digits only.
        self.push(unsafe { std::str::from_utf8_unchecked(&tmp[i..]) })
    }

    /// Write the buffered line to stderr and the crash fd, then reset.
    fn emit(&mut self) {
        write_fd(2, &self.buf[..self.len]);
        write_fd(CRASH_FD.load(Ordering::SeqCst), &self.buf[..self.len]);
        self.len = 0;
    }
}

fn signal_name(sig: i32) -> &'static str {
    FATAL_SIGNALS
        .iter()
        .find(|&&(_, n)| n == sig)
        .map(|&(name, _)| name)
        .unwrap_or("SIG?")
}

/// Restore the default disposition for `sig`.
///
/// # Safety
/// Async-signal-safe (`sigaction` only).
unsafe fn restore_default(sig: i32) {
    let act = Sigaction {
        sa_sigaction: SIG_DFL,
        sa_mask: 0,
        sa_flags: 0,
    };
    // SAFETY: valid sigaction struct; SIG_DFL is always a valid disposition.
    unsafe {
        sigaction(sig, &act, std::ptr::null_mut());
    }
}

/// Register state extracted from the signal's `ucontext`.
struct Regs {
    pc: u64,
    lr: u64,
    fp: u64,
    sp: u64,
}

/// Extract pc/lr/fp/sp from a darwin `ucontext_t`.
///
/// # Safety
/// `ctx` must be the `ucontext_t*` passed to an `SA_SIGINFO` handler.
unsafe fn regs_from_ucontext(ctx: *const u8) -> Option<Regs> {
    if ctx.is_null() {
        return None;
    }
    // struct ucontext64 { int uc_onstack; sigset_t uc_sigmask; sigaltstack
    // uc_stack; ucontext* uc_link; size_t uc_mcsize; mcontext64* uc_mcontext }
    // → the mcontext pointer lives at byte offset 48.
    // SAFETY: caller guarantees `ctx` points at a live ucontext_t.
    let mcontext = unsafe { ctx.add(48).cast::<*const u8>().read() };
    if mcontext.is_null() {
        return None;
    }
    // SAFETY: mcontext64 layouts below are fixed ABI on macOS.
    unsafe {
        #[cfg(target_arch = "aarch64")]
        {
            // __darwin_mcontext64: 16-byte exception state, then
            // __darwin_arm_thread_state64 { x[29], fp, lr, sp, pc, cpsr }.
            let ss = mcontext.add(16);
            Some(Regs {
                fp: ss.add(29 * 8).cast::<u64>().read(),
                lr: ss.add(30 * 8).cast::<u64>().read(),
                sp: ss.add(31 * 8).cast::<u64>().read(),
                pc: ss.add(32 * 8).cast::<u64>().read(),
            })
        }
        #[cfg(target_arch = "x86_64")]
        {
            // __darwin_mcontext64: 16-byte exception state, then
            // __darwin_x86_thread_state64 { rax,rbx,rcx,rdx,rdi,rsi,rbp,rsp,
            // r8..r15, rip, … }.
            let ss = mcontext.add(16);
            Some(Regs {
                fp: ss.add(6 * 8).cast::<u64>().read(),
                sp: ss.add(7 * 8).cast::<u64>().read(),
                lr: 0,
                pc: ss.add(16 * 8).cast::<u64>().read(),
            })
        }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            let _ = mcontext;
            None
        }
    }
}

extern "C" fn fatal_signal_handler(sig: i32, info: *mut u8, ctx: *mut u8) {
    // Restore default disposition immediately: a nested fault while reporting
    // (e.g. walking a corrupt frame chain) terminates instead of recursing.
    // SAFETY: async-signal-safe.
    unsafe { restore_default(sig) };

    if IN_SIGNAL_HANDLER.swap(true, Ordering::SeqCst) {
        // Nested fault while reporting — die now.
        // SAFETY: re-raising with default disposition terminates the process.
        unsafe { raise(sig) };
        return;
    }

    // SIGABRT immediately after a panic report (panic = "abort") adds nothing.
    if sig == 6 && PANIC_REPORTED.load(Ordering::SeqCst) {
        // SAFETY: as above.
        unsafe { raise(sig) };
        return;
    }

    let mut line = SigBuf::new();
    line.push("\n=== spiceio crash report (fatal signal) ===\n")
        .emit();
    line.push("signal  : ")
        .push(signal_name(sig))
        .push(" (")
        .push_dec(sig as u64)
        .push("), version ")
        .push(env!("CARGO_PKG_VERSION"))
        .push(", pid ")
        .push_dec(std::process::id() as u64)
        .push(", uptime ")
        .push_dec(uptime_secs())
        .push("s\n")
        .emit();

    // Fault address: darwin siginfo_t has si_addr at byte offset 24.
    if !info.is_null() {
        // SAFETY: `info` is the siginfo_t* delivered to an SA_SIGINFO handler.
        let fault_addr = unsafe { info.add(24).cast::<u64>().read() };
        line.push("fault   : address ")
            .push_hex(fault_addr)
            .push("\n")
            .emit();
    }

    let base = IMAGE_BASE.get().copied().unwrap_or(0) as u64;
    let slide = IMAGE_SLIDE.get().copied().unwrap_or(0) as u64;
    line.push("image   : base ")
        .push_hex(base)
        .push(" slide ")
        .push_hex(slide)
        .push(" (symbolize: atos -o spiceio.dSYM/... -l ")
        .push_hex(base)
        .push(" <addr>)\n")
        .emit();

    // SAFETY: ctx is the ucontext_t* delivered to an SA_SIGINFO handler.
    if let Some(regs) = unsafe { regs_from_ucontext(ctx) } {
        line.push("regs    : pc ")
            .push_hex(regs.pc)
            .push(" lr ")
            .push_hex(regs.lr)
            .push(" fp ")
            .push_hex(regs.fp)
            .push(" sp ")
            .push_hex(regs.sp)
            .push("\n")
            .emit();
        line.push("backtrace (raw, frame-pointer walk):\n").emit();
        line.push("  pc: ").push_hex(regs.pc).push("\n").emit();
        if regs.lr != 0 {
            line.push("  lr: ").push_hex(regs.lr).push("\n").emit();
        }
        // Frame-pointer walk: [fp] = caller fp, [fp+8] = return address.
        // Each line is written immediately, so a fault mid-walk (default
        // disposition already restored) still leaves the frames so far.
        let mut fp = regs.fp;
        for _ in 0..48 {
            if fp == 0 || fp % 8 != 0 {
                break;
            }
            // SAFETY: best-effort read of the saved frame record; alignment
            // checked above, and a wild pointer faults into the now-default
            // signal disposition (process exits with a truncated report).
            let (next_fp, ret) =
                unsafe { ((fp as *const u64).read(), (fp as *const u64).add(1).read()) };
            if ret == 0 {
                break;
            }
            line.push("  fp: ").push_hex(ret).push("\n").emit();
            if next_fp <= fp {
                break; // frame chain must walk strictly up the stack
            }
            fp = next_fp;
        }
    }
    line.push("=== end crash report ===\n").emit();

    // Re-raise with the default disposition: correct exit status, and the OS
    // crash reporter (.ips) still fires.
    // SAFETY: async-signal-safe.
    unsafe { raise(sig) };
}

// ── Crash-test hooks (used by integration tests) ───────────────────────────

/// Deliberately crash the process — exercises the full crash-report pipeline
/// end-to-end. Invoked via the hidden `--crash-test <mode>` CLI flag.
pub fn crash_test(mode: &str) -> ! {
    match mode {
        "panic" => panic!("crash-test: deliberate panic"),
        "segv" => {
            // Deliver SIGSEGV via `raise` rather than performing a real invalid
            // memory access. It drives the exact same SA_SIGINFO handler path
            // (signal, siginfo with si_addr 0, ucontext registers, report,
            // re-raise) deterministically, while keeping the shipped binary
            // free of an intentional invalid-pointer dereference — there is no
            // reason to bake reachable undefined behavior into a release just
            // to test the handler.
            const SIGSEGV: i32 = 11;
            // SAFETY: `raise` is async-signal-safe and simply posts the signal
            // to this thread, where the installed fatal-signal handler runs.
            unsafe {
                raise(SIGSEGV);
            }
            unreachable!("raise(SIGSEGV) did not terminate");
        }
        "abort" => std::process::abort(),
        other => {
            crate::serr!("[spiceio] unknown --crash-test mode: {other}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigbuf_hex_formats() {
        let mut b = SigBuf::new();
        b.push_hex(0);
        assert_eq!(&b.buf[..b.len], b"0x0");
        b.len = 0;
        b.push_hex(0xdead_beef);
        assert_eq!(&b.buf[..b.len], b"0xdeadbeef");
        b.len = 0;
        b.push_hex(u64::MAX);
        assert_eq!(&b.buf[..b.len], b"0xffffffffffffffff");
    }

    #[test]
    fn sigbuf_dec_formats() {
        let mut b = SigBuf::new();
        b.push_dec(0);
        assert_eq!(&b.buf[..b.len], b"0");
        b.len = 0;
        b.push_dec(65536);
        assert_eq!(&b.buf[..b.len], b"65536");
    }

    #[test]
    fn sigbuf_truncates_instead_of_overflowing() {
        let mut b = SigBuf::new();
        for _ in 0..100 {
            b.push("0123456789");
        }
        assert_eq!(b.len, b.buf.len());
    }

    #[test]
    fn signal_names_cover_fatal_set() {
        assert_eq!(signal_name(11), "SIGSEGV");
        assert_eq!(signal_name(10), "SIGBUS");
        assert_eq!(signal_name(6), "SIGABRT");
        assert_eq!(signal_name(99), "SIG?");
    }
}
