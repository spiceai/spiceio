//! End-to-end crash-report tests: spawn the real binary with the hidden
//! `--crash-test` flag and assert a report reaches stderr and the log file.

use std::path::PathBuf;
use std::process::Command;

fn crash(mode: &str, log: &PathBuf) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_spiceio"))
        .arg("--crash-test")
        .arg(mode)
        .env("SPICEIO_LOG_FILE", log)
        .output()
        .expect("failed to spawn spiceio")
}

fn temp_log(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "spiceio-crash-test-{tag}-{}.log",
        std::process::id()
    ))
}

#[test]
fn panic_writes_crash_report_to_stderr_and_log_file() {
    let log = temp_log("panic");
    let _ = std::fs::remove_file(&log);
    let out = crash("panic", &log);

    assert!(!out.status.success(), "crash-test must not exit cleanly");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("=== spiceio crash report (panic) ==="),
        "missing report header in stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("crash-test: deliberate panic"),
        "missing panic message in stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("panicked at") && stderr.contains("crash.rs"),
        "missing panic location in stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("backtrace:"),
        "missing backtrace in stderr:\n{stderr}"
    );

    let logged = std::fs::read_to_string(&log).expect("crash log file should exist");
    assert!(
        logged.contains("=== spiceio crash report (panic) ==="),
        "report missing from log file:\n{logged}"
    );
    let _ = std::fs::remove_file(&log);
}

#[test]
fn segv_writes_fatal_signal_report() {
    let log = temp_log("segv");
    let _ = std::fs::remove_file(&log);
    let out = crash("segv", &log);

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("=== spiceio crash report (fatal signal) ==="),
        "missing signal report in stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("SIGSEGV"),
        "missing signal name in stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("fault   : address 0x0"),
        "missing fault address in stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("regs    : pc 0x"),
        "missing register state in stderr:\n{stderr}"
    );

    let logged = std::fs::read_to_string(&log).expect("crash log file should exist");
    assert!(
        logged.contains("=== spiceio crash report (fatal signal) ==="),
        "report missing from log file:\n{logged}"
    );
    let _ = std::fs::remove_file(&log);
}

#[test]
fn abort_writes_fatal_signal_report_without_panic_duplication() {
    let log = temp_log("abort");
    let _ = std::fs::remove_file(&log);
    let out = crash("abort", &log);

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("SIGABRT"),
        "missing SIGABRT report in stderr:\n{stderr}"
    );
    let _ = std::fs::remove_file(&log);
}

#[test]
fn panic_report_is_not_duplicated_by_abort_handler() {
    // With panic=abort (release) the panic raises SIGABRT after the hook has
    // already reported; the signal handler must skip the second report. In
    // dev builds (panic=unwind) there is no SIGABRT at all. Either way the
    // panic report must appear exactly once.
    let log = temp_log("dedup");
    let _ = std::fs::remove_file(&log);
    let out = crash("panic", &log);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        stderr.matches("=== spiceio crash report").count(),
        1,
        "expected exactly one crash report:\n{stderr}"
    );
    let _ = std::fs::remove_file(&log);
}
