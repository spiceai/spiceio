//! spiceio — S3-compatible API proxy to SMB 3.1.x file shares.
//!
//! Library crate exposing modules for benchmarking and testing.

pub mod log;

/// Log to stdout and optionally to a file (non-blocking).
#[macro_export]
macro_rules! slog {
    ($($arg:tt)*) => {
        $crate::log::emit(format_args!($($arg)*))
    };
}

/// Log to stderr and optionally to a file (non-blocking).
#[macro_export]
macro_rules! serr {
    ($($arg:tt)*) => {
        $crate::log::emit_err(format_args!($($arg)*))
    };
}

pub mod crypto;
pub mod s3;
pub mod smb;
