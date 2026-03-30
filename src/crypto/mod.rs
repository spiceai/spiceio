//! macOS CommonCrypto FFI — zero-dependency cryptographic primitives.
//!
//! We link directly to `Security.framework` / `libcommonCrypto` which ships
//! with every macOS installation, avoiding any Rust crypto crate.

mod ffi;

pub use ffi::{aes128_cmac, hex_encode, hmac_md5, hmac_sha256, md4, sha256, sha512};
