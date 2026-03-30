//! SMB 3.1.1 client — speaks the wire protocol directly over TCP (macOS 26).
//!
//! No local mount, no libsmbclient. Pure Rust + macOS CommonCrypto for auth.

pub mod auth;
pub mod client;
pub mod ops;
pub mod protocol;

pub use client::SmbClient;
