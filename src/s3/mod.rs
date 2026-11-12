//! S3-compatible API layer — full API surface.
//!
//! Optional SigV4 authentication (header and presigned, with signed payloads
//! and signed aws-chunked uploads; see `auth`), aws-chunked decoding in every
//! mode, all headers, conditional ops, range reads, copy, multipart,
//! ACL/tagging/versioning stubs, CORS, region selection.

pub mod auth;
pub mod body;
mod condition;
pub mod existence;
pub mod headers;
pub mod listing;
pub mod multipart;
pub mod object_cache;
pub mod request_body;
pub mod router;
pub mod sigv4;
pub mod spill;
pub mod writeback;
pub mod xml;
