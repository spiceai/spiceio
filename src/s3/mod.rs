//! S3-compatible API layer — full API surface.
//!
//! Auth (SigV4 + presigned), all headers, conditional ops, range reads,
//! copy, multipart, ACL/tagging/versioning stubs, CORS, region selection.

pub mod auth;
pub mod body;
pub mod headers;
pub mod multipart;
pub mod router;
pub mod xml;
