//! Streaming response body for S3 operations.
//!
//! `SpiceioBody` is an enum body that can be either a full in-memory response
//! (for XML, errors, small payloads) or a streaming channel body (for
//! GetObject reads from SMB).

use bytes::Bytes;
use http_body::{Body, Frame};
use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::mpsc;

/// Unified response body — either fully buffered or streamed via channel.
pub enum SpiceioBody {
    /// Complete body in memory (XML responses, errors, small payloads).
    Full(Option<Bytes>),
    /// Streaming body fed by an mpsc channel (GetObject, large reads).
    Stream(mpsc::Receiver<Bytes>),
}

impl SpiceioBody {
    /// Create a full body from bytes.
    pub fn full(data: Bytes) -> Self {
        if data.is_empty() {
            Self::Full(None)
        } else {
            Self::Full(Some(data))
        }
    }

    /// Create an empty body.
    pub fn empty() -> Self {
        Self::Full(None)
    }

    /// Create a streaming body, returning (body, sender).
    pub fn channel(buffer: usize) -> (Self, mpsc::Sender<Bytes>) {
        let (tx, rx) = mpsc::channel(buffer);
        (Self::Stream(rx), tx)
    }
}

impl Body for SpiceioBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            SpiceioBody::Full(data) => {
                // Yield the data once, then signal end of stream
                Poll::Ready(data.take().map(|b| Ok(Frame::data(b))))
            }
            SpiceioBody::Stream(rx) => rx.poll_recv(cx).map(|opt| opt.map(|b| Ok(Frame::data(b)))),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            SpiceioBody::Full(None) => true,
            SpiceioBody::Full(Some(b)) => b.is_empty(),
            SpiceioBody::Stream(_) => false,
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match self {
            SpiceioBody::Full(None) => http_body::SizeHint::with_exact(0),
            SpiceioBody::Full(Some(b)) => http_body::SizeHint::with_exact(b.len() as u64),
            SpiceioBody::Stream(_) => http_body::SizeHint::default(),
        }
    }
}
