//! The request body as the handlers see it: aws-chunked framing removed and,
//! for a signed request, the payload checked against its signature.
//!
//! **aws-chunked is decoded in every auth mode.** aws-cli v2's `aws s3 cp`
//! sends `Content-Encoding: aws-chunked` with
//! `STREAMING-UNSIGNED-PAYLOAD-TRAILER` over plain HTTP — even with
//! `--no-sign-request` — and minio-go/mc sends signed chunks. A proxy that
//! passes that body through stores the framing (`B\r\nhello world\r\n0\r\n
//! x-amz-checksum-crc64nvme:…`) as the object, so decoding is a correctness
//! requirement, not an auth feature. The trailing checksum is parsed but not
//! verified, the same as a checksum sent as a header.
//!
//! Every check that can only finish at the end of the body (the payload
//! digest, the final chunk and trailer signatures, the decoded length) is
//! reported as an error frame *in place of* end-of-stream. Every consumer
//! already treats a body error as fatal before its point of no return — a
//! WAL temp is aborted rather than renamed, a collected body is never
//! enqueued or acknowledged — so an unverified payload is never published,
//! even though its bytes may have streamed into a temp file first.

use std::collections::VecDeque;
use std::error::Error as StdError;
use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use http::HeaderMap;
use http_body::{Body, Frame};
use hyper::body::Incoming;

use super::auth::{self, ChunkSigning, PayloadAuth, PayloadPlan};
use super::sigv4;
use crate::crypto::Sha256;

/// Longest chunk-header, CRLF or trailer line accepted. A signed chunk header
/// is ~85 bytes; this only bounds what a hostile body can make spiceio buffer.
const MAX_LINE: usize = 4096;
/// Bound on the whole trailer section.
const MAX_TRAILERS: usize = 16 * 1024;

/// How the body is framed on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    Plain,
    /// `Content-Encoding: aws-chunked`; the decoded body is `decoded_len`
    /// bytes (`x-amz-decoded-content-length`, which S3 requires).
    AwsChunked {
        decoded_len: u64,
    },
}

/// A request whose framing headers contradict each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramingError {
    /// aws-chunked without a usable `x-amz-decoded-content-length`.
    MissingDecodedLength,
    /// aws-chunked body with a whole-body digest as its payload hash: the
    /// digest of which bytes is ambiguous, and no client sends it.
    DigestWithChunked,
}

/// Decide the framing from the headers. A `STREAMING-*` payload hash is
/// aws-chunked by definition; so is `Content-Encoding: aws-chunked` from a
/// client that sends no payload hash at all.
pub fn framing(headers: &HeaderMap) -> Result<Framing, FramingError> {
    let payload = headers
        .get("x-amz-content-sha256")
        .map(http::HeaderValue::as_bytes);
    let streaming = payload.is_some_and(|p| p.starts_with(b"STREAMING-"));
    let encoded = headers
        .get_all(http::header::CONTENT_ENCODING)
        .iter()
        .any(|v| {
            v.as_bytes()
                .split(|&b| b == b',')
                .any(|t| t.trim_ascii().eq_ignore_ascii_case(b"aws-chunked"))
        });
    if !streaming && !encoded {
        return Ok(Framing::Plain);
    }
    if !streaming && payload.is_some_and(|p| p != sigv4::UNSIGNED_PAYLOAD.as_bytes()) {
        return Err(FramingError::DigestWithChunked);
    }
    let decoded_len = headers
        .get("x-amz-decoded-content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .ok_or(FramingError::MissingDecodedLength)?;
    Ok(Framing::AwsChunked { decoded_len })
}

/// Why a request body could not be delivered intact.
#[derive(Debug)]
pub enum BodyError {
    /// The connection failed or the client hung up.
    Transport(Box<dyn StdError + Send + Sync>),
    /// The body does not hash to `x-amz-content-sha256`.
    DigestMismatch,
    /// A chunk or trailer signature in a signed aws-chunked body is wrong.
    ChunkSignature,
    /// The aws-chunked framing is malformed or truncated.
    Framing(&'static str),
    /// The decoded body is not `x-amz-decoded-content-length` bytes.
    DecodedLength { expected: u64, actual: u64 },
}

impl fmt::Display for BodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BodyError::Transport(e) => write!(f, "body read error: {e}"),
            BodyError::DigestMismatch => {
                f.write_str("body does not match its x-amz-content-sha256 digest")
            }
            BodyError::ChunkSignature => f.write_str("aws-chunked signature does not match"),
            BodyError::Framing(m) => f.write_str(m),
            BodyError::DecodedLength { expected, actual } => write!(
                f,
                "aws-chunked body decoded to at least {actual} bytes; \
                 x-amz-decoded-content-length is {expected}"
            ),
        }
    }
}

impl StdError for BodyError {}

/// Per-chunk signature state for a signed aws-chunked body.
struct ChunkVerifier {
    signing: ChunkSigning,
    /// The previous signature in the chain (the seed, before the first chunk).
    prev: [u8; 32],
    hasher: Sha256,
    /// The current chunk's claimed signature.
    claimed: Option<[u8; 32]>,
    /// `name:value\n` for each trailer, for the trailer signature.
    trailer_canonical: Vec<u8>,
    trailer_signature: Option<[u8; 32]>,
    enforce: bool,
    /// Log mode reports the first failure only; one bad link breaks the chain.
    reported: bool,
}

impl ChunkVerifier {
    /// A signature check failed: fatal when enforcing, otherwise logged once.
    fn fail(&mut self, what: &str) -> Result<(), BodyError> {
        if self.enforce {
            return Err(BodyError::ChunkSignature);
        }
        if !self.reported {
            self.reported = true;
            auth::log_event(format_args!(
                "auth: would reject (log mode) aws-chunked upload: {what}"
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Reading `size[;chunk-signature=…]\r\n`.
    Header,
    /// Inside a chunk's data.
    Data,
    /// Expecting the `\r\n` after a chunk's data.
    DataEnd,
    /// After the zero-length chunk: trailer lines until an empty line.
    Trailer,
    Done,
}

/// Incremental aws-chunked decoder: accepts the encoded body in arbitrary
/// pieces and emits the payload as zero-copy slices of them.
pub struct ChunkedDecoder {
    state: State,
    line: Vec<u8>,
    /// Data bytes left in the current chunk.
    remaining: u64,
    /// Payload bytes announced so far (sum of chunk sizes).
    decoded: u64,
    expected: u64,
    trailer_bytes: usize,
    verify: Option<ChunkVerifier>,
}

impl ChunkedDecoder {
    pub fn new(expected: u64, signing: Option<ChunkSigning>, enforce: bool) -> Self {
        Self {
            state: State::Header,
            line: Vec::new(),
            remaining: 0,
            decoded: 0,
            expected,
            trailer_bytes: 0,
            verify: signing.map(|signing| ChunkVerifier {
                prev: signing.seed,
                signing,
                hasher: Sha256::new(),
                claimed: None,
                trailer_canonical: Vec::new(),
                trailer_signature: None,
                enforce,
                reported: false,
            }),
        }
    }

    /// Decode the next piece of the encoded body, appending payload to `out`.
    pub fn feed(&mut self, mut buf: Bytes, out: &mut VecDeque<Bytes>) -> Result<(), BodyError> {
        while !buf.is_empty() {
            match self.state {
                State::Data => {
                    let n = self.remaining.min(buf.len() as u64) as usize;
                    let piece = buf.split_to(n);
                    if let Some(v) = &mut self.verify {
                        v.hasher.update(&piece);
                    }
                    self.remaining -= n as u64;
                    out.push_back(piece);
                    if self.remaining == 0 {
                        self.end_chunk()?;
                        self.state = State::DataEnd;
                    }
                }
                State::Done => {
                    return Err(BodyError::Framing(
                        "aws-chunked body continues after its final chunk",
                    ));
                }
                State::Header | State::DataEnd | State::Trailer => {
                    if !self.take_line(&mut buf)? {
                        break;
                    }
                    // Process the completed line, then hand the buffer back
                    // so the next line reuses its allocation.
                    let mut line = std::mem::take(&mut self.line);
                    let result = self.on_line(&line);
                    line.clear();
                    self.line = line;
                    result?;
                }
            }
        }
        Ok(())
    }

    /// The encoded body ended: check it ended where it should.
    pub fn finish(&mut self) -> Result<(), BodyError> {
        // Tolerate a missing final blank line after complete trailers — the
        // payload and every signature before it are already accounted for.
        if self.state == State::Trailer && self.line.is_empty() {
            self.end_trailers()?;
            self.state = State::Done;
        }
        if self.state != State::Done {
            return Err(BodyError::Framing(
                "aws-chunked body ended before its final chunk",
            ));
        }
        if self.decoded != self.expected {
            return Err(BodyError::DecodedLength {
                expected: self.expected,
                actual: self.decoded,
            });
        }
        Ok(())
    }

    /// Move bytes into `self.line` up to and including the next `\n`. Returns
    /// true once a whole line (CRLF stripped) is in `self.line`.
    fn take_line(&mut self, buf: &mut Bytes) -> Result<bool, BodyError> {
        let (take, complete) = match buf.iter().position(|&b| b == b'\n') {
            Some(i) => (i + 1, true),
            None => (buf.len(), false),
        };
        if self.line.len() + take > MAX_LINE {
            return Err(BodyError::Framing("aws-chunked line is too long"));
        }
        self.line.extend_from_slice(&buf.split_to(take));
        if !complete {
            return Ok(false);
        }
        if !self.line.ends_with(b"\r\n") {
            return Err(BodyError::Framing("aws-chunked line does not end in CRLF"));
        }
        self.line.truncate(self.line.len() - 2);
        Ok(true)
    }

    fn on_line(&mut self, line: &[u8]) -> Result<(), BodyError> {
        match self.state {
            State::Header => self.on_chunk_header(line),
            State::DataEnd if line.is_empty() => {
                self.state = State::Header;
                Ok(())
            }
            State::DataEnd => Err(BodyError::Framing(
                "aws-chunked chunk data is longer than its declared size",
            )),
            State::Trailer => self.on_trailer_line(line),
            State::Data | State::Done => unreachable!("lines are only read between chunks"),
        }
    }

    fn on_chunk_header(&mut self, line: &[u8]) -> Result<(), BodyError> {
        let (size_hex, extensions) = match line.iter().position(|&b| b == b';') {
            Some(i) => (&line[..i], &line[i + 1..]),
            None => (line, &[][..]),
        };
        let size = parse_hex_u64(size_hex)
            .ok_or(BodyError::Framing("aws-chunked chunk size is not hex"))?;
        if size > self.expected - self.decoded {
            return Err(BodyError::DecodedLength {
                expected: self.expected,
                actual: self.decoded.saturating_add(size),
            });
        }
        self.decoded += size;
        if let Some(v) = &mut self.verify {
            v.claimed = extensions
                .split(|&b| b == b';')
                .find_map(|e| e.trim_ascii().strip_prefix(b"chunk-signature="))
                .and_then(sigv4::decode_hex32);
        }
        if size == 0 {
            self.end_chunk()?;
            self.state = State::Trailer;
        } else {
            self.remaining = size;
            self.state = State::Data;
        }
        Ok(())
    }

    /// A chunk's data is complete: check its signature and advance the chain.
    fn end_chunk(&mut self) -> Result<(), BodyError> {
        let Some(v) = &mut self.verify else {
            return Ok(());
        };
        let hash = std::mem::take(&mut v.hasher).finalize();
        let Some(claimed) = v.claimed.take() else {
            return v.fail("a chunk has no chunk-signature");
        };
        let sts =
            sigv4::chunk_string_to_sign(&v.signing.amz_date, &v.signing.scope, &v.prev, &hash);
        let ok = sigv4::ct_eq(&sigv4::sign(&v.signing.key, &sts), &claimed);
        v.prev = claimed;
        if !ok {
            return v.fail("a chunk signature does not match");
        }
        Ok(())
    }

    fn on_trailer_line(&mut self, line: &[u8]) -> Result<(), BodyError> {
        if line.is_empty() {
            self.end_trailers()?;
            self.state = State::Done;
            return Ok(());
        }
        self.trailer_bytes += line.len() + 2;
        if self.trailer_bytes > MAX_TRAILERS {
            return Err(BodyError::Framing("aws-chunked trailers are too large"));
        }
        let colon = line
            .iter()
            .position(|&b| b == b':')
            .ok_or(BodyError::Framing("aws-chunked trailer is not name:value"))?;
        let (name, value) = (line[..colon].trim_ascii(), line[colon + 1..].trim_ascii());
        if let Some(v) = &mut self.verify {
            if name.eq_ignore_ascii_case(b"x-amz-trailer-signature") {
                v.trailer_signature = sigv4::decode_hex32(value);
            } else {
                v.trailer_canonical
                    .extend(name.iter().map(u8::to_ascii_lowercase));
                v.trailer_canonical.push(b':');
                v.trailer_canonical.extend_from_slice(value);
                v.trailer_canonical.push(b'\n');
            }
        }
        Ok(())
    }

    fn end_trailers(&mut self) -> Result<(), BodyError> {
        let Some(v) = &mut self.verify else {
            return Ok(());
        };
        if !v.signing.trailer_signed {
            return Ok(());
        }
        let hash = crate::crypto::sha256(&v.trailer_canonical);
        let sts =
            sigv4::trailer_string_to_sign(&v.signing.amz_date, &v.signing.scope, &v.prev, &hash);
        let expected = sigv4::sign(&v.signing.key, &sts);
        match v.trailer_signature {
            Some(s) if sigv4::ct_eq(&expected, &s) => Ok(()),
            Some(_) => v.fail("the trailer signature does not match"),
            None => v.fail("the trailers have no x-amz-trailer-signature"),
        }
    }
}

fn parse_hex_u64(s: &[u8]) -> Option<u64> {
    if s.is_empty() || s.len() > 16 {
        return None;
    }
    let mut v = 0u64;
    for &c in s {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        };
        v = (v << 4) | u64::from(d);
    }
    Some(v)
}

enum Kind {
    Plain,
    Digest {
        hasher: Sha256,
        expected: [u8; 32],
        enforce: bool,
    },
    Chunked(Box<ChunkedDecoder>),
}

/// A request body with framing removed and the payload verified.
///
/// Generic over the wire body so the pipeline can be tested without a socket;
/// the server always uses hyper's `Incoming`.
pub struct RequestBody<B = Incoming> {
    inner: B,
    kind: Kind,
    queue: VecDeque<Bytes>,
    done: bool,
}

impl<B> RequestBody<B> {
    pub fn new(inner: B, framing: Framing, plan: PayloadPlan) -> Self {
        let kind = match (framing, plan.auth) {
            (Framing::AwsChunked { decoded_len }, PayloadAuth::Chunks(signing)) => {
                Kind::Chunked(Box::new(ChunkedDecoder::new(
                    decoded_len,
                    Some(signing),
                    plan.enforce,
                )))
            }
            // `framing` refuses a digest with aws-chunked, and a signed
            // STREAMING-* payload hash is aws-chunked by definition, so these
            // are decode-only: there is no signature left to check.
            (Framing::AwsChunked { decoded_len }, _) => {
                Kind::Chunked(Box::new(ChunkedDecoder::new(decoded_len, None, false)))
            }
            (Framing::Plain, PayloadAuth::Sha256(expected)) => Kind::Digest {
                hasher: Sha256::new(),
                expected,
                enforce: plan.enforce,
            },
            (Framing::Plain, _) => Kind::Plain,
        };
        Self {
            inner,
            kind,
            queue: VecDeque::new(),
            done: false,
        }
    }
}

impl<B> Body for RequestBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = self.get_mut();
        loop {
            if let Some(data) = this.queue.pop_front() {
                return Poll::Ready(Some(Ok(Frame::data(data))));
            }
            if this.done {
                return Poll::Ready(None);
            }
            match ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
                Some(Ok(frame)) => {
                    let data = match frame.into_data() {
                        Ok(data) => data,
                        // HTTP trailers: nothing here reads them.
                        Err(frame) => return Poll::Ready(Some(Ok(frame))),
                    };
                    match &mut this.kind {
                        Kind::Plain => return Poll::Ready(Some(Ok(Frame::data(data)))),
                        Kind::Digest { hasher, .. } => {
                            hasher.update(&data);
                            return Poll::Ready(Some(Ok(Frame::data(data))));
                        }
                        Kind::Chunked(decoder) => {
                            if let Err(e) = decoder.feed(data, &mut this.queue) {
                                this.done = true;
                                this.queue.clear();
                                return Poll::Ready(Some(Err(e)));
                            }
                        }
                    }
                }
                Some(Err(e)) => {
                    this.done = true;
                    this.queue.clear();
                    return Poll::Ready(Some(Err(BodyError::Transport(e.into()))));
                }
                None => {
                    this.done = true;
                    if let Err(e) = this.finish() {
                        return Poll::Ready(Some(Err(e)));
                    }
                }
            }
        }
    }
}

impl<B> RequestBody<B> {
    /// End-of-body checks; an error here replaces end-of-stream.
    fn finish(&mut self) -> Result<(), BodyError> {
        match &mut self.kind {
            Kind::Plain => Ok(()),
            Kind::Digest {
                hasher,
                expected,
                enforce,
            } => {
                let actual = std::mem::take(hasher).finalize();
                if sigv4::ct_eq(&actual, expected) {
                    Ok(())
                } else if *enforce {
                    Err(BodyError::DigestMismatch)
                } else {
                    auth::log_event(format_args!(
                        "auth: would reject (log mode) body: it does not match its x-amz-content-sha256"
                    ));
                    Ok(())
                }
            }
            Kind::Chunked(decoder) => decoder.finish(),
        }
    }
}

#[cfg(test)]
mod tests;
