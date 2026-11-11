//! aws-chunked decoding and payload verification, independent of auth policy.
//! (Captured client uploads are exercised end to end in `auth::tests`.)

use std::collections::VecDeque;

use bytes::Bytes;
use http::HeaderMap;

use super::*;
use crate::crypto::sha256;
use crate::s3::auth::{ChunkSigning, PayloadAuth, PayloadPlan};
use crate::test_support::{PiecewiseBody, drain_request_body};

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in pairs {
        h.append(
            http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
            v.parse().unwrap(),
        );
    }
    h
}

#[test]
fn framing_follows_the_payload_hash_and_content_encoding() {
    assert_eq!(framing(&headers(&[])), Ok(Framing::Plain));
    assert_eq!(
        framing(&headers(&[(
            "x-amz-content-sha256",
            sigv4::UNSIGNED_PAYLOAD
        )])),
        Ok(Framing::Plain)
    );
    for streaming in [
        sigv4::STREAMING_SIGNED,
        sigv4::STREAMING_SIGNED_TRAILER,
        sigv4::STREAMING_UNSIGNED_TRAILER,
    ] {
        assert_eq!(
            framing(&headers(&[
                ("x-amz-content-sha256", streaming),
                ("x-amz-decoded-content-length", "11"),
            ])),
            Ok(Framing::AwsChunked { decoded_len: 11 }),
            "{streaming}"
        );
    }
    // Content-Encoding alone (an anonymous client that sends no payload hash),
    // as one token of several, in any case.
    assert_eq!(
        framing(&headers(&[
            ("content-encoding", "gzip, AWS-Chunked"),
            ("x-amz-decoded-content-length", "0"),
        ])),
        Ok(Framing::AwsChunked { decoded_len: 0 })
    );
    assert_eq!(
        framing(&headers(&[("content-encoding", "aws-chunked")])),
        Err(FramingError::MissingDecodedLength)
    );
    assert_eq!(
        framing(&headers(&[
            ("content-encoding", "aws-chunked"),
            ("x-amz-content-sha256", sigv4::EMPTY_SHA256),
            ("x-amz-decoded-content-length", "0"),
        ])),
        Err(FramingError::DigestWithChunked)
    );
}

/// Decode `encoded` in `piece`-byte frames with no signature checking.
async fn decode(encoded: &[u8], decoded_len: u64, piece: usize) -> Result<Vec<u8>, BodyError> {
    drain_request_body(RequestBody::new(
        PiecewiseBody::split(encoded, piece),
        Framing::AwsChunked { decoded_len },
        PayloadPlan::unchecked(),
    ))
    .await
}

const UNSIGNED: &[u8] = b"5\r\nhello\r\n6\r\n world\r\n0\r\nx-amz-checksum-crc32:DUoRhQ==\r\n\r\n";

#[tokio::test]
async fn unsigned_chunks_decode_at_every_frame_boundary() {
    for piece in 1..=UNSIGNED.len() {
        assert_eq!(
            decode(UNSIGNED, 11, piece).await.unwrap(),
            b"hello world",
            "{piece}"
        );
    }
    // No trailers, and a body that stops after complete trailers without the
    // final blank line.
    assert_eq!(
        decode(b"3\r\nabc\r\n0\r\n\r\n", 3, 2).await.unwrap(),
        b"abc"
    );
    assert_eq!(
        decode(b"3\r\nabc\r\n0\r\nx-amz-checksum-crc32:x\r\n", 3, 4)
            .await
            .unwrap(),
        b"abc"
    );
}

#[tokio::test]
async fn malformed_or_truncated_framing_never_completes() {
    let cases: &[(&[u8], u64, &str)] = &[
        (
            b"5\r\nhello world\r\n0\r\n\r\n",
            11,
            "chunk longer than declared",
        ),
        (b"5\r\nhel", 5, "ends mid-chunk"),
        (b"5\r\nhello\r\n", 5, "ends before the final chunk"),
        (
            b"5\r\nhello\r\n0\r\n\r\nextra",
            5,
            "data after the final chunk",
        ),
        (
            b"5\r\nhello\r\n0\r\n\r\n",
            6,
            "shorter than x-amz-decoded-content-length",
        ),
        (
            b"6\r\nhello!\r\n0\r\n\r\n",
            5,
            "longer than x-amz-decoded-content-length",
        ),
        (b"zz\r\nhello\r\n0\r\n\r\n", 5, "size not hex"),
        (b"\r\nhello\r\n0\r\n\r\n", 5, "empty size"),
        (b"5\nhello\r\n0\r\n\r\n", 5, "bare LF"),
        (b"11111111111111111\r\n", 5, "size overflows u64"),
        (
            b"5\r\nhello\r\n0\r\nno-colon\r\n\r\n",
            5,
            "malformed trailer",
        ),
    ];
    for &(body, len, what) in cases {
        for piece in [1, 3, body.len()] {
            assert!(
                decode(body, len, piece).await.is_err(),
                "{what} (frames of {piece})"
            );
        }
    }
    let long = [b"5;".as_slice(), &[b'x'; MAX_LINE]].concat();
    assert!(matches!(
        decode(&long, 5, 1024).await,
        Err(BodyError::Framing(_))
    ));
}

/// Encode `chunks` as a signed aws-chunked body, signing with the verifier's
/// own primitives (agreement with real signers is covered by the mc and AWS
/// documentation fixtures in `auth::tests`). `trailers` adds a signed trailer.
fn signed_body(signing: &ChunkSigning, chunks: &[&[u8]], trailers: Option<&str>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut prev = signing.seed;
    for data in chunks.iter().copied().chain(std::iter::once(&b""[..])) {
        let sts =
            sigv4::chunk_string_to_sign(&signing.amz_date, &signing.scope, &prev, &sha256(data));
        prev = sigv4::sign(&signing.key, &sts);
        let sig = sigv4::hex32(&prev);
        out.extend_from_slice(format!("{:x};chunk-signature=", data.len()).as_bytes());
        out.extend_from_slice(&sig);
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(data);
        if !data.is_empty() {
            out.extend_from_slice(b"\r\n");
        }
    }
    if let Some(t) = trailers {
        out.extend_from_slice(t.as_bytes());
        out.extend_from_slice(b"\r\n");
        let canonical = format!("{t}\n");
        let sts = sigv4::trailer_string_to_sign(
            &signing.amz_date,
            &signing.scope,
            &prev,
            &sha256(canonical.as_bytes()),
        );
        let sig = sigv4::hex32(&sigv4::sign(&signing.key, &sts));
        out.extend_from_slice(b"x-amz-trailer-signature:");
        out.extend_from_slice(&sig);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

fn signing(trailer_signed: bool) -> ChunkSigning {
    ChunkSigning {
        key: [9; 32],
        amz_date: "20261111T194142Z".into(),
        scope: "20261111/us-east-1/s3/aws4_request".into(),
        seed: [3; 32],
        trailer_signed,
    }
}

async fn verify(
    body: &[u8],
    s: ChunkSigning,
    len: u64,
    enforce: bool,
    piece: usize,
) -> Result<Vec<u8>, BodyError> {
    drain_request_body(RequestBody::new(
        PiecewiseBody::split(body, piece),
        Framing::AwsChunked { decoded_len: len },
        PayloadPlan {
            auth: PayloadAuth::Chunks(s),
            enforce,
        },
    ))
    .await
}

#[tokio::test]
async fn signed_trailer_uploads_verify_the_trailer_too() {
    let s = signing(true);
    let body = signed_body(
        &s,
        &[b"hello", b" world"],
        Some("x-amz-checksum-crc32c:yZRlqg=="),
    );
    for piece in [1, 5, 64, body.len()] {
        assert_eq!(
            verify(&body, s.clone(), 11, true, piece).await.unwrap(),
            b"hello world"
        );
    }
    // A changed checksum value, or no trailer signature at all.
    let changed = String::from_utf8(body.clone())
        .unwrap()
        .replace("yZRlqg==", "AAAAAA==");
    assert!(matches!(
        verify(changed.as_bytes(), s.clone(), 11, true, 7).await,
        Err(BodyError::ChunkSignature)
    ));
    let unsigned_trailer = signed_body(&signing(false), &[b"hello world"], None);
    assert!(matches!(
        verify(&unsigned_trailer, s, 11, true, 7).await,
        Err(BodyError::ChunkSignature)
    ));
}

#[tokio::test]
async fn chunks_cannot_be_reordered_dropped_or_unsigned() {
    let s = signing(false);
    let ab = signed_body(&s, &[b"aa", b"bb"], None);
    assert_eq!(verify(&ab, s.clone(), 4, true, 3).await.unwrap(), b"aabb");

    // Swapping two equally sized chunks keeps every chunk individually
    // well-formed; only the chain catches it.
    let text = String::from_utf8(ab).unwrap();
    let parts: Vec<&str> = text.split("\r\n").collect();
    let swapped = [parts[2], parts[3], parts[0], parts[1], parts[4], "", ""].join("\r\n");
    assert!(matches!(
        verify(swapped.as_bytes(), s.clone(), 4, true, 3).await,
        Err(BodyError::ChunkSignature)
    ));

    // Plain unsigned framing where signatures are required.
    assert!(matches!(
        verify(b"2\r\naa\r\n0\r\n\r\n", s.clone(), 2, true, 3).await,
        Err(BodyError::ChunkSignature)
    ));
    // ... which log mode delivers.
    assert_eq!(
        verify(b"2\r\naa\r\n0\r\n\r\n", s, 2, false, 3)
            .await
            .unwrap(),
        b"aa"
    );
}

async fn digest(body: &[u8], claimed: &[u8], enforce: bool) -> (Vec<Bytes>, Option<BodyError>) {
    use http_body_util::BodyExt;
    let mut b = RequestBody::new(
        PiecewiseBody::split(body, 4),
        Framing::Plain,
        PayloadPlan {
            auth: PayloadAuth::Sha256(sha256(claimed)),
            enforce,
        },
    );
    let mut frames = Vec::new();
    while let Some(f) = b.frame().await {
        match f {
            Ok(f) => frames.push(f.into_data().unwrap()),
            Err(e) => return (frames, Some(e)),
        }
    }
    (frames, None)
}

#[tokio::test]
async fn a_digest_mismatch_replaces_end_of_stream() {
    let (frames, err) = digest(b"exact bytes", b"exact bytes", true).await;
    assert_eq!(frames.concat(), b"exact bytes");
    assert!(err.is_none());

    // Every byte streams (a consumer may already be writing a temp file), but
    // the body never *ends* successfully, so nothing reaches a commit.
    let (frames, err) = digest(b"other bytes", b"exact bytes", true).await;
    assert_eq!(frames.concat(), b"other bytes");
    assert!(matches!(err, Some(BodyError::DigestMismatch)));

    let (frames, err) = digest(b"other bytes", b"exact bytes", false).await;
    assert_eq!(frames.concat(), b"other bytes");
    assert!(err.is_none(), "log mode reports and delivers");
}

/// A wire body that fails partway through.
struct Failing(VecDeque<Result<Bytes, std::io::Error>>);

impl Body for Failing {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        Poll::Ready(self.0.pop_front().map(|r| r.map(Frame::data)))
    }
}

#[tokio::test]
async fn transport_errors_pass_through_as_such() {
    for framing in [Framing::Plain, Framing::AwsChunked { decoded_len: 5 }] {
        let wire = Failing(VecDeque::from([
            Ok(Bytes::from_static(b"5\r\nhe")),
            Err(std::io::Error::other("reset")),
        ]));
        let err = drain_request_body(RequestBody::new(wire, framing, PayloadPlan::unchecked()))
            .await
            .unwrap_err();
        assert!(matches!(err, BodyError::Transport(_)), "{err}");
    }
}
