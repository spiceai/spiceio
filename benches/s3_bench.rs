use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use bytes::Bytes;
use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use spiceio::s3::auth::{Authenticator, ChunkSigning, Mode, PayloadAuth, PayloadPlan};
use spiceio::s3::headers::{RangeSpec, parse_http_date, parse_range};
use spiceio::s3::request_body::{Framing, RequestBody};
use spiceio::s3::sigv4::{self, CanonicalRequest};
use spiceio::s3::xml::{
    XmlWriter, epoch_to_http_date, epoch_to_iso8601, extract_element, extract_sections,
};

// ── XML builder ──────────────────────────────────────────────────────────

fn bench_xml_writer_list_response(c: &mut Criterion) {
    // Simulate building a ListObjectsV2 response with 100 objects
    c.bench_function("xml_list_100_objects", |b| {
        b.iter(|| {
            let mut w = XmlWriter::new();
            w.declaration();
            w.open_ns(
                "ListBucketResult",
                "http://s3.amazonaws.com/doc/2006-03-01/",
            );
            w.element("Name", "mybucket");
            w.element("Prefix", "sccache/us-east-1/");
            w.element("KeyCount", "100");
            w.element("MaxKeys", "1000");
            w.element("IsTruncated", "false");
            for i in 0..100 {
                w.open("Contents");
                w.element("Key", &format!("sccache/us-east-1/cache/{i:016x}.bin"));
                w.element("LastModified", "2024-01-15T12:30:45.000Z");
                w.element("ETag", &format!("\"{i:016x}\""));
                w.element("Size", "32768");
                w.element("StorageClass", "STANDARD");
                w.close("Contents");
            }
            w.close("ListBucketResult");
            black_box(w.finish())
        })
    });
}

fn bench_xml_escape_heavy(c: &mut Criterion) {
    let nasty = "a&b<c>d\"e'f&g<h>i\"j'k";
    c.bench_function("xml_element_escape_heavy", |b| {
        b.iter(|| {
            let mut w = XmlWriter::new();
            w.element("Key", black_box(nasty));
            w.finish()
        })
    });
}

fn bench_extract_element(c: &mut Criterion) {
    let xml = "<Root><Key>my/very/long/path/to/some/object.bin</Key><Other>x</Other></Root>";
    c.bench_function("extract_element", |b| {
        b.iter(|| extract_element(black_box(xml), "Key"))
    });
}

fn bench_extract_sections_delete(c: &mut Criterion) {
    // Simulate a multi-delete request with 50 keys
    let mut xml = String::from("<Delete><Quiet>true</Quiet>");
    for i in 0..50 {
        xml.push_str(&format!(
            "<Object><Key>prefix/file_{i:04}.txt</Key></Object>"
        ));
    }
    xml.push_str("</Delete>");

    c.bench_function("extract_sections_50_keys", |b| {
        b.iter(|| extract_sections(black_box(&xml), "<Key>", "</Key>"))
    });
}

// ── Date formatting / parsing ────────────────────────────────────────────

fn bench_epoch_to_iso8601(c: &mut Criterion) {
    c.bench_function("epoch_to_iso8601", |b| {
        b.iter(|| epoch_to_iso8601(black_box(1705321845)))
    });
}

fn bench_epoch_to_http_date(c: &mut Criterion) {
    c.bench_function("epoch_to_http_date", |b| {
        b.iter(|| epoch_to_http_date(black_box(1705321845)))
    });
}

fn bench_parse_http_date_rfc7231(c: &mut Criterion) {
    c.bench_function("parse_http_date_rfc7231", |b| {
        b.iter(|| parse_http_date(black_box("Mon, 15 Jan 2024 12:30:45 GMT")))
    });
}

fn bench_parse_http_date_iso8601(c: &mut Criterion) {
    c.bench_function("parse_http_date_iso8601", |b| {
        b.iter(|| parse_http_date(black_box("2024-01-15T12:30:45.000Z")))
    });
}

// ── Range parsing ────────────────────────────────────────────────────────

fn bench_parse_range(c: &mut Criterion) {
    c.bench_function("parse_range", |b| {
        b.iter(|| parse_range(black_box("bytes=0-65535")))
    });
}

fn bench_range_resolve(c: &mut Criterion) {
    let spec = RangeSpec {
        start: Some(1024),
        end: Some(65535),
    };
    c.bench_function("range_resolve", |b| {
        b.iter(|| black_box(&spec).resolve(black_box(1048576)))
    });
}

// ── Authentication ───────────────────────────────────────────────────────
//
// What SPICEIO_S3_AUTH=enforce adds to a request. `auth_check/sigv4_get` is
// the whole per-request cost on the hot path (an sccache cache hit): parse,
// canonicalize, SHA-256, five HMACs. The body group is the per-byte cost for
// uploads that carry a signed digest or signed chunks, against the plain
// pass-through every mode pays.

const BENCH_KEY: &str = "bench-key";
const BENCH_SECRET: &str = "bench-secret-0123456789";
const BENCH_AMZ_DATE: &str = "20261111T194142Z";
const BENCH_NOW: u64 = 1_794_426_102;
const BENCH_SCOPE: &str = "20261111/us-east-1/s3/aws4_request";

fn bench_signing_key() -> [u8; 32] {
    sigv4::signing_key(
        format!("AWS4{BENCH_SECRET}").as_bytes(),
        "20261111",
        "us-east-1",
    )
}

/// An sccache-shaped signed GET of a content hash.
fn signed_get() -> http::request::Parts {
    let (mut parts, ()) = http::Request::get(
        "/sccache/sccache/a/b/c/abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    )
    .header("host", "127.0.0.1:8333")
    .header("user-agent", "sccache/0.19.0")
    .header("x-amz-content-sha256", sigv4::UNSIGNED_PAYLOAD)
    .header("x-amz-date", BENCH_AMZ_DATE)
    .body(())
    .unwrap()
    .into_parts();
    let signed = "host;x-amz-content-sha256;x-amz-date";
    let canonical = CanonicalRequest {
        method: "GET",
        raw_path: parts.uri.path(),
        raw_query: "",
        exclude_query: None,
        headers: &parts.headers,
        signed_headers: signed,
        payload_hash: sigv4::UNSIGNED_PAYLOAD,
    }
    .build();
    let sts = sigv4::string_to_sign(BENCH_AMZ_DATE, BENCH_SCOPE, &canonical);
    let sig = sigv4::hex32(&sigv4::sign(&bench_signing_key(), &sts));
    let value = format!(
        "AWS4-HMAC-SHA256 Credential={BENCH_KEY}/{BENCH_SCOPE}, SignedHeaders={signed}, Signature={}",
        std::str::from_utf8(&sig).unwrap()
    );
    parts
        .headers
        .insert("authorization", value.parse().unwrap());
    parts
}

fn bench_auth_check(c: &mut Criterion) {
    let parts = signed_get();
    let off = Authenticator::disabled();
    let enforce =
        Authenticator::new(Mode::Enforce, vec![(BENCH_KEY.into(), BENCH_SECRET.into())]).unwrap();
    assert!(
        enforce.check(&parts, BENCH_NOW).is_ok(),
        "bench request must verify"
    );
    // The router reads the framing once, for this and for the body.
    let framing = Some(Framing::Plain);
    let mut g = c.benchmark_group("auth_check");
    g.bench_function("off", |b| {
        b.iter(|| {
            off.check_framed(black_box(&parts), framing, BENCH_NOW)
                .is_ok()
        })
    });
    g.bench_function("sigv4_get", |b| {
        b.iter(|| {
            enforce
                .check_framed(black_box(&parts), framing, BENCH_NOW)
                .is_ok()
        })
    });
    g.finish();
}

/// Wire body delivered as fixed frames, always ready.
struct Frames(VecDeque<Bytes>);

impl http_body::Body for Frames {
    type Data = Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        Poll::Ready(self.0.pop_front().map(|b| Ok(http_body::Frame::data(b))))
    }
}

fn frames(encoded: &Bytes, frame: usize) -> Frames {
    Frames(
        (0..encoded.len())
            .step_by(frame)
            .map(|i| encoded.slice(i..(i + frame).min(encoded.len())))
            .collect(),
    )
}

/// Drive the pipeline to completion; every frame source here is always ready.
fn drain(body: RequestBody<Frames>) -> usize {
    use http_body::Body;
    let mut body = std::pin::pin!(body);
    let mut cx = Context::from_waker(Waker::noop());
    let mut n = 0;
    loop {
        match body.as_mut().poll_frame(&mut cx) {
            Poll::Ready(Some(Ok(f))) => n += f.into_data().map_or(0, |d| d.len()),
            Poll::Ready(Some(Err(e))) => panic!("{e}"),
            Poll::Ready(None) => return n,
            Poll::Pending => unreachable!("frames are always ready"),
        }
    }
}

/// aws-chunked encoding of `payload` in 64 KiB chunks, signed when `signing`.
fn aws_chunked(payload: &[u8], signing: Option<&ChunkSigning>) -> Bytes {
    let mut out = Vec::with_capacity(payload.len() + 4096);
    let mut prev = signing.map(|s| s.seed);
    for chunk in payload.chunks(65536).chain(std::iter::once(&[][..])) {
        out.extend_from_slice(format!("{:x}", chunk.len()).as_bytes());
        if let (Some(s), Some(p)) = (signing, prev.as_mut()) {
            let sts = sigv4::chunk_string_to_sign(
                &s.amz_date,
                &s.scope,
                p,
                &spiceio::crypto::sha256(chunk),
            );
            *p = sigv4::sign(&s.key, &sts);
            out.extend_from_slice(b";chunk-signature=");
            out.extend_from_slice(&sigv4::hex32(p));
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(chunk);
        if !chunk.is_empty() {
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(b"\r\n");
    Bytes::from(out)
}

fn bench_request_body(c: &mut Criterion) {
    const MIB: usize = 1 << 20;
    const FRAME: usize = 64 * 1024;
    let payload: Vec<u8> = (0..MIB).map(|i| (i * 31 % 251) as u8).collect();
    let plain = Bytes::from(payload.clone());
    let signing = ChunkSigning {
        key: bench_signing_key(),
        amz_date: BENCH_AMZ_DATE.into(),
        scope: BENCH_SCOPE.into(),
        seed: [7; 32],
        trailer_signed: false,
    };
    let unsigned_chunked = aws_chunked(&payload, None);
    let signed_chunked = aws_chunked(&payload, Some(&signing));
    let digest = spiceio::crypto::sha256(&payload);
    let chunked = Framing::AwsChunked {
        decoded_len: MIB as u64,
    };

    let mut g = c.benchmark_group("request_body_1MiB");
    g.throughput(Throughput::Bytes(MIB as u64));
    g.bench_function("plain", |b| {
        b.iter(|| {
            drain(RequestBody::new(
                frames(&plain, FRAME),
                Framing::Plain,
                PayloadPlan::unchecked(),
            ))
        })
    });
    g.bench_function("signed_digest", |b| {
        b.iter(|| {
            drain(RequestBody::new(
                frames(&plain, FRAME),
                Framing::Plain,
                PayloadPlan {
                    auth: PayloadAuth::Sha256(digest),
                    enforce: true,
                },
            ))
        })
    });
    g.bench_function("aws_chunked_unsigned", |b| {
        b.iter(|| {
            drain(RequestBody::new(
                frames(&unsigned_chunked, FRAME),
                chunked,
                PayloadPlan::unchecked(),
            ))
        })
    });
    g.bench_function("aws_chunked_signed", |b| {
        b.iter(|| {
            drain(RequestBody::new(
                frames(&signed_chunked, FRAME),
                chunked,
                PayloadPlan {
                    auth: PayloadAuth::Chunks(signing.clone()),
                    enforce: true,
                },
            ))
        })
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_auth_check,
    bench_request_body,
    bench_xml_writer_list_response,
    bench_xml_escape_heavy,
    bench_extract_element,
    bench_extract_sections_delete,
    bench_epoch_to_iso8601,
    bench_epoch_to_http_date,
    bench_parse_http_date_rfc7231,
    bench_parse_http_date_iso8601,
    bench_parse_range,
    bench_range_resolve,
);
criterion_main!(benches);
