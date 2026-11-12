//! SigV4 verification tests.
//!
//! Three layers, each catching what the others cannot:
//!
//! 1. **Captured requests from independent signers** (`testdata/sigv4/`:
//!    curl's `--aws-sigv4`, aws-cli v2, MinIO's mc, and an `aws s3 presign`
//!    URL), all signed with `AKIDTEST` / `secretsecretsecret`. A verifier
//!    that only ever checks its own signatures can agree with itself about a
//!    canonicalization no real client produces; these cannot.
//! 2. **AWS's published worked examples**, for the same reason, from a fourth
//!    source.
//! 3. **Policy cases** built with a test signer made from the verifier's own
//!    primitives — fine for "is this request accepted", which is all they ask.
//!
//! Then the whole path through `handle_request` in every mode.

use std::sync::Arc;

use bytes::Bytes;
use http::Request;
use http::header::AUTHORIZATION;

use super::*;
use crate::crypto::sha256;
use crate::s3::request_body::{Framing, RequestBody, framing};
use crate::test_support::{PiecewiseBody, drain_request_body, parse_raw_request};

const AKID: &str = "AKIDTEST";
const SECRET: &str = "secretsecretsecret";

const CURL_LIST: &[u8] = include_bytes!("../testdata/sigv4/curl-list-query.http");
const CURL_PUT: &[u8] = include_bytes!("../testdata/sigv4/curl-put-signed-payload.http");
const AWSCLI_PUT: &[u8] = include_bytes!("../testdata/sigv4/awscli-put-object.http");
const AWSCLI_CP_CHUNKED: &[u8] = include_bytes!("../testdata/sigv4/awscli-cp-aws-chunked.http");
const AWSCLI_LIST: &[u8] = include_bytes!("../testdata/sigv4/awscli-list-objects-v2.http");
const MC_PUT: &[u8] = include_bytes!("../testdata/sigv4/mc-put-signed-chunks.http");
const MC_PUT_MULTI_HEAD: &[u8] = include_bytes!("../testdata/sigv4/mc-put-multi-chunk.head");
/// `aws s3 presign s3://bkt/dir/a b.txt --expires-in 600` (aws-cli 2.39.7).
const PRESIGNED: &str = "/bkt/dir/a%20b.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256\
    &X-Amz-Credential=AKIDTEST%2F20261111%2Fus-east-1%2Fs3%2Faws4_request\
    &X-Amz-Date=20261111T194142Z&X-Amz-Expires=600&X-Amz-SignedHeaders=host\
    &X-Amz-Signature=1b44ec728b04bddc134e4add7eb2b8c3e01c1fa200a64971a8fa7653507b86b2";
const PRESIGNED_AT: u64 = 1_794_426_102; // 20261111T194142Z

fn authenticator(mode: Mode) -> Authenticator {
    Authenticator::new(mode, vec![(AKID.into(), SECRET.into())]).unwrap()
}

fn enforce() -> Authenticator {
    authenticator(Mode::Enforce)
}

/// A captured request, and the time it was signed at.
fn fixture(raw: &[u8]) -> (Parts, Bytes, u64) {
    let (parts, body) = parse_raw_request(raw);
    let now = parse_amz_date(parts.headers["x-amz-date"].to_str().unwrap()).unwrap();
    (parts, body, now)
}

/// Run a body through the pipeline the router builds, in `piece`-byte frames.
async fn deliver(
    parts: &Parts,
    body: &[u8],
    plan: PayloadPlan,
    piece: usize,
) -> Result<Vec<u8>, String> {
    let framing = framing(&parts.headers).map_err(|e| format!("{e:?}"))?;
    drain_request_body(RequestBody::new(
        PiecewiseBody::split(body, piece),
        framing,
        plan,
    ))
    .await
    .map_err(|e| e.to_string())
}

fn failure(r: Result<PayloadPlan, AuthFailure>) -> AuthFailure {
    match r {
        Ok(plan) => panic!("expected a rejection, got {plan:?}"),
        Err(f) => f,
    }
}

// ── 1. Independent signers ──────────────────────────────────────────────────

#[test]
fn curl_get_with_a_raw_slash_in_the_query() {
    let (parts, _, now) = fixture(CURL_LIST);
    let plan = enforce().check(&parts, now).unwrap();
    assert!(plan.enforce);
    assert!(matches!(plan.auth, PayloadAuth::Sha256(d) if d == sha256(b"")));
}

#[test]
fn the_canonical_request_is_exactly_what_curl_signed() {
    // Same request, wrong secret: the failure carries the canonical request
    // spiceio built. Since the right secret verifies (above), this string is
    // byte-for-byte what curl signed — pinned here so a canonicalization
    // change shows up as a readable diff rather than only as a bad signature.
    let (parts, _, now) = fixture(CURL_LIST);
    let wrong = Authenticator::new(
        Mode::Enforce,
        vec![(AKID.into(), "not-the-right-secret".into())],
    )
    .unwrap();
    let f = failure(wrong.check(&parts, now));
    assert_eq!(f.code, "SignatureDoesNotMatch");
    assert_eq!(f.status, StatusCode::FORBIDDEN);
    assert_eq!(f.access_key_id(), Some(AKID));
    assert_eq!(
        f.canonical_request().unwrap(),
        "GET\n/bkt/a%20b\nlist-type=2&prefix=x%2Fy\n\
         host:127.0.0.1:18999\n\
         x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\
         x-amz-date:20261111T194154Z\n\n\
         host;x-amz-content-sha256;x-amz-date\n\
         e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert!(
        f.string_to_sign().unwrap().starts_with(
            "AWS4-HMAC-SHA256\n20261111T194154Z\n20261111/us-east-1/s3/aws4_request\n"
        )
    );
}

#[test]
fn equivalent_encodings_of_the_same_request_verify() {
    // curl sent `prefix=x/y`; `prefix=x%2Fy` and `%2f` are the same request,
    // and the router would execute them identically.
    let (mut parts, _, now) = fixture(CURL_LIST);
    for uri in [
        "/bkt/a%20b?list-type=2&prefix=x%2Fy",
        "/bkt/a%20b?prefix=x%2fy&list-type=2",
    ] {
        parts.uri = uri.parse().unwrap();
        assert!(enforce().check(&parts, now).is_ok(), "{uri}");
    }
}

#[test]
fn any_change_to_what_curl_signed_is_rejected() {
    let (parts, _, now) = fixture(CURL_LIST);
    type Edit = Box<dyn Fn(&mut Parts)>;
    let tampered: [(&str, Edit); 5] = [
        (
            "path",
            Box::new(|p| p.uri = "/bkt/a%20c?list-type=2&prefix=x/y".parse().unwrap()),
        ),
        (
            "query value",
            Box::new(|p| p.uri = "/bkt/a%20b?list-type=2&prefix=x/z".parse().unwrap()),
        ),
        (
            "added query",
            Box::new(|p| {
                p.uri = "/bkt/a%20b?list-type=2&prefix=x/y&delimiter=%2F"
                    .parse()
                    .unwrap()
            }),
        ),
        ("method", Box::new(|p| p.method = http::Method::DELETE)),
        (
            "host",
            Box::new(|p| {
                p.headers.insert("host", "other:1".parse().unwrap());
            }),
        ),
    ];
    for (what, edit) in tampered {
        let mut p = parts.clone();
        edit(&mut p);
        assert_eq!(
            failure(enforce().check(&p, now)).code,
            "SignatureDoesNotMatch",
            "tampered {what}"
        );
    }
}

#[tokio::test]
async fn curl_put_with_a_signed_payload_verifies_the_body() {
    let (parts, body, now) = fixture(CURL_PUT);
    let plan = enforce().check(&parts, now).unwrap();
    assert!(matches!(plan.auth, PayloadAuth::Sha256(d) if d == sha256(b"hello world")));
    assert_eq!(
        deliver(&parts, &body, plan.clone(), 3).await.unwrap(),
        b"hello world"
    );
    // A different body under the same signature never completes.
    let err = deliver(&parts, b"hello wOrld", plan, 64).await.unwrap_err();
    assert!(err.contains("x-amz-content-sha256"), "{err}");
}

#[test]
fn awscli_put_object_with_encoded_key_and_checksum_headers() {
    // Key `dir/a b+c.txt`, sent as `a%20b%2Bc.txt`, with x-amz-checksum-*
    // and x-amz-sdk-* headers signed.
    let (parts, _, now) = fixture(AWSCLI_PUT);
    let plan = enforce().check(&parts, now).unwrap();
    assert!(matches!(plan.auth, PayloadAuth::Sha256(d) if d == sha256(b"hello world")));
}

#[test]
fn awscli_list_objects_v2_with_unicode_prefix() {
    let (parts, _, now) = fixture(AWSCLI_LIST);
    assert!(enforce().check(&parts, now).is_ok());
}

#[tokio::test]
async fn awscli_cp_sends_aws_chunked_and_it_decodes() {
    // `aws s3 cp` (aws-cli 2.39): Content-Encoding aws-chunked,
    // STREAMING-UNSIGNED-PAYLOAD-TRAILER, a crc64nvme trailer, and
    // content-length / content-encoding among the signed headers.
    let (parts, body, now) = fixture(AWSCLI_CP_CHUNKED);
    let plan = enforce().check(&parts, now).unwrap();
    assert!(matches!(plan.auth, PayloadAuth::None), "unsigned payload");
    assert_eq!(
        framing(&parts.headers).unwrap(),
        Framing::AwsChunked { decoded_len: 11 }
    );
    for piece in 1..=body.len() {
        assert_eq!(
            deliver(&parts, &body, plan.clone(), piece).await.unwrap(),
            b"hello world",
            "frames of {piece} bytes"
        );
    }
}

#[tokio::test]
async fn mc_signed_chunks_verify_at_every_frame_boundary() {
    let (parts, body, now) = fixture(MC_PUT);
    let plan = enforce().check(&parts, now).unwrap();
    assert!(matches!(&plan.auth, PayloadAuth::Chunks(c) if !c.trailer_signed));
    for piece in 1..=body.len() {
        assert_eq!(
            deliver(&parts, &body, plan.clone(), piece).await.unwrap(),
            b"hello world",
            "frames of {piece} bytes"
        );
    }
}

#[tokio::test]
async fn mc_tampered_chunk_is_rejected_when_enforcing_and_logged_otherwise() {
    let (parts, body, now) = fixture(MC_PUT);
    let tampered = body.to_vec();
    let at = tampered
        .windows(11)
        .position(|w| w == b"hello world")
        .unwrap();
    let mut data = tampered.clone();
    data[at] = b'j';
    let mut sig = tampered;
    let s = sig
        .windows(16)
        .position(|w| w == b"chunk-signature=")
        .unwrap()
        + 16;
    sig[s] = if sig[s] == b'0' { b'1' } else { b'0' };

    let plan = enforce().check(&parts, now).unwrap();
    for bad in [&data, &sig] {
        let err = deliver(&parts, bad, plan.clone(), 7).await.unwrap_err();
        assert!(err.contains("signature"), "{err}");
    }
    // Log mode verifies the same way but delivers the body.
    let plan = authenticator(Mode::Log).check(&parts, now).unwrap();
    assert!(!plan.enforce);
    assert_eq!(
        deliver(&parts, &data, plan, 7).await.unwrap(),
        b"jello world"
    );
}

#[tokio::test]
async fn mc_multi_chunk_upload_chains_signatures_across_chunks() {
    // 70000 bytes of 'a' in 64 KiB chunks; signatures from the capture.
    let (parts, _) = parse_raw_request(MC_PUT_MULTI_HEAD);
    let now = parse_amz_date(parts.headers["x-amz-date"].to_str().unwrap()).unwrap();
    let mut body = Vec::new();
    for (len, sig) in [
        (
            65536usize,
            "7e69f558bfba91ac5aa0edc5e2482e3fd6fa5e570542001dd8e6b21f4ba4a39f",
        ),
        (
            4464,
            "dddd7b928801db62244f23580610dacfeee3a18aef86c4ffcd735eb2768142c5",
        ),
        (
            0,
            "51689a2e2a22f353c8a48c7bb68107d913d78449f963f3499f7f8fb94b3c7540",
        ),
    ] {
        body.extend_from_slice(format!("{len:x};chunk-signature={sig}\r\n").as_bytes());
        body.extend(std::iter::repeat_n(b'a', len));
        if len > 0 {
            body.extend_from_slice(b"\r\n");
        }
    }
    body.extend_from_slice(b"\r\n");
    assert_eq!(body.len().to_string(), parts.headers["content-length"]);
    let plan = enforce().check(&parts, now).unwrap();
    for piece in [1, 7, 4096, 65536, body.len()] {
        let out = deliver(&parts, &body, plan.clone(), piece).await.unwrap();
        assert_eq!(out.len(), 70000);
        assert!(out.iter().all(|&b| b == b'a'));
    }
}

fn presigned(uri: &str) -> Parts {
    let (parts, ()) = Request::get(uri)
        .header("host", "127.0.0.1:18999")
        .body(())
        .unwrap()
        .into_parts();
    parts
}

#[test]
fn awscli_presigned_url_is_valid_for_exactly_its_lifetime() {
    let parts = presigned(PRESIGNED);
    for now in [
        PRESIGNED_AT,
        PRESIGNED_AT + 600,
        PRESIGNED_AT - MAX_SKEW_SECS,
    ] {
        let plan = enforce().check(&parts, now).unwrap();
        assert!(matches!(plan.auth, PayloadAuth::None), "UNSIGNED-PAYLOAD");
    }
    let f = failure(enforce().check(&parts, PRESIGNED_AT + 601));
    assert_eq!(
        (f.code, &*f.message),
        ("AccessDenied", "Request has expired.")
    );
    let f = failure(enforce().check(&parts, PRESIGNED_AT - MAX_SKEW_SECS - 1));
    assert_eq!(
        (f.code, &*f.message),
        ("AccessDenied", "Request is not valid yet.")
    );
}

#[test]
fn presigned_url_cannot_be_extended_or_reused_for_another_key() {
    for uri in [
        PRESIGNED.replace("X-Amz-Expires=600", "X-Amz-Expires=6000"),
        PRESIGNED.replace("/bkt/dir/a%20b.txt", "/bkt/dir/other.txt"),
        format!("{PRESIGNED}&versionId=1"),
    ] {
        let f = failure(enforce().check(&presigned(&uri), PRESIGNED_AT));
        assert_eq!(f.code, "SignatureDoesNotMatch", "{uri}");
    }
}

#[test]
fn presigned_url_rejects_mixed_auth_tokens_and_unsigned_headers() {
    let mut both = presigned(PRESIGNED);
    both.headers
        .insert(AUTHORIZATION, "AWS4-HMAC-SHA256 x".parse().unwrap());
    assert_eq!(
        failure(enforce().check(&both, PRESIGNED_AT)).code,
        "InvalidArgument"
    );

    let token = presigned(&format!("{PRESIGNED}&X-Amz-Security-Token=t"));
    assert_eq!(
        failure(enforce().check(&token, PRESIGNED_AT)).code,
        "InvalidToken"
    );

    let mut extra = presigned(PRESIGNED);
    extra
        .headers
        .insert("x-amz-acl", "public-read".parse().unwrap());
    let f = failure(enforce().check(&extra, PRESIGNED_AT));
    assert_eq!(f.code, "AccessDenied");
    assert_eq!(f.headers_not_signed(), Some("x-amz-acl"));

    for (from, to) in [
        ("X-Amz-Expires=600", "X-Amz-Expires=0"),
        ("X-Amz-Expires=600", "X-Amz-Expires=604801"),
        ("X-Amz-Date=20261111T194142Z", "X-Amz-Date=20261112T194142Z"),
        ("X-Amz-SignedHeaders=host", "X-Amz-SignedHeaders=x-amz-date"),
        (
            "X-Amz-Algorithm=AWS4-HMAC-SHA256",
            "X-Amz-Algorithm=AWS4-HMAC-SHA1",
        ),
    ] {
        let f = failure(enforce().check(&presigned(&PRESIGNED.replace(from, to)), PRESIGNED_AT));
        assert_eq!(f.code, "AuthorizationQueryParametersError", "{to}");
    }
}

// ── 2. AWS's published examples ─────────────────────────────────────────────

const DOC_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const DOC_AKID: &str = "AKIAIOSFODNN7EXAMPLE";
const DOC_NOW: u64 = 1_369_353_600; // 20130524T000000Z

fn doc_authenticator() -> Authenticator {
    Authenticator::new(Mode::Enforce, vec![(DOC_AKID.into(), DOC_SECRET.into())]).unwrap()
}

fn doc_request(
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    signed: &str,
    sig: &str,
) -> Parts {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "examplebucket.s3.amazonaws.com")
        .header("x-amz-date", "20130524T000000Z");
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b = b.header(
        AUTHORIZATION,
        format!(
            "AWS4-HMAC-SHA256 Credential={DOC_AKID}/20130524/us-east-1/s3/aws4_request,\
             SignedHeaders={signed},Signature={sig}"
        ),
    );
    b.body(()).unwrap().into_parts().0
}

#[test]
fn aws_documentation_header_examples() {
    let e3 = sigv4::EMPTY_SHA256;
    let cases = [
        doc_request(
            "GET",
            "/test.txt",
            &[("range", "bytes=0-9"), ("x-amz-content-sha256", e3)],
            "host;range;x-amz-content-sha256;x-amz-date",
            "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
        ),
        doc_request(
            "PUT",
            "/test%24file.text",
            &[
                ("date", "Fri, 24 May 2013 00:00:00 GMT"),
                ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
                (
                    "x-amz-content-sha256",
                    "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
                ),
            ],
            "date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class",
            "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd",
        ),
        doc_request(
            "GET",
            "/?lifecycle",
            &[("x-amz-content-sha256", e3)],
            "host;x-amz-content-sha256;x-amz-date",
            "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
        ),
        doc_request(
            "GET",
            "/?max-keys=2&prefix=J",
            &[("x-amz-content-sha256", e3)],
            "host;x-amz-content-sha256;x-amz-date",
            "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
        ),
    ];
    for parts in cases {
        assert!(
            doc_authenticator().check(&parts, DOC_NOW).is_ok(),
            "{} {}",
            parts.method,
            parts.uri
        );
    }
}

#[test]
fn aws_documentation_presigned_example() {
    let (parts, ()) = Request::get(
        "/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256\
         &X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request\
         &X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host\
         &X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404",
    )
    .header("host", "examplebucket.s3.amazonaws.com")
    .body(())
    .unwrap()
    .into_parts();
    assert!(doc_authenticator().check(&parts, DOC_NOW + 3600).is_ok());
}

#[tokio::test]
async fn aws_documentation_chunked_upload_example() {
    // 66560 bytes of 'a' as 64 KiB + 1 KiB + final chunk.
    let parts = doc_request(
        "PUT",
        "/examplebucket/chunkObject.txt",
        &[
            ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
            ("x-amz-content-sha256", sigv4::STREAMING_SIGNED),
            ("content-encoding", "aws-chunked"),
            ("x-amz-decoded-content-length", "66560"),
            ("content-length", "66824"),
        ],
        "content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;\
         x-amz-decoded-content-length;x-amz-storage-class",
        "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9",
    );
    let mut parts = parts;
    parts
        .headers
        .insert("host", "s3.amazonaws.com".parse().unwrap());
    let plan = doc_authenticator().check(&parts, DOC_NOW).unwrap();
    let mut body = Vec::new();
    for (len, sig) in [
        (
            65536usize,
            "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648",
        ),
        (
            1024,
            "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497",
        ),
        (
            0,
            "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9",
        ),
    ] {
        body.extend_from_slice(format!("{len:x};chunk-signature={sig}\r\n").as_bytes());
        body.extend(std::iter::repeat_n(b'a', len));
        body.extend_from_slice(b"\r\n");
    }
    assert_eq!(body.len(), 66824);
    let out = deliver(&parts, &body, plan, 8192).await.unwrap();
    assert_eq!(out.len(), 66560);
}

// ── 3. Policy ───────────────────────────────────────────────────────────────

const NOW: u64 = 1_794_426_102; // 20261111T194142Z
const NOW_AMZ: &str = "20261111T194142Z";

/// Sign `parts` (header scheme) with every `x-amz-*` header and `host`.
/// `payload` None leaves `x-amz-content-sha256` off and signs the empty hash.
fn sign(parts: &mut Parts, secret: &str, amz_date: &str, payload: Option<&str>) {
    parts
        .headers
        .insert("x-amz-date", amz_date.parse().unwrap());
    if let Some(p) = payload {
        parts
            .headers
            .insert("x-amz-content-sha256", p.parse().unwrap());
    }
    sign_as(
        parts,
        secret,
        amz_date,
        payload.unwrap_or(sigv4::EMPTY_SHA256),
    );
}

fn sign_as(parts: &mut Parts, secret: &str, amz_date: &str, payload: &str) {
    if !parts.headers.contains_key("host") {
        parts.headers.insert("host", "localhost".parse().unwrap());
    }
    let mut names: Vec<&str> = parts
        .headers
        .keys()
        .map(http::HeaderName::as_str)
        .filter(|n| *n == "host" || *n == "date" || n.starts_with("x-amz-"))
        .collect();
    names.sort_unstable();
    let signed = names.join(";");
    sign_over(parts, secret, &signed, amz_date, payload);
}

/// Sign `parts` (header scheme) over exactly the `signed` header names,
/// whether the request carries them or not.
fn sign_over(parts: &mut Parts, secret: &str, signed: &str, amz_date: &str, payload: &str) {
    let date = &amz_date[..8];
    let scope = format!("{date}/us-east-1/s3/aws4_request");
    let canonical = CanonicalRequest {
        method: parts.method.as_str(),
        raw_path: parts.uri.path(),
        raw_query: parts.uri.query().unwrap_or(""),
        exclude_query: None,
        headers: &parts.headers,
        signed_headers: signed,
        payload_hash: payload,
    }
    .build();
    let sts = sigv4::string_to_sign(amz_date, &scope, &canonical);
    let key = sigv4::signing_key(&Secret::new(secret).prefixed, date, "us-east-1");
    let sig = sigv4::hex32(&sigv4::sign(&key, &sts));
    let value = format!(
        "AWS4-HMAC-SHA256 Credential={AKID}/{scope}, SignedHeaders={signed}, Signature={}",
        std::str::from_utf8(&sig).unwrap()
    );
    parts.headers.insert(AUTHORIZATION, value.parse().unwrap());
}

/// Presign `parts` (query scheme) over `signed`, putting `query_hash` in
/// `X-Amz-Content-Sha256` when given; the canonical payload is then that
/// hash, and `UNSIGNED-PAYLOAD` otherwise.
fn presign(parts: &mut Parts, signed: &str, amz_date: &str, query_hash: Option<&str>) {
    let date = &amz_date[..8];
    let scope = format!("{date}/us-east-1/s3/aws4_request");
    let mut query = format!(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256\
         &X-Amz-Credential={AKID}%2F{date}%2Fus-east-1%2Fs3%2Faws4_request\
         &X-Amz-Date={amz_date}&X-Amz-Expires=600&X-Amz-SignedHeaders={}",
        signed.replace(';', "%3B")
    );
    if let Some(h) = query_hash {
        query.push_str("&X-Amz-Content-Sha256=");
        query.push_str(h);
    }
    let path = parts.uri.path().to_string();
    let canonical = CanonicalRequest {
        method: parts.method.as_str(),
        raw_path: &path,
        raw_query: &query,
        exclude_query: None,
        headers: &parts.headers,
        signed_headers: signed,
        payload_hash: query_hash.unwrap_or(sigv4::UNSIGNED_PAYLOAD),
    }
    .build();
    let sts = sigv4::string_to_sign(amz_date, &scope, &canonical);
    let key = sigv4::signing_key(&Secret::new(SECRET).prefixed, date, "us-east-1");
    let sig = sigv4::hex32(&sigv4::sign(&key, &sts));
    parts.uri = format!(
        "{path}?{query}&X-Amz-Signature={}",
        std::str::from_utf8(&sig).unwrap()
    )
    .parse()
    .unwrap();
}

fn hex_digest(body: &[u8]) -> String {
    String::from_utf8(sigv4::hex32(&sha256(body)).to_vec()).unwrap()
}

fn get(uri: &str) -> Parts {
    Request::get(uri)
        .header("host", "localhost")
        .body(())
        .unwrap()
        .into_parts()
        .0
}

#[test]
fn signed_requests_pass_within_the_skew_window_only() {
    let mut parts = get("/b/k");
    sign(&mut parts, SECRET, NOW_AMZ, Some(sigv4::UNSIGNED_PAYLOAD));
    for now in [NOW, NOW - MAX_SKEW_SECS, NOW + MAX_SKEW_SECS] {
        assert!(enforce().check(&parts, now).is_ok());
    }
    for now in [NOW - MAX_SKEW_SECS - 1, NOW + MAX_SKEW_SECS + 1] {
        assert_eq!(
            failure(enforce().check(&parts, now)).code,
            "RequestTimeTooSkewed"
        );
    }
}

#[test]
fn unauthenticated_and_unsupported_schemes_are_refused() {
    let f = failure(enforce().check(&get("/b/k"), NOW));
    assert_eq!((f.status, f.code), (StatusCode::FORBIDDEN, "AccessDenied"));

    let mut v2 = get("/b/k");
    v2.headers
        .insert(AUTHORIZATION, "AWS AKIDTEST:c2lnbmF0dXJl".parse().unwrap());
    assert_eq!(failure(enforce().check(&v2, NOW)).code, "InvalidRequest");
    let v2q = get("/b/k?AWSAccessKeyId=AKIDTEST&Expires=1&Signature=x");
    assert_eq!(failure(enforce().check(&v2q, NOW)).code, "InvalidRequest");

    let mut other = get("/b/k");
    other.headers.insert(
        AUTHORIZATION,
        "AWS4-ECDSA-P256-SHA256 Credential=x".parse().unwrap(),
    );
    assert_eq!(
        failure(enforce().check(&other, NOW)).code,
        "AuthorizationHeaderMalformed"
    );
}

#[test]
fn unknown_keys_and_wrong_secrets_are_distinguished() {
    let mut parts = get("/b/k");
    sign(&mut parts, SECRET, NOW_AMZ, None);
    let other =
        Authenticator::new(Mode::Enforce, vec![("SOMEONEELSE".into(), SECRET.into())]).unwrap();
    let f = failure(other.check(&parts, NOW));
    assert_eq!(
        (f.code, f.access_key_id()),
        ("InvalidAccessKeyId", Some(AKID))
    );

    let mut forged = get("/b/k");
    sign(&mut forged, "a-guess-at-the-secret", NOW_AMZ, None);
    assert_eq!(
        failure(enforce().check(&forged, NOW)).code,
        "SignatureDoesNotMatch"
    );
}

#[test]
fn every_amz_header_must_be_signed() {
    // An unsigned x-amz-copy-source would turn a signed PUT into a copy of
    // any object the attacker names.
    let mut parts = Request::put("/b/k").body(()).unwrap().into_parts().0;
    sign(&mut parts, SECRET, NOW_AMZ, Some(sigv4::UNSIGNED_PAYLOAD));
    parts
        .headers
        .insert("x-amz-copy-source", "/b/secret".parse().unwrap());
    parts.headers.insert("x-amz-meta-a", "1".parse().unwrap());
    let f = failure(enforce().check(&parts, NOW));
    assert_eq!(f.code, "AccessDenied");
    let mut unsigned: Vec<&str> = f.headers_not_signed().unwrap().split(',').collect();
    unsigned.sort_unstable();
    assert_eq!(unsigned, ["x-amz-copy-source", "x-amz-meta-a"]);
}

#[test]
fn repeats_the_signature_cannot_order_are_refused() {
    // The canonical query is sorted and repeated header values are joined
    // with `,`, so neither the order of a repeated parameter nor the split of
    // a header into several lines is signed — while dispatch and the
    // handlers read the first of each. A request carrying either cannot be
    // read the way its signer meant, so it is refused.
    for q in [
        "uploadId=a&uploadId=b",
        "uploadId=b&uploadId=a",
        "uploadId=a&%75ploadId=b",
        "acl&acl=",
    ] {
        let mut parts = get(&format!("/b/k?{q}"));
        sign(&mut parts, SECRET, NOW_AMZ, None);
        let f = failure(enforce().check(&parts, NOW));
        assert_eq!(
            (f.status, f.code),
            (StatusCode::BAD_REQUEST, "InvalidArgument"),
            "{q}: {}",
            f.message
        );
    }
    // X-Amz-Signature is left out of the canonical query, so a second one
    // changes nothing that was signed.
    let uri = format!("{PRESIGNED}&X-Amz-Signature={}", "0".repeat(64));
    assert_eq!(
        failure(enforce().check(&presigned(&uri), PRESIGNED_AT)).code,
        "InvalidArgument"
    );

    // One header holding `a,b` and the same header twice sign identically.
    let mut parts = Request::put("/b/k")
        .header("x-amz-meta-note", "a,b")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    sign(&mut parts, SECRET, NOW_AMZ, Some(sigv4::UNSIGNED_PAYLOAD));
    assert!(enforce().check(&parts, NOW).is_ok());
    parts.headers.remove("x-amz-meta-note");
    parts
        .headers
        .append("x-amz-meta-note", "a".parse().unwrap());
    parts
        .headers
        .append("x-amz-meta-note", "b".parse().unwrap());
    let f = failure(enforce().check(&parts, NOW));
    assert_eq!(
        (f.status, f.code),
        (StatusCode::BAD_REQUEST, "InvalidArgument"),
        "{}",
        f.message
    );
}

/// SignedHeaders names headers the request carries. An absent header and an
/// empty one canonicalize alike (`name:`), so a signed empty header could
/// otherwise be stripped in flight under the same signature.
#[test]
fn every_signed_header_must_be_present() {
    let unsigned = sigv4::UNSIGNED_PAYLOAD;
    let mut put = Request::put("/b/k")
        .header("host", "localhost")
        .header("if-match", "")
        .header("x-amz-date", NOW_AMZ)
        .header("x-amz-content-sha256", unsigned)
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let signed = "host;if-match;x-amz-content-sha256;x-amz-date";
    sign_over(&mut put, SECRET, signed, NOW_AMZ, unsigned);
    assert!(enforce().check(&put, NOW).is_ok());
    put.headers.remove("if-match");
    let f = failure(enforce().check(&put, NOW));
    assert_eq!((f.status.as_u16(), f.code), (403, "AccessDenied"), "{f:?}");
    assert!(f.message.contains("\"if-match\""), "{}", f.message);

    let mut get = Request::get("/b/k")
        .header("host", "localhost")
        .header("if-none-match", "")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    presign(&mut get, "host;if-none-match", NOW_AMZ, None);
    assert!(enforce().check(&get, NOW).is_ok());
    get.headers.remove("if-none-match");
    let f = failure(enforce().check(&get, NOW));
    assert_eq!(f.code, "AccessDenied", "{f:?}");
}

/// A presigned request can also pin its payload with a signed
/// `x-amz-content-sha256` header; the body must then match it, and it must
/// agree with any hash in the query. Neither that header nor `x-amz-date` is
/// covered by a presigned signature unless listed, so unlisted they are
/// unsigned `x-amz-*` headers like any other.
#[tokio::test]
async fn presigned_payload_is_pinned_by_a_signed_content_sha256_header() {
    let put = |hash: Option<&str>| {
        let mut b = Request::put("/b/k").header("host", "localhost");
        if let Some(h) = hash {
            b = b.header("x-amz-content-sha256", h);
        }
        b.body(()).unwrap().into_parts().0
    };
    let x = hex_digest(b"x");
    let y = hex_digest(b"y");

    for query in [None, Some(x.as_str()), Some(sigv4::UNSIGNED_PAYLOAD)] {
        let mut parts = put(Some(&x));
        presign(&mut parts, "host;x-amz-content-sha256", NOW_AMZ, query);
        let plan = enforce().check(&parts, NOW).unwrap();
        assert!(
            matches!(plan.auth, PayloadAuth::Sha256(_)),
            "{query:?}: {plan:?}"
        );
        assert_eq!(deliver(&parts, b"x", plan.clone(), 1).await.unwrap(), b"x");
        let err = deliver(&parts, b"y", plan, 1).await.unwrap_err();
        assert!(err.contains("x-amz-content-sha256"), "{query:?}: {err}");
    }

    // The header and the query disagree about the payload.
    for (header, query) in [
        (x.as_str(), y.as_str()),
        (sigv4::UNSIGNED_PAYLOAD, y.as_str()),
        (sigv4::STREAMING_UNSIGNED_TRAILER, y.as_str()),
    ] {
        let mut parts = put(Some(header));
        presign(
            &mut parts,
            "host;x-amz-content-sha256",
            NOW_AMZ,
            Some(query),
        );
        let f = failure(enforce().check(&parts, NOW));
        assert_eq!(f.code, "InvalidArgument", "{header}: {f:?}");
    }

    // Signed chunks chain from a header signature; no presigning client
    // sends them.
    let mut parts = put(Some(sigv4::STREAMING_SIGNED));
    presign(&mut parts, "host;x-amz-content-sha256", NOW_AMZ, None);
    assert_eq!(
        failure(enforce().check(&parts, NOW)).code,
        "InvalidArgument"
    );

    for (name, value) in [
        ("x-amz-content-sha256", x.as_str()),
        ("x-amz-date", NOW_AMZ),
    ] {
        let mut parts = put(None);
        parts.headers.insert(name, value.parse().unwrap());
        presign(&mut parts, "host", NOW_AMZ, None);
        let f = failure(enforce().check(&parts, NOW));
        assert_eq!(f.code, "AccessDenied", "{name}: {f:?}");
        assert_eq!(f.headers_not_signed(), Some(name));
    }
}

/// What the body is decoded as must be what the signature pins. A whole-body
/// digest cannot describe an aws-chunked body, so a request whose unsigned
/// headers turn it into one is refused rather than decoded unchecked (and
/// only logged in log mode). `RequestBody` refuses the pairing on its own as
/// well, so no caller can drop the digest by building one.
#[tokio::test]
async fn framing_cannot_unpin_a_signed_digest() {
    let hello = hex_digest(b"hello");
    let parts = || {
        let mut parts = Request::put("/b/k")
            .header("host", "localhost")
            .header("x-amz-decoded-content-length", "5")
            .header("content-encoding", "aws-chunked")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        presign(
            &mut parts,
            "host;x-amz-decoded-content-length",
            NOW_AMZ,
            Some(&hello),
        );
        parts
    };
    let f = failure(enforce().check(&parts(), NOW));
    assert_eq!(
        (f.status.as_u16(), f.code),
        (400, "InvalidArgument"),
        "{f:?}"
    );
    let plan = authenticator(Mode::Log).check(&parts(), NOW).unwrap();
    assert!(
        !plan.enforce && matches!(plan.auth, PayloadAuth::None),
        "{plan:?}"
    );

    let chunked = b"5\r\nHELLO\r\n0\r\n\r\n";
    let pinned = PayloadPlan {
        auth: PayloadAuth::Sha256(sha256(b"hello")),
        enforce: true,
    };
    let err = deliver(&parts(), chunked, pinned, 4).await.unwrap_err();
    assert!(err.contains("aws-chunked"), "{err}");
}

/// Canonical header values collapse runs of spaces and tabs, so a copy
/// source of `/bkt/a b` and one of `/bkt/a  b` carry one signature while
/// naming different objects. Signed requests must percent-encode whitespace
/// in it, as S3 clients do.
#[test]
fn signed_copy_source_must_encode_whitespace() {
    let copy = |source: &str| {
        Request::put("/bkt/dest")
            .header("host", "localhost")
            .header("x-amz-copy-source", source)
            .body(())
            .unwrap()
            .into_parts()
            .0
    };
    let mut parts = copy("/bkt/a%20b");
    sign(&mut parts, SECRET, NOW_AMZ, None);
    assert!(enforce().check(&parts, NOW).is_ok());
    let mut parts = copy("/bkt/a%20b");
    presign(&mut parts, "host;x-amz-copy-source", NOW_AMZ, None);
    assert!(enforce().check(&parts, NOW).is_ok());

    let mut signed = copy("/bkt/a b");
    sign(&mut signed, SECRET, NOW_AMZ, None);
    for source in ["/bkt/a b", "/bkt/a  b", "/bkt/a\tb"] {
        signed
            .headers
            .insert("x-amz-copy-source", source.parse().unwrap());
        let f = failure(enforce().check(&signed, NOW));
        assert_eq!(f.code, "InvalidArgument", "{source:?}: {f:?}");
    }
    let mut parts = copy("/bkt/a b");
    presign(&mut parts, "host;x-amz-copy-source", NOW_AMZ, None);
    assert_eq!(
        failure(enforce().check(&parts, NOW)).code,
        "InvalidArgument"
    );
}

#[test]
fn session_tokens_are_refused_not_ignored() {
    let mut parts = get("/b/k");
    parts
        .headers
        .insert("x-amz-security-token", "token".parse().unwrap());
    sign(&mut parts, SECRET, NOW_AMZ, None);
    assert_eq!(failure(enforce().check(&parts, NOW)).code, "InvalidToken");
}

#[test]
fn payload_hash_rules() {
    // Bodyless and no x-amz-content-sha256: signed over the empty hash.
    let mut parts = get("/b/k");
    sign(&mut parts, SECRET, NOW_AMZ, None);
    let plan = enforce().check(&parts, NOW).unwrap();
    assert!(matches!(plan.auth, PayloadAuth::Sha256(d) if d == sha256(b"")));

    // A body with no declared hash cannot be verified without buffering it.
    let mut parts = Request::put("/b/k")
        .header("content-length", "5")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    sign(&mut parts, SECRET, NOW_AMZ, None);
    assert_eq!(failure(enforce().check(&parts, NOW)).code, "InvalidRequest");

    let mut parts = get("/b/k");
    sign(&mut parts, SECRET, NOW_AMZ, Some("not-a-digest"));
    assert_eq!(
        failure(enforce().check(&parts, NOW)).code,
        "InvalidArgument"
    );
}

#[test]
fn a_client_that_signs_the_date_header_instead_of_x_amz_date() {
    let mut parts = get("/b/k");
    parts
        .headers
        .insert("date", "Wed, 11 Nov 2026 19:41:42 GMT".parse().unwrap());
    parts
        .headers
        .insert("x-amz-content-sha256", sigv4::EMPTY_SHA256.parse().unwrap());
    sign_as(&mut parts, SECRET, NOW_AMZ, sigv4::EMPTY_SHA256);
    assert!(enforce().check(&parts, NOW).is_ok());
}

#[test]
fn credential_date_must_match_the_request_date() {
    let mut parts = get("/b/k");
    sign(&mut parts, SECRET, NOW_AMZ, None);
    parts
        .headers
        .insert("x-amz-date", "20261112T000000Z".parse().unwrap());
    assert_eq!(
        failure(enforce().check(&parts, NOW)).code,
        "AuthorizationHeaderMalformed"
    );
    parts
        .headers
        .insert("x-amz-date", "yesterday".parse().unwrap());
    assert_eq!(failure(enforce().check(&parts, NOW)).code, "AccessDenied");
}

#[test]
fn log_mode_serves_what_enforce_would_reject() {
    let log = authenticator(Mode::Log);
    let plan = log.check(&get("/b/k"), NOW).unwrap();
    assert!(matches!(plan.auth, PayloadAuth::None) && !plan.enforce);

    let mut parts = get("/b/k");
    sign(&mut parts, SECRET, NOW_AMZ, None);
    let plan = log.check(&parts, NOW).unwrap();
    assert!(
        matches!(plan.auth, PayloadAuth::Sha256(_)) && !plan.enforce,
        "a valid request is still verified, so its payload is checked (and logged)"
    );
}

#[test]
fn off_mode_checks_nothing() {
    let off = Authenticator::disabled();
    for parts in [get("/b/k"), get("/b/k?X-Amz-Algorithm=bogus")] {
        let plan = off.check(&parts, NOW).unwrap();
        assert!(matches!(plan.auth, PayloadAuth::None) && !plan.enforce);
    }
}

#[test]
fn date_header_timestamps_convert_to_the_basic_form() {
    assert_eq!(basic_timestamp(DOC_NOW), "20130524T000000Z");
    assert_eq!(basic_timestamp(NOW), NOW_AMZ);
}

// ── Configuration ───────────────────────────────────────────────────────────

fn from(vars: &[(&str, &str)]) -> Result<Authenticator, String> {
    let vars: HashMap<String, String> = vars
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    Authenticator::from_vars(|k| vars.get(k).cloned())
}

#[test]
fn mode_defaults_to_enforce_once_a_key_is_configured() {
    assert_eq!(from(&[]).unwrap().mode(), Mode::Off);
    let pair = [
        ("SPICEIO_S3_ACCESS_KEY_ID", AKID),
        ("SPICEIO_S3_SECRET_ACCESS_KEY", SECRET),
    ];
    assert_eq!(from(&pair).unwrap().mode(), Mode::Enforce);
    for (mode, want) in [
        ("log", Mode::Log),
        ("ENFORCE", Mode::Enforce),
        ("off", Mode::Off),
    ] {
        let mut vars = pair.to_vec();
        vars.push(("SPICEIO_S3_AUTH", mode));
        assert_eq!(from(&vars).unwrap().mode(), want);
    }
    // Empty values are unset (CI forwards optional variables as "").
    assert_eq!(
        from(&[
            ("SPICEIO_S3_ACCESS_KEY_ID", ""),
            ("SPICEIO_S3_SECRET_ACCESS_KEY", ""),
            ("SPICEIO_S3_AUTH", ""),
        ])
        .unwrap()
        .mode(),
        Mode::Off
    );
}

#[test]
fn misconfiguration_stops_startup() {
    for vars in [
        vec![("SPICEIO_S3_ACCESS_KEY_ID", AKID)],
        vec![("SPICEIO_S3_SECRET_ACCESS_KEY", SECRET)],
        vec![("SPICEIO_S3_AUTH", "enforce")],
        vec![("SPICEIO_S3_AUTH", "log")],
        vec![
            ("SPICEIO_S3_ACCESS_KEY_ID", AKID),
            ("SPICEIO_S3_SECRET_ACCESS_KEY", SECRET),
            ("SPICEIO_S3_AUTH", "yes"),
        ],
        vec![
            ("SPICEIO_S3_ACCESS_KEY_ID", AKID),
            ("SPICEIO_S3_SECRET_ACCESS_KEY", "short"),
        ],
        vec![
            ("SPICEIO_S3_ACCESS_KEY_ID", "has space"),
            ("SPICEIO_S3_SECRET_ACCESS_KEY", SECRET),
        ],
        vec![("SPICEIO_S3_CREDENTIALS_FILE", "/nonexistent/spiceio-keys")],
    ] {
        assert!(from(&vars).is_err(), "{vars:?} must be refused");
    }
}

#[test]
fn credentials_file_supports_several_keys_and_must_be_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = crate::test_support::TempDir::new("auth-keys");
    let path = dir.0.join("keys");
    std::fs::write(
        &path,
        "# rotation: old and new side by side\n\nOLDKEY  old-secret-0123456789\nNEWKEY\tnew-secret-0123456789\n",
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let p = path.to_str().unwrap();
    let a = from(&[("SPICEIO_S3_CREDENTIALS_FILE", p)]).unwrap();
    assert_eq!(a.mode(), Mode::Enforce);
    assert_eq!(a.access_key_ids(), ["NEWKEY", "OLDKEY"]);

    // Combined with the env pair; the same id twice is refused.
    let combined = from(&[
        ("SPICEIO_S3_CREDENTIALS_FILE", p),
        ("SPICEIO_S3_ACCESS_KEY_ID", AKID),
        ("SPICEIO_S3_SECRET_ACCESS_KEY", SECRET),
    ])
    .unwrap();
    assert_eq!(combined.access_key_ids().len(), 3);
    assert!(
        from(&[
            ("SPICEIO_S3_CREDENTIALS_FILE", p),
            ("SPICEIO_S3_ACCESS_KEY_ID", "OLDKEY"),
            ("SPICEIO_S3_SECRET_ACCESS_KEY", SECRET),
        ])
        .is_err()
    );

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let err = from(&[("SPICEIO_S3_CREDENTIALS_FILE", p)]).unwrap_err();
    assert!(err.contains("chmod 600"), "{err}");

    std::fs::write(&path, "ONLYANID\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let err = from(&[("SPICEIO_S3_CREDENTIALS_FILE", p)]).unwrap_err();
    assert!(err.contains(":1:"), "names the line: {err}");
}

#[test]
fn derived_keys_are_cached_only_after_a_signature_verifies() {
    let auth = enforce();
    let secret = auth.keys.get(AKID).unwrap();

    // A forged request (known key id, wrong secret) leaves the cache alone,
    // whatever region it claims.
    for region in ["us-east-1", "made-up-1", "made-up-2"] {
        let mut forged = get("/b/k");
        sign(&mut forged, "a-guess-at-the-secret", NOW_AMZ, None);
        let value = forged.headers[AUTHORIZATION]
            .to_str()
            .unwrap()
            .replace("/us-east-1/", &format!("/{region}/"));
        forged.headers.insert(AUTHORIZATION, value.parse().unwrap());
        assert!(auth.check(&forged, NOW).is_err());
    }
    assert_eq!(secret.derived_len(), 0);

    // A valid one fills it, and the cached key verifies the next request.
    let mut parts = get("/b/k");
    sign(&mut parts, SECRET, NOW_AMZ, None);
    assert!(auth.check(&parts, NOW).is_ok());
    assert_eq!(secret.derived_len(), 1);
    assert!(auth.check(&parts, NOW).is_ok());
    assert_eq!(secret.derived_len(), 1, "a hit does not re-insert");

    // A cached key for one secret never verifies another's signature, and a
    // new day derives a new key.
    let mut forged = get("/b/k");
    sign(&mut forged, "a-guess-at-the-secret", NOW_AMZ, None);
    assert_eq!(
        failure(auth.check(&forged, NOW)).code,
        "SignatureDoesNotMatch"
    );
    let mut tomorrow = get("/b/k");
    sign(&mut tomorrow, SECRET, "20261112T010000Z", None);
    assert!(
        auth.check(&tomorrow, NOW + 6 * 3600).is_err(),
        "outside the skew window"
    );
    assert!(auth.check(&tomorrow, 1_794_445_200).is_ok());
    assert_eq!(secret.derived_len(), 2);
}

#[test]
fn secrets_never_appear_in_debug_output() {
    let shown = format!("{:?}", enforce());
    assert!(shown.contains(AKID) && !shown.contains(SECRET), "{shown}");
}

// ── Through the router ──────────────────────────────────────────────────────

/// Render a request head + body as raw HTTP/1.1 for `http_request`.
fn raw(parts: &Parts, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "{} {} HTTP/1.1\r\n",
        parts.method,
        parts.uri.path_and_query().unwrap()
    )
    .into_bytes();
    for (k, v) in &parts.headers {
        out.extend_from_slice(k.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if !parts.headers.contains_key("content-length") {
        out.extend_from_slice(format!("content-length: {}\r\n", body.len()).as_bytes());
    }
    out.extend_from_slice(b"connection: close\r\n\r\n");
    out.extend_from_slice(body);
    out
}

fn now_amz() -> String {
    let now = crate::smb::ops::now_epoch_secs();
    basic_timestamp(now)
}

/// Router state with the given authenticator. Nothing these tests send
/// reaches SMB — ListBuckets is answered in memory and small PUTs are
/// acknowledged from write-back memory — but the fake server's socket is
/// returned so it stays open for the test's duration.
async fn router_state(
    auth: Authenticator,
) -> (Arc<crate::s3::router::AppState>, tokio::net::TcpStream) {
    let (mut state, server) = crate::test_support::state().await;
    state.auth = Arc::new(auth);
    (Arc::new(state), server)
}

async fn send(state: &Arc<crate::s3::router::AppState>, request: Vec<u8>) -> String {
    String::from_utf8_lossy(&crate::test_support::http_request(Arc::clone(state), &request).await)
        .into_owned()
}

fn status(response: &str) -> &str {
    response.split_whitespace().nth(1).unwrap_or("")
}

#[tokio::test]
async fn router_off_mode_serves_unsigned_requests_as_before() {
    let (state, _smb) = router_state(Authenticator::disabled()).await;
    let resp = send(&state, raw(&get("/"), b"")).await;
    assert_eq!(status(&resp), "200", "{resp}");
}

#[tokio::test]
async fn router_enforce_mode_requires_a_signature_for_everything_but_preflight() {
    let (state, _smb) = router_state(enforce()).await;

    let resp = send(&state, raw(&get("/"), b"")).await;
    assert_eq!(status(&resp), "403", "{resp}");
    assert!(resp.contains("<Code>AccessDenied</Code>"), "{resp}");

    // Cache and existence-index answers must not bypass it either.
    let resp = send(&state, raw(&get("/audit/some/key"), b"")).await;
    assert_eq!(status(&resp), "403", "{resp}");

    let mut signed = get("/");
    sign(&mut signed, SECRET, &now_amz(), None);
    let resp = send(&state, raw(&signed, b"")).await;
    assert_eq!(status(&resp), "200", "{resp}");
    assert!(resp.contains("<Name>audit</Name>"), "{resp}");

    let mut forged = get("/");
    sign(&mut forged, "a-guess-at-the-secret", &now_amz(), None);
    let resp = send(&state, raw(&forged, b"")).await;
    assert_eq!(status(&resp), "403", "{resp}");
    assert!(
        resp.contains("<Code>SignatureDoesNotMatch</Code>")
            && resp.contains("<CanonicalRequest>GET\n/\n"),
        "the mismatch response shows what spiceio signed: {resp}"
    );

    let preflight = Request::builder()
        .method("OPTIONS")
        .uri("/audit/key")
        .header("host", "localhost")
        .header("origin", "http://example")
        .header("access-control-request-method", "PUT")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let resp = send(&state, raw(&preflight, b"")).await;
    assert_eq!(status(&resp), "200", "{resp}");
}

#[tokio::test]
async fn router_log_mode_serves_and_reports() {
    let (state, _smb) = router_state(authenticator(Mode::Log)).await;
    let resp = send(&state, raw(&get("/"), b"")).await;
    assert_eq!(status(&resp), "200", "{resp}");
}

/// The aws-cli `aws s3 cp` body, re-targeted at the test bucket.
fn awscli_chunked_put(key: &str) -> (Parts, Bytes) {
    let (mut parts, body) = parse_raw_request(AWSCLI_CP_CHUNKED);
    parts.uri = format!("/audit/{key}").parse().unwrap();
    parts.headers.remove(AUTHORIZATION);
    parts.headers.remove("x-amz-date");
    (parts, body)
}

#[tokio::test]
async fn router_off_mode_stores_the_decoded_body_of_an_aws_chunked_upload() {
    // Regression: before aws-chunked decoding, spiceio stored the framing
    // (`B\r\nhello world\r\n0\r\nx-amz-checksum-crc64nvme:…`) as the object.
    let (state, _smb) = router_state(Authenticator::disabled()).await;
    let (parts, body) = awscli_chunked_put("chunked.txt");
    let resp = send(&state, raw(&parts, &body)).await;
    assert_eq!(status(&resp), "200", "{resp}");
    let resp = send(&state, raw(&get("/audit/chunked.txt"), b"")).await;
    assert_eq!(status(&resp), "200", "{resp}");
    assert!(resp.ends_with("\r\n\r\nhello world"), "{resp:?}");
}

#[tokio::test]
async fn router_enforce_mode_verifies_payloads_before_acknowledging() {
    let (state, _smb) = router_state(enforce()).await;

    // Signed aws-chunked (unsigned payload, as aws-cli sends it).
    let (mut parts, body) = awscli_chunked_put("signed-chunked.txt");
    sign(
        &mut parts,
        SECRET,
        &now_amz(),
        Some(sigv4::STREAMING_UNSIGNED_TRAILER),
    );
    let resp = send(&state, raw(&parts, &body)).await;
    assert_eq!(status(&resp), "200", "{resp}");

    // Signed payload digest; then the same signature over a different body.
    let digest = sigv4::hex32(&sha256(b"exact bytes"));
    let digest = std::str::from_utf8(&digest).unwrap();
    let mut put = Request::put("/audit/digest.txt")
        .header("host", "localhost")
        .header("content-length", "11")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    sign(&mut put, SECRET, &now_amz(), Some(digest));
    let resp = send(&state, raw(&put, b"exact bytes")).await;
    assert_eq!(status(&resp), "200", "{resp}");
    let resp = send(&state, raw(&put, b"other bytes")).await;
    assert_eq!(status(&resp), "400", "{resp}");
    assert!(
        resp.contains("<Code>XAmzContentSHA256Mismatch</Code>"),
        "{resp}"
    );

    // Only the verified body was acknowledged.
    let mut read = get("/audit/digest.txt");
    sign(&mut read, SECRET, &now_amz(), None);
    let resp = send(&state, raw(&read, b"")).await;
    assert!(resp.ends_with("\r\n\r\nexact bytes"), "{resp:?}");
    let mut read = get("/audit/signed-chunked.txt");
    sign(&mut read, SECRET, &now_amz(), None);
    let resp = send(&state, raw(&read, b"")).await;
    assert!(resp.ends_with("\r\n\r\nhello world"), "{resp:?}");
}

#[tokio::test]
async fn router_reads_a_signed_query_the_way_it_was_signed() {
    let (state, _smb) = router_state(enforce()).await;
    let mut put = Request::put("/audit/q.txt")
        .header("host", "localhost")
        .header("content-length", "4")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    sign(&mut put, SECRET, &now_amz(), Some(sigv4::UNSIGNED_PAYLOAD));
    let resp = send(&state, raw(&put, b"data")).await;
    assert_eq!(status(&resp), "200", "{resp}");

    // A signed ListParts. Re-encoding the parameter name keeps the canonical
    // query, and so the signature; it must stay a ListParts rather than
    // become a GetObject of the key (the DELETE form of the same rewrite
    // turns AbortMultipartUpload into DeleteObject).
    let mut list_parts = get("/audit/q.txt?uploadId=nope");
    sign(&mut list_parts, SECRET, &now_amz(), None);
    for uri in ["/audit/q.txt?uploadId=nope", "/audit/q.txt?%75ploadId=nope"] {
        list_parts.uri = uri.parse().unwrap();
        let resp = send(&state, raw(&list_parts, b"")).await;
        assert_eq!(status(&resp), "404", "{uri}: {resp}");
        assert!(resp.contains("<Code>NoSuchUpload</Code>"), "{uri}: {resp}");
    }
}

/// Operations that never read the body still answer only once it matches the
/// payload hash that was signed.
#[tokio::test]
async fn router_enforce_mode_verifies_payloads_the_operation_does_not_read() {
    let (state, _smb) = router_state(enforce()).await;
    let digest = sigv4::hex32(&sha256(b"x"));
    let digest = std::str::from_utf8(&digest).unwrap();
    let request = |method: &str, uri: &str, extra: Option<(&str, &str)>| {
        let mut b = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "localhost")
            .header("content-length", "1");
        if let Some((k, v)) = extra {
            b = b.header(k, v);
        }
        let mut parts = b.body(()).unwrap().into_parts().0;
        sign(&mut parts, SECRET, &now_amz(), Some(digest));
        parts
    };

    // Answered from memory, so the signed body shows the handler still runs.
    for (method, uri, extra) in [
        ("GET", "/audit/body.txt?uploadId=nope", None),
        ("DELETE", "/audit/body.txt?uploadId=nope", None),
        (
            "PUT",
            "/audit/body.txt?partNumber=1&uploadId=nope",
            Some(("x-amz-copy-source", "/audit/src.txt")),
        ),
    ] {
        let parts = request(method, uri, extra);
        let resp = send(&state, raw(&parts, b"x")).await;
        assert_eq!(status(&resp), "404", "{method} {uri}, signed body: {resp}");
        let resp = send(&state, raw(&parts, b"y")).await;
        assert_eq!(status(&resp), "400", "{method} {uri}, other body: {resp}");
        assert!(
            resp.contains("<Code>XAmzContentSHA256Mismatch</Code>"),
            "{resp}"
        );
    }

    // These go to the backend once verified, and the test server never
    // answers, so a reply within the timeout is one given before the
    // handler ran.
    for (method, uri, extra) in [
        (
            "PUT",
            "/audit/copy.txt",
            Some(("x-amz-copy-source", "/audit/src.txt")),
        ),
        ("POST", "/audit/new.txt?uploads", None),
        ("DELETE", "/audit/body.txt", None),
    ] {
        let parts = request(method, uri, extra);
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            send(&state, raw(&parts, b"y")),
        )
        .await
        .unwrap_or_else(|_| panic!("{method} {uri} reached the backend with an unverified body"));
        assert_eq!(status(&resp), "400", "{method} {uri}: {resp}");
        assert!(
            resp.contains("<Code>XAmzContentSHA256Mismatch</Code>"),
            "{resp}"
        );
    }
}

/// A PUT signed with an empty `If-Match` is refused as a conditional write;
/// stripping the header must not turn it into an unconditional one under the
/// same signature.
#[tokio::test]
async fn router_refuses_a_request_missing_a_header_it_signed() {
    let (state, _smb) = router_state(enforce()).await;
    let now = now_amz();
    let unsigned = sigv4::UNSIGNED_PAYLOAD;
    let mut put = Request::put("/audit/cond.txt")
        .header("host", "localhost")
        .header("content-length", "4")
        .header("if-match", "")
        .header("x-amz-date", &now)
        .header("x-amz-content-sha256", unsigned)
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let signed = "host;if-match;x-amz-content-sha256;x-amz-date";
    sign_over(&mut put, SECRET, signed, &now, unsigned);
    let resp = send(&state, raw(&put, b"data")).await;
    assert_eq!(status(&resp), "400", "as signed: {resp}");
    put.headers.remove("if-match");
    let resp = send(&state, raw(&put, b"data")).await;
    assert_eq!(status(&resp), "403", "stripped of its If-Match: {resp}");
}

/// A presigned PUT pinned by a query digest, which also signs
/// `x-amz-decoded-content-length`. Headers its signature does not cover must
/// not make the router decode the body as aws-chunked: the digest would go
/// unchecked and other bytes be stored.
#[tokio::test]
async fn router_refuses_framing_that_would_unpin_a_signed_digest() {
    let (state, _smb) = router_state(enforce()).await;
    let now = now_amz();
    let hello = hex_digest(b"hello");
    let put = |extra: Option<(&str, &str)>| {
        let mut b = Request::put("/audit/pinned.txt")
            .header("host", "localhost")
            .header("x-amz-decoded-content-length", "5");
        if let Some((k, v)) = extra {
            b = b.header(k, v);
        }
        let mut parts = b.body(()).unwrap().into_parts().0;
        presign(
            &mut parts,
            "host;x-amz-decoded-content-length",
            &now,
            Some(&hello),
        );
        parts
    };
    let resp = send(&state, raw(&put(None), b"hello")).await;
    assert_eq!(status(&resp), "200", "as signed: {resp}");

    let chunked = b"5\r\nHELLO\r\n0\r\n\r\n";
    for (header, code) in [
        (
            ("x-amz-content-sha256", sigv4::STREAMING_UNSIGNED_TRAILER),
            "403",
        ),
        (("content-encoding", "aws-chunked"), "400"),
    ] {
        let resp = send(&state, raw(&put(Some(header)), chunked)).await;
        assert_eq!(status(&resp), code, "{header:?}: {resp}");
    }

    let mut read = get("/audit/pinned.txt");
    sign(&mut read, SECRET, &now, None);
    let resp = send(&state, raw(&read, b"")).await;
    assert!(resp.ends_with("\r\n\r\nhello"), "{resp:?}");
}

/// The path is signed decoded (`canonical_uri_into`), so `/audit%2Fp.txt`,
/// `/%61udit/p.txt` and `/audit/p.txt` carry one signature and must name one
/// object. Splitting bucket from key before decoding made the first two a
/// bucket that does not exist, and a signed request for one could be
/// rewritten into the other: a DELETE of nothing into a DeleteObject.
#[tokio::test]
async fn router_reads_a_signed_path_the_way_it_was_signed() {
    let (state, _smb) = router_state(enforce()).await;
    let now = now_amz();
    let mut put = Request::put("/audit/p.txt")
        .header("host", "localhost")
        .header("content-length", "4")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    sign(&mut put, SECRET, &now, Some(sigv4::UNSIGNED_PAYLOAD));
    let resp = send(&state, raw(&put, b"data")).await;
    assert_eq!(status(&resp), "200", "{resp}");

    for uri in [
        "/audit/p.txt",
        "/audit%2Fp.txt",
        "/%61udit/p.txt",
        "/%61udit%2Fp%2Etxt",
    ] {
        let mut header = get(uri);
        sign(&mut header, SECRET, &now, None);
        let mut presigned = get(uri);
        presign(&mut presigned, "host", &now, None);
        for (scheme, parts) in [("header", header), ("presigned", presigned)] {
            let resp = send(&state, raw(&parts, b"")).await;
            assert!(resp.ends_with("\r\n\r\ndata"), "{scheme} {uri}: {resp:?}");
        }
    }
}
