//! S3 API router — full API surface translating HTTP to SMB operations.
//!
//! Covers: GetObject (range + conditional), PutObject (conditional-write),
//! CopyObject, DeleteObject, HeadObject, ListObjectsV1/V2, ListBuckets,
//! MultipartUpload (create/upload-part/complete/abort/list-parts/list-uploads),
//! GetBucketLocation, HeadBucket, CreateBucket, DeleteBucket,
//! GetBucketVersioning, GetBucketAcl, PutBucketAcl, GetObjectAcl, PutObjectAcl,
//! GetBucketTagging, PutBucketTagging, DeleteBucketTagging,
//! GetObjectTagging, PutObjectTagging, DeleteObjectTagging,
//! OPTIONS (CORS preflight), and proper S3 error responses.

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use std::io;
use std::sync::Arc;

use super::body::SpiceioBody;
use super::headers::*;
use super::multipart::MultipartStore;
use super::xml::{self, XmlWriter};
use crate::smb::ops::ShareSession;

const S3_XMLNS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

/// Shared application state passed to the router.
pub struct AppState {
    pub share: Arc<ShareSession>,
    pub bucket: String,
    pub region: String,
    pub multipart: MultipartStore,
}

/// Handle an incoming S3 API request.
///
/// Accepts the raw `Incoming` body — GetObject and PutObject stream without
/// buffering the entire payload. Operations that need the full body (multipart,
/// multi-delete, copy) collect it internally.
pub async fn handle_request(req: Request<Incoming>, state: &AppState) -> Response<SpiceioBody> {
    let path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or("").to_owned();
    let method = req.method().clone();
    let hdrs = req.headers().clone();
    let request_id = generate_request_id();

    // CORS preflight
    if method == Method::OPTIONS {
        return cors_preflight(&request_id, &state.region);
    }

    // Parse bucket and key from path-style: /{bucket}/{key...}
    let (req_bucket, key) = parse_path(&path);

    // Service-level operations (no bucket)
    if req_bucket.is_empty() {
        match method {
            Method::GET => {
                return with_common_headers(
                    list_buckets_response(&state.bucket),
                    &request_id,
                    &state.region,
                );
            }
            _ => {
                return with_common_headers(
                    error_response(
                        StatusCode::METHOD_NOT_ALLOWED,
                        "MethodNotAllowed",
                        "Method not allowed",
                    ),
                    &request_id,
                    &state.region,
                );
            }
        }
    }

    // Bucket must match our configured bucket
    if req_bucket != state.bucket {
        return with_common_headers(
            error_response(
                StatusCode::NOT_FOUND,
                "NoSuchBucket",
                "The specified bucket does not exist.",
            ),
            &request_id,
            &state.region,
        );
    }

    let share = &state.share;

    // ── Bucket-level operations (no key) ────────────────────────────────
    if key.is_empty() {
        let resp = match method {
            Method::GET | Method::HEAD if query.contains("location") => {
                handle_get_bucket_location(&state.region)
            }
            Method::GET if query.contains("versioning") => handle_get_bucket_versioning(),
            Method::GET if query.contains("acl") => handle_get_bucket_acl(),
            Method::PUT if query.contains("acl") => ok_empty(),
            Method::GET if query.contains("tagging") => handle_get_bucket_tagging(),
            Method::PUT if query.contains("tagging") => ok_empty(),
            Method::DELETE if query.contains("tagging") => ok_no_content(),
            Method::GET if query.contains("cors") => handle_get_bucket_cors(),
            Method::PUT if query.contains("cors") => ok_empty(),
            Method::DELETE if query.contains("cors") => ok_no_content(),
            Method::GET if query.contains("lifecycle") => handle_get_bucket_lifecycle(),
            Method::GET if query.contains("policy") => handle_get_bucket_policy(),
            Method::GET if query.contains("encryption") => handle_get_bucket_encryption(),
            Method::GET if query.contains("uploads") => {
                handle_list_multipart_uploads(state, &query).await
            }
            Method::POST if query.contains("delete") => {
                let body = collect_body(req).await;
                handle_delete_objects(body, share).await
            }
            Method::GET => handle_list_objects(share, &state.bucket, &query).await,
            Method::HEAD => head_bucket_response(&state.region),
            Method::PUT => ok_empty(),         // CreateBucket — noop
            Method::DELETE => ok_no_content(), // DeleteBucket — noop
            _ => error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "MethodNotAllowed",
                "Method not allowed",
            ),
        };
        return with_common_headers(resp, &request_id, &state.region);
    }

    // ── Object-level operations ─────────────────────────────────────────

    // Multipart: POST with ?uploads (initiate) or ?uploadId=... (complete)
    if method == Method::POST {
        let resp = if query.contains("uploads") && !query.contains("uploadId") {
            handle_create_multipart_upload(&hdrs, state, key).await
        } else if let Some(upload_id) = extract_query_param(&query, "uploadId") {
            let body = collect_body(req).await;
            handle_complete_multipart_upload(body, state, key, &upload_id).await
        } else {
            error_response(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "Invalid POST request",
            )
        };
        return with_common_headers(resp, &request_id, &state.region);
    }

    // Multipart: PUT with ?partNumber=...&uploadId=...
    if method == Method::PUT && query.contains("partNumber") && query.contains("uploadId") {
        let part_number: u32 = extract_query_param(&query, "partNumber")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let upload_id = extract_query_param(&query, "uploadId").unwrap_or_default();
        let resp = handle_upload_part(req, state, key, &upload_id, part_number).await;
        return with_common_headers(resp, &request_id, &state.region);
    }

    // Multipart: GET with ?uploadId=... (list parts)
    if method == Method::GET && query.contains("uploadId") {
        let upload_id = extract_query_param(&query, "uploadId").unwrap_or_default();
        let resp = handle_list_parts(state, key, &upload_id).await;
        return with_common_headers(resp, &request_id, &state.region);
    }

    // Multipart: DELETE with ?uploadId=... (abort)
    if method == Method::DELETE && query.contains("uploadId") {
        let upload_id = extract_query_param(&query, "uploadId").unwrap_or_default();
        let resp = handle_abort_multipart_upload(state, key, &upload_id).await;
        return with_common_headers(resp, &request_id, &state.region);
    }

    // Object ACL
    if query.contains("acl") {
        let resp = match method {
            Method::GET => handle_get_object_acl(),
            Method::PUT => ok_empty(),
            _ => error_response(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", ""),
        };
        return with_common_headers(resp, &request_id, &state.region);
    }

    // Object tagging
    if query.contains("tagging") {
        let resp = match method {
            Method::GET => handle_get_object_tagging(),
            Method::PUT => ok_empty(),
            Method::DELETE => ok_no_content(),
            _ => error_response(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", ""),
        };
        return with_common_headers(resp, &request_id, &state.region);
    }

    // Object legal-hold, retention, torrent — stubs
    if query.contains("legal-hold") || query.contains("retention") || query.contains("torrent") {
        let resp = match method {
            Method::GET | Method::PUT => ok_empty(),
            _ => error_response(StatusCode::NOT_IMPLEMENTED, "NotImplemented", ""),
        };
        return with_common_headers(resp, &request_id, &state.region);
    }

    // Object restore — stub
    if method == Method::POST && query.contains("restore") {
        return with_common_headers(
            Response::builder()
                .status(StatusCode::ACCEPTED)
                .body(SpiceioBody::empty())
                .unwrap(),
            &request_id,
            &state.region,
        );
    }

    // SelectObjectContent — not supported
    if method == Method::POST && query.contains("select") {
        return with_common_headers(
            error_response(
                StatusCode::NOT_IMPLEMENTED,
                "NotImplemented",
                "SelectObjectContent is not supported",
            ),
            &request_id,
            &state.region,
        );
    }

    let resp = match method {
        Method::GET => handle_get_object(&hdrs, share, key).await,
        Method::PUT => {
            // CopyObject: PUT with x-amz-copy-source header
            if hdrs.contains_key(X_AMZ_COPY_SOURCE) {
                handle_copy_object(&hdrs, share, key).await
            } else {
                handle_put_object(req, &hdrs, share, key).await
            }
        }
        Method::DELETE => handle_delete_object(share, key).await,
        Method::HEAD => handle_head_object(&hdrs, share, key).await,
        _ => error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "MethodNotAllowed",
            "Method not allowed",
        ),
    };
    with_common_headers(resp, &request_id, &state.region)
}

// ── Path parsing ────────────────────────────────────────────────────────────

fn parse_path(path: &str) -> (&str, &str) {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        return ("", "");
    }
    match trimmed.find('/') {
        Some(pos) => (&trimmed[..pos], &trimmed[pos + 1..]),
        None => (trimmed, ""),
    }
}

// ── ListObjects V1/V2 ──────────────────────────────────────────────────────

async fn handle_list_objects(
    share: &ShareSession,
    bucket: &str,
    query: &str,
) -> Response<SpiceioBody> {
    let list_type = extract_query_param(query, "list-type").unwrap_or_default();
    let prefix = extract_query_param(query, "prefix").unwrap_or_default();
    let delimiter = extract_query_param(query, "delimiter");
    let max_keys: usize = extract_query_param(query, "max-keys")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);
    let marker = extract_query_param(query, "marker").unwrap_or_default();
    let start_after = extract_query_param(query, "start-after").unwrap_or_default();
    let continuation_token = extract_query_param(query, "continuation-token");
    let encoding_type = extract_query_param(query, "encoding-type");
    let fetch_owner = extract_query_param(query, "fetch-owner")
        .map(|s| s == "true")
        .unwrap_or(false);

    let result = share.list_objects(&prefix, delimiter.as_deref()).await;

    let skip_marker = if list_type == "2" {
        continuation_token.as_deref().unwrap_or(&start_after)
    } else {
        &marker
    };

    match result {
        Ok((mut objects, common_prefixes)) => {
            // Apply marker/start-after/continuation-token filtering
            if !skip_marker.is_empty() {
                objects.retain(|o| o.key.as_str() > skip_marker);
            }

            let truncated = objects.len() > max_keys;
            let display_objects = if truncated {
                &objects[..max_keys]
            } else {
                &objects
            };

            let next_marker = if truncated {
                display_objects.last().map(|o| o.key.clone())
            } else {
                None
            };

            let mut w = XmlWriter::new();
            w.declaration();

            if list_type == "2" {
                // ListObjectsV2
                w.open_ns("ListBucketResult", S3_XMLNS);
                w.element("Name", bucket);
                w.element("Prefix", &prefix);
                if let Some(d) = &delimiter {
                    w.element("Delimiter", d);
                }
                w.element("MaxKeys", &max_keys.to_string());
                if let Some(et) = &encoding_type {
                    w.element("EncodingType", et);
                }
                w.element("KeyCount", &display_objects.len().to_string());
                w.element("IsTruncated", if truncated { "true" } else { "false" });
                if let Some(ct) = &continuation_token {
                    w.element("ContinuationToken", ct);
                }
                if let Some(ref nm) = next_marker {
                    w.element("NextContinuationToken", nm);
                }
                if !start_after.is_empty() {
                    w.element("StartAfter", &start_after);
                }

                for obj in display_objects {
                    w.open("Contents");
                    w.element("Key", &obj.key);
                    w.element("LastModified", &xml::epoch_to_iso8601(obj.last_modified));
                    w.element("ETag", &format!("\"{}\"", obj.etag));
                    w.element("Size", &obj.size.to_string());
                    w.element("StorageClass", "STANDARD");
                    if fetch_owner {
                        w.open("Owner");
                        w.element("ID", "spiceio");
                        w.element("DisplayName", "spiceio");
                        w.close("Owner");
                    }
                    w.close("Contents");
                }
            } else {
                // ListObjectsV1
                w.open_ns("ListBucketResult", S3_XMLNS);
                w.element("Name", bucket);
                w.element("Prefix", &prefix);
                if !marker.is_empty() {
                    w.element("Marker", &marker);
                }
                if let Some(d) = &delimiter {
                    w.element("Delimiter", d);
                }
                w.element("MaxKeys", &max_keys.to_string());
                if let Some(et) = &encoding_type {
                    w.element("EncodingType", et);
                }
                w.element("IsTruncated", if truncated { "true" } else { "false" });
                if let Some(ref nm) = next_marker {
                    w.element("NextMarker", nm);
                }

                for obj in display_objects {
                    w.open("Contents");
                    w.element("Key", &obj.key);
                    w.element("LastModified", &xml::epoch_to_iso8601(obj.last_modified));
                    w.element("ETag", &format!("\"{}\"", obj.etag));
                    w.element("Size", &obj.size.to_string());
                    w.open("Owner");
                    w.element("ID", "spiceio");
                    w.element("DisplayName", "spiceio");
                    w.close("Owner");
                    w.element("StorageClass", "STANDARD");
                    w.close("Contents");
                }
            }

            for cp in &common_prefixes {
                w.open("CommonPrefixes");
                w.element("Prefix", cp);
                w.close("CommonPrefixes");
            }
            w.close("ListBucketResult");
            xml_response(StatusCode::OK, w.finish())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut w = XmlWriter::new();
            w.declaration();
            w.open_ns("ListBucketResult", S3_XMLNS);
            w.element("Name", bucket);
            w.element("Prefix", &prefix);
            w.element("MaxKeys", &max_keys.to_string());
            w.element("KeyCount", "0");
            w.element("IsTruncated", "false");
            w.close("ListBucketResult");
            xml_response(StatusCode::OK, w.finish())
        }
        Err(e) => io_to_s3_error(&e),
    }
}

// ── GetObject (streaming, with Range + Conditional) ─────────────────────────

async fn handle_get_object(
    hdrs: &http::HeaderMap,
    share: &ShareSession,
    key: &str,
) -> Response<SpiceioBody> {
    let range_header = get_header(hdrs, "range").map(String::from);
    let if_match = get_header(hdrs, IF_MATCH).map(String::from);
    let if_none_match = get_header(hdrs, IF_NONE_MATCH).map(String::from);
    let if_modified_since = get_header(hdrs, IF_MODIFIED_SINCE).map(String::from);
    let if_unmodified_since = get_header(hdrs, IF_UNMODIFIED_SINCE).map(String::from);

    // ── Fast path: compound Create+Read+Close for small files ───────
    // Tries to read the entire file in one SMB round trip. Falls back to
    // streaming for large files or range requests.
    let max_read = share.max_read_size();
    let no_range = range_header.is_none();

    if no_range {
        let result = share.get_object_compound(key, max_read).await;
        match result {
            Ok((meta, data)) if meta.size <= max_read as u64 => {
                let etag = format!("\"{}\"", meta.etag);

                if let Some(ref im) = if_match
                    && !etag_matches(im, &etag)
                {
                    return error_response(
                        StatusCode::PRECONDITION_FAILED,
                        "PreconditionFailed",
                        "At least one of the preconditions you specified did not hold.",
                    );
                }
                if let Some(ref inm) = if_none_match
                    && etag_matches(inm, &etag)
                {
                    return Response::builder()
                        .status(StatusCode::NOT_MODIFIED)
                        .header("ETag", &etag)
                        .body(SpiceioBody::empty())
                        .unwrap();
                }
                if let Some(ref ims) = if_modified_since
                    && let Some(since) = parse_http_date(ims)
                    && meta.last_modified <= since
                {
                    return Response::builder()
                        .status(StatusCode::NOT_MODIFIED)
                        .header("ETag", &etag)
                        .body(SpiceioBody::empty())
                        .unwrap();
                }
                if let Some(ref ius) = if_unmodified_since
                    && let Some(since) = parse_http_date(ius)
                    && meta.last_modified > since
                {
                    return error_response(
                        StatusCode::PRECONDITION_FAILED,
                        "PreconditionFailed",
                        "At least one of the preconditions you specified did not hold.",
                    );
                }

                let last_modified = xml::epoch_to_http_date(meta.last_modified);
                return Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", &meta.content_type)
                    .header("Content-Length", data.len().to_string())
                    .header("ETag", &etag)
                    .header("Last-Modified", last_modified)
                    .header("Accept-Ranges", "bytes")
                    .body(SpiceioBody::full(data))
                    .unwrap();
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return error_response(
                    StatusCode::NOT_FOUND,
                    "NoSuchKey",
                    "The specified key does not exist.",
                );
            }
            Err(e) => return io_to_s3_error(&e),
            _ => {} // Large file — fall through to streaming
        }
    }

    // ── Streaming path for large files and range requests ─────────
    let handle = match share.open_read(key).await {
        Ok(h) => h,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return error_response(
                StatusCode::NOT_FOUND,
                "NoSuchKey",
                "The specified key does not exist.",
            );
        }
        Err(e) => return io_to_s3_error(&e),
    };

    let meta = &handle.meta;
    let etag = format!("\"{}\"", meta.etag);

    // Conditional: If-Match
    if let Some(ref im) = if_match
        && !etag_matches(im, &etag)
    {
        let _ = handle.close().await;
        return error_response(
            StatusCode::PRECONDITION_FAILED,
            "PreconditionFailed",
            "At least one of the preconditions you specified did not hold.",
        );
    }

    // Conditional: If-None-Match → 304
    if let Some(ref inm) = if_none_match
        && etag_matches(inm, &etag)
    {
        let _ = handle.close().await;
        return Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header("ETag", &etag)
            .body(SpiceioBody::empty())
            .unwrap();
    }

    // Conditional: If-Modified-Since → 304
    if let Some(ref ims) = if_modified_since
        && let Some(since) = parse_http_date(ims)
        && meta.last_modified <= since
    {
        let _ = handle.close().await;
        return Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header("ETag", &etag)
            .body(SpiceioBody::empty())
            .unwrap();
    }

    // Conditional: If-Unmodified-Since
    if let Some(ref ius) = if_unmodified_since
        && let Some(since) = parse_http_date(ius)
        && meta.last_modified > since
    {
        let _ = handle.close().await;
        return error_response(
            StatusCode::PRECONDITION_FAILED,
            "PreconditionFailed",
            "At least one of the preconditions you specified did not hold.",
        );
    }

    let last_modified = xml::epoch_to_http_date(meta.last_modified);
    let content_type = meta.content_type.clone();
    let file_size = handle.file_size;

    // Determine read range
    let (start, end, is_range) = if let Some(ref range_str) = range_header {
        if let Some(range) = parse_range(range_str) {
            let (s, e) = range.resolve(file_size);
            (s, e, true)
        } else {
            (0, file_size.saturating_sub(1), false)
        }
    } else {
        (0, file_size.saturating_sub(1), false)
    };

    let content_length = end - start + 1;

    // Build response with streaming body
    let (body, tx) = SpiceioBody::channel(4);
    let chunk_size = handle.max_chunk;

    // Spawn background task to stream SMB reads into the channel
    tokio::spawn(async move {
        let mut offset = start;
        let stream_end = end + 1;
        while offset < stream_end {
            let to_read = ((stream_end - offset) as u32).min(chunk_size);
            match handle.read_chunk(offset, to_read).await {
                Ok(chunk) if chunk.is_empty() => break,
                Ok(chunk) => {
                    offset += chunk.len() as u64;
                    if tx.send(chunk).await.is_err() {
                        break; // Client disconnected
                    }
                }
                Err(_) => break,
            }
        }
        let _ = handle.close().await;
    });

    if is_range {
        let content_range = format!("bytes {start}-{end}/{file_size}");
        Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header("Content-Type", &content_type)
            .header("Content-Length", content_length.to_string())
            .header("Content-Range", content_range)
            .header("ETag", &etag)
            .header("Last-Modified", last_modified)
            .header("Accept-Ranges", "bytes")
            .body(body)
            .unwrap()
    } else {
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", &content_type)
            .header("Content-Length", content_length.to_string())
            .header("ETag", &etag)
            .header("Last-Modified", last_modified)
            .header("Accept-Ranges", "bytes")
            .body(body)
            .unwrap()
    }
}

// ── PutObject (streaming, with conditional-write via If-None-Match) ─────────

async fn handle_put_object(
    req: Request<Incoming>,
    hdrs: &http::HeaderMap,
    share: &ShareSession,
    key: &str,
) -> Response<SpiceioBody> {
    let if_none_match = get_header(hdrs, IF_NONE_MATCH).map(String::from);
    let content_type = get_header(hdrs, "content-type").map(String::from);
    // Conditional write: If-None-Match: * means "only if not exists"
    if let Some(ref inm) = if_none_match
        && inm.trim() == "*"
    {
        // Check existence first
        if share.head_object(key).await.is_ok() {
            return error_response(
                StatusCode::PRECONDITION_FAILED,
                "PreconditionFailed",
                "At least one of the preconditions you specified did not hold.",
            );
        }
    }

    // ── Fast path: collect small bodies and use compound write ──────
    let content_length: Option<u64> =
        get_header(hdrs, "content-length").and_then(|s| s.parse().ok());
    let max_write = share.max_write_size() as u64;

    if let Some(cl) = content_length
        && cl <= max_write
    {
        // Collect the (small) body
        match BodyExt::collect(req.into_body()).await {
            Ok(collected) => {
                let data = collected.to_bytes();
                match share.put_object(key, &data).await {
                    Ok(meta) => {
                        let mut builder = Response::builder()
                            .status(StatusCode::OK)
                            .header("ETag", format!("\"{}\"", meta.etag));
                        if let Some(ct) = content_type {
                            builder = builder.header("Content-Type", ct);
                        }
                        return builder.body(SpiceioBody::empty()).unwrap();
                    }
                    Err(e) => return io_to_s3_error(&e),
                }
            }
            Err(e) => {
                return io_to_s3_error(&io::Error::other(format!("body read error: {e}")));
            }
        }
    }

    // ── Streaming path for large or unknown-size bodies ──────────
    let handle = match share.open_write(key).await {
        Ok(h) => h,
        Err(e) => return io_to_s3_error(&e),
    };

    let mut offset = 0u64;
    let mut body = req.into_body();
    let mut total_size = 0u64;
    let mut write_err = None;

    while let Some(frame) = body.frame().await {
        match frame {
            Ok(frame) => {
                if let Ok(data) = frame.into_data()
                    && !data.is_empty()
                {
                    let max_w = handle.max_chunk as usize;
                    for chunk in data.chunks(max_w) {
                        match handle.write_chunk(offset, chunk).await {
                            Ok(written) => {
                                offset += written as u64;
                                total_size += written as u64;
                            }
                            Err(e) => {
                                write_err = Some(e);
                                break;
                            }
                        }
                    }
                    if write_err.is_some() {
                        break;
                    }
                }
            }
            Err(e) => {
                let _ = handle.close().await;
                return io_to_s3_error(&io::Error::other(format!("body read error: {e}")));
            }
        }
    }

    let _ = handle.close().await;

    if let Some(e) = write_err {
        return io_to_s3_error(&e);
    }

    let etag = match share.head_object(key).await {
        Ok(meta) => meta.etag,
        Err(_) => format!("{:016x}", total_size),
    };
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("ETag", format!("\"{etag}\""));
    if let Some(ct) = content_type {
        builder = builder.header("Content-Type", ct);
    }
    builder.body(SpiceioBody::empty()).unwrap()
}

// ── CopyObject ──────────────────────────────────────────────────────────────

async fn handle_copy_object(
    hdrs: &http::HeaderMap,
    share: &ShareSession,
    dest_key: &str,
) -> Response<SpiceioBody> {
    let copy_source = match get_header(hdrs, X_AMZ_COPY_SOURCE) {
        Some(s) => s.to_string(),
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "Missing x-amz-copy-source",
            );
        }
    };

    // Parse source: /bucket/key or bucket/key
    let src_key = copy_source.trim_start_matches('/');
    let src_key = match src_key.find('/') {
        Some(pos) => &src_key[pos + 1..],
        None => src_key,
    };
    let src_key = percent_encoding::percent_decode_str(src_key)
        .decode_utf8_lossy()
        .into_owned();

    // Conditional copy headers
    let if_match = get_header(hdrs, X_AMZ_COPY_SOURCE_IF_MATCH).map(String::from);
    let if_none_match = get_header(hdrs, X_AMZ_COPY_SOURCE_IF_NONE_MATCH).map(String::from);
    let if_modified_since = get_header(hdrs, X_AMZ_COPY_SOURCE_IF_MODIFIED_SINCE).map(String::from);
    let if_unmodified_since =
        get_header(hdrs, X_AMZ_COPY_SOURCE_IF_UNMODIFIED_SINCE).map(String::from);

    // Check source metadata for conditionals
    let src_meta = match share.head_object(&src_key).await {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return error_response(
                StatusCode::NOT_FOUND,
                "NoSuchKey",
                "The specified source key does not exist.",
            );
        }
        Err(e) => return io_to_s3_error(&e),
    };

    let etag = format!("\"{}\"", src_meta.etag);

    if let Some(ref im) = if_match
        && !etag_matches(im, &etag)
    {
        return error_response(StatusCode::PRECONDITION_FAILED, "PreconditionFailed", "");
    }
    if let Some(ref inm) = if_none_match
        && etag_matches(inm, &etag)
    {
        return error_response(StatusCode::PRECONDITION_FAILED, "PreconditionFailed", "");
    }
    if let Some(ref ims) = if_modified_since
        && let Some(since) = parse_http_date(ims)
        && src_meta.last_modified <= since
    {
        return error_response(StatusCode::PRECONDITION_FAILED, "PreconditionFailed", "");
    }
    if let Some(ref ius) = if_unmodified_since
        && let Some(since) = parse_http_date(ius)
        && src_meta.last_modified > since
    {
        return error_response(StatusCode::PRECONDITION_FAILED, "PreconditionFailed", "");
    }

    match share.copy_object(&src_key, dest_key).await {
        Ok(meta) => {
            let mut w = XmlWriter::new();
            w.declaration();
            w.open("CopyObjectResult");
            w.element("LastModified", &xml::epoch_to_iso8601(meta.last_modified));
            w.element("ETag", &format!("\"{}\"", meta.etag));
            w.close("CopyObjectResult");
            xml_response(StatusCode::OK, w.finish())
        }
        Err(e) => io_to_s3_error(&e),
    }
}

// ── DeleteObject ────────────────────────────────────────────────────────────

async fn handle_delete_object(share: &ShareSession, key: &str) -> Response<SpiceioBody> {
    match share.delete_object(key).await {
        Ok(()) | Err(_) => {
            // S3 returns 204 even if not found
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(SpiceioBody::empty())
                .unwrap()
        }
    }
}

// ── HeadObject (with conditional) ───────────────────────────────────────────

async fn handle_head_object(
    hdrs: &http::HeaderMap,
    share: &ShareSession,
    key: &str,
) -> Response<SpiceioBody> {
    let if_match = get_header(hdrs, IF_MATCH).map(String::from);
    let if_none_match = get_header(hdrs, IF_NONE_MATCH).map(String::from);
    let if_modified_since = get_header(hdrs, IF_MODIFIED_SINCE).map(String::from);
    let if_unmodified_since = get_header(hdrs, IF_UNMODIFIED_SINCE).map(String::from);

    match share.head_object(key).await {
        Ok(meta) => {
            let etag = format!("\"{}\"", meta.etag);

            if let Some(ref im) = if_match
                && !etag_matches(im, &etag)
            {
                return error_response(StatusCode::PRECONDITION_FAILED, "PreconditionFailed", "");
            }
            if let Some(ref inm) = if_none_match
                && etag_matches(inm, &etag)
            {
                return Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .header("ETag", &etag)
                    .body(SpiceioBody::empty())
                    .unwrap();
            }
            if let Some(ref ims) = if_modified_since
                && let Some(since) = parse_http_date(ims)
                && meta.last_modified <= since
            {
                return Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .header("ETag", &etag)
                    .body(SpiceioBody::empty())
                    .unwrap();
            }
            if let Some(ref ius) = if_unmodified_since
                && let Some(since) = parse_http_date(ius)
                && meta.last_modified > since
            {
                return error_response(StatusCode::PRECONDITION_FAILED, "PreconditionFailed", "");
            }

            let last_modified = xml::epoch_to_http_date(meta.last_modified);
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", &meta.content_type)
                .header("Content-Length", meta.size.to_string())
                .header("ETag", &etag)
                .header("Last-Modified", last_modified)
                .header("Accept-Ranges", "bytes")
                .body(SpiceioBody::empty())
                .unwrap()
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(SpiceioBody::empty())
            .unwrap(),
        Err(e) => io_to_s3_error(&e),
    }
}

// ── Multi-object Delete ─────────────────────────────────────────────────────

async fn handle_delete_objects(body: Bytes, share: &ShareSession) -> Response<SpiceioBody> {
    let body_str = String::from_utf8_lossy(&body);

    let keys: Vec<String> = xml::extract_sections(&body_str, "<Object>", "</Object>")
        .iter()
        .filter_map(|section| xml::extract_element(section, "Key"))
        .map(|s| s.to_string())
        .collect();

    let quiet = xml::extract_element(&body_str, "Quiet")
        .map(|s| s == "true")
        .unwrap_or(false);

    let mut w = XmlWriter::new();
    w.declaration();
    w.open_ns("DeleteResult", S3_XMLNS);

    for key in &keys {
        match share.delete_object(key).await {
            Ok(()) => {
                if !quiet {
                    w.open("Deleted");
                    w.element("Key", key);
                    w.close("Deleted");
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if !quiet {
                    w.open("Deleted");
                    w.element("Key", key);
                    w.close("Deleted");
                }
            }
            Err(e) => {
                w.open("Error");
                w.element("Key", key);
                w.element("Code", "InternalError");
                w.element("Message", &e.to_string());
                w.close("Error");
            }
        }
    }

    w.close("DeleteResult");
    xml_response(StatusCode::OK, w.finish())
}

// ── Multipart Upload ────────────────────────────────────────────────────────

async fn handle_create_multipart_upload(
    hdrs: &http::HeaderMap,
    state: &AppState,
    key: &str,
) -> Response<SpiceioBody> {
    let _content_type = get_header(hdrs, "content-type");
    let upload_id = state.multipart.create(key).await;

    // Create the temp directory on the share
    let temp_dir = MultipartStore::temp_dir(&upload_id);
    let _ = state
        .share
        .write_temp(&format!("{}\\marker", temp_dir), b"")
        .await;

    let mut w = XmlWriter::new();
    w.declaration();
    w.open_ns("InitiateMultipartUploadResult", S3_XMLNS);
    w.element("Bucket", &state.bucket);
    w.element("Key", key);
    w.element("UploadId", &upload_id);
    w.close("InitiateMultipartUploadResult");
    xml_response(StatusCode::OK, w.finish())
}

async fn handle_upload_part(
    req: Request<Incoming>,
    state: &AppState,
    _key: &str,
    upload_id: &str,
    part_number: u32,
) -> Response<SpiceioBody> {
    if part_number == 0 || part_number > 10000 {
        return error_response(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "Part number must be 1-10000",
        );
    }

    let body = collect_body(req).await;
    let etag = crate::crypto::hex_encode(&crate::crypto::sha256(&body));
    let temp_path = MultipartStore::temp_part_path(upload_id, part_number);

    if let Err(e) = state.share.write_temp(&temp_path, &body).await {
        return io_to_s3_error(&e);
    }

    state
        .multipart
        .put_part(
            upload_id,
            part_number,
            body.len() as u64,
            etag.clone(),
            temp_path,
        )
        .await;

    Response::builder()
        .status(StatusCode::OK)
        .header("ETag", format!("\"{}\"", etag))
        .body(SpiceioBody::empty())
        .unwrap()
}

async fn handle_complete_multipart_upload(
    body_bytes: Bytes,
    state: &AppState,
    key: &str,
    upload_id: &str,
) -> Response<SpiceioBody> {
    let upload = match state.multipart.complete(upload_id).await {
        Some(u) => u,
        None => {
            return error_response(
                StatusCode::NOT_FOUND,
                "NoSuchUpload",
                "The specified upload does not exist.",
            );
        }
    };

    // Parse the completion XML to get ordered parts
    let body_str = String::from_utf8_lossy(&body_bytes);
    let part_numbers: Vec<u32> = xml::extract_sections(&body_str, "<Part>", "</Part>")
        .iter()
        .filter_map(|section| {
            xml::extract_element(section, "PartNumber").and_then(|s| s.parse().ok())
        })
        .collect();

    // Concatenate parts in order and write the final object
    let mut final_data = Vec::new();
    for pn in &part_numbers {
        if let Some(part) = upload.parts.get(pn) {
            match state.share.read_temp(&part.temp_path).await {
                Ok(data) => final_data.extend_from_slice(&data),
                Err(e) => {
                    // Re-register the upload since we consumed it
                    return io_to_s3_error(&e);
                }
            }
        }
    }

    // Write the assembled object
    let meta = match state.share.put_object(key, &final_data).await {
        Ok(m) => m,
        Err(e) => return io_to_s3_error(&e),
    };

    // Clean up temp files (best effort)
    for part in upload.parts.values() {
        state.share.delete_temp(&part.temp_path).await;
    }
    let marker_path = format!("{}\\marker", MultipartStore::temp_dir(upload_id));
    state.share.delete_temp(&marker_path).await;
    state
        .share
        .remove_dir(&MultipartStore::temp_dir(upload_id))
        .await;

    let mut w = XmlWriter::new();
    w.declaration();
    w.open_ns("CompleteMultipartUploadResult", S3_XMLNS);
    w.element("Bucket", &state.bucket);
    w.element("Key", key);
    w.element("ETag", &format!("\"{}\"", meta.etag));
    w.close("CompleteMultipartUploadResult");
    xml_response(StatusCode::OK, w.finish())
}

async fn handle_abort_multipart_upload(
    state: &AppState,
    _key: &str,
    upload_id: &str,
) -> Response<SpiceioBody> {
    let upload = match state.multipart.abort(upload_id).await {
        Some(u) => u,
        None => return error_response(StatusCode::NOT_FOUND, "NoSuchUpload", ""),
    };

    // Clean up temp files
    for part in upload.parts.values() {
        state.share.delete_temp(&part.temp_path).await;
    }
    let marker_path = format!("{}\\marker", MultipartStore::temp_dir(upload_id));
    state.share.delete_temp(&marker_path).await;
    state
        .share
        .remove_dir(&MultipartStore::temp_dir(upload_id))
        .await;

    ok_no_content()
}

async fn handle_list_parts(state: &AppState, key: &str, upload_id: &str) -> Response<SpiceioBody> {
    let upload = match state.multipart.get(upload_id).await {
        Some(u) => u,
        None => return error_response(StatusCode::NOT_FOUND, "NoSuchUpload", ""),
    };

    let mut parts: Vec<_> = upload.parts.values().collect();
    parts.sort_by_key(|p| p.part_number);

    let mut w = XmlWriter::new();
    w.declaration();
    w.open_ns("ListPartsResult", S3_XMLNS);
    w.element("Bucket", &state.bucket);
    w.element("Key", key);
    w.element("UploadId", upload_id);
    w.open("Initiator");
    w.element("ID", "spiceio");
    w.element("DisplayName", "spiceio");
    w.close("Initiator");
    w.open("Owner");
    w.element("ID", "spiceio");
    w.element("DisplayName", "spiceio");
    w.close("Owner");
    w.element("StorageClass", "STANDARD");
    w.element("PartNumberMarker", "0");
    w.element(
        "NextPartNumberMarker",
        &parts
            .last()
            .map(|p| p.part_number.to_string())
            .unwrap_or_default(),
    );
    w.element("MaxParts", "1000");
    w.element("IsTruncated", "false");

    for part in &parts {
        w.open("Part");
        w.element("PartNumber", &part.part_number.to_string());
        w.element("LastModified", &xml::epoch_to_iso8601(upload.initiated));
        w.element("ETag", &format!("\"{}\"", part.etag));
        w.element("Size", &part.size.to_string());
        w.close("Part");
    }

    w.close("ListPartsResult");
    xml_response(StatusCode::OK, w.finish())
}

async fn handle_list_multipart_uploads(state: &AppState, query: &str) -> Response<SpiceioBody> {
    let prefix = extract_query_param(query, "prefix");
    let uploads = state.multipart.list(prefix.as_deref()).await;

    let mut w = XmlWriter::new();
    w.declaration();
    w.open_ns("ListMultipartUploadsResult", S3_XMLNS);
    w.element("Bucket", &state.bucket);
    if let Some(ref p) = prefix {
        w.element("Prefix", p);
    }
    w.element("MaxUploads", "1000");
    w.element("IsTruncated", "false");

    for upload in &uploads {
        w.open("Upload");
        w.element("Key", &upload.key);
        w.element("UploadId", &upload.upload_id);
        w.open("Initiator");
        w.element("ID", "spiceio");
        w.element("DisplayName", "spiceio");
        w.close("Initiator");
        w.open("Owner");
        w.element("ID", "spiceio");
        w.element("DisplayName", "spiceio");
        w.close("Owner");
        w.element("StorageClass", "STANDARD");
        w.element("Initiated", &xml::epoch_to_iso8601(upload.initiated));
        w.close("Upload");
    }

    w.close("ListMultipartUploadsResult");
    xml_response(StatusCode::OK, w.finish())
}

// ── Bucket-level stubs ──────────────────────────────────────────────────────

fn handle_get_bucket_location(region: &str) -> Response<SpiceioBody> {
    let mut w = XmlWriter::new();
    w.declaration();
    w.open_ns("LocationConstraint", S3_XMLNS);
    // AWS returns empty for us-east-1, the region name for others
    if region != "us-east-1" {
        w.buf_push_str(region);
    }
    w.close("LocationConstraint");
    xml_response(StatusCode::OK, w.finish())
}

fn head_bucket_response(region: &str) -> Response<SpiceioBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(X_AMZ_BUCKET_REGION, region)
        .body(SpiceioBody::empty())
        .unwrap()
}

fn handle_get_bucket_versioning() -> Response<SpiceioBody> {
    let mut w = XmlWriter::new();
    w.declaration();
    w.open_ns("VersioningConfiguration", S3_XMLNS);
    // Empty = versioning never enabled
    w.close("VersioningConfiguration");
    xml_response(StatusCode::OK, w.finish())
}

fn handle_get_bucket_acl() -> Response<SpiceioBody> {
    // Return a minimal private ACL
    let mut w = XmlWriter::new();
    w.declaration();
    w.open_ns("AccessControlPolicy", S3_XMLNS);
    w.open("Owner");
    w.element("ID", "spiceio");
    w.element("DisplayName", "spiceio");
    w.close("Owner");
    w.open("AccessControlList");
    w.open("Grant");
    w.open("Grantee");
    w.element("ID", "spiceio");
    w.element("DisplayName", "spiceio");
    w.close("Grantee");
    w.element("Permission", "FULL_CONTROL");
    w.close("Grant");
    w.close("AccessControlList");
    w.close("AccessControlPolicy");
    xml_response(StatusCode::OK, w.finish())
}

fn handle_get_bucket_tagging() -> Response<SpiceioBody> {
    let mut w = XmlWriter::new();
    w.declaration();
    w.open_ns("Tagging", S3_XMLNS);
    w.open("TagSet");
    w.close("TagSet");
    w.close("Tagging");
    xml_response(StatusCode::OK, w.finish())
}

fn handle_get_bucket_cors() -> Response<SpiceioBody> {
    // No CORS configuration
    error_response(
        StatusCode::NOT_FOUND,
        "NoSuchCORSConfiguration",
        "The CORS configuration does not exist",
    )
}

fn handle_get_bucket_lifecycle() -> Response<SpiceioBody> {
    error_response(StatusCode::NOT_FOUND, "NoSuchLifecycleConfiguration", "")
}

fn handle_get_bucket_policy() -> Response<SpiceioBody> {
    error_response(
        StatusCode::NOT_FOUND,
        "NoSuchBucketPolicy",
        "The bucket policy does not exist",
    )
}

fn handle_get_bucket_encryption() -> Response<SpiceioBody> {
    let mut w = XmlWriter::new();
    w.declaration();
    w.open_ns("ServerSideEncryptionConfiguration", S3_XMLNS);
    w.open("Rule");
    w.open("ApplyServerSideEncryptionByDefault");
    w.element("SSEAlgorithm", "AES256");
    w.close("ApplyServerSideEncryptionByDefault");
    w.element("BucketKeyEnabled", "false");
    w.close("Rule");
    w.close("ServerSideEncryptionConfiguration");
    xml_response(StatusCode::OK, w.finish())
}

fn handle_get_object_acl() -> Response<SpiceioBody> {
    handle_get_bucket_acl() // Same structure
}

fn handle_get_object_tagging() -> Response<SpiceioBody> {
    let mut w = XmlWriter::new();
    w.declaration();
    w.open_ns("Tagging", S3_XMLNS);
    w.open("TagSet");
    w.close("TagSet");
    w.close("Tagging");
    xml_response(StatusCode::OK, w.finish())
}

// ── ListBuckets ─────────────────────────────────────────────────────────────

fn list_buckets_response(bucket: &str) -> Response<SpiceioBody> {
    let mut w = XmlWriter::new();
    w.declaration();
    w.open_ns("ListAllMyBucketsResult", S3_XMLNS);
    w.open("Owner");
    w.element("ID", "spiceio");
    w.element("DisplayName", "spiceio");
    w.close("Owner");
    w.open("Buckets");
    w.open("Bucket");
    w.element("Name", bucket);
    w.element("CreationDate", "2024-01-01T00:00:00.000Z");
    w.close("Bucket");
    w.close("Buckets");
    w.close("ListAllMyBucketsResult");
    xml_response(StatusCode::OK, w.finish())
}

// ── CORS preflight ──────────────────────────────────────────────────────────

fn cors_preflight(request_id: &str, region: &str) -> Response<SpiceioBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, HEAD")
        .header("Access-Control-Allow-Headers", "*, Authorization, Content-Type, x-amz-content-sha256, x-amz-date, x-amz-security-token, x-amz-user-agent")
        .header("Access-Control-Expose-Headers", "ETag, x-amz-request-id, x-amz-id-2, x-amz-version-id, x-amz-delete-marker")
        .header("Access-Control-Max-Age", "86400")
        .header(X_AMZ_REQUEST_ID, request_id)
        .header(X_AMZ_BUCKET_REGION, region)
        .body(SpiceioBody::empty())
        .unwrap()
}

// ── Response helpers ────────────────────────────────────────────────────────

fn with_common_headers(
    mut resp: Response<SpiceioBody>,
    request_id: &str,
    region: &str,
) -> Response<SpiceioBody> {
    let headers = resp.headers_mut();
    if !headers.contains_key(X_AMZ_REQUEST_ID) {
        headers.insert(X_AMZ_REQUEST_ID, request_id.parse().unwrap());
    }
    headers.insert(X_AMZ_ID_2, request_id.parse().unwrap());
    headers.insert(X_AMZ_BUCKET_REGION, region.parse().unwrap());
    headers.insert("Server", "spiceio".parse().unwrap());
    // CORS allow
    if !headers.contains_key("access-control-allow-origin") {
        headers.insert("Access-Control-Allow-Origin", "*".parse().unwrap());
        headers.insert(
            "Access-Control-Expose-Headers",
            "ETag, x-amz-request-id, x-amz-id-2, x-amz-version-id, x-amz-delete-marker, Content-Length, Content-Type"
                .parse()
                .unwrap(),
        );
    }
    resp
}

fn xml_response(status: StatusCode, body: String) -> Response<SpiceioBody> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/xml")
        .header("Content-Length", body.len().to_string())
        .body(SpiceioBody::full(Bytes::from(body)))
        .unwrap()
}

fn error_response(status: StatusCode, code: &str, message: &str) -> Response<SpiceioBody> {
    let mut w = XmlWriter::new();
    w.declaration();
    w.open("Error");
    w.element("Code", code);
    w.element("Message", message);
    w.element("RequestId", "");
    w.close("Error");
    xml_response(status, w.finish())
}

fn ok_empty() -> Response<SpiceioBody> {
    Response::builder()
        .status(StatusCode::OK)
        .body(SpiceioBody::empty())
        .unwrap()
}

fn ok_no_content() -> Response<SpiceioBody> {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(SpiceioBody::empty())
        .unwrap()
}

fn io_to_s3_error(e: &io::Error) -> Response<SpiceioBody> {
    match e.kind() {
        io::ErrorKind::NotFound => error_response(
            StatusCode::NOT_FOUND,
            "NoSuchKey",
            "The specified key does not exist.",
        ),
        io::ErrorKind::PermissionDenied => {
            error_response(StatusCode::FORBIDDEN, "AccessDenied", "Access Denied")
        }
        _ => {
            eprintln!("[spiceio] error: {e}");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &e.to_string(),
            )
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn extract_query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == key
        {
            return Some(percent_decode(v));
        }
    }
    None
}

fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

/// Check if an ETag matches a condition value (handles *, "etag", etag forms).
fn etag_matches(condition: &str, etag: &str) -> bool {
    let condition = condition.trim();
    if condition == "*" {
        return true;
    }
    // May be comma-separated
    for part in condition.split(',') {
        let part = part.trim().trim_matches('"');
        let etag_inner = etag.trim_matches('"');
        if part == etag_inner {
            return true;
        }
    }
    false
}

/// Collect an `Incoming` body into `Bytes`, for operations that need the full
/// payload (multi-delete, multipart complete, upload-part).
async fn collect_body(req: Request<Incoming>) -> Bytes {
    match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            eprintln!("[spiceio] body collect error: {e}");
            Bytes::new()
        }
    }
}
