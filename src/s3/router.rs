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
    // Percent-decode the key so encoded characters (spaces, Unicode, `%`, …)
    // map to the real object name instead of a literal `%XX` filename.
    let (req_bucket, raw_key) = parse_path(&path);
    let key_decoded = percent_decode(raw_key);
    let key: &str = &key_decoded;

    // Service-level operations (no bucket)
    if req_bucket.is_empty() {
        match method {
            Method::GET | Method::HEAD => {
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

    // Reject keys that could escape the share via `..` path traversal.
    if !key.is_empty() && key_has_traversal(key) {
        return with_common_headers(
            error_response(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "Object key contains invalid path segments",
            ),
            &request_id,
            &state.region,
        );
    }

    // ── Bucket-level operations (no key) ────────────────────────────────
    if key.is_empty() {
        let resp = match method {
            Method::GET | Method::HEAD if has_query_flag(&query, "location") => {
                handle_get_bucket_location(&state.region)
            }
            Method::GET if has_query_flag(&query, "versioning") => handle_get_bucket_versioning(),
            Method::GET if has_query_flag(&query, "acl") => handle_get_bucket_acl(),
            Method::PUT if has_query_flag(&query, "acl") => ok_empty(),
            Method::GET if has_query_flag(&query, "tagging") => handle_get_bucket_tagging(),
            Method::PUT if has_query_flag(&query, "tagging") => ok_empty(),
            Method::DELETE if has_query_flag(&query, "tagging") => ok_no_content(),
            Method::GET if has_query_flag(&query, "cors") => handle_get_bucket_cors(),
            Method::PUT if has_query_flag(&query, "cors") => ok_empty(),
            Method::DELETE if has_query_flag(&query, "cors") => ok_no_content(),
            Method::GET if has_query_flag(&query, "lifecycle") => handle_get_bucket_lifecycle(),
            Method::GET if has_query_flag(&query, "policy") => handle_get_bucket_policy(),
            Method::GET if has_query_flag(&query, "encryption") => handle_get_bucket_encryption(),
            Method::GET if has_query_flag(&query, "uploads") => {
                handle_list_multipart_uploads(state, &query).await
            }
            Method::POST if has_query_flag(&query, "delete") => match collect_body(req).await {
                Ok(body) => handle_delete_objects(body, share).await,
                Err(resp) => resp,
            },
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
        let resp = if has_query_flag(&query, "uploads") && !has_query_flag(&query, "uploadId") {
            handle_create_multipart_upload(&hdrs, state, key).await
        } else if let Some(upload_id) = extract_query_param(&query, "uploadId") {
            match collect_body(req).await {
                Ok(body) => handle_complete_multipart_upload(body, state, key, &upload_id).await,
                Err(resp) => resp,
            }
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
    if method == Method::PUT
        && has_query_flag(&query, "partNumber")
        && has_query_flag(&query, "uploadId")
    {
        let part_number: u32 = extract_query_param(&query, "partNumber")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let upload_id = extract_query_param(&query, "uploadId").unwrap_or_default();
        let resp = handle_upload_part(req, state, key, &upload_id, part_number).await;
        return with_common_headers(resp, &request_id, &state.region);
    }

    // Multipart: GET with ?uploadId=... (list parts)
    if method == Method::GET && has_query_flag(&query, "uploadId") {
        let upload_id = extract_query_param(&query, "uploadId").unwrap_or_default();
        let resp = handle_list_parts(state, key, &upload_id).await;
        return with_common_headers(resp, &request_id, &state.region);
    }

    // Multipart: DELETE with ?uploadId=... (abort)
    if method == Method::DELETE && has_query_flag(&query, "uploadId") {
        let upload_id = extract_query_param(&query, "uploadId").unwrap_or_default();
        let resp = handle_abort_multipart_upload(state, key, &upload_id).await;
        return with_common_headers(resp, &request_id, &state.region);
    }

    // Object ACL
    if has_query_flag(&query, "acl") {
        let resp = match method {
            Method::GET => handle_get_object_acl(),
            Method::PUT => ok_empty(),
            _ => error_response(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", ""),
        };
        return with_common_headers(resp, &request_id, &state.region);
    }

    // Object tagging
    if has_query_flag(&query, "tagging") {
        let resp = match method {
            Method::GET => handle_get_object_tagging(),
            Method::PUT => ok_empty(),
            Method::DELETE => ok_no_content(),
            _ => error_response(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", ""),
        };
        return with_common_headers(resp, &request_id, &state.region);
    }

    // Object legal-hold, retention, torrent — stubs
    if has_query_flag(&query, "legal-hold")
        || has_query_flag(&query, "retention")
        || has_query_flag(&query, "torrent")
    {
        let resp = match method {
            Method::GET | Method::PUT => ok_empty(),
            _ => error_response(StatusCode::NOT_IMPLEMENTED, "NotImplemented", ""),
        };
        return with_common_headers(resp, &request_id, &state.region);
    }

    // Object restore — stub
    if method == Method::POST && has_query_flag(&query, "restore") {
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
    if method == Method::POST && has_query_flag(&query, "select") {
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
    // S3 caps max-keys at 1000; honor any client value but never exceed it.
    let max_keys: usize = extract_query_param(query, "max-keys")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000)
        .min(1000);
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
        Ok((mut objects, mut common_prefixes)) => {
            // SMB QueryDirectory does not guarantee order, but S3 returns keys
            // (and common prefixes) lexicographically. Sort before any marker
            // filtering / truncation — otherwise paginating with a marker drops
            // or duplicates keys across pages.
            objects.sort_by(|a, b| a.key.cmp(&b.key));
            common_prefixes.sort();

            // Apply marker / start-after / continuation-token filtering.
            if !skip_marker.is_empty() {
                objects.retain(|o| o.key.as_str() > skip_marker);
                common_prefixes.retain(|p| p.as_str() > skip_marker);
            }

            // Merge keys + common prefixes into one lexicographic order and
            // truncate the combined set at max_keys (S3 counts both toward
            // max-keys and KeyCount). Track original indices so each group can
            // be emitted in order.
            let mut merged: Vec<(&str, bool, usize)> = Vec::new();
            for (i, o) in objects.iter().enumerate() {
                merged.push((o.key.as_str(), false, i));
            }
            for (i, p) in common_prefixes.iter().enumerate() {
                merged.push((p.as_str(), true, i));
            }
            merged.sort_by(|a, b| a.0.cmp(b.0));

            let total = merged.len();
            let truncated = total > max_keys;
            let shown = &merged[..total.min(max_keys)];
            let next_marker = if truncated {
                shown.last().map(|e| e.0.to_string())
            } else {
                None
            };
            let key_count = shown.len();
            let shown_obj_idx: Vec<usize> = shown.iter().filter(|e| !e.1).map(|e| e.2).collect();
            let shown_pref_idx: Vec<usize> = shown.iter().filter(|e| e.1).map(|e| e.2).collect();

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
                w.element("KeyCount", &key_count.to_string());
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

                for &oi in &shown_obj_idx {
                    let obj = &objects[oi];
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

                for &oi in &shown_obj_idx {
                    let obj = &objects[oi];
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

            for &pi in &shown_pref_idx {
                let cp = &common_prefixes[pi];
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

/// Compute the SMB-reads→HTTP-writes channel capacity for a streaming
/// GetObject given the SMB-negotiated chunk size.
///
/// Sized to hold one full SMB read pipeline batch (so back-to-back batches
/// can overlap) but capped by an 8 MiB per-request memory budget so a
/// configured `SPICEIO_SMB_MAX_IO` of 1 MiB doesn't blow up to 64 MiB of
/// buffering per concurrent stream.
///
/// Guards against `chunk_size = 0`: `handle.max_chunk` ultimately comes from
/// the SMB server's `max_read_size` in the negotiate response. If a server
/// (or a misconfiguration) yields 0, naive `BUDGET / chunk_size` would
/// divide-by-zero panic and crash the streaming task. We floor at 1 here.
fn stream_channel_capacity(chunk_size: u32) -> usize {
    const STREAM_CHANNEL_MAX_BYTES: usize = 8 * 1024 * 1024;
    let chunk_size_for_cap = (chunk_size as usize).max(1);
    (STREAM_CHANNEL_MAX_BYTES / chunk_size_for_cap).clamp(1, crate::smb::ops::READ_PIPELINE_DEPTH)
}

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
    let max_read = share.compound_max_read_size();
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
                if if_none_match.is_none()
                    && let Some(ref ims) = if_modified_since
                    && let Some(since) = parse_http_date(ims)
                    && meta.last_modified <= since
                {
                    return Response::builder()
                        .status(StatusCode::NOT_MODIFIED)
                        .header("ETag", &etag)
                        .body(SpiceioBody::empty())
                        .unwrap();
                }
                if if_match.is_none()
                    && let Some(ref ius) = if_unmodified_since
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
    if if_none_match.is_none()
        && let Some(ref ims) = if_modified_since
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
    if if_match.is_none()
        && let Some(ref ius) = if_unmodified_since
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
            match range.resolve(file_size) {
                Some((s, e)) => (s, e, true),
                None => {
                    let _ = handle.close().await;
                    return error_response(
                        StatusCode::RANGE_NOT_SATISFIABLE,
                        "InvalidRange",
                        "The requested range is not satisfiable",
                    );
                }
            }
        } else {
            (0, file_size.saturating_sub(1), false)
        }
    } else {
        (0, file_size.saturating_sub(1), false)
    };

    let content_length = end - start + 1;

    // Build response with streaming body.
    //
    // Channel capacity is sized so a full SMB pipeline batch can dump into
    // the channel without blocking the producer — that lets the SMB-reading
    // task immediately issue the next pipelined round-trip while the
    // HTTP-sending task drains the previous batch, overlapping back-to-back
    // batches. We also cap by a per-request memory budget: with a configured
    // `SPICEIO_SMB_MAX_IO` of 1 MiB and `READ_PIPELINE_DEPTH = 64`, an
    // uncapped channel would buffer up to 64 MiB per concurrent GetObject.
    // At default 64 KiB chunks the channel stays at the full pipeline depth
    // (4 MiB); at 1 MiB chunks it falls to 8 (still room to overlap).
    let chunk_size = handle.max_chunk;
    // Defense in depth: the SMB client floors any zero values from the
    // server's negotiate response, but if that floor ever regresses we'd
    // rather return a 500 here than panic the streaming task inside
    // `handle.read_pipeline(...)` on `remaining.div_ceil(0)`.
    if chunk_size == 0 {
        let _ = handle.close().await;
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "SMB server negotiated max_read_size = 0",
        );
    }
    let channel_cap = stream_channel_capacity(chunk_size);
    let (body, tx) = SpiceioBody::channel(channel_cap);

    // Owned handles so the streaming task can transparently reconnect after a
    // mid-stream connection drop (see the resume loop below).
    let resume_share = share.clone();
    let resume_key = key.to_string();
    let expected_size = file_size;

    // Spawn background task to stream pipelined SMB reads into the channel.
    // Sends batches of read requests to fill the network pipe, then pushes
    // each chunk to the HTTP response body as it arrives.
    //
    // Resilience: once the 200/206 + Content-Length headers are committed we
    // can no longer fall back to a retryable 503, so a mid-stream connection
    // drop on an overwhelmed NAS (reset or "early eof") would otherwise
    // truncate the transfer. Instead we reconnect on a fresh pool connection —
    // `read_pipeline` has already backed the adaptive read size off — and
    // resume from the current offset, so the client sees one continuous
    // transfer rather than a partial one it must retry. Bounded by
    // MAX_GET_RESUMES; every delivered chunk refreshes the budget so only
    // sustained failure aborts. The file size is re-verified on each reconnect
    // so we never splice bytes from a file that changed underneath us.
    tokio::spawn(async move {
        const MAX_GET_RESUMES: u32 = 16;
        let mut handle = handle;
        let mut chunk_size = chunk_size;
        let mut offset = start;
        let stream_end = end + 1;
        let mut resumes: u32 = 0;
        'outer: while offset < stream_end {
            let remaining = stream_end - offset;
            match handle.read_pipeline(offset, chunk_size, remaining).await {
                Ok(chunks) if chunks.is_empty() => break,
                Ok(chunks) => {
                    for chunk in chunks {
                        if chunk.is_empty() {
                            break 'outer;
                        }
                        offset += chunk.len() as u64;
                        resumes = 0; // forward progress refreshes the resume budget
                        if tx.send(Ok(chunk)).await.is_err() {
                            crate::serr!("[spiceio] getobject client disconnected");
                            break 'outer;
                        }
                    }
                }
                Err(e) if crate::smb::ops::is_reset(&e) && resumes < MAX_GET_RESUMES => {
                    // Transient mid-stream drop: reconnect and resume instead of
                    // truncating. `read_pipeline` already backed off the read size.
                    resumes += 1;
                    let _ = handle.close().await; // best-effort; may already be dead
                    // open_read picks a non-poisoned connection, so the common
                    // case (this connection dropped, the rest healthy) is
                    // instant. Only when the first re-open fails — the whole pool
                    // is momentarily down — do we pay for a heal + brief pause.
                    let reopened = match resume_share.open_read(&resume_key).await {
                        Ok(h) => Ok(h),
                        Err(_) => {
                            resume_share.heal().await;
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            resume_share.open_read(&resume_key).await
                        }
                    };
                    match reopened {
                        Ok(h) if h.file_size == expected_size => {
                            chunk_size = h.max_chunk; // adopt the backed-off chunk
                            handle = h;
                            crate::slog!(
                                "[spiceio] getobject resumed at {offset}/{stream_end} (attempt {resumes})"
                            );
                            continue 'outer;
                        }
                        Ok(h) => {
                            // File changed underneath us — refuse to splice.
                            // The old handle was already closed above, so end
                            // the task rather than fall to the final close.
                            let got = h.file_size;
                            let _ = h.close().await;
                            crate::serr!(
                                "[spiceio] getobject resume aborted: size changed {expected_size} -> {got}"
                            );
                            let _ = tx
                                .send(Err(io::Error::other(
                                    "object changed during streaming read",
                                )))
                                .await;
                            return;
                        }
                        Err(reopen_err) => {
                            crate::serr!("[spiceio] getobject reconnect failed: {reopen_err}");
                            let _ = tx.send(Err(reopen_err)).await;
                            return;
                        }
                    }
                }
                Err(e) => {
                    crate::serr!("[spiceio] getobject read error: {e}");
                    // Propagate into the body so the client sees an aborted
                    // transfer, not a silently truncated one.
                    let _ = tx.send(Err(e)).await;
                    break 'outer;
                }
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
    let max_write = share.compound_max_write_size() as u64;

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

    // ── Streaming path: buffered WAL write for large or unknown-size bodies ──
    let mut wal = match share.open_wal_write(key).await {
        Ok(w) => w,
        Err(e) => return io_to_s3_error(&e),
    };

    let mut body = req.into_body();
    let mut write_err = None;

    while let Some(frame) = body.frame().await {
        match frame {
            Ok(frame) => {
                if let Ok(data) = frame.into_data()
                    && !data.is_empty()
                    && let Err(e) = wal.write(&data).await
                {
                    write_err = Some(e);
                    break;
                }
            }
            Err(e) => {
                crate::serr!("[spiceio] putobject body read error: {e}");
                wal.abort().await;
                return io_to_s3_error(&io::Error::other(format!("body read error: {e}")));
            }
        }
    }

    if let Some(e) = write_err {
        wal.abort().await;
        return io_to_s3_error(&e);
    }

    // Commit: flush remaining buffer, rename WAL temp → final path
    let meta = match wal.commit(share).await {
        Ok(m) => m,
        Err(e) => return io_to_s3_error(&e),
    };

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("ETag", format!("\"{}\"", meta.etag));
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
    if if_none_match.is_none()
        && let Some(ref ims) = if_modified_since
        && let Some(since) = parse_http_date(ims)
        && src_meta.last_modified <= since
    {
        return error_response(StatusCode::PRECONDITION_FAILED, "PreconditionFailed", "");
    }
    if if_match.is_none()
        && let Some(ref ius) = if_unmodified_since
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
        // DeleteObject is idempotent: 204 for a successful delete and for a
        // missing object. Other errors (access denied, I/O) must surface so a
        // client never assumes a still-present object was deleted.
        Ok(()) => ok_no_content(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => ok_no_content(),
        Err(e) => io_to_s3_error(&e),
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
            if if_none_match.is_none()
                && let Some(ref ims) = if_modified_since
                && let Some(since) = parse_http_date(ims)
                && meta.last_modified <= since
            {
                return Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .header("ETag", &etag)
                    .body(SpiceioBody::empty())
                    .unwrap();
            }
            if if_match.is_none()
                && let Some(ref ius) = if_unmodified_since
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

    // XML-entity-decode keys (a client escapes `&`,`<`,… in the request body);
    // without this a key like `a&amp;b` would target the literal `a&amp;b`.
    let keys: Vec<String> = xml::extract_sections(&body_str, "<Object>", "</Object>")
        .iter()
        .filter_map(|section| xml::extract_element(section, "Key"))
        .map(xml::xml_decode)
        .collect();

    let quiet = xml::extract_element(&body_str, "Quiet")
        .map(|s| s == "true")
        .unwrap_or(false);

    let mut w = XmlWriter::new();
    w.declaration();
    w.open_ns("DeleteResult", S3_XMLNS);

    for key in &keys {
        if key_has_traversal(key) {
            w.open("Error");
            w.element("Key", key);
            w.element("Code", "InvalidArgument");
            w.element("Message", "Object key contains invalid path segments");
            w.close("Error");
            continue;
        }
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

    let body = match collect_body(req).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    // Hashing a multi-hundred-MB part is CPU-bound; run it on the blocking pool
    // so it doesn't tie up an async worker (which would starve other requests on
    // a busy multi-core box). `Bytes::clone` is a cheap refcount bump.
    let etag = {
        let b = body.clone();
        match tokio::task::spawn_blocking(move || {
            crate::crypto::hex_encode(&crate::crypto::sha256(&b))
        })
        .await
        {
            Ok(e) => e,
            Err(e) => {
                crate::serr!("[spiceio] upload-part hash task failed: {e}");
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "hash failed",
                );
            }
        }
    };
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
    let upload = match state.multipart.get(upload_id).await {
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

    // S3 requires PartNumbers to be strictly ascending and unique; otherwise
    // assembling in the client-supplied order would silently produce a
    // byte-reordered or duplicated object.
    if part_numbers.windows(2).any(|w| w[0] >= w[1]) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "InvalidPartOrder",
            "The list of parts was not in ascending order. Parts must be ordered by part number.",
        );
    }

    // Validate all requested parts exist before assembly
    for pn in &part_numbers {
        if !upload.parts.contains_key(pn) {
            return error_response(
                StatusCode::BAD_REQUEST,
                "InvalidPart",
                &format!("Part {pn} not found"),
            );
        }
    }

    // Stream parts through a WAL writer (pipelined reads → pipelined writes
    // → atomic rename). Never buffers the whole file in memory.
    let temp_paths: Vec<&str> = part_numbers
        .iter()
        .filter_map(|pn| upload.parts.get(pn).map(|p| p.temp_path.as_str()))
        .collect();

    let meta = match state.share.assemble_parts(key, &temp_paths).await {
        Ok(m) => m,
        Err(e) => return io_to_s3_error(&e),
    };

    // Only now remove the upload from the store
    let upload = state.multipart.complete(upload_id).await;

    // Clean up temp files (best effort)
    if let Some(upload) = upload {
        for part in upload.parts.values() {
            state.share.delete_temp(&part.temp_path).await;
        }
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
    // `region` is operator-configured; fall back rather than panic on every
    // response if it contains bytes invalid in a header value.
    headers.insert(
        X_AMZ_BUCKET_REGION,
        region
            .parse()
            .unwrap_or_else(|_| http::HeaderValue::from_static("us-east-1")),
    );
    headers.insert(
        "Server",
        concat!("spiceio/", env!("CARGO_PKG_VERSION"))
            .parse()
            .unwrap(),
    );
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
            crate::serr!("[spiceio] access denied: {e}");
            error_response(StatusCode::FORBIDDEN, "AccessDenied", "Access Denied")
        }
        // Transient, retryable conditions → 503 SlowDown (the standard S3
        // retryable status), logged at info level (not `serr!`) since they
        // are not bugs:
        //   - ResourceBusy: sharing violation under concurrent access.
        //   - BrokenPipe/ConnectionReset/ConnectionAborted/NotConnected: the
        //     SMB server dropped a pool connection (common under heavy
        //     concurrent load); the healer reconnects it, so the client should
        //     just retry instead of seeing a hard 500.
        //   - TimedOut: a read/write timed out and we poisoned the connection;
        //     a retry lands on a healthy one.
        //   - UnexpectedEof: an overwhelmed NAS closed the connection with a
        //     FIN mid-response ("early eof"); the healer reconnects it, so the
        //     client should back off and retry rather than see a hard 500.
        io::ErrorKind::ResourceBusy
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::NotConnected
        | io::ErrorKind::TimedOut
        | io::ErrorKind::UnexpectedEof => {
            crate::slog!("[spiceio] transient (retry): {e}");
            error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "SlowDown",
                "The request could not be completed; please retry.",
            )
        }
        _ => {
            crate::serr!("[spiceio] error: {e}");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &e.to_string(),
            )
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// True if `key` is present as a query-parameter *name* (`?key`, `?key=…`, at a
/// `&` boundary) — not merely a substring of some value. Used for sub-resource
/// routing so e.g. `?response-content-disposition=acl.txt` doesn't route to the
/// ACL handler.
fn has_query_flag(query: &str, key: &str) -> bool {
    query
        .split('&')
        .any(|pair| pair.split('=').next() == Some(key))
}

/// Reject object keys that could escape the share via `..` path traversal.
/// Splits on both `/` (S3 separator) and `\` (SMB separator — `to_smb_path`
/// maps one to the other) so neither form slips through.
fn key_has_traversal(key: &str) -> bool {
    key.split(['/', '\\']).any(|seg| seg == "..")
}

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
    // May be comma-separated; tolerate the weak-validator prefix `W/`.
    for part in condition.split(',') {
        let part = part.trim();
        let part = part.strip_prefix("W/").unwrap_or(part);
        let part = part.trim_matches('"');
        let etag_inner = etag.trim_matches('"');
        if part == etag_inner {
            return true;
        }
    }
    false
}

/// Max size of a request body buffered fully in memory (UploadPart,
/// multi-delete, multipart-complete). Bounds memory against a client streaming
/// a huge body. Streaming PutObject is not affected (it never buffers).
const MAX_BUFFERED_BODY: usize = 256 * 1024 * 1024;

/// Collect an `Incoming` body into `Bytes` for operations that need the full
/// payload, rejecting bodies over [`MAX_BUFFERED_BODY`] with `EntityTooLarge`
/// instead of buffering them unbounded.
async fn collect_body(req: Request<Incoming>) -> Result<Bytes, Response<SpiceioBody>> {
    let mut body = req.into_body();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(frame) = body.frame().await {
        match frame {
            Ok(f) => {
                if let Ok(data) = f.into_data() {
                    if buf.len().saturating_add(data.len()) > MAX_BUFFERED_BODY {
                        return Err(error_response(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "EntityTooLarge",
                            "Request body exceeds the maximum buffered size",
                        ));
                    }
                    buf.extend_from_slice(&data);
                }
            }
            Err(e) => {
                crate::serr!("[spiceio] body collect error: {e}");
                return Ok(Bytes::new());
            }
        }
    }
    Ok(Bytes::from(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_flag_matches_name_not_value_substring() {
        assert!(has_query_flag("acl", "acl"));
        assert!(has_query_flag("foo=1&acl&bar=2", "acl"));
        assert!(has_query_flag("acl=", "acl"));
        // A substring inside a value must NOT route to the sub-resource.
        assert!(!has_query_flag("prefix=my-acl-doc", "acl"));
        assert!(!has_query_flag(
            "response-content-disposition=acl.txt",
            "acl"
        ));
    }

    #[test]
    fn key_traversal_detection() {
        assert!(key_has_traversal("../etc/passwd"));
        assert!(key_has_traversal("a/../../b"));
        assert!(key_has_traversal("a\\..\\b"));
        assert!(!key_has_traversal("a/b/c.txt"));
        // ".." only as a full path segment, not a prefix.
        assert!(!key_has_traversal("..foo/bar"));
    }

    #[test]
    fn etag_matches_handles_weak_and_star() {
        assert!(etag_matches("W/\"abc\"", "\"abc\""));
        assert!(etag_matches("\"abc\"", "abc"));
        assert!(etag_matches("*", "anything"));
        assert!(etag_matches("\"x\", W/\"abc\"", "\"abc\""));
        assert!(!etag_matches("\"xyz\"", "\"abc\""));
    }

    /// The whole reason this file exists: unit tests in `smb::client` already
    /// verify `STATUS_SHARING_VIOLATION → io::ErrorKind::ResourceBusy`. What
    /// was missing was the next hop — that the HTTP layer maps that kind to
    /// a retryable S3 status, not 500 InternalError. Without this assertion,
    /// the prior regression (sharing violations leaking as 500 with noisy
    /// `error:` logs) had no test to catch it.
    #[test]
    fn io_to_s3_error_maps_resource_busy_to_slow_down() {
        let err = io::Error::new(io::ErrorKind::ResourceBusy, "sharing violation: foo");
        let resp = io_to_s3_error(&err);
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn io_to_s3_error_maps_dropped_connection_to_retryable() {
        // A pool connection the SMB server dropped under load must surface as a
        // retryable 503, not a hard 500, so clients back off and retry.
        for kind in [
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::NotConnected,
            io::ErrorKind::TimedOut,
            // "early eof": NAS closed the connection mid-response under load.
            io::ErrorKind::UnexpectedEof,
        ] {
            let resp = io_to_s3_error(&io::Error::new(kind, "dropped"));
            assert_eq!(
                resp.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "{kind:?} should map to 503"
            );
        }
    }

    #[test]
    fn io_to_s3_error_maps_not_found_to_404() {
        let err = io::Error::new(io::ErrorKind::NotFound, "missing");
        let resp = io_to_s3_error(&err);
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn io_to_s3_error_maps_permission_denied_to_403() {
        let err = io::Error::new(io::ErrorKind::PermissionDenied, "nope");
        let resp = io_to_s3_error(&err);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn io_to_s3_error_other_falls_back_to_500() {
        let err = io::Error::other("unexpected");
        let resp = io_to_s3_error(&err);
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ── stream_channel_capacity ─────────────────────────────────────────────

    #[test]
    fn stream_channel_capacity_handles_zero_chunk() {
        // The SMB negotiate response is the source of `max_chunk`; an
        // unusual server (or a misconfiguration) could yield 0. The naive
        // `BUDGET / 0` would panic and crash the streaming task — the
        // floor-at-1 inside `stream_channel_capacity` keeps it safe. The
        // exact value doesn't matter (a 0-byte chunk is nonsense anyway);
        // we only assert (a) we don't panic and (b) the result is a sane
        // pipeline-depth-bounded slot count.
        let cap = stream_channel_capacity(0);
        assert!(
            (1..=crate::smb::ops::READ_PIPELINE_DEPTH).contains(&cap),
            "expected 1..={} got {cap}",
            crate::smb::ops::READ_PIPELINE_DEPTH
        );
    }

    #[test]
    fn stream_channel_capacity_default_chunk_uses_full_pipeline() {
        // 64 KiB chunks → 8 MiB / 64 KiB = 128, clamped to the pipeline
        // depth so a full SMB read batch can dump into the channel.
        assert_eq!(
            stream_channel_capacity(65536),
            crate::smb::ops::READ_PIPELINE_DEPTH
        );
    }

    #[test]
    fn stream_channel_capacity_large_chunk_falls_below_pipeline() {
        // 1 MiB chunks → 8 MiB / 1 MiB = 8, well below pipeline depth.
        // This is the case the per-request memory budget exists to handle.
        assert_eq!(stream_channel_capacity(1024 * 1024), 8);
    }

    #[test]
    fn stream_channel_capacity_huge_chunk_floors_at_one() {
        // A chunk bigger than the entire budget still yields a 1-slot
        // channel, never 0 — the producer can always make progress.
        assert_eq!(stream_channel_capacity(16 * 1024 * 1024), 1);
    }
}
