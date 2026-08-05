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
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::body::SpiceioBody;
use super::headers::*;
use super::multipart::MultipartStore;
use super::object_cache::ObjectCache;
use super::writeback::WriteBack;
use super::xml::{self, XmlWriter};
use crate::smb::ops::{ShareSession, guess_content_type};

const S3_XMLNS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

/// How long a non-overloaded request may wait for an SMB admission slot before
/// we answer 503 instead of queueing forever inside the process.
const ADMISSION_WAIT: Duration = Duration::from_secs(15);

/// Shared application state passed to the router.
pub struct AppState {
    pub share: Arc<ShareSession>,
    pub bucket: String,
    pub region: String,
    pub multipart: MultipartStore,
    /// Caps concurrent S3 ops that hit the SMB pool. Sized from the pool
    /// (`admission_limit`) so an sccache stampede cannot bury spiceio under
    /// unbounded blocked handlers when the NAS is slow or overloaded.
    pub smb_slots: Arc<Semaphore>,
    /// GET body cache (etag-validated; optional immutable-key mode).
    pub object_cache: Arc<ObjectCache>,
    /// Writes acknowledged from memory that have not reached the NAS yet.
    /// Enabled by default; when `SPICEIO_WRITE_BACK=0` disables it, every
    /// method below short-circuits on a single bool check.
    pub writeback: Arc<WriteBack>,
}

/// How long an operation that needs an object *on the backend* — a range read,
/// a server-side copy — waits for its pending write to flush. Generous: the
/// alternative is answering from a view the NAS does not share yet.
const PENDING_FLUSH_TIMEOUT: Duration = Duration::from_secs(30);

/// Acquire an SMB work slot, or fail with 503.
///
/// * Healthy: wait up to `ADMISSION_WAIT` so a short burst queues rather than
///   fails.
/// * Overloaded (recent reset/busy, or half the pool poisoned): **try** only —
///   fail immediately with Retry-After so we stop amplifying the overload.
///
/// The uncontended case is one atomic compare-exchange. It is worth splitting
/// out because `tokio::time::timeout` arms a timer whether or not the wait
/// happens — a timer-wheel insert and a cancel on drop, on every request, to
/// bound a wait that in the common case is not a wait at all. Trying first also
/// subsumes the overloaded branch: that arm *is* a bare try, so when a permit
/// is free both branches do the same thing and the overload check is only
/// needed once the semaphore is actually contended.
async fn acquire_smb_slot(state: &AppState) -> Result<OwnedSemaphorePermit, ()> {
    if let Ok(permit) = state.smb_slots.clone().try_acquire_owned() {
        return Ok(permit);
    }
    if state.share.is_overloaded() {
        return Err(());
    }
    match tokio::time::timeout(ADMISSION_WAIT, state.smb_slots.clone().acquire_owned()).await {
        Ok(Ok(permit)) => Ok(permit),
        // Closed semaphore (process shutting down) or wait timed out.
        _ => Err(()),
    }
}

/// Handle an incoming S3 API request.
///
/// Accepts the raw `Incoming` body — GetObject and PutObject stream without
/// buffering the entire payload. Operations that need the full body (multipart,
/// multi-delete, copy) collect it internally.
pub async fn handle_request(req: Request<Incoming>, state: &AppState) -> Response<SpiceioBody> {
    // Split the request once, up front. The handlers below need the headers
    // and the body independently, and the only way to have both from an intact
    // `Request` is to deep-clone the HeaderMap (every name and value) on every
    // request — pure overhead on the hottest path. Splitting also lets the
    // path and query stay borrowed instead of copied into two Strings.
    let (parts, body) = req.into_parts();
    let path = parts.uri.path();
    let query = parts.uri.query().unwrap_or("");
    let method = &parts.method;
    let hdrs = &parts.headers;
    let declared_len: Option<u64> = get_header(hdrs, "content-length").and_then(|v| v.parse().ok());
    let request_id = generate_request_id();

    // CORS preflight — no SMB, no admission slot.
    if *method == Method::OPTIONS {
        return cors_preflight(&request_id, &state.region);
    }

    // Parse bucket and key from path-style: /{bucket}/{key...}
    // Percent-decode the key so encoded characters (spaces, Unicode, `%`, …)
    // map to the real object name instead of a literal `%XX` filename.
    let (req_bucket, raw_key) = parse_path(path);
    let key_decoded = percent_decode(raw_key);
    let key: &str = &key_decoded;

    // Service-level operations (no bucket) — ListBuckets is in-memory and must
    // stay available as a liveness probe even when the NAS is overloaded.
    if req_bucket.is_empty() {
        match *method {
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

    // Bucket must match our configured bucket (no SMB needed).
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

    // Requests the cache can answer outright take no admission permit: they
    // claim no SMB connection, so queueing them behind saturated backend work
    // would throttle the only path the backend does not limit. Nothing
    // unbounded is admitted by this — the bodies are already resident in the
    // cache, and the response holds a refcount, not a copy.
    if *method == Method::GET
        && !key.is_empty()
        && is_plain_object_query(query)
        && let Some(resp) = try_backendless_get(hdrs, state, key).await
    {
        return with_common_headers(resp, &request_id, &state.region);
    }

    // Everything below talks to SMB. Hold an admission permit for the whole
    // request so a saturated NAS cannot grow unbounded work inside the process.
    let _smb_permit = match acquire_smb_slot(state).await {
        Ok(p) => p,
        Err(()) => {
            return with_common_headers(
                service_unavailable(
                    "spiceio is at capacity waiting on the SMB backend; please retry.",
                ),
                &request_id,
                &state.region,
            );
        }
    };

    // ── Bucket-level operations (no key) ────────────────────────────────
    if key.is_empty() {
        let resp = match *method {
            Method::GET | Method::HEAD if has_query_flag(query, "location") => {
                handle_get_bucket_location(&state.region)
            }
            Method::GET if has_query_flag(query, "versioning") => handle_get_bucket_versioning(),
            Method::GET if has_query_flag(query, "acl") => handle_get_bucket_acl(),
            Method::PUT if has_query_flag(query, "acl") => ok_empty(),
            Method::GET if has_query_flag(query, "tagging") => handle_get_bucket_tagging(),
            Method::PUT if has_query_flag(query, "tagging") => ok_empty(),
            Method::DELETE if has_query_flag(query, "tagging") => ok_no_content(),
            Method::GET if has_query_flag(query, "cors") => handle_get_bucket_cors(),
            Method::PUT if has_query_flag(query, "cors") => ok_empty(),
            Method::DELETE if has_query_flag(query, "cors") => ok_no_content(),
            Method::GET if has_query_flag(query, "lifecycle") => handle_get_bucket_lifecycle(),
            Method::GET if has_query_flag(query, "policy") => handle_get_bucket_policy(),
            Method::GET if has_query_flag(query, "encryption") => handle_get_bucket_encryption(),
            Method::GET if has_query_flag(query, "uploads") => {
                handle_list_multipart_uploads(state, query).await
            }
            Method::POST if has_query_flag(query, "delete") => {
                match collect_body(body, declared_len).await {
                    Ok(body) => handle_delete_objects(body, state).await,
                    Err(resp) => resp,
                }
            }
            Method::GET => handle_list_objects(state, query).await,
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
    if *method == Method::POST {
        let resp = if has_query_flag(query, "uploads") && !has_query_flag(query, "uploadId") {
            handle_create_multipart_upload(hdrs, state, key).await
        } else if let Some(upload_id) = extract_query_param(query, "uploadId") {
            match collect_body(body, declared_len).await {
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
    if *method == Method::PUT
        && has_query_flag(query, "partNumber")
        && has_query_flag(query, "uploadId")
    {
        let part_number: u32 = extract_query_param(query, "partNumber")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let upload_id = extract_query_param(query, "uploadId").unwrap_or_default();
        // UploadPartCopy: a part sourced from another object carries
        // x-amz-copy-source (no body) — the form `aws s3 cp` / `sync` use for
        // any object over the multipart threshold (~8 MiB). Without this
        // branch the copy-source PUT falls through to a normal UploadPart,
        // which reads an empty body and returns the wrong response shape.
        let resp = if hdrs.contains_key(X_AMZ_COPY_SOURCE) {
            handle_upload_part_copy(hdrs, state, key, &upload_id, part_number).await
        } else {
            handle_upload_part(body, declared_len, state, key, &upload_id, part_number).await
        };
        return with_common_headers(resp, &request_id, &state.region);
    }

    // Multipart: GET with ?uploadId=... (list parts)
    if *method == Method::GET && has_query_flag(query, "uploadId") {
        let upload_id = extract_query_param(query, "uploadId").unwrap_or_default();
        let resp = handle_list_parts(state, key, &upload_id).await;
        return with_common_headers(resp, &request_id, &state.region);
    }

    // Multipart: DELETE with ?uploadId=... (abort)
    if *method == Method::DELETE && has_query_flag(query, "uploadId") {
        let upload_id = extract_query_param(query, "uploadId").unwrap_or_default();
        let resp = handle_abort_multipart_upload(state, key, &upload_id).await;
        return with_common_headers(resp, &request_id, &state.region);
    }

    // Object ACL
    if has_query_flag(query, "acl") {
        let resp = match *method {
            Method::GET => handle_get_object_acl(),
            Method::PUT => ok_empty(),
            _ => error_response(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", ""),
        };
        return with_common_headers(resp, &request_id, &state.region);
    }

    // Object tagging
    if has_query_flag(query, "tagging") {
        let resp = match *method {
            Method::GET => handle_get_object_tagging(),
            Method::PUT => ok_empty(),
            Method::DELETE => ok_no_content(),
            _ => error_response(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", ""),
        };
        return with_common_headers(resp, &request_id, &state.region);
    }

    // Object legal-hold, retention, torrent — stubs
    if has_query_flag(query, "legal-hold")
        || has_query_flag(query, "retention")
        || has_query_flag(query, "torrent")
    {
        let resp = match *method {
            Method::GET | Method::PUT => ok_empty(),
            _ => error_response(StatusCode::NOT_IMPLEMENTED, "NotImplemented", ""),
        };
        return with_common_headers(resp, &request_id, &state.region);
    }

    // Object restore — stub
    if *method == Method::POST && has_query_flag(query, "restore") {
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
    if *method == Method::POST && has_query_flag(query, "select") {
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

    let resp = match *method {
        Method::GET => handle_get_object(hdrs, state, key).await,
        Method::PUT => {
            // CopyObject: PUT with x-amz-copy-source header
            if hdrs.contains_key(X_AMZ_COPY_SOURCE) {
                handle_copy_object(hdrs, state, key).await
            } else {
                handle_put_object(body, declared_len, hdrs, state, key).await
            }
        }
        Method::DELETE => handle_delete_object(state, key).await,
        Method::HEAD => handle_head_object(hdrs, state, key).await,
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

/// Fold this instance's pending write-backs into a listing.
///
/// Mirrors the backend walk's own prefix/delimiter rules: a key that still has
/// a separator after the prefix is a directory the walk would have reported as
/// a common prefix, not an object.
///
/// The separator is `/` regardless of the requested delimiter, because that is
/// what the backend walk does — SMB directories are the only grouping it can
/// report, so `smb::ops::list_objects` rolls up at directory boundaries and
/// appends `/`. Honouring an arbitrary delimiter *here* would not fix that; it
/// would only make the overlay disagree with the listing it is merging into. A pending key that the walk *did* find (an
/// overwrite of an existing object) keeps its listed entry rather than being
/// duplicated — the size and mtime it will have once the flush lands are the
/// pending ones, so those win.
async fn overlay_pending(
    state: &AppState,
    prefix: &str,
    delimiter: Option<&str>,
    objects: &mut Vec<crate::smb::ops::ObjectInfo>,
    common_prefixes: &mut Vec<String>,
) {
    let pending = state.writeback.snapshot().await;
    merge_pending(prefix, delimiter, pending, objects, common_prefixes);
}

/// The merge itself, split out so it is testable without a live backend.
fn merge_pending(
    prefix: &str,
    delimiter: Option<&str>,
    pending: Vec<(String, String, u64, u64)>,
    objects: &mut Vec<crate::smb::ops::ObjectInfo>,
    common_prefixes: &mut Vec<String>,
) {
    for (key, etag, last_modified, size) in pending {
        let Some(rest) = key.strip_prefix(prefix) else {
            continue;
        };
        if delimiter.is_some()
            && let Some(pos) = rest.find('/')
        {
            let roll_up = format!("{prefix}{}/", &rest[..pos]);
            if !common_prefixes.contains(&roll_up) {
                common_prefixes.push(roll_up);
            }
            continue;
        }
        let info = crate::smb::ops::ObjectInfo {
            key,
            size,
            last_modified,
            etag,
        };
        match objects.iter_mut().find(|o| o.key == info.key) {
            Some(existing) => *existing = info,
            None => objects.push(info),
        }
    }
}

async fn handle_list_objects(state: &AppState, query: &str) -> Response<SpiceioBody> {
    let share = &state.share;
    let bucket = &state.bucket;
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
            // Objects whose writes were acknowledged from memory are not on the
            // NAS for the walk above to have found. Overlaying them here is what
            // keeps a client that PUTs and then lists from concluding its write
            // vanished. Only this instance's pending writes are visible; a peer's
            // appear once they flush.
            overlay_pending(
                state,
                &prefix,
                delimiter.as_deref(),
                &mut objects,
                &mut common_prefixes,
            )
            .await;

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

/// Evaluate If-Match / If-None-Match / If-Modified-Since / If-Unmodified-Since
/// for GetObject. Returns `Some(response)` when the request is fully handled
/// (304 or 412); `None` means the caller should serve the body.
fn conditional_get_short_circuit(
    if_match: &Option<String>,
    if_none_match: &Option<String>,
    if_modified_since: &Option<String>,
    if_unmodified_since: &Option<String>,
    etag: &str,
    last_modified: u64,
) -> Option<Response<SpiceioBody>> {
    if let Some(im) = if_match
        && !etag_matches(im, etag)
    {
        return Some(error_response(
            StatusCode::PRECONDITION_FAILED,
            "PreconditionFailed",
            "",
        ));
    }
    if let Some(inm) = if_none_match
        && etag_matches(inm, etag)
    {
        return Some(
            Response::builder()
                .status(StatusCode::NOT_MODIFIED)
                .header("ETag", etag)
                .body(SpiceioBody::empty())
                .unwrap(),
        );
    }
    if if_none_match.is_none()
        && let Some(ims) = if_modified_since
        && let Some(since) = parse_http_date(ims)
        && last_modified <= since
    {
        return Some(
            Response::builder()
                .status(StatusCode::NOT_MODIFIED)
                .header("ETag", etag)
                .body(SpiceioBody::empty())
                .unwrap(),
        );
    }
    if if_match.is_none()
        && let Some(ius) = if_unmodified_since
        && let Some(since) = parse_http_date(ius)
        && last_modified > since
    {
        return Some(error_response(
            StatusCode::PRECONDITION_FAILED,
            "PreconditionFailed",
            "",
        ));
    }
    None
}

fn cached_get_response(
    meta_content_type: &str,
    meta_last_modified: u64,
    etag: &str,
    body: Bytes,
) -> Response<SpiceioBody> {
    let last_modified = xml::epoch_to_http_date(meta_last_modified);
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", meta_content_type)
        .header("Content-Length", body.len().to_string())
        .header("ETag", etag)
        .header("Last-Modified", last_modified)
        .header("Accept-Ranges", "bytes")
        .header("x-spiceio-cache", "HIT")
        .body(SpiceioBody::full(body))
        .unwrap()
}

/// Sub-resource selectors that make a keyed request something other than a
/// plain object read — `?acl`, `?tagging`, `?uploadId`, …
///
/// The dispatch below routes on these one at a time, in order. Anything that
/// short-circuits *before* that dispatch has to reject them all, or it answers
/// `GET /key?acl` with the object's body.
const OBJECT_SUBRESOURCES: &[&str] = &[
    "acl",
    "cors",
    "delete",
    "encryption",
    "legal-hold",
    "lifecycle",
    "location",
    "partNumber",
    "policy",
    "restore",
    "retention",
    "select",
    "tagging",
    "torrent",
    "uploadId",
    "uploads",
    "versioning",
];

/// True when a keyed GET is a plain object read, so the cache may answer it
/// before the sub-resource dispatch runs.
fn is_plain_object_query(query: &str) -> bool {
    query.is_empty() || !OBJECT_SUBRESOURCES.iter().any(|f| has_query_flag(query, f))
}

/// Answer a GET without touching the backend, or `None` if the backend is
/// needed after all.
///
/// Called *before* admission control, which is the point of it existing
/// separately. An admission permit is a claim on the SMB pool, and it is held
/// for the whole request; a request served from cache claims nothing, so making
/// it queue for a permit — and then hold one while it copies bytes it already
/// has — caps the one path in the proxy that the backend does not limit, at the
/// backend's own concurrency. Worse, at a high hit rate most permits end up
/// held by requests that need no connection, crowding out the misses that do.
///
/// Only paths that provably issue no SMB operation belong here. Both of these
/// already answered from memory; the change is *when* they are tried, not what
/// they return.
async fn try_backendless_get(
    hdrs: &http::HeaderMap,
    state: &AppState,
    key: &str,
) -> Option<Response<SpiceioBody>> {
    let cache = &state.object_cache;
    // A range read has to seek inside the object, which only the backend can
    // do. It still has to go through the pending check below first: returning
    // early here would send a range read of a just-acknowledged object to a NAS
    // that does not have it yet, and answer 404 for an object the client was
    // told it had written.
    let is_range = hdrs.contains_key("range");

    // ── Acknowledged-but-unwritten key ──────────────────────────────
    // Write-back returned 200 for this object before the NAS had it, so the
    // cache is its only authority right now. Revalidating would stat the
    // *previous* version, or nothing at all, and answer a client with a body
    // it has already been told was replaced.
    let hit = if state.writeback.pending_meta(key).await.is_some() {
        match cache.lookup_pending(key).await {
            Some(hit) if !is_range => hit,
            // A range read, or a body evicted from both tiers — neither is ours
            // to answer. Wait for the flush (without a permit, since waiting is
            // not backend work) and let the caller take the normal path against
            // a backend that now has the object.
            _ => {
                state.writeback.flush_key(key, PENDING_FLUSH_TIMEOUT).await;
                return None;
            }
        }
    } else if is_range {
        return None;
    }
    // ── Immutable-key fast path ─────────────────────────────────────
    //
    // Sound only because `immutable` asserts the key determines the content:
    // in a content-addressed store like sccache the key *is* a hash of these
    // bytes, so nothing can put different content under it and a revalidation
    // has nothing to discover. What it gives up is noticing a backend-side
    // delete — harmless for a cache, since the client asked for a content hash
    // and receives exactly those bytes.
    else if cache.immutable() {
        cache.lookup_key(key).await?
    } else {
        return None;
    };

    let etag = format!("\"{}\"", hit.etag);
    if let Some(resp) = conditional_get_short_circuit(
        &get_header(hdrs, IF_MATCH).map(String::from),
        &get_header(hdrs, IF_NONE_MATCH).map(String::from),
        &get_header(hdrs, IF_MODIFIED_SINCE).map(String::from),
        &get_header(hdrs, IF_UNMODIFIED_SINCE).map(String::from),
        &etag,
        hit.last_modified,
    ) {
        return Some(resp);
    }
    Some(cached_get_response(
        &guess_content_type(key),
        hit.last_modified,
        &etag,
        hit.body,
    ))
}

async fn handle_get_object(
    hdrs: &http::HeaderMap,
    state: &AppState,
    key: &str,
) -> Response<SpiceioBody> {
    let share = &state.share;
    let cache = &state.object_cache;
    let range_header = get_header(hdrs, "range").map(String::from);
    let if_match = get_header(hdrs, IF_MATCH).map(String::from);
    let if_none_match = get_header(hdrs, IF_NONE_MATCH).map(String::from);
    let if_modified_since = get_header(hdrs, IF_MODIFIED_SINCE).map(String::from);
    let if_unmodified_since = get_header(hdrs, IF_UNMODIFIED_SINCE).map(String::from);

    // ── Fast path: compound Create+Read+Close for small files ───────
    // Tries to read the entire file in one SMB round trip. Falls back to
    // streaming for large files or range requests.
    //
    // Body cache: after a successful compound (or open/stat) we may serve a
    // previously cached body when the fresh etag matches — S3-safe because
    // open/stat always hits the NAS first.
    let max_read = share.compound_max_read_size();
    let no_range = range_header.is_none();

    if no_range {
        // Warm cache, etag mode: revalidate with a compound stat (one round
        // trip) rather than an open.
        //
        // Opening leaves a handle that has to be closed, so a *hit* — the case
        // `may_hold` has already made likely — cost two round trips where
        // one will do. The open only pays off when revalidation fails and the
        // handle can be reused to stream, which is the rarer path; that path
        // now opens for itself below.
        //
        // Not needed at all in immutable mode, which returned above without
        // touching the backend.
        if cache.may_hold(key).await {
            match share.head_object(key).await {
                Ok(meta) => {
                    let etag = format!("\"{}\"", meta.etag);
                    if let Some(resp) = conditional_get_short_circuit(
                        &if_match,
                        &if_none_match,
                        &if_modified_since,
                        &if_unmodified_since,
                        &etag,
                        meta.last_modified,
                    ) {
                        return resp;
                    }
                    if let Some(cached) = cache.lookup_etag(key, &meta.etag).await
                        && cached.len() as u64 == meta.size
                    {
                        return cached_get_response(
                            &meta.content_type,
                            meta.last_modified,
                            &etag,
                            cached,
                        );
                    }
                    // Stale entry — drop it and fall through to a cold read.
                    cache.invalidate_stale(key).await;
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    cache.invalidate_stale(key).await;
                    return error_response(
                        StatusCode::NOT_FOUND,
                        "NoSuchKey",
                        "The specified key does not exist.",
                    );
                }
                Err(e) if crate::smb::ops::is_reset(&e) => {} // fall through
                Err(e) => return io_to_s3_error(&e),
            }
        }

        cache.note_miss();
        let result = share.get_object_compound(key, max_read).await;
        match result {
            Ok((meta, data)) if meta.size <= max_read as u64 => {
                let etag = format!("\"{}\"", meta.etag);

                if let Some(resp) = conditional_get_short_circuit(
                    &if_match,
                    &if_none_match,
                    &if_modified_since,
                    &if_unmodified_since,
                    &etag,
                    meta.last_modified,
                ) {
                    return resp;
                }

                // Insert on miss so subsequent GETs can revalidate without a
                // body re-fetch. Prefer an existing matching entry when present.
                let body_data = match cache.lookup_etag(key, &meta.etag).await {
                    Some(cached) => cached,
                    None => {
                        if (data.len() as u64) <= cache.max_object_bytes() {
                            cache.store(key, &meta.etag, meta.last_modified, data.clone());
                        }
                        data
                    }
                };

                let last_modified = xml::epoch_to_http_date(meta.last_modified);
                return Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", &meta.content_type)
                    .header("Content-Length", body_data.len().to_string())
                    .header("ETag", &etag)
                    .header("Last-Modified", last_modified)
                    .header("Accept-Ranges", "bytes")
                    .body(SpiceioBody::full(body_data))
                    .unwrap();
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                cache.invalidate_stale(key).await;
                return error_response(
                    StatusCode::NOT_FOUND,
                    "NoSuchKey",
                    "The specified key does not exist.",
                );
            }
            // A transient reset on the one-shot compound probe falls through to
            // the streaming path, which reconnects and retries the open rather
            // than surfacing a 503 the client must absorb.
            Err(e) if crate::smb::ops::is_reset(&e) => {}
            Err(e) => return io_to_s3_error(&e),
            _ => {} // Large file — fall through to streaming
        }
    }

    // ── Streaming path for large files and range requests ─────────
    let handle = match share.open_read(key).await {
        Ok(h) => h,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            cache.invalidate_stale(key).await;
            return error_response(
                StatusCode::NOT_FOUND,
                "NoSuchKey",
                "The specified key does not exist.",
            );
        }
        Err(e) => return io_to_s3_error(&e),
    };

    stream_get_object(
        handle,
        share,
        key,
        range_header.as_deref(),
        &if_match,
        &if_none_match,
        &if_modified_since,
        &if_unmodified_since,
        cache,
        false,
    )
    .await
}

/// Shared streaming GetObject path (large files, ranges, and warm-cache misses
/// that already hold an open handle).
#[allow(clippy::too_many_arguments)]
async fn stream_get_object(
    handle: crate::smb::ops::FileHandle,
    share: &ShareSession,
    key: &str,
    range_header: Option<&str>,
    if_match: &Option<String>,
    if_none_match: &Option<String>,
    if_modified_since: &Option<String>,
    if_unmodified_since: &Option<String>,
    cache: &Arc<ObjectCache>,
    conditionals_done: bool,
) -> Response<SpiceioBody> {
    let meta = &handle.meta;
    let etag = format!("\"{}\"", meta.etag);

    if !conditionals_done
        && let Some(resp) = conditional_get_short_circuit(
            if_match,
            if_none_match,
            if_modified_since,
            if_unmodified_since,
            &etag,
            meta.last_modified,
        )
    {
        let _ = handle.close().await;
        return resp;
    }

    let no_range = range_header.is_none();
    // Full-object GET: etag-validated cache hit after open/stat — close the
    // handle without reading the body from SMB.
    if no_range
        && let Some(cached) = cache.lookup_etag(key, &meta.etag).await
        && cached.len() as u64 == handle.file_size
    {
        let content_type = meta.content_type.clone();
        let last_modified = meta.last_modified;
        let _ = handle.close().await;
        return cached_get_response(&content_type, last_modified, &etag, cached);
    }

    let last_modified = xml::epoch_to_http_date(meta.last_modified);
    let content_type = meta.content_type.clone();
    let file_size = handle.file_size;
    let cache_etag = meta.etag.clone();
    let cache_last_modified = meta.last_modified;
    let cache_key = key.to_string();
    let may_fill_cache = no_range && file_size > 0 && file_size <= cache.max_object_bytes();
    let cache_for_task = Arc::clone(cache);

    // Determine read range
    let (start, end, is_range) = if let Some(range_str) = range_header {
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

    // A zero-byte object (reachable here when the compound fast path hit a
    // transient reset, or when an invalid Range header is ignored): the
    // `end - start + 1` math below assumes at least one byte and would emit
    // Content-Length: 1 with an aborted body. Serve the empty object directly.
    // (A *valid* Range on an empty object already returned 416 above.)
    if !is_range && file_size == 0 {
        let _ = handle.close().await;
        return Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", &content_type)
            .header("Content-Length", "0")
            .header("ETag", &etag)
            .header("Last-Modified", last_modified)
            .header("Accept-Ranges", "bytes")
            .body(SpiceioBody::empty())
            .unwrap();
    }

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
    // Etag (size+mtime) must match on resume so a same-size overwrite cannot
    // splice bytes from a different version into the already-committed body.
    let expected_etag = cache_etag.clone();

    // Spawn background task to stream pipelined SMB reads into the channel.
    //
    // Double-buffer: while draining batch N into the HTTP channel, already
    // issue batch N+1 on the same handle (stream lock is free between
    // pipeline rounds). That overlaps channel backpressure with the next SMB
    // RTT instead of serialising them.
    //
    // Resilience: once the 200/206 + Content-Length headers are committed we
    // can no longer fall back to a retryable 503, so a mid-stream connection
    // drop on an overwhelmed NAS reconnects and resumes from the current
    // offset (bounded by MAX_GET_RESUMES).
    tokio::spawn(async move {
        const MAX_GET_RESUMES: u32 = 16;
        const MAX_GET_REOPEN_TRIES: u32 = 12;
        let mut handle = handle;
        let mut chunk_size = chunk_size;
        let mut offset = start;
        let stream_end = end + 1;
        let mut resumes: u32 = 0;
        let mut cache_buf: Option<Vec<u8>> = if may_fill_cache {
            Some(Vec::with_capacity(file_size as usize))
        } else {
            None
        };
        let mut cache_ok = may_fill_cache;

        // Helper: reopen after a reset, updating handle/chunk_size.
        // Requires both size *and* etag so a same-size rewrite is rejected.
        async fn reopen_for_resume(
            resume_share: &ShareSession,
            resume_key: &str,
            expected_size: u64,
            expected_etag: &str,
            resumes: u32,
            offset: u64,
            stream_end: u64,
        ) -> Result<(crate::smb::ops::FileHandle, u32), io::Error> {
            if resumes > 1 {
                tokio::time::sleep(Duration::from_millis(((resumes as u64) * 50).min(500))).await;
            }
            let mut reopened = resume_share.open_read(resume_key).await;
            let mut rtry = 0u32;
            while reopened.is_err() && rtry < MAX_GET_REOPEN_TRIES {
                rtry += 1;
                resume_share.heal().await;
                tokio::time::sleep(Duration::from_millis((rtry as u64 * 150).min(750))).await;
                reopened = resume_share.open_read(resume_key).await;
            }
            match reopened {
                Ok(h) if h.file_size == expected_size && h.meta.etag == expected_etag => {
                    let chunk = h.max_chunk;
                    crate::slog!(
                        "[spiceio] getobject resumed at {offset}/{stream_end} (attempt {resumes})"
                    );
                    Ok((h, chunk))
                }
                Ok(h) => {
                    let got_size = h.file_size;
                    let got_etag = h.meta.etag.clone();
                    let _ = h.close().await;
                    crate::serr!(
                        "[spiceio] getobject resume aborted: size/etag changed \
                         {expected_size}/{expected_etag} -> {got_size}/{got_etag}"
                    );
                    Err(io::Error::other("object changed during streaming read"))
                }
                Err(e) => {
                    crate::serr!("[spiceio] getobject reconnect failed: {e}");
                    Err(e)
                }
            }
        }

        // Prime the first batch.
        let mut pending: Option<Vec<Bytes>> = None;
        'outer: while offset < stream_end || pending.is_some() {
            // Ensure we have a batch at `offset` (unless finishing a tail).
            let chunks = if let Some(c) = pending.take() {
                c
            } else {
                let remaining = stream_end - offset;
                match handle.read_pipeline(offset, chunk_size, remaining).await {
                    Ok(c) => c,
                    Err(e) if crate::smb::ops::is_reset(&e) && resumes < MAX_GET_RESUMES => {
                        resumes += 1;
                        let _ = handle.close().await;
                        match reopen_for_resume(
                            &resume_share,
                            &resume_key,
                            expected_size,
                            &expected_etag,
                            resumes,
                            offset,
                            stream_end,
                        )
                        .await
                        {
                            Ok((h, cs)) => {
                                handle = h;
                                chunk_size = cs;
                                continue 'outer;
                            }
                            Err(re) => {
                                let _ = tx.send(Err(re)).await;
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        crate::serr!("[spiceio] getobject read error: {e}");
                        let _ = tx.send(Err(e)).await;
                        return;
                    }
                }
            };

            if chunks.is_empty() {
                crate::serr!("[spiceio] getobject short read at {offset}/{stream_end}");
                cache_ok = false;
                let _ = tx
                    .send(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "object ended before the expected length",
                    )))
                    .await;
                break 'outer;
            }

            // Advance the logical offset for the next prefetch based on this
            // batch's sizes; drain and prefetch run concurrently below.
            let batch_bytes: u64 = chunks.iter().map(|c| c.len() as u64).sum();
            if chunks.iter().any(|c| c.is_empty()) {
                crate::serr!("[spiceio] getobject short read at {offset}/{stream_end}");
                cache_ok = false;
                let _ = tx
                    .send(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "object ended before the expected length",
                    )))
                    .await;
                break 'outer;
            }
            let next_offset = offset + batch_bytes;
            let need_prefetch = next_offset < stream_end;

            // Double-buffer: drain this batch to HTTP while reading the next.
            let drain = async {
                let mut local_offset = offset;
                for chunk in chunks {
                    if let Some(ref mut buf) = cache_buf {
                        buf.extend_from_slice(&chunk);
                    }
                    local_offset += chunk.len() as u64;
                    if tx.send(Ok(chunk)).await.is_err() {
                        crate::serr!("[spiceio] getobject client disconnected");
                        return Err(());
                    }
                }
                Ok(local_offset)
            };

            let prefetch = async {
                if !need_prefetch {
                    return Ok(None);
                }
                let remaining = stream_end - next_offset;
                match handle
                    .read_pipeline(next_offset, chunk_size, remaining)
                    .await
                {
                    Ok(c) => Ok(Some(c)),
                    Err(e) => Err(e),
                }
            };

            let (drain_res, pref_res) = tokio::join!(drain, prefetch);
            match drain_res {
                Ok(new_off) => {
                    offset = new_off;
                    resumes = 0;
                }
                Err(()) => {
                    cache_ok = false;
                    break 'outer;
                }
            }

            match pref_res {
                Ok(next) => {
                    pending = next;
                }
                Err(e) if crate::smb::ops::is_reset(&e) && resumes < MAX_GET_RESUMES => {
                    // Prefetch failed; data already drained is fine — resume
                    // from the new offset on a fresh connection.
                    resumes += 1;
                    let _ = handle.close().await;
                    match reopen_for_resume(
                        &resume_share,
                        &resume_key,
                        expected_size,
                        &expected_etag,
                        resumes,
                        offset,
                        stream_end,
                    )
                    .await
                    {
                        Ok((h, cs)) => {
                            handle = h;
                            chunk_size = cs;
                            pending = None;
                            continue 'outer;
                        }
                        Err(re) => {
                            let _ = tx.send(Err(re)).await;
                            return;
                        }
                    }
                }
                Err(e) => {
                    crate::serr!("[spiceio] getobject read error: {e}");
                    let _ = tx.send(Err(e)).await;
                    return;
                }
            }
        }

        if cache_ok
            && let Some(buf) = cache_buf
            && buf.len() as u64 == file_size
        {
            cache_for_task.store(
                &cache_key,
                &cache_etag,
                cache_last_modified,
                Bytes::from(buf),
            );
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
    mut body: Incoming,
    content_length: Option<u64>,
    hdrs: &http::HeaderMap,
    state: &AppState,
    key: &str,
) -> Response<SpiceioBody> {
    let share = &state.share;
    let if_none_match = get_header(hdrs, IF_NONE_MATCH).map(String::from);
    let content_type = get_header(hdrs, "content-type").map(String::from);
    // Conditional write: If-None-Match: * means "only if not exists"
    if let Some(ref inm) = if_none_match
        && inm.trim() == "*"
    {
        // A write acknowledged from memory is an object that exists, even
        // though the NAS cannot see it yet — the stat below would miss it and
        // let the conditional write through.
        if state.writeback.pending_meta(key).await.is_some() {
            return error_response(
                StatusCode::PRECONDITION_FAILED,
                "PreconditionFailed",
                "At least one of the preconditions you specified did not hold.",
            );
        }
        // Check existence first
        if share.head_object(key).await.is_ok() {
            return error_response(
                StatusCode::PRECONDITION_FAILED,
                "PreconditionFailed",
                "At least one of the preconditions you specified did not hold.",
            );
        }
    }

    // ── Write-back: acknowledge from memory, reach the NAS later ────
    //
    // The whole body has to be in hand for this: the cache answers every read
    // of this key until the flush lands, so a body it cannot hold is a body
    // nobody could serve. Within that bound the backend round trip is pure
    // latency for the client — see `writeback` for what the 200 promises.
    if state.writeback.enabled()
        && let Some(cl) = content_length
        && cl <= state.object_cache.max_object_bytes()
    {
        let data = match collect_body(body, content_length).await {
            Ok(b) => b,
            Err(resp) => return resp,
        };
        let now = crate::smb::ops::now_epoch_secs();
        // Provisional metadata, in the backend's own etag format: the NAS
        // assigns the real mtime when the flush lands, and both cache tiers
        // adopt it then (see `WriteBack::flush_one`).
        let etag = crate::smb::ops::provisional_etag(data.len() as u64, now);
        if state.writeback.enqueue(key, &etag, now, data.clone()).await {
            state.object_cache.insert(key, &etag, now, data);
            let mut builder = Response::builder()
                .status(StatusCode::OK)
                .header("ETag", format!("\"{etag}\""))
                .header("x-spiceio-write", "ASYNC");
            if let Some(ct) = content_type {
                builder = builder.header("Content-Type", ct);
            }
            return builder.body(SpiceioBody::empty()).unwrap();
        }
        // Refused — the queue is at its ceiling or shutdown has begun. Write
        // through synchronously with the body already collected, which is the
        // backpressure a backlogged backend is supposed to apply to clients.
        // Retiring any older pending body first is what keeps its flush from
        // landing on top of this write.
        state.writeback.cancel(key).await;
        return match share.put_object_atomic(key, &data).await {
            Ok(meta) => {
                state
                    .object_cache
                    .store(key, &meta.etag, meta.last_modified, data);
                let mut builder = Response::builder()
                    .status(StatusCode::OK)
                    .header("ETag", format!("\"{}\"", meta.etag));
                if let Some(ct) = content_type {
                    builder = builder.header("Content-Type", ct);
                }
                builder.body(SpiceioBody::empty()).unwrap()
            }
            Err(e) => io_to_s3_write_error(&e),
        };
    }

    // Every path below writes straight to the NAS, so a queued write-back for
    // this key has to be retired first — flushing it afterwards would restore
    // the body this request is replacing. Waits out a flush already in flight.
    state.writeback.cancel(key).await;

    // ── Fast path: collect small bodies and use compound write ──────
    let max_write = share.compound_max_write_size() as u64;

    if let Some(cl) = content_length
        && cl <= max_write
    {
        // Collect the (small) body — through the shared collector, so the
        // size cap and the Content-Length check apply here too.
        let data = match collect_body(body, content_length).await {
            Ok(b) => b,
            Err(resp) => return resp,
        };
        match share.put_object(key, &data).await {
            Ok(meta) => {
                // Write through rather than invalidate. The one thing about a
                // cache client's future that is not a guess is that it will
                // read back what it just wrote — sccache PUTs an object and
                // GETs it on the next build — and the bytes are already in
                // hand, so populating costs a refcount bump and saves a full
                // backend read later. `insert` replaces any prior entry, so
                // this is also the invalidation the overwrite needs.
                state
                    .object_cache
                    .store(key, &meta.etag, meta.last_modified, data.clone());
                let mut builder = Response::builder()
                    .status(StatusCode::OK)
                    .header("ETag", format!("\"{}\"", meta.etag));
                if let Some(ct) = content_type {
                    builder = builder.header("Content-Type", ct);
                }
                return builder.body(SpiceioBody::empty()).unwrap();
            }
            Err(e) => return io_to_s3_write_error(&e),
        }
    }

    // ── Streaming path: buffered WAL write for large or unknown-size bodies ──
    let mut wal = match share.open_wal_write(key).await {
        Ok(w) => w,
        Err(e) => return io_to_s3_write_error(&e),
    };

    let mut write_err = None;

    // Accumulate the body as it streams so the write can populate the cache
    // (see the compound path above for why). Dropped the moment it outgrows
    // what the cache would accept, so a multi-gigabyte upload buffers nothing.
    let cache_cap = state.object_cache.max_object_bytes();
    let mut cache_buf: Option<Vec<u8>> = Some(Vec::new());

    while let Some(frame) = body.frame().await {
        match frame {
            Ok(frame) => {
                if let Ok(data) = frame.into_data()
                    && !data.is_empty()
                {
                    match cache_buf.as_mut() {
                        Some(buf) if buf.len() as u64 + data.len() as u64 <= cache_cap => {
                            buf.extend_from_slice(&data);
                        }
                        // Too large to cache — stop accumulating and give the
                        // memory back rather than carrying it to the end.
                        _ => cache_buf = None,
                    }
                    if let Err(e) = wal.write(&data).await {
                        write_err = Some(e);
                        break;
                    }
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
        return io_to_s3_write_error(&e);
    }

    // A body that ended short of its declared Content-Length must not be
    // published as a complete object. Hyper normally surfaces a truncated
    // HTTP/1.1 body as a frame error (handled above), but this makes the
    // guarantee explicit at the point of no return — after commit, the object
    // is live under the client's key.
    if let Some(cl) = content_length
        && wal.total_size != cl
    {
        crate::serr!(
            "[spiceio] putobject body was {} bytes, Content-Length said {cl}",
            wal.total_size
        );
        wal.abort().await;
        return error_response(
            StatusCode::BAD_REQUEST,
            "IncompleteBody",
            "The request body was shorter or longer than the declared Content-Length.",
        );
    }

    // Commit: flush remaining buffer, rename WAL temp → final path
    let meta = match wal.commit(share).await {
        Ok(m) => m,
        Err(e) => return io_to_s3_write_error(&e),
    };

    // Same write-through as the compound path. The size check is what makes it
    // safe to trust the buffer: a short read or a mid-stream abort would leave
    // it disagreeing with what was actually published.
    match cache_buf {
        Some(buf) if buf.len() as u64 == meta.size => {
            state
                .object_cache
                .store(key, &meta.etag, meta.last_modified, Bytes::from(buf));
        }
        _ => state.object_cache.invalidate_stale(key).await,
    }

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("ETag", format!("\"{}\"", meta.etag));
    if let Some(ct) = content_type {
        builder = builder.header("Content-Type", ct);
    }
    builder.body(SpiceioBody::empty()).unwrap()
}

// ── CopyObject ──────────────────────────────────────────────────────────────

/// Parse an `x-amz-copy-source` header into (bucket, percent-decoded key).
/// Accepts `/bucket/key` and `bucket/key`; strips a `?versionId=…` suffix
/// (versioning is not supported, but clients send it — it must not become
/// part of the key).
fn parse_copy_source(header: &str) -> (String, String) {
    let path = header.split('?').next().unwrap_or(header);
    let path = path.trim_start_matches('/');
    let (bucket, raw_key) = match path.find('/') {
        Some(pos) => (&path[..pos], &path[pos + 1..]),
        None => (path, ""),
    };
    (bucket.to_string(), percent_decode(raw_key))
}

async fn handle_copy_object(
    hdrs: &http::HeaderMap,
    state: &AppState,
    dest_key: &str,
) -> Response<SpiceioBody> {
    let share = &state.share;
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

    let (src_bucket, src_key) = parse_copy_source(&copy_source);

    // The source must name our (single) bucket — without this check a copy
    // from "any-bucket/key" silently reads key from this share.
    if src_bucket != state.bucket {
        return error_response(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified source bucket does not exist.",
        );
    }
    // The destination key was traversal-checked by the router; the source key
    // arrives via this header and needs the same check, or `..` segments
    // could read files outside the share root.
    if src_key.is_empty() || key_has_traversal(&src_key) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "Invalid x-amz-copy-source key",
        );
    }

    // A server-side copy is issued *to the NAS*, which opens the source path
    // itself — a write still queued in memory is not there for it to read.
    if !state
        .writeback
        .flush_key(&src_key, PENDING_FLUSH_TIMEOUT)
        .await
    {
        return service_unavailable(
            "A pending write to the copy source has not reached the backend yet; please retry.",
        );
    }
    // The destination is replaced wholesale, so a write-back queued for it must
    // be retired before it can land on top of the copy.
    state.writeback.cancel(dest_key).await;

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
            state.object_cache.forget(dest_key).await;
            let mut w = XmlWriter::new();
            w.declaration();
            w.open("CopyObjectResult");
            w.element("LastModified", &xml::epoch_to_iso8601(meta.last_modified));
            w.element("ETag", &format!("\"{}\"", meta.etag));
            w.close("CopyObjectResult");
            xml_response(StatusCode::OK, w.finish())
        }
        // Destination write: the source key was resolved above, so a missing
        // path here is about where we are writing, not what we are reading.
        Err(e) => io_to_s3_write_error(&e),
    }
}

// ── DeleteObject ────────────────────────────────────────────────────────────

async fn handle_delete_object(state: &AppState, key: &str) -> Response<SpiceioBody> {
    // Ordered before the delete: cancelling a queued write-back drops it, and
    // waiting out an in-flight one keeps its backend write from landing after
    // the object is gone.
    state.writeback.cancel(key).await;
    match state.share.delete_object(key).await {
        // DeleteObject is idempotent: 204 for a successful delete and for a
        // missing object. Other errors (access denied, I/O) must surface so a
        // client never assumes a still-present object was deleted.
        Ok(()) => {
            state.object_cache.forget(key).await;
            ok_no_content()
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            state.object_cache.forget(key).await;
            ok_no_content()
        }
        Err(e) => io_to_s3_error(&e),
    }
}

// ── HeadObject (with conditional) ───────────────────────────────────────────

async fn handle_head_object(
    hdrs: &http::HeaderMap,
    state: &AppState,
    key: &str,
) -> Response<SpiceioBody> {
    let share = &state.share;
    let if_match = get_header(hdrs, IF_MATCH).map(String::from);
    let if_none_match = get_header(hdrs, IF_NONE_MATCH).map(String::from);
    let if_modified_since = get_header(hdrs, IF_MODIFIED_SINCE).map(String::from);
    let if_unmodified_since = get_header(hdrs, IF_UNMODIFIED_SINCE).map(String::from);

    // A write acknowledged from memory is not on the NAS to be stat'd. Answer
    // from the pending metadata instead — a stat here would 404 an object the
    // client was told it had written.
    if let Some((etag, last_modified, size)) = state.writeback.pending_meta(key).await {
        let etag = format!("\"{etag}\"");
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
        return Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", guess_content_type(key))
            .header("Content-Length", size.to_string())
            .header("ETag", &etag)
            .header("Last-Modified", xml::epoch_to_http_date(last_modified))
            .header("Accept-Ranges", "bytes")
            .body(SpiceioBody::empty())
            .unwrap();
    }

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

async fn handle_delete_objects(body: Bytes, state: &AppState) -> Response<SpiceioBody> {
    let share = &state.share;
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
        state.writeback.cancel(key).await;
        match share.delete_object(key).await {
            Ok(()) => {
                state.object_cache.forget(key).await;
                if !quiet {
                    w.open("Deleted");
                    w.element("Key", key);
                    w.close("Deleted");
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                state.object_cache.forget(key).await;
                if !quiet {
                    w.open("Deleted");
                    w.element("Key", key);
                    w.close("Deleted");
                }
            }
            Err(e) => {
                let code = match e.kind() {
                    io::ErrorKind::PermissionDenied => "AccessDenied",
                    _ => "InternalError",
                };
                w.open("Error");
                w.element("Key", key);
                w.element("Code", code);
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

    // Create the temp directory on the share, and its liveness marker.
    let _ = state
        .share
        .write_temp(&MultipartStore::marker_path(&upload_id), b"")
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
    req_body: Incoming,
    declared_len: Option<u64>,
    state: &AppState,
    key: &str,
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

    // Reject an unknown/completed/aborted uploadId — or one initiated for a
    // different key (the uploadId is scoped to its key, matching the check in
    // CompleteMultipartUpload) — before buffering the body and writing a temp
    // file the upload map would never track.
    match state.multipart.get(upload_id).await {
        Some(u) if u.key == key => {}
        _ => {
            return error_response(
                StatusCode::NOT_FOUND,
                "NoSuchUpload",
                "The specified upload does not exist.",
            );
        }
    }

    let body = match collect_body(req_body, declared_len).await {
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
        return io_to_s3_write_error(&e);
    }

    // The upload can be completed/aborted/reaped while the part body was
    // uploading; `put_part` returns None then. Returning 200 anyway would
    // acknowledge a part that no completion can ever reference — surface
    // NoSuchUpload (per S3) and remove the orphaned temp file.
    if state
        .multipart
        .put_part(
            upload_id,
            part_number,
            body.len() as u64,
            etag.clone(),
            temp_path.clone(),
        )
        .await
        .is_none()
    {
        state.share.delete_temp(&temp_path).await;
        return error_response(
            StatusCode::NOT_FOUND,
            "NoSuchUpload",
            "The specified upload does not exist.",
        );
    }

    Response::builder()
        .status(StatusCode::OK)
        .header("ETag", format!("\"{}\"", etag))
        .body(SpiceioBody::empty())
        .unwrap()
}

/// Record a finished part and build the `CopyPartResult` response, shared by
/// the server-side-copy and streaming paths.
async fn finish_part_copy(
    state: &AppState,
    upload_id: &str,
    part_number: u32,
    temp_path: &str,
    size: u64,
    etag: String,
    last_modified: u64,
) -> Response<SpiceioBody> {
    // The upload may have been completed/aborted/reaped while the source was
    // being copied; acknowledging a part no completion can reference would be
    // a lie, so surface NoSuchUpload and drop the orphaned temp.
    if state
        .multipart
        .put_part(
            upload_id,
            part_number,
            size,
            etag.clone(),
            temp_path.to_string(),
        )
        .await
        .is_none()
    {
        state.share.delete_temp(temp_path).await;
        return error_response(
            StatusCode::NOT_FOUND,
            "NoSuchUpload",
            "The specified upload does not exist.",
        );
    }

    let mut w = XmlWriter::new();
    w.declaration();
    w.open_ns("CopyPartResult", S3_XMLNS);
    w.element("LastModified", &xml::epoch_to_iso8601(last_modified));
    w.element("ETag", &format!("\"{etag}\""));
    w.close("CopyPartResult");
    xml_response(StatusCode::OK, w.finish())
}

/// UploadPartCopy — a multipart part whose content is a (range of a) source
/// object rather than the request body. This is what `aws s3 cp` / `sync` and
/// the SDKs use to copy any object above the multipart threshold (~8 MiB), so
/// without it large server-side copies fail. The part is materialized as a
/// temp file with a real SHA-256 ETag, exactly like a body-sourced part, and
/// the response is a `CopyPartResult` (the ETag lives in the XML body here,
/// not the header — that response-shape difference is why a copy-source PUT
/// must not fall through to the regular UploadPart handler).
async fn handle_upload_part_copy(
    hdrs: &http::HeaderMap,
    state: &AppState,
    key: &str,
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

    // Reject an unknown/completed/aborted uploadId — or one initiated for a
    // different key — before touching the source. The uploadId is scoped to
    // its key (same rule as CompleteMultipartUpload); accepting a part against
    // a mismatched key would create a part no completion could reference.
    match state.multipart.get(upload_id).await {
        Some(u) if u.key == key => {}
        _ => {
            return error_response(
                StatusCode::NOT_FOUND,
                "NoSuchUpload",
                "The specified upload does not exist.",
            );
        }
    }

    // Source key: same parse + validation as CopyObject (bucket match,
    // traversal check, versionId stripped).
    let copy_source = get_header(hdrs, X_AMZ_COPY_SOURCE).unwrap_or_default();
    let (src_bucket, src_key) = parse_copy_source(copy_source);
    if src_bucket != state.bucket {
        return error_response(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "The specified source bucket does not exist.",
        );
    }
    if src_key.is_empty() || key_has_traversal(&src_key) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "Invalid x-amz-copy-source key",
        );
    }

    // A server-side copy is issued *to the NAS*, which opens the source path
    // itself — a write still queued in memory is not there for it to read.
    if !state
        .writeback
        .flush_key(&src_key, PENDING_FLUSH_TIMEOUT)
        .await
    {
        return service_unavailable(
            "A pending write to the copy source has not reached the backend yet; please retry.",
        );
    }

    // Optional byte range of the source for this part. Unlike Range, S3's
    // copy-source-range requires both bounds; we resolve/clamp in read_range.
    let range = match get_header(hdrs, X_AMZ_COPY_SOURCE_RANGE) {
        Some(r) => match parse_range(r).and_then(|spec| match (spec.start, spec.end) {
            (Some(s), Some(e)) => Some((s, e)),
            _ => None,
        }) {
            Some(pair) => Some(pair),
            None => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "InvalidArgument",
                    "Invalid x-amz-copy-source-range",
                );
            }
        },
        None => None,
    };

    // Preflight the source size and resolve an explicit byte range *before*
    // reading, so a part copy never buffers more than MAX_BUFFERED_BODY. A
    // range-less copy (`x-amz-copy-source-range` absent) would otherwise pull
    // the whole source object into memory and only reject it afterward — a
    // client could omit the range to force buffering an arbitrarily large
    // object and OOM the proxy.
    let src_meta = match state.share.head_object(&src_key).await {
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
    let size = src_meta.size;
    let (start, end) = match range {
        Some((s, e)) => {
            if s > e || s >= size {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "InvalidRange",
                    "The x-amz-copy-source-range is not satisfiable",
                );
            }
            (s, e.min(size - 1)) // size > 0 here since s < size
        }
        None if size == 0 => (0, 0), // empty source → empty part
        None => (0, size - 1),
    };
    let span = if size == 0 { 0 } else { end - start + 1 };
    if span > MAX_BUFFERED_BODY as u64 {
        return error_response(
            StatusCode::BAD_REQUEST,
            "EntityTooLarge",
            "Copy-source range exceeds the maximum part size",
        );
    }

    let temp_path = MultipartStore::temp_part_path(upload_id, part_number);

    // Server-side copy first: the NAS copies the range into the part file
    // itself, so nothing crosses this proxy. This is the dominant cost of
    // `aws s3 cp`/`sync` on a large object, which copies it part by part.
    //
    // The part's ETag is then derived from its size and timestamp rather than
    // a content hash, because the content never passes through us. Both forms
    // are opaque — the completion identifies parts by number, and integrity is
    // enforced by the per-part size check in `assemble_parts` — but the ETag
    // for a given part does depend on which path produced it.
    match state
        .share
        .copy_range_to_temp(&src_key, start, span, &temp_path)
        .await
    {
        Ok(Some(meta)) => {
            return finish_part_copy(
                state,
                upload_id,
                part_number,
                &temp_path,
                meta.size,
                meta.etag,
                meta.last_modified,
            )
            .await;
        }
        Ok(None) => {} // Not supported — fall through to streaming.
        // Writes the part temp; the source key was validated above, so a
        // missing path here is the destination and must stay retryable.
        Err(e) => return io_to_s3_write_error(&e),
    }

    // Read exactly the validated range — bounded by the check above, so memory
    // is capped regardless of the source object's size.
    let data = if span == 0 {
        Vec::new()
    } else {
        match state.share.read_range(&src_key, Some((start, end))).await {
            Ok((_, d)) => d,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return error_response(
                    StatusCode::NOT_FOUND,
                    "NoSuchKey",
                    "The specified source key does not exist.",
                );
            }
            Err(e) if e.kind() == io::ErrorKind::InvalidInput => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "InvalidRange",
                    "The x-amz-copy-source-range is not satisfiable",
                );
            }
            Err(e) => return io_to_s3_write_error(&e),
        }
    };

    // Hash on the blocking pool. Move `data` into the task and hand it back
    // alongside the ETag rather than cloning it — `data` is a `Vec` (a real
    // copy), so cloning would double peak memory for every part.
    let (etag, data) = match tokio::task::spawn_blocking(move || {
        let etag = crate::crypto::hex_encode(&crate::crypto::sha256(&data));
        (etag, data)
    })
    .await
    {
        Ok(pair) => pair,
        Err(e) => {
            crate::serr!("[spiceio] upload-part-copy hash task failed: {e}");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "hash failed",
            );
        }
    };

    if let Err(e) = state.share.write_temp(&temp_path, &data).await {
        return io_to_s3_write_error(&e);
    }
    finish_part_copy(
        state,
        upload_id,
        part_number,
        &temp_path,
        data.len() as u64,
        etag,
        src_meta.last_modified,
    )
    .await
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

    // An uploadId is scoped to the key it was initiated for. Completing it
    // against a different key would assemble the object at a path the client
    // never initiated — S3 treats the pair as nonexistent.
    if upload.key != key {
        return error_response(
            StatusCode::NOT_FOUND,
            "NoSuchUpload",
            "The specified upload does not exist for this key.",
        );
    }

    // Parse the completion XML to get ordered parts
    let body_str = String::from_utf8_lossy(&body_bytes);
    let part_numbers: Vec<u32> = xml::extract_sections(&body_str, "<Part>", "</Part>")
        .iter()
        .filter_map(|section| {
            xml::extract_element(section, "PartNumber").and_then(|s| s.parse().ok())
        })
        .collect();

    // S3 rejects a completion naming zero parts; assembling it would quietly
    // produce an empty object.
    if part_numbers.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "You must specify at least one part",
        );
    }

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
    //
    // Each part is paired with the size we acknowledged to the client when it
    // was uploaded. `assemble_parts` checks every part against that size while
    // streaming and aborts before the WAL is renamed into place, so a part that
    // changed on the share since upload fails the completion without ever
    // publishing a corrupt object — and without a compensating delete that
    // could race a concurrent writer for the same key. The validation loop
    // above already proved every part number resolves.
    let parts: Vec<(&str, u64)> = part_numbers
        .iter()
        .filter_map(|pn| upload.parts.get(pn))
        .map(|p| (p.temp_path.as_str(), p.size))
        .collect();

    state.writeback.cancel(key).await;
    let meta = match state.share.assemble_parts(key, &parts).await {
        Ok(m) => m,
        Err(e) => return io_to_s3_write_error(&e),
    };

    state.object_cache.forget(key).await;

    // Only now remove the upload from the store
    let upload = state.multipart.complete(upload_id).await;

    // Clean up temp files (best effort)
    if let Some(upload) = upload {
        for part in upload.parts.values() {
            state.share.delete_temp(&part.temp_path).await;
        }
    }
    let marker_path = MultipartStore::marker_path(upload_id);
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
    let marker_path = MultipartStore::marker_path(upload_id);
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
        //   - ResourceBusy: sharing violation under concurrent access, or SMB
        //     server capacity (too many sessions / insufficient resources /
        //     request not accepted) — we surface the NTSTATUS detail in the
        //     io error; healer / connect backoff will retry.
        //   - BrokenPipe/ConnectionReset/ConnectionAborted/NotConnected: the
        //     SMB server dropped a pool connection (common under heavy
        //     concurrent load); the healer reconnects it, so the client should
        //     just retry instead of seeing a hard 500.
        //   - TimedOut: a read/write timed out and we poisoned the connection;
        //     a retry lands on a healthy one.
        //   - UnexpectedEof: an overwhelmed NAS closed the connection with a
        //     FIN mid-response ("early eof"); the healer reconnects it, so the
        //     client should back off and retry rather than see a hard 500.
        //   - ConnectionRefused: TCP connect refused (server unreachable or
        //     temporarily out of capacity/backlog); connect retry + healer
        //     handle it.
        //
        // Prefer absorbing these *inside* SMB ops (see `retry_read_open` /
        // `retry_write_op`) so clients like sccache never see a temporary
        // error on a one-shot HEAD/GET/PUT. This arm is the last resort when
        // the retry budget is exhausted.
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ResourceBusy
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::NotConnected
        | io::ErrorKind::TimedOut
        | io::ErrorKind::UnexpectedEof => {
            crate::slog!("[spiceio] transient (retry): {e}");
            service_unavailable("The request could not be completed; please retry.")
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

/// Map an SMB error from an object-*write* path to an S3 response.
///
/// Identical to [`io_to_s3_error`] except for `NotFound`, which cannot mean
/// what 404 NoSuchKey says it means: a PUT creates the key, so "the specified
/// key does not exist" is never a truthful description of why the write failed.
/// The real cause is a missing *path* — a parent directory that vanished, or a
/// server that transiently could not resolve one — which is retryable, so it is
/// reported as such.
///
/// This matters beyond tidiness. sccache records a 404 on write as a cache
/// write error and moves on, so the artifact is silently never cached and the
/// next build recompiles it, while the build itself still succeeds. A 503 is
/// retried instead.
///
/// Only for the destination of a write. CopyObject's *source* lookup keeps
/// [`io_to_s3_error`], where a missing key really is 404.
fn io_to_s3_write_error(e: &io::Error) -> Response<SpiceioBody> {
    if e.kind() == io::ErrorKind::NotFound {
        crate::slog!("[spiceio] write path not found (reporting retryable): {e}");
        return service_unavailable("The write could not be completed; please retry.");
    }
    io_to_s3_error(e)
}

/// 503 SlowDown with `Retry-After: 1` — used when the SMB backend is not yet
/// ready at startup, and as the last-resort mapping for exhausted transient
/// retries. sccache classifies temporary storage errors; returning a clean
/// retryable status (rather than dropping the TCP connection) lets a client
/// that retries the check succeed once the NAS is up.
pub fn service_unavailable(message: &str) -> Response<SpiceioBody> {
    let mut resp = error_response(StatusCode::SERVICE_UNAVAILABLE, "SlowDown", message);
    // hyper Response builders don't re-open; insert on the built response.
    resp.headers_mut().insert(
        http::header::RETRY_AFTER,
        http::HeaderValue::from_static("1"),
    );
    resp
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
///
/// `declared_len` is the request's `Content-Length`, when it sent one. A body
/// that does not match it is refused here rather than by each handler: every
/// buffered path (UploadPart, CompleteMultipartUpload, multi-delete, the small
/// PutObject fast path) is a point of no return that would otherwise record a
/// short body as if it were whole — an UploadPart in particular would
/// acknowledge a part size that no later completion can reproduce.
async fn collect_body(
    mut body: Incoming,
    declared_len: Option<u64>,
) -> Result<Bytes, Response<SpiceioBody>> {
    if let Some(declared) = declared_len
        && declared > MAX_BUFFERED_BODY as u64
    {
        // Knowable before a byte is read — no reason to buffer 256 MiB first.
        return Err(error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "EntityTooLarge",
            "Request body exceeds the maximum buffered size",
        ));
    }
    // Size the buffer from the declared length so a large part does not walk
    // up through ~20 reallocations. Bounded, so a lying Content-Length cannot
    // force a big allocation up front.
    let mut buf: Vec<u8> =
        Vec::with_capacity(declared_len.unwrap_or(0).min(8 * 1024 * 1024) as usize);
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
                // A failed body read must not be treated as an empty body —
                // that would let mutating ops (UploadPart, CompleteMultipartUpload,
                // multi-delete) silently proceed on a truncated request and
                // return success. Surface it as an incomplete-body error.
                crate::serr!("[spiceio] body collect error: {e}");
                return Err(error_response(
                    StatusCode::BAD_REQUEST,
                    "IncompleteBody",
                    "The request body could not be read completely.",
                ));
            }
        }
    }
    if let Some(declared) = declared_len
        && buf.len() as u64 != declared
    {
        crate::serr!(
            "[spiceio] request body was {} bytes, Content-Length said {declared}",
            buf.len()
        );
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "IncompleteBody",
            "The request body did not match the declared Content-Length.",
        ));
    }
    Ok(Bytes::from(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Pre-admission cache probe gating ─────────────────────────────

    #[test]
    fn plain_object_query_admits_only_real_object_reads() {
        assert!(is_plain_object_query(""));
        assert!(is_plain_object_query("response-content-type=text/plain"));
        // Sub-resources must not be answered with the object's body.
        for q in [
            "acl",
            "tagging",
            "uploadId=abc",
            "legal-hold",
            "retention",
            "torrent",
            "partNumber=2",
            "select",
        ] {
            assert!(!is_plain_object_query(q), "{q} treated as a plain GET");
        }
        // A sub-resource name appearing inside a *value* is not a selector —
        // same rule `has_query_flag` applies at the dispatch below.
        assert!(is_plain_object_query("prefix=my-acl-doc"));
    }

    #[test]
    fn every_dispatched_subresource_is_gated() {
        // The pre-admission probe runs before the sub-resource dispatch, so it
        // has to reject everything that dispatch routes on. Reading the router's
        // own source keeps the two in step: adding a `has_query_flag` branch
        // without listing it here fails this test instead of quietly answering
        // that sub-resource with an object body.
        let src = include_str!("router.rs");
        let mut missing = Vec::new();
        for (i, _) in src.match_indices("has_query_flag(query, \"") {
            let rest = &src[i + "has_query_flag(query, \"".len()..];
            let Some(end) = rest.find('"') else { continue };
            let flag = &rest[..end];
            if !OBJECT_SUBRESOURCES.contains(&flag) && !missing.contains(&flag) {
                missing.push(flag);
            }
        }
        assert!(
            missing.is_empty(),
            "sub-resources dispatched but not gated out of the pre-admission \
             cache probe: {missing:?} — add them to OBJECT_SUBRESOURCES"
        );
    }

    // ── Pending-write listing overlay ────────────────────────────────

    fn obj(key: &str, size: u64, last_modified: u64) -> crate::smb::ops::ObjectInfo {
        crate::smb::ops::ObjectInfo {
            key: key.into(),
            size,
            last_modified,
            etag: "on-nas".into(),
        }
    }

    fn pending(key: &str, size: u64, last_modified: u64) -> (String, String, u64, u64) {
        (key.into(), "pending-etag".into(), last_modified, size)
    }

    #[test]
    fn overlay_adds_keys_the_backend_walk_could_not_see() {
        // The anomaly this exists to prevent: PUT then LIST concluding the
        // write vanished, because it is acknowledged but not yet on the NAS.
        let mut objects = vec![obj("a.o", 1, 100)];
        let mut prefixes = Vec::new();
        merge_pending(
            "",
            None,
            vec![pending("b.o", 42, 200)],
            &mut objects,
            &mut prefixes,
        );
        assert_eq!(objects.len(), 2);
        let added = objects.iter().find(|o| o.key == "b.o").unwrap();
        assert_eq!((added.size, added.last_modified), (42, 200));
        assert_eq!(added.etag, "pending-etag");
    }

    #[test]
    fn overlay_replaces_a_listed_key_rather_than_duplicating_it() {
        // An overwrite: the NAS still reports the old size, but the pending
        // body is what every read of this key now returns.
        let mut objects = vec![obj("a.o", 1, 100)];
        let mut prefixes = Vec::new();
        merge_pending(
            "",
            None,
            vec![pending("a.o", 999, 300)],
            &mut objects,
            &mut prefixes,
        );
        assert_eq!(objects.len(), 1, "duplicated a key that was already listed");
        assert_eq!((objects[0].size, objects[0].last_modified), (999, 300));
    }

    #[test]
    fn overlay_honors_the_prefix() {
        let mut objects = Vec::new();
        let mut prefixes = Vec::new();
        merge_pending(
            "keep/",
            None,
            vec![pending("keep/a.o", 1, 1), pending("other/b.o", 1, 1)],
            &mut objects,
            &mut prefixes,
        );
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].key, "keep/a.o");
    }

    #[test]
    fn overlay_rolls_deeper_keys_into_common_prefixes() {
        // With a delimiter the backend walk reports a directory, not the keys
        // under it; a pending key has to be folded the same way or a listing
        // grows an entry the un-delimited walk would never produce.
        let mut objects = Vec::new();
        let mut prefixes = vec!["p/existing/".to_string()];
        merge_pending(
            "p/",
            Some("/"),
            vec![
                pending("p/deep/a.o", 1, 1),
                pending("p/deep/b.o", 1, 1),
                pending("p/existing/c.o", 1, 1),
                pending("p/flat.o", 7, 1),
            ],
            &mut objects,
            &mut prefixes,
        );
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].key, "p/flat.o");
        prefixes.sort();
        assert_eq!(
            prefixes,
            vec!["p/deep/", "p/existing/"],
            "duplicated a prefix"
        );
    }

    #[test]
    fn overlay_without_a_delimiter_lists_deep_keys_directly() {
        let mut objects = Vec::new();
        let mut prefixes = Vec::new();
        merge_pending(
            "",
            None,
            vec![pending("a/b/c.o", 5, 1)],
            &mut objects,
            &mut prefixes,
        );
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].key, "a/b/c.o");
        assert!(prefixes.is_empty());
    }

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
    fn parse_copy_source_forms() {
        // Leading slash and bare forms.
        assert_eq!(
            parse_copy_source("/bucket/a/b.txt"),
            ("bucket".into(), "a/b.txt".into())
        );
        assert_eq!(
            parse_copy_source("bucket/a/b.txt"),
            ("bucket".into(), "a/b.txt".into())
        );
        // Percent-decoding applies to the key.
        assert_eq!(
            parse_copy_source("/bucket/a%20b.txt"),
            ("bucket".into(), "a b.txt".into())
        );
        // versionId suffix is stripped, never folded into the key.
        assert_eq!(
            parse_copy_source("/bucket/k.txt?versionId=abc123"),
            ("bucket".into(), "k.txt".into())
        );
        // Bucket-only (no key) yields an empty key, which the handler rejects.
        assert_eq!(parse_copy_source("/bucket"), ("bucket".into(), "".into()));
        // Traversal survives decoding for the handler's check to catch.
        let (_, k) = parse_copy_source("/bucket/%2e%2e/etc/passwd");
        assert!(key_has_traversal(&k));
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
        // Connection and capacity errors (dropped conns under load, TCP refused,
        // server session limits) must surface as retryable 503, not hard 500.
        for kind in [
            io::ErrorKind::ConnectionRefused,
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
    fn io_to_s3_write_error_never_answers_404_for_a_missing_path() {
        // A PUT creates the key, so NoSuchKey cannot describe why it failed.
        // Answering 404 makes sccache record a cache write error and drop the
        // artifact silently; 503 gets retried instead.
        let resp =
            io_to_s3_write_error(&io::Error::new(io::ErrorKind::NotFound, "not found: a\\b"));
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn io_to_s3_write_error_leaves_every_other_kind_alone() {
        // Only NotFound is reinterpreted; the write path must not soften real
        // failures into retryable ones.
        for (kind, expected) in [
            (io::ErrorKind::PermissionDenied, StatusCode::FORBIDDEN),
            (io::ErrorKind::ResourceBusy, StatusCode::SERVICE_UNAVAILABLE),
            (
                io::ErrorKind::ConnectionReset,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                io::ErrorKind::InvalidData,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ] {
            let resp = io_to_s3_write_error(&io::Error::new(kind, "x"));
            assert_eq!(resp.status(), expected, "{kind:?}");
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
