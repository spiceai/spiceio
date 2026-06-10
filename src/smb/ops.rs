//! High-level SMB file operations used by the S3 layer.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;

use super::client::SmbClient;
use super::pool::SmbPool;
use super::protocol::*;

/// Max times a single op rides the back-off ladder on transient resets before
/// giving up — enough halving steps (4 MiB → 64 KiB) plus headroom, while still
/// terminating well within a client's request timeout if the server is down.
const MAX_RESET_RETRIES: u32 = 16;

/// A connected share session backed by a pool of SMB connections.
///
/// Each operation picks a connection from the pool via round-robin, so
/// concurrent S3 requests fan out across multiple TCP streams instead of
/// serializing on a single mutex.
#[derive(Clone)]
pub struct ShareSession {
    pool: Arc<SmbPool>,
}

/// An open file handle for streaming reads or writes.
/// Pinned to the specific connection that opened the file.
pub struct FileHandle {
    client: Arc<SmbClient>,
    /// Pool handle, used to report large-read resets so the adaptive read size
    /// backs off for subsequent operations.
    pool: Arc<SmbPool>,
    tree_id: u32,
    file_id: [u8; 16],
    pub meta: ObjectMeta,
    pub file_size: u64,
    /// Per-op chunk size (adaptive: `min(negotiated max, in-flight budget)`).
    pub max_chunk: u32,
}

impl ShareSession {
    /// Connect to a share on every connection in the pool.
    pub async fn connect(pool: Arc<SmbPool>, share: &str) -> io::Result<Self> {
        pool.connect_share(share).await?;
        Ok(Self { pool })
    }

    /// Reconnect any poisoned pool connections. Run periodically by a
    /// background task so the pool recovers from transient SMB outages.
    pub async fn heal(&self) {
        self.pool.heal().await;
    }

    /// Pick the next connection + tree_id via round-robin (owned `Arc`).
    fn pick(&self) -> (Arc<SmbClient>, u32) {
        self.pool.pick()
    }

    /// Max read size for compound operations (64KB cap for compatibility).
    /// Used by the S3 layer to decide compound vs. streaming path.
    pub fn compound_max_read_size(&self) -> u32 {
        self.pool.compound_max_read_size
    }

    /// Max write size for compound operations (64KB cap for compatibility).
    /// Used by the S3 layer to decide compound vs. streaming path.
    pub fn compound_max_write_size(&self) -> u32 {
        self.pool.compound_max_write_size
    }

    /// Compound Create+Read+Close. Returns metadata and data bytes.
    /// File handle is already closed on return. For files larger than
    /// `compound_max_read_size`, only the first chunk is returned.
    pub async fn get_object_compound(
        &self,
        key: &str,
        max_read: u32,
    ) -> io::Result<(ObjectMeta, Bytes)> {
        let (client, tree_id) = self.pick();
        let smb_path = to_smb_path(key);
        let (cr, data) = client
            .create_read_close(tree_id, &smb_path, max_read)
            .await?;

        let meta = ObjectMeta {
            size: cr.file_size,
            last_modified: filetime_to_epoch_secs(cr.last_write_time),
            etag: etag_for(cr.file_size, cr.last_write_time),
            content_type: guess_content_type(key),
        };

        Ok((meta, data))
    }

    // ── Streaming file operations ───────────────────────────────────────

    /// Open a file for streaming reads. Returns a handle pinned to one connection.
    pub async fn open_read(&self, key: &str) -> io::Result<FileHandle> {
        let smb_path = to_smb_path(key);
        // Resilient open: under heavy concurrent load on a degraded NAS the
        // create can hit a transient reset; retry on a fresh connection so the
        // initial open of a streaming GET isn't lost (the client may not retry).
        // A genuine NotFound is not a reset and returns immediately.
        let (client, tree_id, file) = self
            .retry_read_open(|client, tree_id| {
                let smb_path = smb_path.clone();
                async move {
                    let file = client
                        .create(
                            tree_id,
                            &smb_path,
                            DesiredAccess::GenericRead as u32,
                            ShareAccess::All as u32,
                            CreateDisposition::Open as u32,
                            CreateOptions::NonDirectoryFile as u32,
                        )
                        .await?;
                    Ok((client, tree_id, file))
                }
            })
            .await?;

        let meta = ObjectMeta {
            size: file.file_size,
            last_modified: filetime_to_epoch_secs(file.last_write_time),
            etag: etag_for(file.file_size, file.last_write_time),
            content_type: guess_content_type(key),
        };

        Ok(FileHandle {
            client,
            pool: Arc::clone(&self.pool),
            tree_id,
            file_id: file.file_id,
            file_size: file.file_size,
            max_chunk: self.pool.read_chunk_size(),
            meta,
        })
    }

    /// Read the inclusive byte range `[start, end]` of `key` into memory,
    /// along with the source's metadata. Used by UploadPartCopy, where the
    /// part is fully materialized as a temp file anyway (mirroring the regular
    /// UploadPart path, which buffers the part to hash it). Callers cap the
    /// range to bound memory; pass `None` for the whole object.
    ///
    /// Returns the source `ObjectMeta` and the range bytes. A genuine read
    /// reset surfaces as a retryable error (the client retries the part).
    pub async fn read_range(
        &self,
        key: &str,
        range: Option<(u64, u64)>,
    ) -> io::Result<(ObjectMeta, Vec<u8>)> {
        let handle = self.open_read(key).await?;
        let meta = handle.meta.clone();
        let file_size = handle.file_size;

        let (start, end) = match range {
            Some((s, e)) => {
                // copy-source-range names explicit, in-bounds positions.
                if s > e || s >= file_size {
                    let _ = handle.close().await;
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "copy-source-range is not satisfiable",
                    ));
                }
                (s, e.min(file_size.saturating_sub(1)))
            }
            None => {
                if file_size == 0 {
                    let _ = handle.close().await;
                    return Ok((meta, Vec::new()));
                }
                (0, file_size - 1)
            }
        };

        let stream_end = end + 1;
        let chunk = handle.max_chunk.max(1);
        let mut buf: Vec<u8> = Vec::with_capacity((stream_end - start) as usize);
        let mut offset = start;
        let result: io::Result<()> = async {
            while offset < stream_end {
                let chunks = handle
                    .read_pipeline(offset, chunk, stream_end - offset)
                    .await?;
                if chunks.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "source ended before the requested range",
                    ));
                }
                for c in chunks {
                    if c.is_empty() {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "short read while copying range",
                        ));
                    }
                    // The last pipelined chunk can overshoot `end` (reads are
                    // chunk-aligned); take only the bytes within the range.
                    let take = ((stream_end - offset) as usize).min(c.len());
                    buf.extend_from_slice(&c[..take]);
                    offset += take as u64;
                    if offset >= stream_end {
                        break;
                    }
                }
            }
            Ok(())
        }
        .await;
        let _ = handle.close().await;
        result?;
        Ok((meta, buf))
    }

    /// Open (or create) a file for streaming writes. Handle pinned to one connection.
    pub async fn open_write(&self, key: &str) -> io::Result<FileHandle> {
        let (client, tree_id) = self.pick();
        let smb_path = to_smb_path(key);
        self.ensure_parent_dirs_on(&client, tree_id, &smb_path)
            .await?;

        let file = client
            .create(
                tree_id,
                &smb_path,
                DesiredAccess::GenericWrite as u32,
                ShareAccess::Read as u32,
                CreateDisposition::OverwriteIf as u32,
                CreateOptions::NonDirectoryFile as u32,
            )
            .await?;

        let meta = ObjectMeta {
            size: 0,
            last_modified: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            etag: String::new(),
            content_type: guess_content_type(key),
        };

        Ok(FileHandle {
            client: Arc::clone(&client),
            pool: Arc::clone(&self.pool),
            tree_id,
            file_id: file.file_id,
            file_size: 0,
            max_chunk: self.pool.write_chunk_size(),
            meta,
        })
    }

    // ── Buffered file operations (existing) ─────────────────────────────

    /// List objects under a prefix. `prefix` uses forward-slash separators.
    ///
    /// With a delimiter (the common `delimiter=/` case), one directory level
    /// is listed and subdirectories become common prefixes. Without a
    /// delimiter, S3 semantics require *every* key under the prefix, so the
    /// walk descends into subdirectories (breadth-first). Spiceio-internal
    /// bookkeeping directories (`.spiceio-wal/`, `.spiceio-uploads/`) at the
    /// share root are hidden from both forms.
    pub async fn list_objects(
        &self,
        prefix: &str,
        delimiter: Option<&str>,
    ) -> io::Result<(Vec<ObjectInfo>, Vec<String>)> {
        // Backstops for the recursive walk so a pathological tree cannot pin
        // unbounded memory: fail loudly rather than return a silently
        // incomplete listing a client would trust (IsTruncated=false).
        const MAX_LIST_DIRS: usize = 100_000;
        const MAX_LIST_ENTRIES: usize = 1_000_000;

        let (client, tree_id) = self.pick();
        let smb_path = to_smb_path(prefix);
        let (dir_path, pattern) = split_dir_pattern(&smb_path);

        let mut objects = Vec::new();
        let mut common_prefixes = Vec::new();

        // Work queue of (SMB directory path, query pattern). The first level
        // uses the prefix-derived pattern; descended levels list everything
        // (their full subtree already shares the requested prefix).
        let mut queue: std::collections::VecDeque<(String, String)> =
            std::collections::VecDeque::new();
        queue.push_back((dir_path, pattern));
        let mut first = true;
        let mut dirs_visited = 0usize;

        while let Some((dir_path, pattern)) = queue.pop_front() {
            dirs_visited += 1;
            if dirs_visited > MAX_LIST_DIRS
                || objects.len() + common_prefixes.len() > MAX_LIST_ENTRIES
            {
                return Err(io::Error::other(format!(
                    "listing under prefix '{prefix}' exceeds {MAX_LIST_DIRS} directories or {MAX_LIST_ENTRIES} entries; use a narrower prefix or a delimiter"
                )));
            }

            let dir = match client
                .create(
                    tree_id,
                    &dir_path,
                    DesiredAccess::GenericRead as u32 | DesiredAccess::ReadAttributes as u32,
                    ShareAccess::All as u32,
                    CreateDisposition::Open as u32,
                    CreateOptions::DirectoryFile as u32,
                )
                .await
            {
                Ok(d) => d,
                // The top-level open always propagates (NotFound → empty
                // listing at the router). For a subdirectory, only a vanished
                // dir (NotFound) is skipped — that matches S3's view of a key
                // concurrently deleted mid-walk. Any other error
                // (PermissionDenied, an SMB protocol failure, …) propagates:
                // silently dropping it would return an incomplete listing the
                // client trusts as complete (IsTruncated=false).
                Err(e) if first || e.kind() != io::ErrorKind::NotFound => return Err(e),
                Err(_) => continue,
            };

            let entries = client
                .query_directory(tree_id, &dir.file_id, &pattern)
                .await;
            let _ = client.close(tree_id, &dir.file_id).await;
            let entries = match entries {
                Ok(e) => e,
                // Same rule as the open above: tolerate only a vanished
                // subdirectory; propagate every other error rather than
                // truncate the listing silently.
                Err(e) if first || e.kind() != io::ErrorKind::NotFound => return Err(e),
                Err(_) => continue,
            };
            first = false;

            for entry in entries {
                // Hide spiceio's own bookkeeping dirs at the share root —
                // recursing into them would surface WAL temps and multipart
                // part files as objects.
                if dir_path.is_empty()
                    && entry.is_directory()
                    && (entry.file_name == WAL_DIR || entry.file_name == UPLOADS_DIR)
                {
                    continue;
                }

                let key = if dir_path.is_empty() {
                    entry.file_name.replace('\\', "/")
                } else {
                    format!(
                        "{}/{}",
                        dir_path.replace('\\', "/"),
                        entry.file_name.replace('\\', "/")
                    )
                };

                if entry.is_directory() {
                    if delimiter.is_some() {
                        common_prefixes.push(format!("{}/", key));
                    } else {
                        queue.push_back((to_smb_path(&key), "*".to_string()));
                    }
                } else {
                    objects.push(ObjectInfo {
                        key,
                        size: entry.file_size,
                        last_modified: filetime_to_epoch_secs(entry.last_write_time),
                        etag: etag_for(entry.file_size, entry.last_write_time),
                    });
                }
            }
        }

        Ok((objects, common_prefixes))
    }

    /// Put object (write file). Uses compound Create+Write+Close for small
    /// files, falling back to sequential for larger files.
    pub async fn put_object(&self, key: &str, data: &[u8]) -> io::Result<ObjectMeta> {
        let (client, tree_id) = self.pick();
        let smb_path = to_smb_path(key);
        self.ensure_parent_dirs_on(&client, tree_id, &smb_path)
            .await?;

        let compound_max = self.pool.compound_max_write_size as usize;
        let chunk_size = self.pool.write_chunk_size() as usize;

        if data.len() <= compound_max {
            // Compound Create+Write+Close — 1 round trip, metadata from Close
            let cl = client.create_write_close(tree_id, &smb_path, data).await?;
            return Ok(ObjectMeta {
                size: data.len() as u64,
                last_modified: filetime_to_epoch_secs(cl.last_write_time),
                etag: etag_for(data.len() as u64, cl.last_write_time),
                content_type: guess_content_type(key),
            });
        }

        // Large file — sequential write
        let file = client
            .create(
                tree_id,
                &smb_path,
                DesiredAccess::GenericWrite as u32,
                ShareAccess::Read as u32,
                CreateDisposition::OverwriteIf as u32,
                CreateOptions::NonDirectoryFile as u32,
            )
            .await?;

        // Write all chunks, then close the handle on every path. On a write
        // error, also remove the partial/corrupt file rather than leaking the
        // handle and leaving torn data on the share.
        let write_result: io::Result<()> = async {
            let mut offset = 0u64;
            for chunk in data.chunks(chunk_size) {
                client.write(tree_id, &file.file_id, offset, chunk).await?;
                offset += chunk.len() as u64;
            }
            Ok(())
        }
        .await;
        let _ = client.close(tree_id, &file.file_id).await;
        if let Err(e) = write_result {
            if is_reset(&e) {
                self.pool.note_write_reset();
            }
            // Clean up the partial object on a fresh connection — the one that
            // just failed is likely poisoned, so reusing it would no-op the
            // delete and leave the torn file behind.
            let (dc, dt) = self.pick_live().await;
            let _ = Self::delete_object_path_on(&dc, dt, &smb_path).await;
            return Err(e);
        }

        let meta = self.head_object(key).await?;
        Ok(ObjectMeta {
            size: data.len() as u64,
            last_modified: meta.last_modified,
            etag: meta.etag,
            content_type: guess_content_type(key),
        })
    }

    /// Delete an object. Compound Create(DELETE_ON_CLOSE)+Close in 1 round trip.
    pub async fn delete_object(&self, key: &str) -> io::Result<()> {
        let (client, tree_id) = self.pick();
        let smb_path = to_smb_path(key);
        let _ = client
            .create_close(
                tree_id,
                &smb_path,
                DesiredAccess::Delete as u32,
                ShareAccess::Delete as u32,
                CreateDisposition::Open as u32,
                CreateOptions::NonDirectoryFile as u32 | CreateOptions::DeleteOnClose as u32,
            )
            .await?;
        Ok(())
    }

    /// Head object (metadata only). Compound Create+Close in 1 round trip.
    pub async fn head_object(&self, key: &str) -> io::Result<ObjectMeta> {
        let (client, tree_id) = self.pick();
        let smb_path = to_smb_path(key);
        let (cr, _) = client
            .create_close(
                tree_id,
                &smb_path,
                DesiredAccess::ReadAttributes as u32,
                ShareAccess::All as u32,
                CreateDisposition::Open as u32,
                CreateOptions::NonDirectoryFile as u32,
            )
            .await?;

        Ok(ObjectMeta {
            size: cr.file_size,
            last_modified: filetime_to_epoch_secs(cr.last_write_time),
            etag: etag_for(cr.file_size, cr.last_write_time),
            content_type: guess_content_type(key),
        })
    }

    /// Copy a file on the SMB share, streaming through a WAL temp file
    /// (pipelined reads → pipelined writes → atomic rename).
    ///
    /// Never buffers the whole object in memory (the previous implementation
    /// did, so copying a multi-GB object could OOM the proxy), and the
    /// destination is only replaced once the copy has fully landed — a failed
    /// copy leaves an existing destination object untouched instead of
    /// truncated or deleted.
    pub async fn copy_object(&self, src_key: &str, dst_key: &str) -> io::Result<ObjectMeta> {
        let src_path = to_smb_path(src_key);
        let mut wal = self.open_wal_write(dst_key).await?;

        // Same guard as assemble_parts: protect the per-batch `div_ceil`
        // inside stream_part_into_wal from a zero-floored pool entry.
        if self.pool.max_read_size == 0 {
            wal.abort().await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "copy_object: pool max_read_size = 0",
            ));
        }

        if let Err(e) = self.stream_part_into_wal(&mut wal, &src_path).await {
            wal.abort().await;
            return Err(e);
        }

        let meta = wal.commit(self).await?;
        Ok(ObjectMeta {
            content_type: guess_content_type(dst_key),
            ..meta
        })
    }

    /// Write a temp part file for multipart upload.
    pub async fn write_temp(&self, smb_path: &str, data: &[u8]) -> io::Result<()> {
        let (client, tree_id) = self.pick();
        self.ensure_parent_dirs_on(&client, tree_id, smb_path)
            .await?;

        let compound_max = self.pool.compound_max_write_size as usize;
        if data.len() <= compound_max {
            let _ = client.create_write_close(tree_id, smb_path, data).await?;
            return Ok(());
        }

        // Large part — resilient windowed write that rides the back-off ladder
        // internally so a single UploadPart survives a degraded NAS instead of
        // failing to a 503 the client (e.g. the AWS CLI, with its small retry
        // budget) must absorb.
        self.write_all_resilient(smb_path, data).await
    }

    /// Write `data` to `smb_path` (truncating any existing file) in
    /// in-flight-sized windows. On a reset, back off the adaptive write size,
    /// reconnect on a fresh pool connection, and retry the same window — so a
    /// single large write rides the back-off ladder down to a sustainable burst
    /// internally rather than surfacing a retryable error. The handle is always
    /// closed; the partial file is removed on failure. Bounded by MAX_RESET_RETRIES,
    /// which each landed window refreshes.
    async fn write_all_resilient(&self, smb_path: &str, data: &[u8]) -> io::Result<()> {
        let (mut client, mut tree_id) = self.pick_live().await;
        // First open truncates/creates; reconnects re-open with Open so the
        // bytes already written are preserved and the offset stays valid.
        let mut file = client
            .create(
                tree_id,
                smb_path,
                DesiredAccess::GenericWrite as u32,
                ShareAccess::Read as u32,
                CreateDisposition::OverwriteIf as u32,
                CreateOptions::NonDirectoryFile as u32,
            )
            .await?;
        let mut sent = 0usize;
        let mut offset = 0u64;
        let mut attempt = 0u32;
        let result: io::Result<()> = loop {
            if sent >= data.len() {
                break Ok(());
            }
            let chunk = (self.pool.write_chunk_size() as usize).max(1);
            let budget = (self.pool.write_inflight() as usize).max(chunk);
            let end = (sent + budget).min(data.len());
            let window: Vec<&[u8]> = data[sent..end].chunks(chunk).collect();
            match client
                .pipelined_write(tree_id, &file.file_id, offset, &window)
                .await
            {
                Ok(written) => {
                    let w = written as usize;
                    if w == 0 {
                        break Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "pipelined write reported 0 bytes written",
                        ));
                    }
                    offset += written;
                    sent += w;
                    attempt = 0; // forward progress refreshes the retry budget
                }
                Err(e) => {
                    if is_reset(&e) {
                        self.pool.note_write_reset();
                    }
                    if !is_reset(&e) || attempt >= MAX_RESET_RETRIES {
                        break Err(e);
                    }
                    attempt += 1;
                    let _ = client.close(tree_id, &file.file_id).await;
                    let (c, t) = self.pick_live().await;
                    match c
                        .create(
                            t,
                            smb_path,
                            DesiredAccess::GenericWrite as u32,
                            ShareAccess::Read as u32,
                            CreateDisposition::Open as u32,
                            CreateOptions::NonDirectoryFile as u32,
                        )
                        .await
                    {
                        Ok(f) => {
                            client = c;
                            tree_id = t;
                            file = f;
                        }
                        Err(ce) => break Err(ce),
                    }
                }
            }
        };
        let _ = client.close(tree_id, &file.file_id).await;
        if result.is_err() {
            // Clean up the partial file on a fresh connection — the one that
            // just failed is likely poisoned, so reusing it would no-op the
            // delete and leave the torn part behind.
            let (dc, dt) = self.pick_live().await;
            let _ = Self::delete_object_path_on(&dc, dt, smb_path).await;
        }
        result
    }

    /// Pick a pool connection that is not poisoned (see `SmbPool::pick_live`).
    async fn pick_live(&self) -> (Arc<SmbClient>, u32) {
        self.pool.pick_live().await
    }

    /// Run a one-shot read open/stat with bounded retry on transient resets,
    /// each attempt on a freshly-picked live connection. A non-reset error (e.g.
    /// a genuine NotFound) returns immediately; a reset backs off the adaptive
    /// read size. The op receives the picked connection and returns whatever the
    /// caller needs (typically the picked `(client, tree_id)` plus the result).
    async fn retry_read_open<T, F, Fut>(&self, mut op: F) -> io::Result<T>
    where
        F: FnMut(Arc<SmbClient>, u32) -> Fut,
        Fut: Future<Output = io::Result<T>>,
    {
        let mut attempt = 0u32;
        loop {
            let (client, tree_id) = self.pick_live().await;
            match op(client, tree_id).await {
                Ok(v) => return Ok(v),
                Err(e) => {
                    if is_reset(&e) {
                        self.pool.note_read_reset();
                    }
                    if !is_reset(&e) || attempt >= MAX_RESET_RETRIES {
                        return Err(e);
                    }
                    attempt += 1;
                }
            }
        }
    }

    /// Assemble multipart upload parts into a single file via streaming.
    ///
    /// Reads each temp part using pipelined reads and writes through a WalWriter
    /// (pipelined writes + atomic rename). Never holds more than one pipeline
    /// buffer in memory — supports arbitrarily large files.
    pub async fn assemble_parts(&self, key: &str, temp_paths: &[&str]) -> io::Result<ObjectMeta> {
        let mut wal = self.open_wal_write(key).await?;

        // Guard before the per-part `remaining.div_ceil(max_read as u64)` in
        // stream_part_into_wal — a zero-floored pool entry (shouldn't happen
        // post the negotiate floor, but defense in depth) would otherwise
        // panic the task.
        if self.pool.max_read_size == 0 {
            wal.abort().await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "assemble_parts: pool max_read_size = 0",
            ));
        }

        for &temp_path in temp_paths {
            if let Err(e) = self.stream_part_into_wal(&mut wal, temp_path).await {
                // Release the WAL handle and delete its temp file before bailing.
                wal.abort().await;
                return Err(e);
            }
        }

        wal.commit(self).await
    }

    /// Stream one source file (a multipart part, or a copy source) into the
    /// WAL writer, always closing the source handle on every exit path
    /// (success, EOF, or read error).
    ///
    /// On a mid-read reset the source read reconnects on a fresh pool
    /// connection and resumes from the current offset (re-reading the adaptive
    /// size each batch so the burst shrinks under degradation), so multipart
    /// assembly and CopyObject survive a degraded NAS internally instead of
    /// failing back to the client. Bounded by MAX_RESET_RETRIES, refreshed by
    /// each batch that lands.
    async fn stream_part_into_wal(&self, wal: &mut WalWriter, src_path: &str) -> io::Result<()> {
        let (mut client, mut tree_id) = self.pick_live().await;
        let cr = client
            .create(
                tree_id,
                src_path,
                DesiredAccess::GenericRead as u32,
                ShareAccess::All as u32,
                CreateDisposition::Open as u32,
                CreateOptions::NonDirectoryFile as u32,
            )
            .await?;
        let mut file_id = cr.file_id;
        let file_size = cr.file_size;

        let mut offset = 0u64;
        let mut attempt = 0u32;
        let read_result: io::Result<()> = 'read: loop {
            if offset >= file_size {
                break 'read Ok(());
            }
            // Re-read the adaptive size each batch so the read burst shrinks
            // under degradation and recovers as the server does.
            let max_read = self.pool.read_chunk_size().max(1);
            let read_depth = ((self.pool.read_inflight() / max_read).max(1) as u64)
                .min(READ_PIPELINE_DEPTH as u64);
            let remaining = file_size - offset;
            let batch = remaining.div_ceil(max_read as u64).min(read_depth) as usize;
            match client
                .pipelined_read(tree_id, &file_id, offset, max_read, batch)
                .await
            {
                Ok(chunks) if chunks.is_empty() => {
                    break 'read Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!(
                            "unexpected EOF streaming '{src_path}': read {offset} of {file_size} bytes"
                        ),
                    ));
                }
                Ok(chunks) => {
                    for chunk in &chunks {
                        if let Err(e) = wal.write(chunk).await {
                            break 'read Err(e);
                        }
                        offset += chunk.len() as u64;
                    }
                    attempt = 0; // forward progress refreshes the retry budget
                }
                Err(e) => {
                    if is_reset(&e) {
                        self.pool.note_read_reset();
                    }
                    if !is_reset(&e) || attempt >= MAX_RESET_RETRIES {
                        break 'read Err(e);
                    }
                    attempt += 1;
                    let _ = client.close(tree_id, &file_id).await;
                    let (c, t) = self.pick_live().await;
                    match c
                        .create(
                            t,
                            src_path,
                            DesiredAccess::GenericRead as u32,
                            ShareAccess::All as u32,
                            CreateDisposition::Open as u32,
                            CreateOptions::NonDirectoryFile as u32,
                        )
                        .await
                    {
                        // Refuse to splice if the part changed underneath us
                        // (size differs) — we must not assemble bytes from a
                        // different version of the file.
                        Ok(ncr) if ncr.file_size == file_size => {
                            client = c;
                            tree_id = t;
                            file_id = ncr.file_id;
                        }
                        Ok(ncr) => {
                            let _ = c.close(t, &ncr.file_id).await;
                            break 'read Err(io::Error::other(format!(
                                "source '{src_path}' changed mid-stream: size {file_size} -> {}",
                                ncr.file_size
                            )));
                        }
                        Err(ce) => break 'read Err(ce),
                    }
                }
            }
        };

        let _ = client.close(tree_id, &file_id).await;
        read_result
    }

    /// Delete a temp file (best effort).
    pub async fn delete_temp(&self, smb_path: &str) {
        let (client, tree_id) = self.pick();
        let _ = Self::delete_object_path_on(&client, tree_id, smb_path).await;
    }

    /// Delete by SMB path directly. Compound Create+Close in 1 round trip.
    async fn delete_object_path_on(
        client: &SmbClient,
        tree_id: u32,
        smb_path: &str,
    ) -> io::Result<()> {
        let _ = client
            .create_close(
                tree_id,
                smb_path,
                DesiredAccess::Delete as u32,
                ShareAccess::Delete as u32,
                CreateDisposition::Open as u32,
                CreateOptions::NonDirectoryFile as u32 | CreateOptions::DeleteOnClose as u32,
            )
            .await?;
        Ok(())
    }

    /// Try to remove an empty directory (best effort). Compound Create+Close.
    pub async fn remove_dir(&self, smb_path: &str) {
        let (client, tree_id) = self.pick();
        let _ = client
            .create_close(
                tree_id,
                smb_path,
                DesiredAccess::Delete as u32,
                ShareAccess::Delete as u32,
                CreateDisposition::Open as u32,
                CreateOptions::DirectoryFile as u32 | CreateOptions::DeleteOnClose as u32,
            )
            .await;
    }

    // ── WAL buffered write operations ─────────────────────────────────────

    /// Open a WAL writer for a streaming PutObject. Writes are buffered in
    /// memory and flushed to a temp file under `.spiceio-wal/` via pipelined
    /// SMB writes. Call `commit()` to atomically rename to the final path.
    pub async fn open_wal_write(&self, key: &str) -> io::Result<WalWriter> {
        let final_path = to_smb_path(key);
        let wal_path = wal_temp_path();

        // Resilient setup: opening a streaming PUT takes several round trips
        // (ensure parent dirs exist + create the temp file), and under heavy
        // concurrent load on a degraded NAS any of them can hit a transient
        // reset. Retry the whole setup on a fresh connection so a single PUT is
        // not lost before its first byte (the client may not retry). Bounded by
        // MAX_RESET_RETRIES; each reset also backs off the adaptive write size.
        let mut attempt = 0u32;
        let (client, tree_id, file_id) = loop {
            let (client, tree_id) = self.pick_live().await;
            let setup: io::Result<[u8; 16]> = async {
                self.ensure_parent_dirs_on(&client, tree_id, &final_path)
                    .await?;
                self.ensure_parent_dirs_on(&client, tree_id, &wal_path)
                    .await?;
                let file = client
                    .create(
                        tree_id,
                        &wal_path,
                        DesiredAccess::GenericWrite as u32 | DesiredAccess::Delete as u32,
                        ShareAccess::Read as u32 | ShareAccess::Delete as u32,
                        CreateDisposition::OverwriteIf as u32,
                        CreateOptions::NonDirectoryFile as u32,
                    )
                    .await?;
                Ok(file.file_id)
            }
            .await;
            match setup {
                Ok(file_id) => break (client, tree_id, file_id),
                Err(e) => {
                    if is_reset(&e) {
                        self.pool.note_write_reset();
                    }
                    if !is_reset(&e) || attempt >= MAX_RESET_RETRIES {
                        return Err(e);
                    }
                    attempt += 1;
                }
            }
        };

        // chunk = per-write size; flush_cap = in-flight burst budget. Both come
        // from the adaptive in-flight value (chunk = min(max, inflight)), so a
        // flush issues flush_cap/chunk writes — shrinking to a single write when
        // degraded.
        let chunk_size = self.pool.write_chunk_size() as usize;
        let flush_cap = (self.pool.write_inflight() as usize).max(chunk_size);
        Ok(WalWriter {
            client,
            pool: Arc::clone(&self.pool),
            tree_id,
            file_id,
            wal_path,
            final_path,
            buf: Vec::with_capacity(flush_cap),
            flush_cap,
            offset: 0,
            total_size: 0,
        })
    }

    /// Head object by raw SMB path (no S3 key conversion).
    async fn head_object_smb(&self, smb_path: &str) -> io::Result<ObjectMeta> {
        // Resilient stat: retry the one-shot compound probe on a transient reset
        // (fresh connection each attempt) so a HEAD — and the post-rename
        // metadata read in WAL commit — survives a degraded NAS. A genuine
        // NotFound is not a reset and returns immediately.
        let smb_path = smb_path.to_string();
        let (cr, _) = self
            .retry_read_open(|client, tree_id| {
                let smb_path = smb_path.clone();
                async move {
                    client
                        .create_close(
                            tree_id,
                            &smb_path,
                            DesiredAccess::ReadAttributes as u32,
                            ShareAccess::All as u32,
                            CreateDisposition::Open as u32,
                            CreateOptions::NonDirectoryFile as u32,
                        )
                        .await
                }
            })
            .await?;

        Ok(ObjectMeta {
            size: cr.file_size,
            last_modified: filetime_to_epoch_secs(cr.last_write_time),
            etag: etag_for(cr.file_size, cr.last_write_time),
            content_type: String::new(),
        })
    }

    /// Clean up orphaned WAL temp files from prior crashes.
    /// Best-effort — logs errors but does not fail.
    pub async fn cleanup_wal(&self) {
        let (client, tree_id) = self.pick();

        // Try to open the WAL directory
        let dir = match client
            .create(
                tree_id,
                WAL_DIR,
                DesiredAccess::GenericRead as u32 | DesiredAccess::ReadAttributes as u32,
                ShareAccess::All as u32,
                CreateDisposition::Open as u32,
                CreateOptions::DirectoryFile as u32,
            )
            .await
        {
            Ok(d) => d,
            Err(_) => return, // No WAL directory — nothing to clean up
        };

        let entries = client.query_directory(tree_id, &dir.file_id, "*").await;
        let _ = client.close(tree_id, &dir.file_id).await;

        let entries = match entries {
            Ok(e) => e,
            Err(_) => return,
        };

        let mut count = 0u32;
        for entry in &entries {
            if entry.is_directory() {
                continue;
            }
            let path = format!("{WAL_DIR}\\{}", entry.file_name);
            if Self::delete_object_path_on(&client, tree_id, &path)
                .await
                .is_ok()
            {
                count += 1;
            }
        }

        if count > 0 {
            crate::slog!("[spiceio] wal cleanup: removed {count} orphaned temp file(s)");
        }

        // Try to remove the now-empty WAL directory (best effort)
        let _ = client
            .create_close(
                tree_id,
                WAL_DIR,
                DesiredAccess::Delete as u32,
                ShareAccess::Delete as u32,
                CreateDisposition::Open as u32,
                CreateOptions::DirectoryFile as u32 | CreateOptions::DeleteOnClose as u32,
            )
            .await;
    }

    /// Clean up orphaned multipart upload temp dirs from prior runs (best
    /// effort). Removes `.spiceio-uploads/<id>/part-*` files, each per-upload
    /// directory, and the parent. Run at startup; logs but never fails.
    pub async fn cleanup_uploads(&self) {
        let (client, tree_id) = self.pick();

        let root = match client
            .create(
                tree_id,
                UPLOADS_DIR,
                DesiredAccess::GenericRead as u32 | DesiredAccess::ReadAttributes as u32,
                ShareAccess::All as u32,
                CreateDisposition::Open as u32,
                CreateOptions::DirectoryFile as u32,
            )
            .await
        {
            Ok(d) => d,
            Err(_) => return, // No uploads directory — nothing to clean up
        };
        let subdirs = client.query_directory(tree_id, &root.file_id, "*").await;
        let _ = client.close(tree_id, &root.file_id).await;
        let subdirs = match subdirs {
            Ok(e) => e,
            Err(_) => return,
        };

        let mut removed = 0u32;
        for entry in &subdirs {
            if !entry.is_directory() || entry.file_name == "." || entry.file_name == ".." {
                continue;
            }
            let subpath = format!("{UPLOADS_DIR}\\{}", entry.file_name);

            // Delete the part files inside this upload directory.
            if let Ok(sub) = client
                .create(
                    tree_id,
                    &subpath,
                    DesiredAccess::GenericRead as u32 | DesiredAccess::ReadAttributes as u32,
                    ShareAccess::All as u32,
                    CreateDisposition::Open as u32,
                    CreateOptions::DirectoryFile as u32,
                )
                .await
            {
                let files = client.query_directory(tree_id, &sub.file_id, "*").await;
                let _ = client.close(tree_id, &sub.file_id).await;
                if let Ok(files) = files {
                    for f in &files {
                        if f.is_directory() {
                            continue;
                        }
                        let fpath = format!("{subpath}\\{}", f.file_name);
                        let _ = Self::delete_object_path_on(&client, tree_id, &fpath).await;
                    }
                }
            }

            // Remove the now-empty upload directory. Only count it as removed
            // when the delete-on-close actually succeeds, so the log doesn't
            // overreport (e.g. a non-empty dir or a permission error).
            if client
                .create_close(
                    tree_id,
                    &subpath,
                    DesiredAccess::Delete as u32,
                    ShareAccess::Delete as u32,
                    CreateDisposition::Open as u32,
                    CreateOptions::DirectoryFile as u32 | CreateOptions::DeleteOnClose as u32,
                )
                .await
                .is_ok()
            {
                removed += 1;
            }
        }

        if removed > 0 {
            crate::slog!("[spiceio] uploads cleanup: removed {removed} stale upload dir(s)");
        }

        // Remove the now-empty uploads root.
        let _ = client
            .create_close(
                tree_id,
                UPLOADS_DIR,
                DesiredAccess::Delete as u32,
                ShareAccess::Delete as u32,
                CreateDisposition::Open as u32,
                CreateOptions::DirectoryFile as u32 | CreateOptions::DeleteOnClose as u32,
            )
            .await;
    }

    /// Ensure parent directories exist for a given path on a specific connection.
    async fn ensure_parent_dirs_on(
        &self,
        client: &SmbClient,
        tree_id: u32,
        smb_path: &str,
    ) -> io::Result<()> {
        let parts: Vec<&str> = smb_path.split('\\').collect();
        if parts.len() <= 1 {
            return Ok(());
        }

        let mut dirs = Vec::with_capacity(parts.len() - 1);
        let mut current = String::new();
        for part in &parts[..parts.len() - 1] {
            if !current.is_empty() {
                current.push('\\');
            }
            current.push_str(part);
            dirs.push(current.clone());
        }

        client.ensure_dirs(tree_id, &dirs).await
    }
}

/// Number of read requests to pipeline in a single batch.
///
/// Public so the HTTP streaming path can size its response channel to the
/// same depth — back-to-back read batches overlap with HTTP draining when
/// the channel can hold a full batch (see `s3::router::handle_get_object`).
pub const READ_PIPELINE_DEPTH: usize = 64;

impl FileHandle {
    /// Read a chunk at the given offset. Returns empty bytes at EOF.
    pub async fn read_chunk(&self, offset: u64, len: u32) -> io::Result<Bytes> {
        self.client
            .read(self.tree_id, &self.file_id, offset, len)
            .await
    }

    /// Pipelined read: send multiple read requests in one batch, then collect
    /// all responses. Returns chunks in offset order. Stops early on EOF.
    pub async fn read_pipeline(
        &self,
        offset: u64,
        chunk_size: u32,
        remaining: u64,
    ) -> io::Result<Vec<Bytes>> {
        // Guard before `div_ceil` — the guard inside `SmbClient::pipelined_read`
        // is too late, since `remaining.div_ceil(0)` would panic right here.
        if chunk_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "FileHandle::read_pipeline called with chunk_size = 0",
            ));
        }
        // Batch size is bounded by the adaptive in-flight budget (and capped at
        // READ_PIPELINE_DEPTH): under degradation the budget shrinks, so the read
        // burst shrinks too — down to a single op at the floor. Read the budget
        // live so it tracks the pool's current adaptive size.
        let batch = ((self.pool.read_inflight() / chunk_size).max(1) as u64)
            .min(READ_PIPELINE_DEPTH as u64);
        let count = remaining.div_ceil(chunk_size as u64).min(batch) as usize;
        let r = self
            .client
            .pipelined_read(self.tree_id, &self.file_id, offset, chunk_size, count)
            .await;
        if let Err(e) = &r
            && is_reset(e)
        {
            // Server reset a large read — back off the adaptive read size so the
            // retry (and other GET streams) use a sustainable chunk.
            self.pool.note_read_reset();
        }
        r
    }

    /// Write a chunk at the given offset. Returns bytes written.
    pub async fn write_chunk(&self, offset: u64, data: &[u8]) -> io::Result<u32> {
        self.client
            .write(self.tree_id, &self.file_id, offset, data)
            .await
    }

    /// Close the file handle.
    pub async fn close(self) -> io::Result<()> {
        self.client.close(self.tree_id, &self.file_id).await
    }
}

// ── WAL (Write-Ahead Log) buffered writer ──────────────────────────────────

/// Directory on the SMB share where WAL temp files are stored.
const WAL_DIR: &str = ".spiceio-wal";

/// Directory on the SMB share where multipart upload parts are stored.
const UPLOADS_DIR: &str = ".spiceio-uploads";

/// True if the error means the SMB server dropped/reset the connection (or timed
/// out) on a write — the signal to back off the adaptive write size so the next
/// attempt uses a smaller, server-sustainable I/O size.
pub(crate) fn is_reset(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::TimedOut
            // A dropped pool connection can surface as NotConnected; the HTTP
            // layer already maps it to a retryable 503, so the retry/resume
            // paths must agree or they'd abort instead of reconnecting.
            | io::ErrorKind::NotConnected
            // An overwhelmed NAS often closes the TCP connection with a FIN
            // (graceful close) mid-response rather than an RST, so `read_exact`
            // returns `UnexpectedEof` ("early eof") instead of a reset. In the
            // length-framed SMB transport an EOF mid-frame is never valid data —
            // it is always a dropped/overloaded connection, so treat it as a
            // reset: back the in-flight window off and let the healer reconnect.
            | io::ErrorKind::UnexpectedEof
    )
}

/// Monotonic counter for unique WAL file names within this process.
static WAL_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a unique WAL temp file path on the SMB share.
fn wal_temp_path() -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let seq = WAL_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{WAL_DIR}\\{ts:020}-{seq:04}")
}

/// A buffered write-ahead-log writer for streaming PutObject.
///
/// Data flows: HTTP body chunks → memory buffer → pipelined SMB writes to a
/// WAL temp file. On commit, the temp file is renamed to the final path.
/// If the proxy crashes mid-write, the original file is untouched and orphaned
/// WAL files are cleaned up on next startup.
pub struct WalWriter {
    client: Arc<SmbClient>,
    /// Pool handle, used to report large-write resets so the adaptive write
    /// size backs off for subsequent operations.
    pool: Arc<SmbPool>,
    tree_id: u32,
    file_id: [u8; 16],
    wal_path: String,
    final_path: String,
    /// In-memory write buffer — flushed when it reaches `flush_cap`.
    buf: Vec<u8>,
    /// In-flight burst budget: the buffer flushes once it reaches this many
    /// bytes, issuing `flush_cap / chunk_size` pipelined writes.
    flush_cap: usize,
    /// Current write offset in the WAL temp file.
    offset: u64,
    /// Total bytes accepted (buffered + flushed).
    pub total_size: u64,
}

impl WalWriter {
    /// Append data to the write buffer. Flushes automatically when the buffer
    /// fills to the in-flight burst budget (`flush_cap`).
    pub async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        let pipeline_cap = self.flush_cap;
        let mut pos = 0;

        while pos < data.len() {
            let space = pipeline_cap - self.buf.len();
            let take = space.min(data.len() - pos);
            self.buf.extend_from_slice(&data[pos..pos + take]);
            pos += take;
            self.total_size += take as u64;

            if self.buf.len() >= pipeline_cap {
                self.flush().await?;
            }
        }
        Ok(())
    }

    /// Flush the memory buffer to the WAL temp file using pipelined writes.
    ///
    /// The buffer is sent in in-flight-sized windows so the write burst shrinks
    /// with the adaptive size. On a mid-flush reset (an overwhelmed NAS closing
    /// or dropping the connection), back off, reconnect on a fresh pool
    /// connection, and retry the same window at the smaller size — so a single
    /// PUT rides the back-off ladder down to a sustainable burst internally
    /// rather than failing back to the client and burning its limited retry
    /// budget. Bounded by MAX_FLUSH_RETRIES; every window that lands resets the
    /// budget so only sustained failure aborts.
    async fn flush(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        const MAX_FLUSH_RETRIES: u32 = 16;
        let mut sent = 0usize;
        let mut attempt = 0u32;
        while sent < self.buf.len() {
            // Re-read the adaptive size each window so the burst shrinks under
            // degradation (and recovers as the server does).
            let chunk_size = (self.pool.write_chunk_size() as usize).max(1);
            let budget = (self.pool.write_inflight() as usize).max(chunk_size);
            let end = (sent + budget).min(self.buf.len());
            let window: Vec<&[u8]> = self.buf[sent..end].chunks(chunk_size).collect();
            match self
                .client
                .pipelined_write(self.tree_id, &self.file_id, self.offset, &window)
                .await
            {
                Ok(written) => {
                    let w = written as usize;
                    if w == 0 {
                        // A "success" that wrote nothing would spin the loop
                        // forever — treat it as a transport fault instead.
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "pipelined write reported 0 bytes written",
                        ));
                    }
                    // Advance by the bytes actually written (normally the whole
                    // window); a short write just re-sends the remainder.
                    self.offset += written;
                    sent += w;
                    attempt = 0; // forward progress refreshes the retry budget
                }
                Err(e) => {
                    // Server reset a large write — back off the adaptive write
                    // size so this retry (and other streams) use a sustainable
                    // burst.
                    if is_reset(&e) {
                        self.pool.note_write_reset();
                    }
                    if !is_reset(&e) || attempt >= MAX_FLUSH_RETRIES {
                        return Err(e);
                    }
                    attempt += 1;
                    self.reopen().await?;
                }
            }
        }
        self.buf.clear();
        Ok(())
    }

    /// Reconnect the WAL writer on a fresh pool connection after a mid-flush
    /// reset. Re-opens the temp file with `Open` (never `OverwriteIf`) so the
    /// bytes already flushed are preserved — `self.offset` is unchanged, and the
    /// caller re-sends the same window at the backed-off size.
    async fn reopen(&mut self) -> io::Result<()> {
        let _ = self.client.close(self.tree_id, &self.file_id).await; // best-effort
        let (client, tree_id) = self.pool.pick_live().await;
        let file = client
            .create(
                tree_id,
                &self.wal_path,
                DesiredAccess::GenericWrite as u32 | DesiredAccess::Delete as u32,
                ShareAccess::Read as u32 | ShareAccess::Delete as u32,
                CreateDisposition::Open as u32,
                CreateOptions::NonDirectoryFile as u32,
            )
            .await?;
        self.client = client;
        self.tree_id = tree_id;
        self.file_id = file.file_id;
        Ok(())
    }

    /// Flush remaining data, close the WAL file, and rename it to the final path.
    /// Returns the object metadata from a head_object on the final path.
    pub async fn commit(mut self, share: &ShareSession) -> io::Result<ObjectMeta> {
        // Flush all buffered data (windowed retry inside flush), then rename the
        // temp to the final path. The rename retries on a transient reset by
        // reconnecting and re-opening the temp file (which still exists until the
        // rename completes), so a single PUT is not lost at the finish line. On
        // unrecoverable failure, close the handle and best-effort delete the
        // temp — the caller cannot abort() after commit takes self. The delete
        // ignores errors (a poisoned connection may make it fail); any temp left
        // behind is swept up by the startup WAL cleanup.
        if let Err(e) = self.flush().await {
            self.discard_temp().await;
            return Err(e);
        }

        let mut attempt = 0u32;
        let rename_result: io::Result<()> = loop {
            match self
                .client
                .rename(self.tree_id, &self.file_id, &self.final_path, true)
                .await
            {
                Ok(()) => break Ok(()),
                Err(e) => {
                    if is_reset(&e) {
                        self.pool.note_write_reset();
                    }
                    if !is_reset(&e) || attempt >= MAX_RESET_RETRIES {
                        break Err(e);
                    }
                    attempt += 1;
                    // Reconnect and re-open the temp to retry. If the temp is
                    // gone, a prior rename actually completed (its response was
                    // lost to the reset) — treat that as success.
                    match self.reopen().await {
                        Ok(()) => {}
                        Err(re) if re.kind() == io::ErrorKind::NotFound => break Ok(()),
                        Err(re) => break Err(re),
                    }
                }
            }
        };

        if let Err(e) = rename_result {
            self.discard_temp().await;
            return Err(e);
        }

        // Rename succeeded — close the handle (now at the final path).
        let _ = self.client.close(self.tree_id, &self.file_id).await;
        share.head_object_smb(&self.final_path).await
    }

    /// Close the current handle and best-effort delete the WAL temp file.
    async fn discard_temp(&self) {
        let _ = self.client.close(self.tree_id, &self.file_id).await;
        let _ = self
            .client
            .create_close(
                self.tree_id,
                &self.wal_path,
                DesiredAccess::Delete as u32,
                ShareAccess::Delete as u32,
                CreateDisposition::Open as u32,
                CreateOptions::NonDirectoryFile as u32 | CreateOptions::DeleteOnClose as u32,
            )
            .await;
    }

    /// Abort the WAL write — close and delete the temp file.
    pub async fn abort(self) {
        let _ = self.client.close(self.tree_id, &self.file_id).await;
        // Best-effort delete of the WAL temp file
        let _ = self
            .client
            .create_close(
                self.tree_id,
                &self.wal_path,
                DesiredAccess::Delete as u32,
                ShareAccess::Delete as u32,
                CreateDisposition::Open as u32,
                CreateOptions::NonDirectoryFile as u32 | CreateOptions::DeleteOnClose as u32,
            )
            .await;
    }
}

// ── Helper types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ObjectInfo {
    pub key: String,
    pub size: u64,
    pub last_modified: u64,
    pub etag: String,
}

#[derive(Debug, Clone)]
pub struct ObjectMeta {
    pub size: u64,
    pub last_modified: u64,
    pub etag: String,
    pub content_type: String,
}

// ── Path conversion ─────────────────────────────────────────────────────────

/// Build an opaque ETag from an object's size and last-write time.
///
/// Not a content hash — that would require reading the whole object on every
/// HEAD/LIST. Combining size with mtime avoids the collisions a bare mtime
/// suffers when two different-sized objects share a coarse timestamp, and is
/// stable across GET/HEAD/LIST for the same object. (Multipart parts still use
/// a real SHA-256 ETag.) Two same-size edits within the backend's mtime
/// resolution can still collide — documented limitation.
fn etag_for(size: u64, last_write_time: u64) -> String {
    format!("{last_write_time:016x}{size:016x}")
}

/// Convert S3 key (forward-slash) to SMB path (backslash).
fn to_smb_path(key: &str) -> String {
    key.trim_start_matches('/').replace('/', "\\")
}

/// Split an SMB path into (directory, file-pattern) for QueryDirectory.
fn split_dir_pattern(path: &str) -> (String, String) {
    if path.is_empty() {
        return (String::new(), "*".into());
    }
    // If path contains a wildcard or looks like a directory, query it directly
    if path.ends_with('\\') || path.contains('*') {
        (path.trim_end_matches('\\').to_string(), "*".into())
    } else {
        // Check if path has directory components
        if let Some(pos) = path.rfind('\\') {
            let dir = &path[..pos];
            let pattern = &path[pos + 1..];
            if pattern.is_empty() {
                (dir.to_string(), "*".into())
            } else {
                (dir.to_string(), format!("{}*", pattern))
            }
        } else {
            // Single component — could be a directory or a prefix
            (String::new(), format!("{}*", path))
        }
    }
}

/// Convert Windows FILETIME (100ns since 1601) to Unix epoch seconds.
fn filetime_to_epoch_secs(ft: u64) -> u64 {
    const EPOCH_DIFF: u64 = 116444736000000000;
    if ft <= EPOCH_DIFF {
        return 0;
    }
    (ft - EPOCH_DIFF) / 10_000_000
}

/// Very simple content type guessing based on extension.
fn guess_content_type(key: &str) -> String {
    let ext = key.rsplit('.').next().unwrap_or("");
    match ext.to_ascii_lowercase().as_str() {
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" => "application/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "txt" | "log" => "text/plain",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" | "gzip" => "application/gzip",
        "tar" => "application/x-tar",
        _ => "application/octet-stream",
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── to_smb_path ──────────────────────────────────────────────────

    #[test]
    fn to_smb_path_simple() {
        assert_eq!(to_smb_path("a/b/c.txt"), "a\\b\\c.txt");
    }

    #[test]
    fn to_smb_path_strips_leading_slash() {
        assert_eq!(to_smb_path("/dir/file"), "dir\\file");
    }

    #[test]
    fn to_smb_path_root() {
        assert_eq!(to_smb_path("file.txt"), "file.txt");
    }

    #[test]
    fn to_smb_path_empty() {
        assert_eq!(to_smb_path(""), "");
    }

    // ── split_dir_pattern ────────────────────────────────────────────

    #[test]
    fn split_dir_pattern_empty() {
        assert_eq!(split_dir_pattern(""), (String::new(), "*".into()));
    }

    #[test]
    fn split_dir_pattern_directory_trailing() {
        assert_eq!(
            split_dir_pattern("foo\\bar\\"),
            ("foo\\bar".into(), "*".into())
        );
    }

    #[test]
    fn split_dir_pattern_with_prefix() {
        assert_eq!(split_dir_pattern("foo\\bar"), ("foo".into(), "bar*".into()));
    }

    #[test]
    fn split_dir_pattern_single_component() {
        assert_eq!(
            split_dir_pattern("prefix"),
            (String::new(), "prefix*".into())
        );
    }

    #[test]
    fn split_dir_pattern_wildcard() {
        // Path contains wildcard — treated as directory query
        assert_eq!(split_dir_pattern("foo\\*"), ("foo\\*".into(), "*".into()));
    }

    // ── filetime_to_epoch_secs ───────────────────────────────────────

    #[test]
    fn filetime_epoch() {
        // Windows FILETIME for Unix epoch (Jan 1 1970):
        // 116444736000000000 (100ns ticks between 1601-01-01 and 1970-01-01)
        const EPOCH_FT: u64 = 116444736000000000;
        assert_eq!(filetime_to_epoch_secs(EPOCH_FT), 0);
    }

    #[test]
    fn filetime_known_date() {
        // 2024-01-01T00:00:00Z = 1704067200 unix
        // FILETIME = (1704067200 * 10_000_000) + 116444736000000000
        const FT: u64 = 1704067200 * 10_000_000 + 116444736000000000;
        assert_eq!(filetime_to_epoch_secs(FT), 1704067200);
    }

    #[test]
    fn filetime_zero() {
        assert_eq!(filetime_to_epoch_secs(0), 0);
    }

    #[test]
    fn filetime_before_epoch() {
        assert_eq!(filetime_to_epoch_secs(100), 0);
    }

    // ── delete-older-than (age-based expiry) ─────────────────────────
    //
    // spiceio is a pure S3↔SMB proxy and does not expire objects itself.
    // A client deletes "objects older than N seconds" by reading each
    // object's LastModified — which the proxy derives from the SMB
    // last_write_time via `filetime_to_epoch_secs` — and issuing
    // DeleteObject for the stale ones. These tests verify that the proxy's
    // timestamp conversion yields epochs that make that age decision
    // correct, including the boundary, clock-skew, and sub-second cases the
    // workflow hits in practice.

    /// Inverse of `filetime_to_epoch_secs`, for building fixtures: a
    /// whole-second Unix epoch as a Windows FILETIME (100ns ticks since 1601).
    fn epoch_to_filetime(secs: u64) -> u64 {
        const EPOCH_DIFF: u64 = 116444736000000000;
        secs * 10_000_000 + EPOCH_DIFF
    }

    /// The client-side "older than `max_age_secs`" predicate, evaluated
    /// against proxy-reported epochs. Saturating subtraction means an object
    /// whose timestamp is ahead of `now` (clock skew) reports age 0 instead of
    /// underflowing. Expiry is inclusive at the threshold, so `max_age_secs ==
    /// 0` sweeps everything.
    fn is_expired(now: u64, last_modified: u64, max_age_secs: u64) -> bool {
        now.saturating_sub(last_modified) >= max_age_secs
    }

    /// Run a FILETIME-stamped object through the real conversion and age it.
    fn aged(now: u64, mtime_secs: u64, max_age: u64) -> bool {
        let lm = filetime_to_epoch_secs(epoch_to_filetime(mtime_secs));
        assert_eq!(lm, mtime_secs, "filetime round-trip for {mtime_secs}");
        is_expired(now, lm, max_age)
    }

    #[test]
    fn expiry_deletes_only_aged_objects() {
        // now = 100s, threshold = 5s. Objects written at 88/90 (ages 12/10)
        // expire; fresh ones at 98/100 (ages 2/0) survive.
        let now = 100;
        let verdicts: Vec<bool> = [88u64, 90, 98, 100]
            .iter()
            .map(|&t| aged(now, t, 5))
            .collect();
        assert_eq!(verdicts, vec![true, true, false, false]);
    }

    #[test]
    fn expiry_one_minute_retention_keeps_fresh() {
        // A 60s policy applied to freshly written objects deletes nothing;
        // an object 61s old is swept.
        let now = 100;
        assert!(!aged(now, 99, 60), "1s old kept");
        assert!(!aged(now, 100, 60), "0s old kept");
        assert!(aged(now, 39, 60), "61s old expired");
    }

    #[test]
    fn expiry_zero_threshold_sweeps_all() {
        let now = 100;
        for t in [0u64, 50, 99, 100] {
            assert!(aged(now, t, 0), "age-0 threshold should sweep mtime {t}");
        }
    }

    #[test]
    fn expiry_threshold_is_inclusive() {
        assert!(!is_expired(100, 96, 5)); // age 4 < 5 -> kept
        assert!(is_expired(100, 95, 5)); // age 5 == 5 -> expired
        assert!(is_expired(100, 94, 5)); // age 6 > 5 -> expired
    }

    #[test]
    fn expiry_tolerates_clock_skew() {
        // Object timestamp ahead of `now` (server clock ahead): age saturates
        // to 0 rather than underflowing, so a future-dated file is not expired
        // by a positive threshold — but a zero threshold still sweeps it.
        assert_eq!(100u64.saturating_sub(105), 0);
        assert!(!is_expired(100, 105, 5));
        assert!(is_expired(100, 105, 0));
    }

    #[test]
    fn expiry_subsecond_filetime_floors_down() {
        // SMB FILETIME has 100ns resolution; the proxy floors to whole seconds.
        // A file written at T + 0.9s reports T (can look up to ~1s older) —
        // harmless for multi-second thresholds. Verify the floor.
        let ft = epoch_to_filetime(100) + 9_000_000; // +0.9s in 100ns ticks
        assert_eq!(filetime_to_epoch_secs(ft), 100);
    }

    // ── etag_for ─────────────────────────────────────────────────────

    #[test]
    fn etag_for_combines_size_and_mtime() {
        // Different sizes at the same mtime must not collide (the bare-mtime bug).
        assert_ne!(etag_for(10, 1234), etag_for(20, 1234));
        // Different mtimes must not collide.
        assert_ne!(etag_for(10, 1234), etag_for(10, 5678));
        // Stable for the same inputs.
        assert_eq!(etag_for(10, 1234), etag_for(10, 1234));
    }

    // ── guess_content_type ───────────────────────────────────────────

    #[test]
    fn content_type_known() {
        assert_eq!(guess_content_type("file.json"), "application/json");
        assert_eq!(guess_content_type("page.html"), "text/html");
        assert_eq!(guess_content_type("image.PNG"), "image/png");
        assert_eq!(guess_content_type("doc.pdf"), "application/pdf");
    }

    #[test]
    fn content_type_unknown() {
        assert_eq!(guess_content_type("file.xyz"), "application/octet-stream");
        assert_eq!(guess_content_type("noext"), "application/octet-stream");
    }

    #[test]
    fn content_type_nested_path() {
        assert_eq!(guess_content_type("a/b/c.txt"), "text/plain");
    }

    // ── WAL path generation ─────────────────────────────────────────

    #[test]
    fn wal_dir_constant() {
        assert_eq!(WAL_DIR, ".spiceio-wal");
    }

    #[test]
    fn wal_temp_path_under_wal_dir() {
        let path = wal_temp_path();
        assert!(
            path.starts_with(".spiceio-wal\\"),
            "WAL path must start with .spiceio-wal\\, got: {path}"
        );
    }

    #[test]
    fn wal_temp_path_no_nested_dirs() {
        let path = wal_temp_path();
        // After the WAL dir prefix, the filename should have no more backslashes
        let filename = path.strip_prefix(".spiceio-wal\\").unwrap();
        assert!(
            !filename.contains('\\'),
            "WAL filename should be flat, got: {filename}"
        );
    }

    #[test]
    fn wal_temp_path_unique() {
        let p1 = wal_temp_path();
        let p2 = wal_temp_path();
        let p3 = wal_temp_path();
        assert_ne!(p1, p2);
        assert_ne!(p2, p3);
        assert_ne!(p1, p3);
    }

    #[test]
    fn wal_temp_path_contains_counter() {
        // The counter portion should differ between consecutive calls
        let p1 = wal_temp_path();
        let p2 = wal_temp_path();
        let f1 = p1.strip_prefix(".spiceio-wal\\").unwrap();
        let f2 = p2.strip_prefix(".spiceio-wal\\").unwrap();
        // Format is "{timestamp}-{counter}" — extract counter suffix
        let c1: &str = f1.rsplit('-').next().unwrap();
        let c2: &str = f2.rsplit('-').next().unwrap();
        let n1: u64 = c1.parse().expect("counter should be numeric");
        let n2: u64 = c2.parse().expect("counter should be numeric");
        assert_eq!(n2, n1 + 1, "counter should increment monotonically");
    }

    #[test]
    fn wal_temp_path_format_dash_separated() {
        let path = wal_temp_path();
        let filename = path.strip_prefix(".spiceio-wal\\").unwrap();
        let parts: Vec<&str> = filename.split('-').collect();
        assert_eq!(
            parts.len(),
            2,
            "expected timestamp-counter, got: {filename}"
        );
        // Timestamp part should be a large number (nanoseconds)
        let ts: u128 = parts[0].parse().expect("timestamp should be numeric");
        assert!(ts > 1_000_000_000_000_000_000, "timestamp looks too small");
    }
}
