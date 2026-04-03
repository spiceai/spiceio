//! High-level SMB file operations used by the S3 layer.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;

use super::client::SmbClient;
use super::pool::SmbPool;
use super::protocol::*;

/// A connected share session backed by a pool of SMB connections.
///
/// Each operation picks a connection from the pool via round-robin, so
/// concurrent S3 requests fan out across multiple TCP streams instead of
/// serializing on a single mutex.
pub struct ShareSession {
    pool: Arc<SmbPool>,
    tree_ids: Vec<u32>,
}

/// An open file handle for streaming reads or writes.
/// Pinned to the specific connection that opened the file.
pub struct FileHandle {
    client: Arc<SmbClient>,
    tree_id: u32,
    file_id: [u8; 16],
    pub meta: ObjectMeta,
    pub file_size: u64,
    pub max_chunk: u32,
}

impl ShareSession {
    /// Connect to a share on every connection in the pool.
    pub async fn connect(pool: Arc<SmbPool>, share: &str) -> io::Result<Self> {
        let mut tree_ids = Vec::with_capacity(pool.size());
        for i in 0..pool.size() {
            let client = &pool.clients()[i];
            let tree_id = client.tree_connect(share).await?;
            tree_ids.push(tree_id);
        }
        Ok(Self { pool, tree_ids })
    }

    /// Pick the next connection + tree_id via round-robin.
    fn pick(&self) -> (&Arc<SmbClient>, u32) {
        let idx = self.pool.next_index() % self.pool.size();
        (self.pool.client(idx), self.tree_ids[idx])
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
            etag: format!("{:016x}", cr.last_write_time),
            content_type: guess_content_type(key),
        };

        Ok((meta, data))
    }

    // ── Streaming file operations ───────────────────────────────────────

    /// Open a file for streaming reads. Returns a handle pinned to one connection.
    pub async fn open_read(&self, key: &str) -> io::Result<FileHandle> {
        let (client, tree_id) = self.pick();
        let smb_path = to_smb_path(key);
        let file = client
            .create(
                tree_id,
                &smb_path,
                DesiredAccess::GenericRead as u32,
                ShareAccess::Read as u32,
                CreateDisposition::Open as u32,
                CreateOptions::NonDirectoryFile as u32,
            )
            .await?;

        let meta = ObjectMeta {
            size: file.file_size,
            last_modified: filetime_to_epoch_secs(file.last_write_time),
            etag: format!("{:016x}", file.last_write_time),
            content_type: guess_content_type(key),
        };

        Ok(FileHandle {
            client: Arc::clone(client),
            tree_id,
            file_id: file.file_id,
            file_size: file.file_size,
            max_chunk: self.pool.max_read_size,
            meta,
        })
    }

    /// Open (or create) a file for streaming writes. Handle pinned to one connection.
    pub async fn open_write(&self, key: &str) -> io::Result<FileHandle> {
        let (client, tree_id) = self.pick();
        let smb_path = to_smb_path(key);
        self.ensure_parent_dirs_on(client, tree_id, &smb_path)
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
            client: Arc::clone(client),
            tree_id,
            file_id: file.file_id,
            file_size: 0,
            max_chunk: self.pool.max_write_size,
            meta,
        })
    }

    // ── Buffered file operations (existing) ─────────────────────────────

    /// List objects in a directory. `prefix` uses forward-slash separators.
    pub async fn list_objects(
        &self,
        prefix: &str,
        delimiter: Option<&str>,
    ) -> io::Result<(Vec<ObjectInfo>, Vec<String>)> {
        let (client, tree_id) = self.pick();
        let smb_path = to_smb_path(prefix);
        let (dir_path, pattern) = split_dir_pattern(&smb_path);

        // Open the directory
        let dir = client
            .create(
                tree_id,
                &dir_path,
                DesiredAccess::GenericRead as u32 | DesiredAccess::ReadAttributes as u32,
                ShareAccess::All as u32,
                CreateDisposition::Open as u32,
                CreateOptions::DirectoryFile as u32,
            )
            .await?;

        let entries = client
            .query_directory(tree_id, &dir.file_id, &pattern)
            .await;

        // Close directory handle regardless
        let _ = client.close(tree_id, &dir.file_id).await;

        let entries = entries?;

        let mut objects = Vec::new();
        let mut common_prefixes = Vec::new();

        for entry in entries {
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
                }
                // If no delimiter, we'd recurse — but keep it simple for now
            } else {
                objects.push(ObjectInfo {
                    key,
                    size: entry.file_size,
                    last_modified: filetime_to_epoch_secs(entry.last_write_time),
                    etag: format!("{:016x}", entry.last_write_time),
                });
            }
        }

        Ok((objects, common_prefixes))
    }

    /// Get object (file) content. Uses compound Create+Read+Close for files
    /// that fit in one read chunk, falling back to sequential for larger files.
    pub async fn get_object(&self, key: &str) -> io::Result<(ObjectMeta, Vec<u8>)> {
        let (client, tree_id) = self.pick();
        let smb_path = to_smb_path(key);
        let compound_max = self.pool.compound_max_read_size;
        let max_read = self.pool.max_read_size;

        // Compound: Create+Read+Close in 1 round trip (uses compound cap)
        let (cr, first_chunk) = client
            .create_read_close(tree_id, &smb_path, compound_max)
            .await?;

        let meta = ObjectMeta {
            size: cr.file_size,
            last_modified: filetime_to_epoch_secs(cr.last_write_time),
            etag: format!("{:016x}", cr.last_write_time),
            content_type: guess_content_type(key),
        };

        // Small file — got everything in the compound
        if cr.file_size <= first_chunk.len() as u64 {
            return Ok((meta, first_chunk.to_vec()));
        }

        // Large file — re-open and read sequentially
        let file = client
            .create(
                tree_id,
                &smb_path,
                DesiredAccess::GenericRead as u32,
                ShareAccess::Read as u32,
                CreateDisposition::Open as u32,
                CreateOptions::NonDirectoryFile as u32,
            )
            .await?;

        let mut data = Vec::with_capacity(cr.file_size as usize);
        let mut offset = 0u64;
        loop {
            let chunk = client
                .read(tree_id, &file.file_id, offset, max_read)
                .await?;
            if chunk.is_empty() {
                break;
            }
            offset += chunk.len() as u64;
            data.extend_from_slice(&chunk);
            if offset >= cr.file_size {
                break;
            }
        }

        let _ = client.close(tree_id, &file.file_id).await;
        Ok((meta, data))
    }

    /// Put object (write file). Uses compound Create+Write+Close for small
    /// files, falling back to sequential for larger files.
    pub async fn put_object(&self, key: &str, data: &[u8]) -> io::Result<ObjectMeta> {
        let (client, tree_id) = self.pick();
        let smb_path = to_smb_path(key);
        self.ensure_parent_dirs_on(client, tree_id, &smb_path)
            .await?;

        let compound_max = self.pool.compound_max_write_size as usize;
        let chunk_size = self.pool.max_write_size as usize;

        if data.len() <= compound_max {
            // Compound Create+Write+Close — 1 round trip, metadata from Close
            let cl = client.create_write_close(tree_id, &smb_path, data).await?;
            return Ok(ObjectMeta {
                size: data.len() as u64,
                last_modified: filetime_to_epoch_secs(cl.last_write_time),
                etag: format!("{:016x}", cl.last_write_time),
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

        let mut offset = 0u64;
        for chunk in data.chunks(chunk_size) {
            client.write(tree_id, &file.file_id, offset, chunk).await?;
            offset += chunk.len() as u64;
        }

        let _ = client.close(tree_id, &file.file_id).await;

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
                CreateOptions::NonDirectoryFile as u32 | 0x00001000,
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
            etag: format!("{:016x}", cr.last_write_time),
            content_type: guess_content_type(key),
        })
    }

    /// Copy a file on the SMB share (read source, write dest).
    pub async fn copy_object(&self, src_key: &str, dst_key: &str) -> io::Result<ObjectMeta> {
        let (meta, data) = self.get_object(src_key).await?;
        let dst_meta = self.put_object(dst_key, &data).await?;
        Ok(ObjectMeta {
            last_modified: dst_meta.last_modified,
            etag: dst_meta.etag,
            size: meta.size,
            content_type: meta.content_type,
        })
    }

    /// Write a temp part file for multipart upload.
    pub async fn write_temp(&self, smb_path: &str, data: &[u8]) -> io::Result<()> {
        let (client, tree_id) = self.pick();
        self.ensure_parent_dirs_on(client, tree_id, smb_path)
            .await?;

        let compound_max = self.pool.compound_max_write_size as usize;
        let chunk_size = self.pool.max_write_size as usize;
        if data.len() <= compound_max {
            let _ = client.create_write_close(tree_id, smb_path, data).await?;
            return Ok(());
        }

        let file = client
            .create(
                tree_id,
                smb_path,
                DesiredAccess::GenericWrite as u32,
                ShareAccess::Read as u32,
                CreateDisposition::OverwriteIf as u32,
                CreateOptions::NonDirectoryFile as u32,
            )
            .await?;

        let mut offset = 0u64;
        for chunk in data.chunks(chunk_size) {
            client.write(tree_id, &file.file_id, offset, chunk).await?;
            offset += chunk.len() as u64;
        }

        let _ = client.close(tree_id, &file.file_id).await;
        Ok(())
    }

    /// Read a temp file.
    pub async fn read_temp(&self, smb_path: &str) -> io::Result<Vec<u8>> {
        let (client, tree_id) = self.pick();
        let compound_max = self.pool.compound_max_read_size;
        let max_read = self.pool.max_read_size;
        let (cr, first_chunk) = client
            .create_read_close(tree_id, smb_path, compound_max)
            .await?;

        if cr.file_size <= first_chunk.len() as u64 {
            return Ok(first_chunk.to_vec());
        }

        // Large temp file — re-open and read sequentially
        let file = client
            .create(
                tree_id,
                smb_path,
                DesiredAccess::GenericRead as u32,
                ShareAccess::Read as u32,
                CreateDisposition::Open as u32,
                CreateOptions::NonDirectoryFile as u32,
            )
            .await?;

        let mut data = Vec::with_capacity(cr.file_size as usize);
        let mut offset = 0u64;
        loop {
            let chunk = client
                .read(tree_id, &file.file_id, offset, max_read)
                .await?;
            if chunk.is_empty() {
                break;
            }
            offset += chunk.len() as u64;
            data.extend_from_slice(&chunk);
            if offset >= cr.file_size {
                break;
            }
        }

        let _ = client.close(tree_id, &file.file_id).await;
        Ok(data)
    }

    /// Delete a temp file (best effort).
    pub async fn delete_temp(&self, smb_path: &str) {
        let (client, tree_id) = self.pick();
        let _ = Self::delete_object_path_on(client, tree_id, smb_path).await;
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
                CreateOptions::NonDirectoryFile as u32 | 0x00001000,
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
                CreateOptions::DirectoryFile as u32 | 0x00001000,
            )
            .await;
    }

    // ── WAL buffered write operations ─────────────────────────────────────

    /// Open a WAL writer for a streaming PutObject. Writes are buffered in
    /// memory and flushed to a temp file under `.spiceio-wal/` via pipelined
    /// SMB writes. Call `commit()` to atomically rename to the final path.
    pub async fn open_wal_write(&self, key: &str) -> io::Result<WalWriter> {
        let (client, tree_id) = self.pick();
        let final_path = to_smb_path(key);

        // Ensure final destination's parent dirs exist (so rename can succeed)
        self.ensure_parent_dirs_on(client, tree_id, &final_path)
            .await?;

        // Generate WAL temp path and ensure its parent dir exists
        let wal_path = wal_temp_path();
        self.ensure_parent_dirs_on(client, tree_id, &wal_path)
            .await?;

        // Create the WAL temp file
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

        let chunk_size = self.pool.max_write_size as usize;
        Ok(WalWriter {
            client: Arc::clone(client),
            tree_id,
            file_id: file.file_id,
            wal_path,
            final_path,
            buf: Vec::with_capacity(chunk_size * WRITE_PIPELINE_DEPTH),
            chunk_size,
            offset: 0,
            total_size: 0,
        })
    }

    /// Head object by raw SMB path (no S3 key conversion).
    async fn head_object_smb(&self, smb_path: &str) -> io::Result<ObjectMeta> {
        let (client, tree_id) = self.pick();
        let (cr, _) = client
            .create_close(
                tree_id,
                smb_path,
                DesiredAccess::ReadAttributes as u32,
                ShareAccess::All as u32,
                CreateDisposition::Open as u32,
                CreateOptions::NonDirectoryFile as u32,
            )
            .await?;

        Ok(ObjectMeta {
            size: cr.file_size,
            last_modified: filetime_to_epoch_secs(cr.last_write_time),
            etag: format!("{:016x}", cr.last_write_time),
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
            if Self::delete_object_path_on(client, tree_id, &path)
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
                CreateOptions::DirectoryFile as u32 | 0x00001000,
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
const PIPELINE_DEPTH: usize = 64;

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
        let count = remaining
            .div_ceil(chunk_size as u64)
            .min(PIPELINE_DEPTH as u64) as usize;
        self.client
            .pipelined_read(self.tree_id, &self.file_id, offset, chunk_size, count)
            .await
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

/// Number of write requests to pipeline in a single batch.
const WRITE_PIPELINE_DEPTH: usize = 64;

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
    tree_id: u32,
    file_id: [u8; 16],
    wal_path: String,
    final_path: String,
    /// In-memory write buffer — flushed when it reaches capacity.
    buf: Vec<u8>,
    /// Max bytes per individual SMB Write request.
    chunk_size: usize,
    /// Current write offset in the WAL temp file.
    offset: u64,
    /// Total bytes accepted (buffered + flushed).
    pub total_size: u64,
}

impl WalWriter {
    /// Append data to the write buffer. Flushes automatically when the buffer
    /// fills to pipeline capacity (WRITE_PIPELINE_DEPTH * chunk_size).
    pub async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        let pipeline_cap = self.chunk_size * WRITE_PIPELINE_DEPTH;
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
    async fn flush(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }

        // Split buffer into chunk_size slices for pipelining
        let chunks: Vec<&[u8]> = self.buf.chunks(self.chunk_size).collect();
        let written = self
            .client
            .pipelined_write(self.tree_id, &self.file_id, self.offset, &chunks)
            .await?;
        self.offset += written;
        self.buf.clear();
        Ok(())
    }

    /// Flush remaining data, close the WAL file, and rename it to the final path.
    /// Returns the object metadata from a head_object on the final path.
    pub async fn commit(mut self, share: &ShareSession) -> io::Result<ObjectMeta> {
        // Flush any remaining buffered data
        self.flush().await?;

        // Rename the WAL temp file to the final destination
        self.client
            .rename(self.tree_id, &self.file_id, &self.final_path, true)
            .await?;

        // Close the file handle (now at the final path)
        let _ = self.client.close(self.tree_id, &self.file_id).await;

        // Fetch final metadata
        let meta = share.head_object_smb(&self.final_path).await?;
        Ok(meta)
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
                CreateOptions::NonDirectoryFile as u32 | 0x00001000,
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
    fn wal_pipeline_depth() {
        // Pipeline depth should match read pipeline for consistency
        assert_eq!(WRITE_PIPELINE_DEPTH, PIPELINE_DEPTH);
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
