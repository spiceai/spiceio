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
        let (client, tree_id) = self.pick();
        let smb_path = to_smb_path(key);
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

        let meta = ObjectMeta {
            size: file.file_size,
            last_modified: filetime_to_epoch_secs(file.last_write_time),
            etag: etag_for(file.file_size, file.last_write_time),
            content_type: guess_content_type(key),
        };

        Ok(FileHandle {
            client: Arc::clone(&client),
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
                    etag: etag_for(entry.file_size, entry.last_write_time),
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
            etag: etag_for(cr.file_size, cr.last_write_time),
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
                ShareAccess::All as u32,
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
        self.ensure_parent_dirs_on(&client, tree_id, &smb_path)
            .await?;

        let compound_max = self.pool.compound_max_write_size as usize;
        let chunk_size = self.pool.max_write_size as usize;

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
            let _ = Self::delete_object_path_on(&client, tree_id, &smb_path).await;
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
            etag: etag_for(cr.file_size, cr.last_write_time),
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
        self.ensure_parent_dirs_on(&client, tree_id, smb_path)
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
            let _ = Self::delete_object_path_on(&client, tree_id, smb_path).await;
            return Err(e);
        }
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
                ShareAccess::All as u32,
                CreateDisposition::Open as u32,
                CreateOptions::NonDirectoryFile as u32,
            )
            .await?;

        let read_result: io::Result<Vec<u8>> = async {
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
            Ok(data)
        }
        .await;

        let _ = client.close(tree_id, &file.file_id).await;
        read_result
    }

    /// Assemble multipart upload parts into a single file via streaming.
    ///
    /// Reads each temp part using pipelined reads and writes through a WalWriter
    /// (pipelined writes + atomic rename). Never holds more than one pipeline
    /// buffer in memory — supports arbitrarily large files.
    pub async fn assemble_parts(&self, key: &str, temp_paths: &[&str]) -> io::Result<ObjectMeta> {
        let mut wal = self.open_wal_write(key).await?;

        for &temp_path in temp_paths {
            if let Err(e) = self.stream_part_into_wal(&mut wal, temp_path).await {
                // Release the WAL handle and delete its temp file before bailing.
                wal.abort().await;
                return Err(e);
            }
        }

        wal.commit(self).await
    }

    /// Stream one part file into the WAL writer, always closing the part handle
    /// on every exit path (success, EOF, or read error).
    async fn stream_part_into_wal(&self, wal: &mut WalWriter, temp_path: &str) -> io::Result<()> {
        let (client, tree_id) = self.pick();
        let cr = client
            .create(
                tree_id,
                temp_path,
                DesiredAccess::GenericRead as u32,
                ShareAccess::All as u32,
                CreateDisposition::Open as u32,
                CreateOptions::NonDirectoryFile as u32,
            )
            .await?;
        let file_id = cr.file_id;
        let file_size = cr.file_size;
        let max_read = self.pool.max_read_size;

        let read_result: io::Result<()> = async {
            let mut offset = 0u64;
            while offset < file_size {
                let remaining = file_size - offset;
                let batch = remaining
                    .div_ceil(max_read as u64)
                    .min(PIPELINE_DEPTH as u64) as usize;
                let chunks = client
                    .pipelined_read(tree_id, &file_id, offset, max_read, batch)
                    .await?;
                if chunks.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!(
                            "unexpected EOF assembling part '{}': read {} of {} bytes",
                            temp_path, offset, file_size
                        ),
                    ));
                }
                for chunk in &chunks {
                    wal.write(chunk).await?;
                    offset += chunk.len() as u64;
                }
            }
            Ok(())
        }
        .await;

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
        self.ensure_parent_dirs_on(&client, tree_id, &final_path)
            .await?;

        // Generate WAL temp path and ensure its parent dir exists
        let wal_path = wal_temp_path();
        self.ensure_parent_dirs_on(&client, tree_id, &wal_path)
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
            client: Arc::clone(&client),
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
                CreateOptions::DirectoryFile as u32 | 0x00001000,
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

            // Remove the now-empty upload directory.
            let _ = client
                .create_close(
                    tree_id,
                    &subpath,
                    DesiredAccess::Delete as u32,
                    ShareAccess::Delete as u32,
                    CreateDisposition::Open as u32,
                    CreateOptions::DirectoryFile as u32 | 0x00001000,
                )
                .await;
            removed += 1;
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
///
/// Public so the HTTP streaming path can size its response channel to the
/// same depth — back-to-back read batches overlap with HTTP draining when
/// the channel can hold a full batch (see `s3::router::handle_get_object`).
pub const READ_PIPELINE_DEPTH: usize = 64;
const PIPELINE_DEPTH: usize = READ_PIPELINE_DEPTH;

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

/// Directory on the SMB share where multipart upload parts are stored.
const UPLOADS_DIR: &str = ".spiceio-uploads";

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
        // Flush remaining data and rename to the final path. On any failure,
        // close the handle and delete the WAL temp so we never leak a handle or
        // orphan a temp file — the caller cannot abort() after commit takes self.
        let staged: io::Result<()> = async {
            self.flush().await?;
            self.client
                .rename(self.tree_id, &self.file_id, &self.final_path, true)
                .await?;
            Ok(())
        }
        .await;

        if let Err(e) = staged {
            let _ = self.client.close(self.tree_id, &self.file_id).await;
            // Rename did not complete, so the temp is still at wal_path.
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
            return Err(e);
        }

        // Rename succeeded — close the handle (now at the final path).
        let _ = self.client.close(self.tree_id, &self.file_id).await;
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
