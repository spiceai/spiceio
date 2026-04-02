//! High-level SMB file operations used by the S3 layer.

use std::io;
use std::sync::Arc;

use bytes::Bytes;

use super::client::SmbClient;
use super::protocol::*;

/// A connected share session wrapping the SMB client + tree ID.
pub struct ShareSession {
    client: Arc<SmbClient>,
    tree_id: u32,
}

/// An open file handle for streaming reads or writes.
pub struct FileHandle {
    client: Arc<SmbClient>,
    tree_id: u32,
    file_id: [u8; 16],
    pub meta: ObjectMeta,
    pub file_size: u64,
    pub max_chunk: u32,
}

impl ShareSession {
    pub async fn connect(client: Arc<SmbClient>, share: &str) -> io::Result<Self> {
        let tree_id = client.tree_connect(share).await?;
        Ok(Self { client, tree_id })
    }

    pub fn max_read_size(&self) -> u32 {
        self.client.max_read_size
    }

    pub fn max_write_size(&self) -> u32 {
        self.client.max_write_size
    }

    /// Compound Create+Read+Close. Returns metadata and data bytes.
    /// File handle is already closed on return. For files larger than
    /// `max_read`, only the first chunk is returned.
    pub async fn get_object_compound(
        &self,
        key: &str,
        max_read: u32,
    ) -> io::Result<(ObjectMeta, Bytes)> {
        let smb_path = to_smb_path(key);
        let (cr, data) = self
            .client
            .create_read_close(self.tree_id, &smb_path, max_read)
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

    /// Open a file for streaming reads. Returns a handle that can read chunks.
    pub async fn open_read(&self, key: &str) -> io::Result<FileHandle> {
        let smb_path = to_smb_path(key);
        let file = self
            .client
            .create(
                self.tree_id,
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
            client: Arc::clone(&self.client),
            tree_id: self.tree_id,
            file_id: file.file_id,
            file_size: file.file_size,
            max_chunk: self.client.max_read_size,
            meta,
        })
    }

    /// Open (or create) a file for streaming writes.
    pub async fn open_write(&self, key: &str) -> io::Result<FileHandle> {
        let smb_path = to_smb_path(key);
        self.ensure_parent_dirs(&smb_path).await?;

        let file = self
            .client
            .create(
                self.tree_id,
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
            client: Arc::clone(&self.client),
            tree_id: self.tree_id,
            file_id: file.file_id,
            file_size: 0,
            max_chunk: self.client.max_write_size,
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
        let smb_path = to_smb_path(prefix);
        let (dir_path, pattern) = split_dir_pattern(&smb_path);

        // Open the directory
        let dir = self
            .client
            .create(
                self.tree_id,
                &dir_path,
                DesiredAccess::GenericRead as u32 | DesiredAccess::ReadAttributes as u32,
                ShareAccess::All as u32,
                CreateDisposition::Open as u32,
                CreateOptions::DirectoryFile as u32,
            )
            .await?;

        let entries = self
            .client
            .query_directory(self.tree_id, &dir.file_id, &pattern)
            .await;

        // Close directory handle regardless
        let _ = self.client.close(self.tree_id, &dir.file_id).await;

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
        let smb_path = to_smb_path(key);
        let max_read = self.client.max_read_size;

        // Compound: Create+Read+Close in 1 round trip
        let (cr, first_chunk) = self
            .client
            .create_read_close(self.tree_id, &smb_path, max_read)
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
        let file = self
            .client
            .create(
                self.tree_id,
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
            let chunk = self
                .client
                .read(self.tree_id, &file.file_id, offset, max_read)
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

        let _ = self.client.close(self.tree_id, &file.file_id).await;
        Ok((meta, data))
    }

    /// Put object (write file). Uses compound Create+Write+Close for small
    /// files, falling back to sequential for larger files.
    pub async fn put_object(&self, key: &str, data: &[u8]) -> io::Result<ObjectMeta> {
        let smb_path = to_smb_path(key);
        self.ensure_parent_dirs(&smb_path).await?;

        let chunk_size = self.client.max_write_size as usize;

        if data.len() <= chunk_size {
            // Compound Create+Write+Close — 1 round trip, metadata from Close
            let cl = self
                .client
                .create_write_close(self.tree_id, &smb_path, data)
                .await?;
            return Ok(ObjectMeta {
                size: data.len() as u64,
                last_modified: filetime_to_epoch_secs(cl.last_write_time),
                etag: format!("{:016x}", cl.last_write_time),
                content_type: guess_content_type(key),
            });
        }

        // Large file — sequential write
        let file = self
            .client
            .create(
                self.tree_id,
                &smb_path,
                DesiredAccess::GenericWrite as u32,
                ShareAccess::Read as u32,
                CreateDisposition::OverwriteIf as u32,
                CreateOptions::NonDirectoryFile as u32,
            )
            .await?;

        let mut offset = 0u64;
        for chunk in data.chunks(chunk_size) {
            self.client
                .write(self.tree_id, &file.file_id, offset, chunk)
                .await?;
            offset += chunk.len() as u64;
        }

        let _ = self.client.close(self.tree_id, &file.file_id).await;

        Ok(ObjectMeta {
            size: data.len() as u64,
            last_modified: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            etag: format!("{:016x}", simple_hash(data)),
            content_type: guess_content_type(key),
        })
    }

    /// Delete an object. Compound Create(DELETE_ON_CLOSE)+Close in 1 round trip.
    pub async fn delete_object(&self, key: &str) -> io::Result<()> {
        let smb_path = to_smb_path(key);
        let _ = self
            .client
            .create_close(
                self.tree_id,
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
        let smb_path = to_smb_path(key);
        let (cr, _) = self
            .client
            .create_close(
                self.tree_id,
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
        self.ensure_parent_dirs(smb_path).await?;

        let chunk_size = self.client.max_write_size as usize;
        if data.len() <= chunk_size {
            let _ = self
                .client
                .create_write_close(self.tree_id, smb_path, data)
                .await?;
            return Ok(());
        }

        let file = self
            .client
            .create(
                self.tree_id,
                smb_path,
                DesiredAccess::GenericWrite as u32,
                ShareAccess::Read as u32,
                CreateDisposition::OverwriteIf as u32,
                CreateOptions::NonDirectoryFile as u32,
            )
            .await?;

        let mut offset = 0u64;
        for chunk in data.chunks(chunk_size) {
            self.client
                .write(self.tree_id, &file.file_id, offset, chunk)
                .await?;
            offset += chunk.len() as u64;
        }

        let _ = self.client.close(self.tree_id, &file.file_id).await;
        Ok(())
    }

    /// Read a temp file.
    pub async fn read_temp(&self, smb_path: &str) -> io::Result<Vec<u8>> {
        let max_read = self.client.max_read_size;
        let (cr, first_chunk) = self
            .client
            .create_read_close(self.tree_id, smb_path, max_read)
            .await?;

        if cr.file_size <= first_chunk.len() as u64 {
            return Ok(first_chunk.to_vec());
        }

        // Large temp file — re-open and read sequentially
        let file = self
            .client
            .create(
                self.tree_id,
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
            let chunk = self
                .client
                .read(self.tree_id, &file.file_id, offset, max_read)
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

        let _ = self.client.close(self.tree_id, &file.file_id).await;
        Ok(data)
    }

    /// Delete a temp file (best effort).
    pub async fn delete_temp(&self, smb_path: &str) {
        let _ = self.delete_object_path(smb_path).await;
    }

    /// Delete by SMB path directly. Compound Create+Close in 1 round trip.
    async fn delete_object_path(&self, smb_path: &str) -> io::Result<()> {
        let _ = self
            .client
            .create_close(
                self.tree_id,
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
        let _ = self
            .client
            .create_close(
                self.tree_id,
                smb_path,
                DesiredAccess::Delete as u32,
                ShareAccess::Delete as u32,
                CreateDisposition::Open as u32,
                CreateOptions::DirectoryFile as u32 | 0x00001000,
            )
            .await;
    }

    /// Ensure parent directories exist for a given path.
    /// Batches all Create+Close pairs into a single compound round trip.
    async fn ensure_parent_dirs(&self, smb_path: &str) -> io::Result<()> {
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

        self.client.ensure_dirs(self.tree_id, &dirs).await
    }
}

impl FileHandle {
    /// Read a chunk at the given offset. Returns empty bytes at EOF.
    pub async fn read_chunk(&self, offset: u64, len: u32) -> io::Result<Bytes> {
        self.client
            .read(self.tree_id, &self.file_id, offset, len)
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

/// Simple non-cryptographic hash for ETags.
fn simple_hash(data: &[u8]) -> u64 {
    // FNV-1a
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
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
}
