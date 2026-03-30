//! Multipart upload state management.
//!
//! Tracks in-progress multipart uploads. Parts are stored as temporary SMB
//! files under a `.spio-uploads/` directory on the share.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;

/// Manages all active multipart uploads.
pub struct MultipartStore {
    uploads: RwLock<HashMap<String, UploadState>>,
    next_id: AtomicU64,
}

/// State of one multipart upload.
#[derive(Debug, Clone)]
pub struct UploadState {
    pub upload_id: String,
    pub key: String,
    pub parts: HashMap<u32, PartInfo>,
    pub metadata: Vec<(String, String)>,
    pub content_type: Option<String>,
    pub initiated: u64,
}

/// Info about a single uploaded part.
#[derive(Debug, Clone)]
pub struct PartInfo {
    pub part_number: u32,
    pub size: u64,
    pub etag: String,
    /// Temp file path on SMB share (under .spio-uploads/)
    pub temp_path: String,
}

impl MultipartStore {
    pub fn new() -> Self {
        Self {
            uploads: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    /// Create a new multipart upload and return its upload ID.
    pub async fn create(
        &self,
        key: &str,
        metadata: Vec<(String, String)>,
        content_type: Option<String>,
    ) -> String {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let upload_id = format!("{:016x}{:016x}", epoch_nanos(), id);

        let state = UploadState {
            upload_id: upload_id.clone(),
            key: key.to_string(),
            parts: HashMap::new(),
            metadata,
            content_type,
            initiated: epoch_secs(),
        };

        self.uploads.write().await.insert(upload_id.clone(), state);
        upload_id
    }

    /// Record a completed part upload.
    pub async fn put_part(
        &self,
        upload_id: &str,
        part_number: u32,
        size: u64,
        etag: String,
        temp_path: String,
    ) -> Option<()> {
        let mut uploads = self.uploads.write().await;
        let state = uploads.get_mut(upload_id)?;
        state.parts.insert(
            part_number,
            PartInfo {
                part_number,
                size,
                etag,
                temp_path,
            },
        );
        Some(())
    }

    /// Get upload state (for listing parts).
    pub async fn get(&self, upload_id: &str) -> Option<UploadState> {
        self.uploads.read().await.get(upload_id).cloned()
    }

    /// Complete and remove an upload, returning its state.
    pub async fn complete(&self, upload_id: &str) -> Option<UploadState> {
        self.uploads.write().await.remove(upload_id)
    }

    /// Abort and remove an upload, returning its state for cleanup.
    pub async fn abort(&self, upload_id: &str) -> Option<UploadState> {
        self.uploads.write().await.remove(upload_id)
    }

    /// List all active uploads, optionally filtered by key prefix.
    pub async fn list(&self, prefix: Option<&str>) -> Vec<UploadState> {
        let uploads = self.uploads.read().await;
        uploads
            .values()
            .filter(|u| match prefix {
                Some(p) => u.key.starts_with(p),
                None => true,
            })
            .cloned()
            .collect()
    }

    /// Get the temp directory path for multipart parts.
    pub fn temp_dir(upload_id: &str) -> String {
        format!(".spio-uploads\\{}", upload_id)
    }

    /// Get the temp file path for a specific part.
    pub fn temp_part_path(upload_id: &str, part_number: u32) -> String {
        format!(".spio-uploads\\{}\\part-{:05}", upload_id, part_number)
    }
}

fn epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn epoch_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}
