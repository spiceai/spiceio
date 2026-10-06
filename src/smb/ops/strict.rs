//! Server-coordinated publication for explicitly configured strict prefixes.
//!
//! Lock files are permanent: deleting them would let an old open and a new
//! open lock different files for the same key. Their checksummed high-water
//! mark prevents timestamp-based ETags being reused, including after DELETE.
//! All operations under a lock use its original SMB connection; reconnecting
//! and continuing would lose the fence. Uncertain commits fail to the caller.

use super::*;
use crate::crypto::{hex_encode, sha256};
use crate::smb::condition::ConditionFailure;

pub(super) const LOCK_DIR: &str = ".spiceio-locks";
const RECORD_MAGIC: &[u8; 8] = b"SPICEV01";
const RECORD_LEN: usize = 48;

/// The name a component reaches the share as: no stream suffix (`key::$DATA`
/// is `key`; a named stream shares its file's lock), no trailing dots or
/// spaces. `.` and `. ` reduce to nothing.
fn canonical_component(s: &str) -> &str {
    s.split(':')
        .next()
        .unwrap_or_default()
        .trim_end_matches(['.', ' '])
}

fn canonical_path(path: &str) -> String {
    // Canonicalize before filtering so components that reduce to nothing
    // are dropped rather than kept as empty segments.
    path.split(['/', '\\'])
        .map(canonical_component)
        .filter(|s| !s.is_empty())
        .map(str::to_uppercase)
        .collect::<Vec<_>>()
        .join("\\")
}

fn lock_name(path: &str) -> String {
    format!(
        "{LOCK_DIR}\\{}",
        hex_encode(&sha256(canonical_path(path).as_bytes()))
    )
}

impl ShareSession {
    /// Comma-separated S3 prefixes; `*` selects the whole bucket. Configure
    /// identically on every instance serving this share, before admitting traffic.
    pub fn with_strict_prefixes(mut self, prefixes: &str) -> io::Result<Self> {
        let mut values = Vec::new();
        if !prefixes.is_empty() {
            for prefix in prefixes.split(',') {
                let prefix = prefix.trim();
                if prefix.is_empty()
                    || prefix.contains([':', '\0'])
                    || prefix.split(['/', '\\']).any(|s| s == "..")
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid SPICEIO_STRICT_PREFIXES",
                    ));
                }
                values.push(if prefix == "*" {
                    String::new()
                } else {
                    let mut path = canonical_path(prefix);
                    // The empty path is the `*` sentinel; a prefix such as `/`
                    // or `.` must not silently select the whole bucket.
                    if path.is_empty() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "invalid SPICEIO_STRICT_PREFIXES: use * for the whole bucket",
                        ));
                    }
                    if prefix.ends_with(['/', '\\']) {
                        path.push('\\');
                    }
                    path
                });
            }
        }
        self.strict_prefixes = Arc::new(values);
        Ok(self)
    }

    pub fn has_strict_prefixes(&self) -> bool {
        !self.strict_prefixes.is_empty()
    }

    pub fn is_strict(&self, key: &str) -> bool {
        // No allocation or backend operation when strict mode is unused.
        if self.strict_prefixes.is_empty() {
            return false;
        }
        if self.strict_prefixes.iter().any(String::is_empty) {
            return true;
        }
        // Ordinary ASCII cache keys need no temporary normalized String even
        // when this instance also serves a strict metadata prefix.
        if key.is_ascii()
            && !key.contains(['.', ' ', ':'])
            && !key.contains("//")
            && !key.contains("\\\\")
            && !key.contains("/\\")
            && !key.contains("\\/")
        {
            let key = key.trim_start_matches(['/', '\\']).as_bytes();
            return self.strict_prefixes.iter().any(|prefix| {
                key.len() >= prefix.len()
                    && prefix.bytes().zip(key.iter().copied()).all(|(p, k)| {
                        p == if k == b'/' {
                            b'\\'
                        } else {
                            k.to_ascii_uppercase()
                        }
                    })
            });
        }
        let path = canonical_path(key);
        self.strict_prefixes.iter().any(|p| path.starts_with(p))
    }

    /// Run a read `lookup` for `path`, holding its lock record when one exists.
    ///
    /// Reads never create a record, so misses cannot grow the permanent lock
    /// namespace. Mutations create the record before checking or publishing
    /// and hold it until they finish, so without one the lookup runs unlocked.
    /// An unlocked miss is trusted only if the record is still absent
    /// afterwards: one that appeared may belong to a peer whose first strict
    /// publication was mid-rename, so take the lock and look again.
    pub(crate) async fn strict_read<T, F, Fut>(&self, path: &str, mut lookup: F) -> io::Result<T>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = io::Result<T>>,
    {
        if !self.is_strict(path) {
            return lookup().await;
        }
        let (client, tree_id) = self.pick_live().await;
        let name = lock_name(path);
        if let Some(_guard) = Self::strict_open_existing(&client, tree_id, &name).await? {
            return lookup().await;
        }
        let result = lookup().await;
        if !result
            .as_ref()
            .is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
        {
            return result;
        }
        match Self::strict_open_existing(&client, tree_id, &name).await? {
            Some(_guard) => lookup().await,
            None => result,
        }
    }

    async fn strict_open_existing(
        client: &Arc<SmbClient>,
        tree_id: u32,
        name: &str,
    ) -> io::Result<Option<StrictGuard>> {
        match Self::strict_open(client, tree_id, name, CreateDisposition::Open).await {
            Ok(guard) => Ok(Some(guard)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The coordination namespace must never be mutable through S3.
    pub fn reserved_key(key: &str) -> bool {
        // Canonicalize each component first: `. ` reaches the share as `.`,
        // so it must not count as the first significant component.
        key.split(['/', '\\'])
            .map(canonical_component)
            .find(|s| !s.is_empty())
            .is_some_and(|first| first.eq_ignore_ascii_case(LOCK_DIR))
    }

    pub(super) async fn strict_lock(
        &self,
        client: &Arc<SmbClient>,
        tree_id: u32,
        path: &str,
    ) -> io::Result<StrictGuard> {
        let name = lock_name(path);
        self.ensure_parent_dirs_on(client, tree_id, &name).await?;
        Self::strict_open(client, tree_id, &name, CreateDisposition::OpenIf).await
    }

    async fn strict_open(
        client: &Arc<SmbClient>,
        tree_id: u32,
        name: &str,
        disposition: CreateDisposition,
    ) -> io::Result<StrictGuard> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            let result = client
                .create(
                    tree_id,
                    name,
                    DesiredAccess::GenericRead as u32 | DesiredAccess::GenericWrite as u32,
                    0, // Server-enforced exclusive open across sessions and machines.
                    disposition as u32,
                    CreateOptions::NonDirectoryFile as u32,
                )
                .await;
            match result {
                Ok(file) => {
                    return Ok(StrictGuard {
                        client: Some(client.clone()),
                        tree_id,
                        file_id: file.file_id,
                        size: file.file_size,
                    });
                }
                Err(e) if is_busy(&e) && tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(4)).await
                }
                Err(e) => {
                    // A malformed successful CREATE can leave an unidentified
                    // exclusive handle. Closing the session is its only cleanup.
                    if e.kind() == io::ErrorKind::InvalidData {
                        client.poison().await;
                    }
                    return Err(e);
                }
            }
        }
    }
}

pub(super) struct StrictGuard {
    client: Option<Arc<SmbClient>>,
    tree_id: u32,
    file_id: [u8; 16],
    size: u64,
}

impl StrictGuard {
    async fn generation(&self) -> io::Result<u64> {
        if self.size == 0 {
            return Ok(0);
        }
        if self.size != RECORD_LEN as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid strict version record size",
            ));
        }
        let data = self
            .client
            .as_ref()
            .unwrap()
            .read(self.tree_id, &self.file_id, 0, RECORD_LEN as u32)
            .await?;
        decode_generation(&data)
    }

    async fn reserve(&self, time: u64) -> io::Result<()> {
        let client = self.client.as_ref().unwrap();
        let data = encode_generation(time);
        if client.write(self.tree_id, &self.file_id, 0, &data).await? != RECORD_LEN as u32 {
            return Err(io::Error::other("short strict version record write"));
        }
        // Reserve durably BEFORE publication. A failed commit can skip a
        // version, but must never reuse one after a crash or a delete.
        client.flush_file(self.tree_id, &self.file_id).await
    }

    pub(super) async fn release(mut self) -> io::Result<()> {
        let client = self.client.as_ref().unwrap().clone();
        let result = client.close(self.tree_id, &self.file_id).await;
        if result.is_err() {
            client.poison().await;
        }
        self.client.take();
        result
    }
}

impl Drop for StrictGuard {
    fn drop(&mut self) {
        if let Some(client) = self.client.take() {
            let (tree, file) = (self.tree_id, self.file_id);
            // Cancellation must release server locks as well as local mutexes.
            tokio::spawn(async move {
                if client.close(tree, &file).await.is_err() {
                    client.poison().await;
                }
            });
        }
    }
}

fn encode_generation(time: u64) -> [u8; RECORD_LEN] {
    let mut out = [0; RECORD_LEN];
    out[..8].copy_from_slice(RECORD_MAGIC);
    out[8..16].copy_from_slice(&time.to_le_bytes());
    let digest = sha256(&out[..16]);
    out[16..].copy_from_slice(&digest);
    out
}

fn decode_generation(data: &[u8]) -> io::Result<u64> {
    if data.len() != RECORD_LEN || &data[..8] != RECORD_MAGIC || sha256(&data[..16]) != data[16..] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "damaged strict version record; refusing to reuse an ETag",
        ));
    }
    Ok(u64::from_le_bytes(data[8..16].try_into().unwrap()))
}

impl WalWriter {
    pub(super) async fn commit_strict(
        self,
        share: &ShareSession,
        meta: ObjectMeta,
        condition: &WriteCondition,
    ) -> io::Result<ObjectMeta> {
        let result = self.publish_strict(share, meta, condition).await;
        if result.is_err() {
            self.discard_temp().await;
        }
        result
    }

    async fn publish_strict(
        &self,
        share: &ShareSession,
        mut meta: ObjectMeta,
        condition: &WriteCondition,
    ) -> io::Result<ObjectMeta> {
        let client = &self.client;
        let guard = share
            .strict_lock(client, self.tree_id, &self.final_path)
            .await?;
        let result = async {
            let current = match client
                .create_close(
                    self.tree_id,
                    &self.final_path,
                    DesiredAccess::ReadAttributes as u32,
                    ShareAccess::All as u32,
                    CreateDisposition::Open as u32,
                    CreateOptions::NonDirectoryFile as u32,
                )
                .await
            {
                Ok((file, _)) => Some(file),
                Err(e) if e.kind() == io::ErrorKind::NotFound => None,
                Err(e) => return Err(e),
            };
            let current_etag = current
                .as_ref()
                .map(|f| etag_for(f.file_size, f.last_write_time));
            condition.check(current_etag.as_deref())?;
            let previous = guard
                .generation()
                .await?
                .max(current.as_ref().map_or(0, |f| f.last_write_time));
            let written = client
                .query_file_metadata(self.tree_id, &self.file_id)
                .await?;
            let next = previous
                .checked_add(1)
                .ok_or_else(|| io::Error::other("strict version exhausted"))?
                .max(written.last_write_time);
            client
                .set_write_time(self.tree_id, &self.file_id, next)
                .await?;
            let mut verified = client
                .query_file_metadata(self.tree_id, &self.file_id)
                .await?;
            if verified.last_write_time <= previous {
                // Coarse server clocks may round away a 100 ns increment.
                let next_second = previous
                    .checked_div(FILETIME_TICKS_PER_SEC)
                    .and_then(|v| v.checked_add(1))
                    .and_then(|v| v.checked_mul(FILETIME_TICKS_PER_SEC))
                    .ok_or_else(|| io::Error::other("strict version exhausted"))?;
                client
                    .set_write_time(self.tree_id, &self.file_id, next_second)
                    .await?;
                verified = client
                    .query_file_metadata(self.tree_id, &self.file_id)
                    .await?;
            }
            if verified.last_write_time <= previous || verified.file_size != meta.size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "server did not preserve strict object metadata",
                ));
            }
            client.flush_file(self.tree_id, &self.file_id).await?;
            guard.reserve(verified.last_write_time).await?;
            // Reuse neither the lock nor this commit across a reconnection.
            // No-replace is an additional server check for create-if-absent.
            let mut attempts = 0;
            loop {
                match client
                    .rename(
                        self.tree_id,
                        &self.file_id,
                        &self.final_path,
                        *condition != WriteCondition::Absent,
                    )
                    .await
                {
                    Ok(()) => break,
                    Err(e)
                        if (is_busy(&e) || e.kind() == io::ErrorKind::PermissionDenied)
                            && attempts < MAX_RESET_RETRIES =>
                    {
                        busy_backoff(attempts).await;
                        attempts += 1;
                    }
                    Err(e)
                        if e.kind() == io::ErrorKind::AlreadyExists
                            && *condition == WriteCondition::Absent =>
                    {
                        return Err(ConditionFailure::PreconditionFailed.into());
                    }
                    Err(e) if is_reset(&e) => return Err(ConditionFailure::Conflict.into()),
                    Err(e) => return Err(e),
                }
            }
            // Include the published name in the stable-storage boundary.
            client.flush_file(self.tree_id, &self.file_id).await?;
            client.close(self.tree_id, &self.file_id).await?;
            meta.etag = etag_for(verified.file_size, verified.last_write_time);
            meta.last_modified = filetime_to_epoch_secs(verified.last_write_time);
            Ok(meta)
        }
        .await;
        let released = guard.release().await;
        // Keep ConditionalRequestConflict when the lost connection also
        // prevents CLOSE from acknowledging lock release.
        match result {
            Err(e) => Err(e),
            Ok(meta) => {
                released?;
                Ok(meta)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_record_fails_closed_on_torn_writes() {
        let data = encode_generation(123);
        assert_eq!(decode_generation(&data).unwrap(), 123);
        for n in 0..data.len() {
            assert!(decode_generation(&data[..n]).is_err());
        }
        for n in 0..data.len() {
            let mut bad = data;
            bad[n] ^= 1;
            assert!(decode_generation(&bad).is_err());
        }
    }

    #[test]
    fn lock_names_cover_smb_path_aliases() {
        assert_eq!(canonical_path("a/b"), canonical_path("/A//./B. "));
        assert_eq!(canonical_path("a/b"), canonical_path("A\\B"));
        assert_eq!(canonical_path("a/b"), canonical_path("a/b::$DATA"));
        assert_eq!(canonical_path("a/b"), canonical_path("a. :x/b"));
    }

    #[tokio::test]
    async fn strict_prefix_matching_preserves_directory_boundaries_and_aliases() {
        let (state, _server) = crate::test_support::state().await;
        let share = (*state.share)
            .clone()
            .with_strict_prefixes("metadata/")
            .unwrap();
        for key in [
            "metadata/key",
            "METADATA\\key",
            "./metadata//key",
            "metadata. /key",
        ] {
            assert!(share.is_strict(key), "{key}");
        }
        for key in ["cache/key", "metadata-other/key", "metadata"] {
            assert!(!share.is_strict(key), "{key}");
        }
        assert!(ShareSession::reserved_key("./.SPICEIO-LOCKS. /x"));
        assert!(ShareSession::reserved_key(". /.spiceio-locks/x"));
        assert!(ShareSession::reserved_key("/. \\.spiceio-locks:s/x"));
        assert!(!ShareSession::reserved_key("x/.spiceio-locks/y"));
        assert!(share.is_strict(". /metadata/key"));
        assert!(share.is_strict("metadata::$DATA/key"));
        assert!(!share.is_strict("metadata-x:y/key"));
    }

    #[tokio::test]
    async fn strict_prefixes_that_normalize_to_nothing_are_rejected() {
        let (state, _server) = crate::test_support::state().await;
        for prefixes in ["/", ".", ". ", "...", "./", "metadata/,/"] {
            assert!(
                (*state.share)
                    .clone()
                    .with_strict_prefixes(prefixes)
                    .is_err(),
                "{prefixes:?}"
            );
        }
        let share = (*state.share).clone().with_strict_prefixes("*").unwrap();
        assert!(share.is_strict("anything"));
    }
}
