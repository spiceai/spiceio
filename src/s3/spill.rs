//! Machine-wide disk spill — the object cache's second tier.
//!
//! The RAM cache is bounded by what one process can hold resident (8 GiB by
//! default). This tier extends it onto local disk, in a directory shared by
//! every spiceio instance on the machine, so a working set larger than memory
//! still avoids the NAS and a second instance benefits from the first one's
//! reads. Local NVMe runs ~2 GB/s against a backend measured at ~100 MiB/s
//! (see `benches/baselines/`), so an L2 hit is roughly an order of magnitude
//! cheaper than the read it replaces.
//!
//! # Sharing between processes
//!
//! There is no coordinating daemon. Every operation is safe under concurrent
//! access by unrelated processes:
//!
//! * **Publish is atomic** — entries are written to a temp file and renamed
//!   into place, so a reader never observes a half-written body, and two
//!   writers racing on one key leave one whole entry rather than a blend.
//! * **Eviction is serialized by an advisory lock** (`flock`) on `.sweep.lock`,
//!   taken non-blocking: whichever instance gets it sweeps, the others skip
//!   that round instead of walking the tree redundantly.
//! * **Unlink-while-open is safe** on Unix — a reader holding the fd keeps
//!   reading the bytes it opened even if the sweeper evicts the name.
//!
//! # Namespacing
//!
//! Entries are addressed by `sha256(namespace \0 key)`, where the namespace
//! identifies the backend share. Two instances fronting *different* shares
//! must not serve each other's `config.json`, and the namespace is what keeps
//! their key spaces apart in one shared directory. The full namespaced id is
//! also stored in the entry header and compared on read, so a hash collision
//! (or a hand-copied file) is a miss, never a wrong body.
//!
//! # Dirty entries (the write-back journal)
//!
//! With `SPICEIO_WRITE_BACK` on, a PUT is acknowledged from memory and written
//! to the NAS in the background. The spill is where that pending body lives in
//! the meantime: the flusher publishes it **dirty** first, and only marks it
//! clean once the NAS write lands. Dirty entries are named `.d` rather than
//! `.o`, which buys two things for free — the sweeper can skip them without
//! opening anything (evicting one would lose an acknowledged write), and a
//! restart, or a *peer* instance, can find writes stranded by a crash with a
//! single directory walk and replay them. See [`Spill::scan_dirty`].

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;

use crate::crypto::{hex_encode, sha256};

/// Default spill directory. `/var/tmp` rather than `/tmp`: on macOS the latter
/// is periodically cleared, and a cache that evaporates is worse than one that
/// is merely cold. Machine-wide (not per-user, not per-session) so every
/// instance on the host shares one pool of bytes.
pub const DEFAULT_DIR: &str = "/var/tmp/spiceio-cache";

/// Default disk budget for the whole directory, across all instances.
pub const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024 * 1024;

/// Never let the cache push the volume below this much free space, whatever
/// the configured budget says. The effective budget is recomputed on every
/// sweep, so a disk filling up from *other* work shrinks the cache instead of
/// fighting it.
const FREE_FLOOR_BYTES: u64 = 10 * 1024 * 1024 * 1024;

/// Of the space above the floor, the share the cache may claim.
///
/// The floor alone would let a cache with a large configured budget take every
/// spare byte on a nearly-full disk. Halving is what keeps this a *default*
/// that is safe to ship enabled: on a roomy volume the configured budget binds
/// long before this does, and it only takes effect when space is genuinely
/// tight — where yielding is the right call for a cache.
const FREE_CLAIM_FRACTION: u64 = 2;

/// Entry header size. Layout (little-endian, matching the SMB protocol code):
///
/// ```text
///  0..4   magic "SPIO"
///  4..6   format version
///  6..8   flags (bit 0: dirty — body is not yet on the backend)
///  8..12  namespaced-id length
/// 12..16  etag length
/// 16..24  body length
/// 24..32  last-modified (epoch seconds)
/// 32..64  SHA-256 of the body
/// ```
const HEADER_LEN: usize = 64;
const MAGIC: &[u8; 4] = b"SPIO";
const FORMAT_VERSION: u16 = 1;
const FLAG_DIRTY: u16 = 1 << 0;

/// Subdirectory holding the entry shards, versioned so a future format change
/// can be introduced by walking away from the old tree rather than by trying
/// to interpret it.
const TREE: &str = "v1";
/// Staging area for not-yet-published entries, swept of strays on startup.
const TMP: &str = "tmp";
const LOCK_FILE: &str = ".sweep.lock";

const CLEAN_EXT: &str = "o";
const DIRTY_EXT: &str = "d";

/// Only restamp an entry's mtime (its LRU position) when it is already this
/// stale. Every read would otherwise pay a write syscall to move a timestamp
/// that eviction reads at minute granularity anyway.
const TOUCH_AFTER: Duration = Duration::from_secs(600);

/// A body recovered from the spill, with the metadata needed to answer a GET
/// or to revalidate against the backend.
pub struct SpillEntry {
    pub etag: String,
    pub last_modified: u64,
    pub body: Bytes,
    /// Digest of `body`, carried so a write-back flush can prove the entry it
    /// is about to mark clean is still the one it wrote.
    pub body_sha: [u8; 32],
}

/// A dirty entry found by [`Spill::scan_dirty`] — an acknowledged write that
/// has not reached the backend.
pub struct DirtyEntry {
    pub key: String,
    pub entry: SpillEntry,
    /// Seconds since the entry was published, on the local clock.
    pub age_secs: u64,
}

/// What one sweep did, for logging and for pacing the next one.
#[derive(Default, Debug, Clone, Copy)]
pub struct SweepStats {
    /// Another instance held the lock; this round did nothing.
    pub skipped: bool,
    pub entries: u64,
    pub bytes: u64,
    pub evicted_entries: u64,
    pub evicted_bytes: u64,
    /// Bytes held by dirty entries, which are never evicted.
    pub dirty_bytes: u64,
    /// Budget actually applied, after the free-space floor.
    pub effective_budget: u64,
}

/// Shared on-disk cache tier.
pub struct Spill {
    /// `<dir>/v1`
    tree: PathBuf,
    /// `<dir>/v1/tmp`
    tmp: PathBuf,
    lock_path: PathBuf,
    /// Identifies the backend share; mixed into every key hash.
    namespace: String,
    max_bytes: u64,
    max_object_bytes: u64,
    hits: AtomicU64,
    misses: AtomicU64,
    hit_bytes: AtomicU64,
    writes: AtomicU64,
    /// Monotonic counter making temp file names unique within the process.
    tmp_seq: AtomicU64,
    /// Keys this process has published dirty and not yet promoted.
    ///
    /// The directory cannot answer "whose is this?" — a dirty entry on disk is
    /// either ours or a live peer's, and the two need opposite treatment at
    /// shutdown: ours must be flushed before we exit, because nothing else is
    /// going to do it promptly, while a peer's is mid-flight on a process that
    /// is still running and is not ours to touch. Tracking what we wrote is
    /// exact, needs no on-disk owner field, and cannot mistake a peer's entry
    /// for our own.
    owned_dirty: Mutex<HashSet<String>>,
}

impl Spill {
    /// Create the directory tree and return a handle.
    ///
    /// Created 0700. "Machine-wide" means every spiceio *process*, which in
    /// practice run as one user on a build host — and a world-writable cache in
    /// `/var/tmp` would let any local user plant an entry. Planting is not
    /// idly defeated by the header checks: an attacker who knows the namespace
    /// and key can compute a valid digest, and in immutable mode that entry is
    /// served with no backend revalidation at all.
    ///
    /// An existing directory's permissions are left exactly as found, so an
    /// administrator who deliberately sets up a group-shared directory (and
    /// points `SPICEIO_SPILL_DIR` at it) gets cross-user sharing by choice
    /// rather than by default.
    pub fn open(
        dir: &Path,
        namespace: String,
        max_bytes: u64,
        max_object_bytes: u64,
    ) -> io::Result<Self> {
        let tree = dir.join(TREE);
        let tmp = tree.join(TMP);
        create_shared_dir(dir)?;
        create_shared_dir(&tree)?;
        create_shared_dir(&tmp)?;
        let max_bytes = max_bytes.max(1);
        let max_object_bytes = max_object_bytes.max(1).min(max_bytes);
        let spill = Self {
            tree,
            tmp,
            lock_path: dir.join(LOCK_FILE),
            namespace,
            max_bytes,
            max_object_bytes,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            hit_bytes: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            tmp_seq: AtomicU64::new(0),
            owned_dirty: Mutex::new(HashSet::new()),
        };
        // A temp file can only be a stray from a crashed writer — nothing
        // reads them, and a live one is at most seconds old.
        spill.clear_stale_temps();
        Ok(spill)
    }

    pub fn max_object_bytes(&self) -> u64 {
        self.max_object_bytes
    }

    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// `(hits, misses, bytes served from disk, entries written)`.
    pub fn stats(&self) -> (u64, u64, u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
            self.hit_bytes.load(Ordering::Relaxed),
            self.writes.load(Ordering::Relaxed),
        )
    }

    /// Path of `key`'s entry with the given extension.
    fn path_for(&self, key: &str, ext: &str) -> PathBuf {
        let mut h = crate::crypto::Sha256::new();
        h.update(self.namespace.as_bytes());
        h.update(b"\0");
        h.update(key.as_bytes());
        let hex = hex_encode(&h.finalize());
        // One level of 256 shards: enough that a full 64 GiB cache holds a few
        // hundred entries per directory, which every filesystem handles well.
        self.tree
            .join(&hex[..2])
            .join(format!("{}.{ext}", &hex[2..]))
    }

    /// The id stored in the header and compared on read.
    fn id_for(&self, key: &str) -> Vec<u8> {
        let mut id = Vec::with_capacity(self.namespace.len() + 1 + key.len());
        id.extend_from_slice(self.namespace.as_bytes());
        id.push(0);
        id.extend_from_slice(key.as_bytes());
        id
    }

    /// Read `key`'s body, or `None` if it is absent or unusable.
    ///
    /// Blocking; call from `spawn_blocking`. A clean entry is preferred over a
    /// dirty one — they are the same bytes, but the clean name is the common
    /// case and this keeps the miss path to a single failed `open`.
    pub fn get(&self, key: &str) -> Option<SpillEntry> {
        let entry = self
            .read_entry(&self.path_for(key, CLEAN_EXT), key)
            .or_else(|| self.read_entry(&self.path_for(key, DIRTY_EXT), key));
        match entry {
            Some(e) => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                self.hit_bytes
                    .fetch_add(e.body.len() as u64, Ordering::Relaxed);
                Some(e)
            }
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Read and validate one entry file.
    ///
    /// Every failure is a miss, never an error: a truncated body, a header from
    /// a different format version, an id that does not match (hash collision or
    /// a stray file) — in each case the cache simply does not have the object,
    /// and the caller falls through to the backend.
    fn read_entry(&self, path: &Path, key: &str) -> Option<SpillEntry> {
        let mut f = File::open(path).ok()?;
        let mut header = [0u8; HEADER_LEN];
        f.read_exact(&mut header).ok()?;
        if &header[0..4] != MAGIC || u16::from_le_bytes([header[4], header[5]]) != FORMAT_VERSION {
            return None;
        }
        let id_len = u32::from_le_bytes(header[8..12].try_into().ok()?) as usize;
        let etag_len = u32::from_le_bytes(header[12..16].try_into().ok()?) as usize;
        let body_len = u64::from_le_bytes(header[16..24].try_into().ok()?);
        let last_modified = u64::from_le_bytes(header[24..32].try_into().ok()?);
        let mut body_sha = [0u8; 32];
        body_sha.copy_from_slice(&header[32..64]);

        // Refuse to allocate on a corrupt length before reading anything.
        if body_len > self.max_object_bytes || id_len > 64 * 1024 || etag_len > 1024 {
            return None;
        }

        let mut id = vec![0u8; id_len];
        f.read_exact(&mut id).ok()?;
        if id != self.id_for(key) {
            return None;
        }
        let mut etag = vec![0u8; etag_len];
        f.read_exact(&mut etag).ok()?;
        let etag = String::from_utf8(etag).ok()?;

        let mut body = vec![0u8; body_len as usize];
        f.read_exact(&mut body).ok()?;

        // The digest is what makes an unclean shutdown safe. `rename` publishes
        // the *name* atomically, but the bytes behind it are not forced to
        // stable storage first (deliberately — an fsync per entry would cost
        // more than the backend read this tier exists to avoid), so a power
        // loss can leave a complete-looking file holding zeroes. Verifying
        // costs ~0.3 ms for the measured mean object against the ~6 ms NAS read
        // it replaces, and turns "silently serve garbage" into "miss".
        if sha256(&body) != body_sha {
            return None;
        }

        self.touch_if_stale(&f);
        Some(SpillEntry {
            etag,
            last_modified,
            body: Bytes::from(body),
            body_sha,
        })
    }

    /// Move an entry to the front of the LRU by restamping its mtime, which is
    /// what the sweeper orders by. Best-effort and throttled — see [`TOUCH_AFTER`].
    fn touch_if_stale(&self, f: &File) {
        let Ok(meta) = f.metadata() else { return };
        let Ok(modified) = meta.modified() else {
            return;
        };
        let now = SystemTime::now();
        if now.duration_since(modified).unwrap_or_default() > TOUCH_AFTER {
            let _ = f.set_times(fs::FileTimes::new().set_modified(now));
        }
    }

    /// Publish `key`. Returns the body digest, which [`Spill::promote`] needs.
    ///
    /// Blocking; call from `spawn_blocking`. Writing to a temp file and
    /// renaming is what makes concurrent publishers safe: the rename is atomic,
    /// so a reader sees either the previous entry or this one, never a splice.
    pub fn put(
        &self,
        key: &str,
        etag: &str,
        last_modified: u64,
        body: &[u8],
        dirty: bool,
    ) -> io::Result<[u8; 32]> {
        let body_sha = sha256(body);
        if body.len() as u64 > self.max_object_bytes {
            return Ok(body_sha);
        }
        let id = self.id_for(key);

        let mut header = [0u8; HEADER_LEN];
        header[0..4].copy_from_slice(MAGIC);
        header[4..6].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        header[6..8].copy_from_slice(&(if dirty { FLAG_DIRTY } else { 0 }).to_le_bytes());
        header[8..12].copy_from_slice(&(id.len() as u32).to_le_bytes());
        header[12..16].copy_from_slice(&(etag.len() as u32).to_le_bytes());
        header[16..24].copy_from_slice(&(body.len() as u64).to_le_bytes());
        header[24..32].copy_from_slice(&last_modified.to_le_bytes());
        header[32..64].copy_from_slice(&body_sha);

        let tmp_path = self.tmp.join(format!(
            "{}-{}",
            std::process::id(),
            self.tmp_seq.fetch_add(1, Ordering::Relaxed)
        ));
        let write = || -> io::Result<()> {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_path)?;
            f.write_all(&header)?;
            f.write_all(&id)?;
            f.write_all(etag.as_bytes())?;
            f.write_all(body)?;
            Ok(())
        };
        if let Err(e) = write() {
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }

        let ext = if dirty { DIRTY_EXT } else { CLEAN_EXT };
        let dest = self.path_for(key, ext);
        // The shard directory is created lazily — 256 of them up front would be
        // 256 syscalls at startup for a cache that may never be written.
        if let Some(parent) = dest.parent()
            && !parent.exists()
        {
            create_shared_dir(parent)?;
        }
        if let Err(e) = fs::rename(&tmp_path, &dest) {
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }
        // The two names are alternate spellings of one entry, so publishing
        // either must retire the other — otherwise a stale clean copy could
        // outlive the dirty body that supersedes it.
        let other = self.path_for(key, if dirty { CLEAN_EXT } else { DIRTY_EXT });
        let _ = fs::remove_file(other);
        // Ownership follows the entry: publishing dirty makes it ours to flush,
        // publishing clean means it no longer needs flushing.
        let mut owned = self.owned_dirty.lock().unwrap_or_else(|e| e.into_inner());
        if dirty {
            owned.insert(key.to_string());
        } else {
            owned.remove(key);
        }
        drop(owned);
        self.writes.fetch_add(1, Ordering::Relaxed);
        Ok(body_sha)
    }

    /// Promote `key` from dirty to clean, now that the body is on the backend.
    ///
    /// The backend assigns the real etag and mtime (both derive from the
    /// server's clock), so promotion also replaces the provisional metadata the
    /// acknowledged write was published with. Without that, every later GET in
    /// etag mode would revalidate against the NAS, miss, and re-read a body
    /// this tier already holds — the cache would work for everything *except*
    /// what this instance wrote.
    ///
    /// `expect_sha` guards against promoting somebody else's bytes: a second
    /// PUT may have replaced the entry while this flush was in flight, and
    /// marking *that* body clean would drop it from the replay set while the
    /// backend still holds the older version. Mismatch → leave it dirty, and
    /// let the newer write's own flush publish it.
    pub fn promote(
        &self,
        key: &str,
        expect_sha: &[u8; 32],
        etag: &str,
        last_modified: u64,
        body: &[u8],
    ) -> io::Result<bool> {
        let dirty_path = self.path_for(key, DIRTY_EXT);
        let mut f = match File::open(&dirty_path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        };
        let mut header = [0u8; HEADER_LEN];
        f.read_exact(&mut header)?;
        if &header[32..64] != expect_sha.as_slice() {
            return Ok(false);
        }
        let id_len = u32::from_le_bytes(header[8..12].try_into().unwrap_or_default()) as usize;
        let etag_len = u32::from_le_bytes(header[12..16].try_into().unwrap_or_default()) as usize;
        drop(f);

        // Etags here are fixed-width (`{mtime:016x}{size:016x}`), so the new
        // one overwrites the old in place and the body — the expensive part —
        // is not rewritten. A width change would be a format change; fall back
        // to republishing rather than corrupting the entry.
        if etag.len() != etag_len {
            self.put(key, etag, last_modified, body, false)?;
            return Ok(true);
        }

        let mut f = OpenOptions::new().write(true).open(&dirty_path)?;
        f.seek(SeekFrom::Start(6))?;
        f.write_all(&0u16.to_le_bytes())?;
        f.seek(SeekFrom::Start(24))?;
        f.write_all(&last_modified.to_le_bytes())?;
        f.seek(SeekFrom::Start((HEADER_LEN + id_len) as u64))?;
        f.write_all(etag.as_bytes())?;
        drop(f);
        // Rename last. A crash between the header rewrite and the rename leaves
        // a file that is still *named* dirty, so it is replayed — an idempotent
        // re-write of bytes the backend already has. The reverse order could
        // publish a clean name over a header that still claims dirty.
        fs::rename(&dirty_path, self.path_for(key, CLEAN_EXT))?;
        self.owned_dirty
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
        Ok(true)
    }

    /// Keys this process published dirty that have not been promoted.
    ///
    /// Shutdown flushes exactly these. A peer's dirty entries are deliberately
    /// absent: that process is still running and will promote them itself.
    pub fn owned_dirty_keys(&self) -> Vec<String> {
        self.owned_dirty
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    /// True if an entry file exists for `key`.
    ///
    /// A name check only — the body is not read or verified, so a corrupt entry
    /// answers true here and misses on the subsequent [`Self::get`]. That is the
    /// right bias: this decides whether a cheap stat revalidation is worth
    /// preferring over a cold read, and being wrong costs one extra round trip,
    /// not correctness.
    pub fn contains_key(&self, key: &str) -> bool {
        self.path_for(key, CLEAN_EXT).exists() || self.path_for(key, DIRTY_EXT).exists()
    }

    /// Drop only the *clean* copy of `key`, leaving any journalled write.
    ///
    /// For cache invalidation — a backend stat that says the object is gone or
    /// has changed. A dirty entry is not a stale cache copy: it is an
    /// acknowledged write that has not reached the backend, which is exactly
    /// why the backend does not have it. Deleting it here would destroy a write
    /// a client was told had succeeded, and if the entry belongs to a peer
    /// instance it is not ours to delete at all.
    pub fn drop_clean(&self, key: &str) {
        let _ = fs::remove_file(self.path_for(key, CLEAN_EXT));
    }

    /// Drop `key` from the spill entirely (an explicit DELETE or overwrite).
    pub fn remove(&self, key: &str) {
        let _ = fs::remove_file(self.path_for(key, CLEAN_EXT));
        let _ = fs::remove_file(self.path_for(key, DIRTY_EXT));
        // Deleted, so there is nothing left to flush on our behalf.
        self.owned_dirty
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
    }

    /// Find acknowledged writes that never reached the backend.
    ///
    /// `min_age` skips entries a *live* instance is probably flushing right
    /// now. Replaying one anyway would be harmless — the same bytes, written
    /// twice — but there is no reason to duplicate work that is already in
    /// progress. Entries older than that are either this instance's own
    /// (recovered after a restart) or a crashed peer's, and in both cases the
    /// bytes are only on this disk until somebody writes them out.
    ///
    /// Also returns how many entries were skipped for being too young, so the
    /// caller can come back for them soon rather than at its normal cadence —
    /// a write stranded seconds ago is exactly the one worth retrying quickly.
    pub fn scan_dirty(&self, min_age: Duration) -> (Vec<DirtyEntry>, usize) {
        let mut out = Vec::new();
        let mut young = 0usize;
        let now = SystemTime::now();
        for shard in read_dir_sorted(&self.tree) {
            if shard.file_name().map(|n| n.as_bytes()) == Some(TMP.as_bytes()) {
                continue;
            }
            for entry in read_dir_sorted(&shard) {
                if entry.extension().map(|e| e.as_bytes()) != Some(DIRTY_EXT.as_bytes()) {
                    continue;
                }
                let Ok(meta) = fs::metadata(&entry) else {
                    continue;
                };
                let age = meta
                    .modified()
                    .ok()
                    .and_then(|m| now.duration_since(m).ok())
                    .unwrap_or_default();
                if age < min_age {
                    young += 1;
                    continue;
                }
                if let Some((key, e)) = self.read_dirty_by_path(&entry) {
                    out.push(DirtyEntry {
                        key,
                        entry: e,
                        age_secs: age.as_secs(),
                    });
                }
            }
        }
        (out, young)
    }

    /// Read an entry whose key is not known up front, recovering it from the
    /// stored id. Only entries in *this* instance's namespace are returned —
    /// another share's pending writes are not ours to publish.
    fn read_dirty_by_path(&self, path: &Path) -> Option<(String, SpillEntry)> {
        let mut f = File::open(path).ok()?;
        let mut header = [0u8; HEADER_LEN];
        f.read_exact(&mut header).ok()?;
        if &header[0..4] != MAGIC || u16::from_le_bytes([header[4], header[5]]) != FORMAT_VERSION {
            return None;
        }
        let id_len = u32::from_le_bytes(header[8..12].try_into().ok()?) as usize;
        let etag_len = u32::from_le_bytes(header[12..16].try_into().ok()?) as usize;
        let body_len = u64::from_le_bytes(header[16..24].try_into().ok()?);
        let last_modified = u64::from_le_bytes(header[24..32].try_into().ok()?);
        let mut body_sha = [0u8; 32];
        body_sha.copy_from_slice(&header[32..64]);
        if body_len > self.max_object_bytes || id_len > 64 * 1024 || etag_len > 1024 {
            return None;
        }
        let mut id = vec![0u8; id_len];
        f.read_exact(&mut id).ok()?;
        let prefix = self.namespace.as_bytes();
        if id.len() <= prefix.len() || &id[..prefix.len()] != prefix || id[prefix.len()] != 0 {
            return None;
        }
        let key = String::from_utf8(id[prefix.len() + 1..].to_vec()).ok()?;
        let mut etag = vec![0u8; etag_len];
        f.read_exact(&mut etag).ok()?;
        let etag = String::from_utf8(etag).ok()?;
        let mut body = vec![0u8; body_len as usize];
        f.read_exact(&mut body).ok()?;
        if sha256(&body) != body_sha {
            return None;
        }
        Some((
            key,
            SpillEntry {
                etag,
                last_modified,
                body: Bytes::from(body),
                body_sha,
            },
        ))
    }

    /// Enforce the machine-wide budget, oldest entry first.
    ///
    /// Blocking; call from `spawn_blocking`. Serialized across instances by a
    /// non-blocking `flock`, so concurrent sweeps cost one failed lock rather
    /// than N redundant tree walks fighting over the same victims.
    pub fn sweep(&self) -> SweepStats {
        self.sweep_to(None)
    }

    /// `sweep`, with the budget optionally forced — the tests need a target
    /// that does not depend on how full the host's disk happens to be.
    fn sweep_to(&self, budget: Option<u64>) -> SweepStats {
        let Some(_lock) = SweepLock::try_acquire(&self.lock_path) else {
            return SweepStats {
                skipped: true,
                ..Default::default()
            };
        };
        self.clear_stale_temps();

        // (mtime, size, path) for every evictable entry, plus the dirty bytes
        // that count against the budget but cannot be reclaimed.
        let mut candidates: Vec<(SystemTime, u64, PathBuf)> = Vec::new();
        let mut stats = SweepStats::default();
        for shard in read_dir_sorted(&self.tree) {
            if shard.file_name().map(|n| n.as_bytes()) == Some(TMP.as_bytes()) {
                continue;
            }
            for entry in read_dir_sorted(&shard) {
                let Ok(meta) = fs::metadata(&entry) else {
                    continue;
                };
                if !meta.is_file() {
                    continue;
                }
                let size = meta.len();
                stats.entries += 1;
                stats.bytes += size;
                // An acknowledged write that is not yet on the backend exists
                // *only* here. Evicting it would turn a 200 the client already
                // received into lost data, so it is charged against the budget
                // but never chosen as a victim.
                if entry.extension().map(|e| e.as_bytes()) == Some(DIRTY_EXT.as_bytes()) {
                    stats.dirty_bytes += size;
                    continue;
                }
                let mtime = meta.modified().unwrap_or(UNIX_EPOCH);
                candidates.push((mtime, size, entry));
            }
        }

        stats.effective_budget = budget.unwrap_or_else(|| self.effective_budget(stats.bytes));
        if stats.bytes <= stats.effective_budget {
            return stats;
        }

        // Oldest first — mtime doubles as the LRU stamp (see `touch_if_stale`).
        candidates.sort_by_key(|c| c.0);
        let mut live = stats.bytes;
        for (_, size, path) in candidates {
            if live <= stats.effective_budget {
                break;
            }
            if fs::remove_file(&path).is_ok() {
                live = live.saturating_sub(size);
                stats.evicted_entries += 1;
                stats.evicted_bytes += size;
            }
        }
        stats
    }

    /// Budget after the free-space floor.
    ///
    /// `used` is what the cache already occupies, and is added back because
    /// evicting it is precisely how the cache gives space back — a volume that
    /// is full *of cache* should shed entries, not clamp its budget to zero and
    /// stop admitting anything.
    fn effective_budget(&self, used: u64) -> u64 {
        let Some(avail) = volume_avail(&self.tree) else {
            return self.max_bytes;
        };
        let spendable = (avail + used).saturating_sub(FREE_FLOOR_BYTES) / FREE_CLAIM_FRACTION;
        self.max_bytes.min(spendable)
    }

    /// Remove staging files left by a crashed writer. Anything currently being
    /// written is renamed within milliseconds, so age alone distinguishes them.
    fn clear_stale_temps(&self) {
        let now = SystemTime::now();
        for entry in read_dir_sorted(&self.tmp) {
            let Ok(meta) = fs::metadata(&entry) else {
                continue;
            };
            let age = meta
                .modified()
                .ok()
                .and_then(|m| now.duration_since(m).ok())
                .unwrap_or_default();
            if age > Duration::from_secs(300) {
                let _ = fs::remove_file(&entry);
            }
        }
    }
}

/// Create a directory for the shared cache, private to this user.
///
/// The mode is set explicitly after creation because `DirBuilder::mode` is
/// subject to the process umask, which can only *remove* bits — a umask of 0
/// would otherwise leave a 0777 directory. Pre-existing directories are left
/// alone; see [`Spill::open`] for why that distinction matters.
fn create_shared_dir(path: &Path) -> io::Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    match fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
    {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Ok(()),
        Err(e) => return Err(e),
    }
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    Ok(())
}

/// Directory entries as paths, in whatever order the filesystem gives them.
/// Errors read as "nothing here" — a cache tier must never fail a request.
fn read_dir_sorted(path: &Path) -> Vec<PathBuf> {
    match fs::read_dir(path) {
        Ok(rd) => rd.filter_map(|e| e.ok().map(|e| e.path())).collect(),
        Err(_) => Vec::new(),
    }
}

// ── Advisory lock ───────────────────────────────────────────────────────────

/// `flock`-based sweep lock. Released when the file closes, including if the
/// process dies mid-sweep — so a crash cannot wedge eviction for everyone else.
struct SweepLock {
    file: File,
}

impl SweepLock {
    fn try_acquire(path: &Path) -> Option<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .ok()?;
        // SAFETY: `file` owns a valid open descriptor for the duration of the
        // call, which is all flock requires.
        let rc = unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) };
        if rc != 0 {
            return None;
        }
        Some(Self { file })
    }
}

impl Drop for SweepLock {
    fn drop(&mut self) {
        // SAFETY: same descriptor, still open until this struct is dropped.
        unsafe {
            flock(self.file.as_raw_fd(), LOCK_UN);
        }
    }
}

const LOCK_EX: i32 = 2;
const LOCK_NB: i32 = 4;
const LOCK_UN: i32 = 8;

unsafe extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
    fn statfs(path: *const i8, buf: *mut Statfs) -> i32;
}

/// macOS `struct statfs` (the 64-bit-inode variant every arm64 build uses).
///
/// Only the leading block counts are read, but the whole struct must be
/// declared at its true size — the kernel fills all of it, and a short buffer
/// would be a stack overwrite. `statfs_layout_matches_the_abi` locks the size
/// down.
#[repr(C)]
struct Statfs {
    f_bsize: u32,
    f_iosize: i32,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    _rest: [u8; 2168 - 32],
}

/// Bytes available to an unprivileged writer on the volume holding `path`.
fn volume_avail(path: &Path) -> Option<u64> {
    let mut c = Vec::with_capacity(path.as_os_str().as_bytes().len() + 1);
    c.extend_from_slice(path.as_os_str().as_bytes());
    c.push(0);
    let mut buf = Statfs {
        f_bsize: 0,
        f_iosize: 0,
        f_blocks: 0,
        f_bfree: 0,
        f_bavail: 0,
        _rest: [0; 2168 - 32],
    };
    // SAFETY: `c` is NUL-terminated and `buf` is the full ABI size.
    let rc = unsafe { statfs(c.as_ptr() as *const i8, &mut buf) };
    if rc != 0 {
        return None;
    }
    Some(buf.f_bavail * buf.f_bsize as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Temp directory that cleans itself up, so the tests leave no strays in
    /// the real shared spill location.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "spiceio-spill-test-{}-{tag}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn spill(tag: &str, dir: &TempDir) -> Spill {
        Spill::open(&dir.0, "test-ns".into(), 1 << 20, 1 << 18).unwrap_or_else(|e| {
            panic!("open spill for {tag}: {e}");
        })
    }

    #[test]
    fn the_cache_directory_is_private_to_this_user() {
        // A world-writable cache in /var/tmp would let any local user plant an
        // entry, and an entry planted with a correct digest is served as a hit
        // — with no backend revalidation at all in immutable mode.
        let d = TempDir::new("perms");
        let s = spill("perms", &d);
        for p in [&s.tree, &s.tmp] {
            let mode = fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{p:?} is group/other accessible: {mode:o}");
        }
    }

    #[test]
    fn an_existing_directory_keeps_its_permissions() {
        // Cross-user sharing stays available to an administrator who sets up a
        // group-shared directory deliberately.
        let d = TempDir::new("preserve");
        let dir = d.0.join("preset");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o770)).unwrap();
        let _ = Spill::open(&dir, "ns".into(), 1 << 20, 1 << 18).unwrap();
        let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o770, "clobbered an administrator's permissions");
    }

    #[test]
    fn round_trips_a_body() {
        let d = TempDir::new("roundtrip");
        let s = spill("roundtrip", &d);
        s.put("a/b.o", "etag1", 42, b"hello", false).unwrap();
        let e = s.get("a/b.o").unwrap();
        assert_eq!(&e.body[..], b"hello");
        assert_eq!(e.etag, "etag1");
        assert_eq!(e.last_modified, 42);
    }

    #[test]
    fn miss_is_none_not_error() {
        let d = TempDir::new("miss");
        let s = spill("miss", &d);
        assert!(s.get("absent").is_none());
        let (_, misses, _, _) = s.stats();
        assert_eq!(misses, 1);
    }

    #[test]
    fn namespaces_do_not_collide() {
        // Two instances fronting different shares share one directory; a key
        // that exists in both must not cross over.
        let d = TempDir::new("ns");
        let a = Spill::open(&d.0, "share-a".into(), 1 << 20, 1 << 18).unwrap();
        let b = Spill::open(&d.0, "share-b".into(), 1 << 20, 1 << 18).unwrap();
        a.put("config.json", "e", 1, b"from-a", false).unwrap();
        b.put("config.json", "e", 1, b"from-b", false).unwrap();
        assert_eq!(&a.get("config.json").unwrap().body[..], b"from-a");
        assert_eq!(&b.get("config.json").unwrap().body[..], b"from-b");
    }

    #[test]
    fn corrupt_body_reads_as_a_miss() {
        // The property that makes an unclean shutdown safe: a file whose bytes
        // do not match the digest must never be served.
        let d = TempDir::new("corrupt");
        let s = spill("corrupt", &d);
        s.put("k", "e", 1, b"good-bytes", false).unwrap();
        let path = s.path_for("k", CLEAN_EXT);
        let mut f = OpenOptions::new().write(true).open(&path).unwrap();
        f.seek(SeekFrom::End(-1)).unwrap();
        f.write_all(b"X").unwrap();
        drop(f);
        assert!(s.get("k").is_none());
    }

    #[test]
    fn truncated_file_reads_as_a_miss() {
        let d = TempDir::new("trunc");
        let s = spill("trunc", &d);
        s.put("k", "e", 1, b"0123456789", false).unwrap();
        let path = s.path_for("k", CLEAN_EXT);
        let f = OpenOptions::new().write(true).open(&path).unwrap();
        f.set_len(HEADER_LEN as u64 + 4).unwrap();
        drop(f);
        assert!(s.get("k").is_none());
    }

    #[test]
    fn dirty_entry_is_readable_and_scannable() {
        let d = TempDir::new("dirty");
        let s = spill("dirty", &d);
        s.put("pending/k", "e", 7, b"body", true).unwrap();
        // Serving a pending write from the spill is what lets a peer instance
        // read an object that has not reached the NAS yet.
        assert_eq!(&s.get("pending/k").unwrap().body[..], b"body");
        let (dirty, _) = s.scan_dirty(Duration::ZERO);
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0].key, "pending/k");
        assert_eq!(&dirty[0].entry.body[..], b"body");
    }

    #[test]
    fn scan_dirty_skips_young_entries() {
        // Young dirty entries belong to a flush that is probably in flight.
        let d = TempDir::new("young");
        let s = spill("young", &d);
        s.put("k", "e", 1, b"body", true).unwrap();
        let (found, young) = s.scan_dirty(Duration::from_secs(60));
        assert!(found.is_empty());
        assert_eq!(
            young, 1,
            "a skipped entry must be reported so it is retried soon"
        );
    }

    #[test]
    fn scan_dirty_ignores_other_namespaces() {
        let d = TempDir::new("ns-dirty");
        let a = Spill::open(&d.0, "share-a".into(), 1 << 20, 1 << 18).unwrap();
        let b = Spill::open(&d.0, "share-b".into(), 1 << 20, 1 << 18).unwrap();
        a.put("k", "e", 1, b"a-body", true).unwrap();
        assert!(b.scan_dirty(Duration::ZERO).0.is_empty());
        assert_eq!(a.scan_dirty(Duration::ZERO).0.len(), 1);
    }

    #[test]
    fn promote_clears_dirty_and_adopts_the_backend_metadata() {
        let d = TempDir::new("clean");
        let s = spill("clean", &d);
        let sha = s.put("k", "provisional-etag", 1, b"body", true).unwrap();
        assert!(
            s.promote("k", &sha, "real-etag-aaaaaa", 999, b"body")
                .unwrap()
        );
        assert!(s.scan_dirty(Duration::ZERO).0.is_empty());
        let e = s.get("k").unwrap();
        assert_eq!(&e.body[..], b"body");
        assert_eq!(e.etag, "real-etag-aaaaaa");
        assert_eq!(e.last_modified, 999);
        // Already clean — nothing to promote, and not an error.
        assert!(
            !s.promote("k", &sha, "real-etag-aaaaaa", 999, b"body")
                .unwrap()
        );
    }

    #[test]
    fn promote_republishes_when_the_etag_width_changes() {
        // The in-place rewrite only holds for a same-width etag; anything else
        // must republish rather than splice a wrong-length field into place.
        let d = TempDir::new("width");
        let s = spill("width", &d);
        let sha = s.put("k", "short", 1, b"body", true).unwrap();
        assert!(
            s.promote("k", &sha, "much-longer-etag", 7, b"body")
                .unwrap()
        );
        let e = s.get("k").unwrap();
        assert_eq!(e.etag, "much-longer-etag");
        assert_eq!(e.last_modified, 7);
        assert_eq!(&e.body[..], b"body");
        assert!(s.scan_dirty(Duration::ZERO).0.is_empty());
    }

    #[test]
    fn promote_refuses_a_superseded_entry() {
        // A second PUT replaced the pending body while the first flush was in
        // flight. Clearing the dirty flag now would drop v2 from the replay
        // set while the backend still holds v1.
        let d = TempDir::new("supersede");
        let s = spill("supersede", &d);
        let sha_v1 = s.put("k", "e1", 1, b"v1", true).unwrap();
        s.put("k", "e2", 2, b"v2-longer", true).unwrap();
        assert!(!s.promote("k", &sha_v1, "e1", 3, b"v1").unwrap());
        let (dirty, _) = s.scan_dirty(Duration::ZERO);
        assert_eq!(dirty.len(), 1);
        assert_eq!(&dirty[0].entry.body[..], b"v2-longer");
    }

    #[test]
    fn publishing_retires_the_other_spelling() {
        // Clean and dirty are two names for one entry; both existing at once
        // would let a stale clean copy outlive the body that replaced it.
        let d = TempDir::new("spelling");
        let s = spill("spelling", &d);
        s.put("k", "e1", 1, b"dirty-body", true).unwrap();
        s.put("k", "e2", 2, b"clean-body", false).unwrap();
        assert!(!s.path_for("k", DIRTY_EXT).exists());
        assert_eq!(&s.get("k").unwrap().body[..], b"clean-body");

        s.put("k", "e3", 3, b"dirty-again", true).unwrap();
        assert!(!s.path_for("k", CLEAN_EXT).exists());
        assert_eq!(&s.get("k").unwrap().body[..], b"dirty-again");
    }

    #[test]
    fn drop_clean_spares_a_journalled_write() {
        // A backend revalidation failure means the object is not there — which
        // is exactly what a pending write looks like. Treating that as "stale
        // cache, delete it" would destroy an acknowledged write, and if the
        // entry belongs to a peer instance it is not ours to delete at all.
        let d = TempDir::new("drop-clean");
        let s = spill("drop-clean", &d);
        s.put("k", "e", 1, b"journalled", true).unwrap();
        s.drop_clean("k");
        assert_eq!(&s.get("k").unwrap().body[..], b"journalled");
        assert_eq!(s.scan_dirty(Duration::ZERO).0.len(), 1);

        // A clean copy is a cache entry and goes.
        s.put("c", "e", 1, b"cached", false).unwrap();
        s.drop_clean("c");
        assert!(s.get("c").is_none());
    }

    #[test]
    fn ownership_tracks_what_this_process_journalled() {
        // Shutdown flushes exactly the entries this instance wrote. A peer's
        // dirty entry belongs to a process that is still running.
        let d = TempDir::new("owned");
        let s = spill("owned", &d);
        assert!(s.owned_dirty_keys().is_empty());
        let sha = s.put("mine", "e", 1, b"body", true).unwrap();
        assert_eq!(s.owned_dirty_keys(), vec!["mine".to_string()]);

        // A second Spill over the same directory stands in for a peer process:
        // it can see the entry on disk but does not own it.
        let peer = Spill::open(&d.0, "test-ns".into(), 1 << 20, 1 << 18).unwrap();
        assert!(
            peer.owned_dirty_keys().is_empty(),
            "claimed ownership of another process's journalled write"
        );
        assert_eq!(
            peer.scan_dirty(Duration::ZERO).0.len(),
            1,
            "peer cannot see it"
        );

        // Promotion releases ownership; so does deletion.
        s.promote("mine", &sha, "real", 2, b"body").unwrap();
        assert!(s.owned_dirty_keys().is_empty());
        s.put("gone", "e", 1, b"body", true).unwrap();
        s.remove("gone");
        assert!(s.owned_dirty_keys().is_empty());
    }

    #[test]
    fn remove_drops_both_spellings() {
        let d = TempDir::new("remove");
        let s = spill("remove", &d);
        s.put("k", "e", 1, b"body", false).unwrap();
        s.remove("k");
        assert!(s.get("k").is_none());
    }

    #[test]
    fn rejects_objects_over_the_per_object_cap() {
        let d = TempDir::new("cap");
        let s = Spill::open(&d.0, "ns".into(), 1 << 20, 8).unwrap();
        s.put("k", "e", 1, b"more than eight bytes", false).unwrap();
        assert!(s.get("k").is_none());
    }

    #[test]
    fn sweep_evicts_oldest_first_and_spares_dirty() {
        let d = TempDir::new("sweep");
        // Each entry is 64 (header) + ~9 (id + etag) + 100 (body) ≈ 173 bytes,
        // so a 600-byte budget holds three of the five written below: the two
        // most recent, plus the dirty one that is not a candidate at all.
        let s = Spill::open(&d.0, "ns".into(), 600, 1 << 16).unwrap();
        let body = vec![b'x'; 100];
        for (i, name) in ["old1", "old2", "new1", "new2"].iter().enumerate() {
            s.put(name, "e", 1, &body, false).unwrap();
            // Stamp distinct mtimes so the LRU order is unambiguous.
            let p = s.path_for(name, CLEAN_EXT);
            let t = SystemTime::now() - Duration::from_secs(1000 - i as u64 * 100);
            let f = OpenOptions::new().write(true).open(&p).unwrap();
            f.set_times(fs::FileTimes::new().set_modified(t)).unwrap();
        }
        s.put("pending", "e", 1, &body, true).unwrap();
        let f = OpenOptions::new()
            .write(true)
            .open(s.path_for("pending", DIRTY_EXT))
            .unwrap();
        // Oldest of all — it would be the first victim if dirty were evictable.
        f.set_times(
            fs::FileTimes::new().set_modified(SystemTime::now() - Duration::from_secs(5000)),
        )
        .unwrap();
        drop(f);

        let stats = s.sweep_to(Some(600));
        assert!(!stats.skipped);
        assert!(stats.evicted_entries > 0, "nothing evicted: {stats:?}");
        assert!(
            s.get("pending").is_some(),
            "evicted an acknowledged write that is not on the backend yet"
        );
        assert!(s.get("new2").is_some(), "evicted the most recent entry");
        assert!(
            s.get("new1").is_some(),
            "evicted more than the budget needed"
        );
        assert!(s.get("old1").is_none(), "kept the oldest entry");
        assert!(s.get("old2").is_none(), "kept the second-oldest entry");
    }

    #[test]
    fn sweep_lock_is_exclusive_and_released() {
        let d = TempDir::new("lock");
        let path = d.0.join(LOCK_FILE);
        let held = SweepLock::try_acquire(&path).expect("first acquire");
        // A second attempt from a *different* descriptor is what a peer
        // instance does; flock is per-open-file, so this is a faithful test.
        assert!(
            SweepLock::try_acquire(&path).is_none(),
            "two sweepers ran at once"
        );
        drop(held);
        assert!(SweepLock::try_acquire(&path).is_some(), "lock not released");
    }

    #[test]
    fn statfs_layout_matches_the_abi() {
        // The kernel writes the whole struct; a short buffer is a stack
        // overwrite, so the declared size is load-bearing, not cosmetic.
        assert_eq!(size_of::<Statfs>(), 2168);
        assert_eq!(align_of::<Statfs>(), 8);
    }

    #[test]
    fn volume_avail_is_plausible() {
        let avail = volume_avail(Path::new("/")).expect("statfs / failed");
        // Bounded above by any real volume: a bad struct layout reads garbage
        // from the wrong offset, which this catches where a bare `> 0` would not.
        assert!(avail < 1 << 50, "implausible free space: {avail}");
    }

    #[test]
    fn effective_budget_yields_to_the_disk() {
        let d = TempDir::new("budget");
        // A budget larger than any real disk must be clamped by free space —
        // this is what keeps an enabled-by-default cache from filling a volume.
        let s = Spill::open(&d.0, "ns".into(), u64::MAX / 2, 1 << 20).unwrap();
        let clamped = s.effective_budget(0);
        assert!(clamped < u64::MAX / 2, "free space did not bind the budget");
        // Space the cache already holds is spendable again, so a volume full of
        // cache sheds entries instead of freezing at a zero budget.
        assert!(s.effective_budget(1 << 30) > clamped);
    }

    #[test]
    fn stale_temp_files_are_cleared() {
        let d = TempDir::new("temps");
        let s = spill("temps", &d);
        let stray = s.tmp.join("12345-0");
        fs::write(&stray, b"partial").unwrap();
        let f = OpenOptions::new().write(true).open(&stray).unwrap();
        f.set_times(
            fs::FileTimes::new().set_modified(SystemTime::now() - Duration::from_secs(3600)),
        )
        .unwrap();
        drop(f);
        s.clear_stale_temps();
        assert!(!stray.exists());
    }

    #[test]
    fn in_flight_temp_files_are_left_alone() {
        let d = TempDir::new("temps-live");
        let s = spill("temps-live", &d);
        let live = s.tmp.join("999-1");
        fs::write(&live, b"being written").unwrap();
        s.clear_stale_temps();
        assert!(live.exists(), "clobbered another writer's staging file");
    }
}
