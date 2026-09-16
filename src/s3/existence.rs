//! Per-directory existence index for cheap 404s on content-addressed stores.
//!
//! A negative cache of past 404s does not help sccache: a cold compile unit
//! GETs a unique hash once. This index is the set of names that *do* exist in
//! a directory, filled by one SMB list on the first miss in that directory.
//! Later missing leaves 404 with no SMB open.
//!
//! Completeness is local. A peer PUT of a name we have not listed (or listed
//! before it landed) 404s until the next list. That is the same contract as
//! [`crate::s3::object_cache::ObjectCache::immutable`]: right for a cache,
//! wrong for a system of record. Default on when immutable objects are on;
//! `SPICEIO_EXISTENCE_INDEX` overrides.
//!
//! PUT/COPY insert the leaf into an already-listed directory. DELETE removes
//! it. An unlisted directory is left incomplete — remembering one PUT must
//! not mark the rest of the directory as empty.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

/// Refuse to treat a directory as complete past this many names; fall back
/// to per-key SMB opens rather than pin unbounded RAM.
const MAX_DIR_NAMES: usize = 1_000_000;

/// Cap on listed/in-flight directories. Analogous to `ensured_dirs` on the
/// share session: a client that 404s a fresh parent every request must not
/// grow the map without bound. Expired listings are dropped first; then the
/// least-recently-probed complete listing.
const MAX_DIRS: usize = 16_384;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Probe {
    /// Index off, listing in flight failed, or this directory has never been
    /// listed. The caller must ask the NAS.
    Unknown,
    /// A complete listing of the parent includes this leaf.
    Present,
    /// A complete listing of the parent does not include this leaf. 404
    /// without an SMB open.
    Absent,
}

enum DirState {
    Inflight {
        notify: Arc<Notify>,
        /// Local PUT/DELETE that raced this listing. Applied when the list
        /// is installed so we never publish a complete set that omits a
        /// name this process just created (or still contains one it deleted).
        pending_insert: HashSet<Box<str>>,
        pending_remove: HashSet<Box<str>>,
    },
    Listed {
        names: HashSet<Box<str>>,
        at: Instant,
        last_used: Instant,
    },
}

pub struct ExistenceIndex {
    enabled: bool,
    ttl: Option<Duration>,
    dirs: Mutex<HashMap<Box<str>, DirState>>,
    absents: AtomicU64,
    lists: AtomicU64,
}

impl ExistenceIndex {
    pub fn new(enabled: bool, ttl: Option<Duration>) -> Self {
        Self {
            enabled,
            ttl,
            dirs: Mutex::new(HashMap::new()),
            absents: AtomicU64::new(0),
            lists: AtomicU64::new(0),
        }
    }

    /// `SPICEIO_EXISTENCE_INDEX` overrides; otherwise follows immutable mode.
    pub fn from_env(immutable: bool) -> Self {
        let enabled = parse_bool_env("SPICEIO_EXISTENCE_INDEX").unwrap_or(immutable);
        let ttl = match std::env::var("SPICEIO_EXISTENCE_INDEX_TTL_SECS") {
            Ok(s) if !s.is_empty() => match s.parse::<u64>() {
                Ok(0) => None,
                Ok(n) => Some(Duration::from_secs(n)),
                Err(_) => None,
            },
            _ => None,
        };
        Self::new(enabled, ttl)
    }

    pub fn disabled() -> Self {
        Self::new(false, None)
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn ttl(&self) -> Option<Duration> {
        self.ttl
    }

    pub fn absents(&self) -> u64 {
        self.absents.load(Ordering::Relaxed)
    }

    pub fn lists(&self) -> u64 {
        self.lists.load(Ordering::Relaxed)
    }

    pub fn note_absent(&self) {
        self.absents.fetch_add(1, Ordering::Relaxed);
    }

    /// Split an S3 key into (parent directory, leaf). Root keys live in `""`.
    pub fn split_key(key: &str) -> (&str, &str) {
        let key = key.trim_matches('/');
        match key.rfind('/') {
            Some(i) => (&key[..i], &key[i + 1..]),
            None => ("", key),
        }
    }

    /// Consult a complete listing without starting one.
    pub fn probe(&self, key: &str) -> Probe {
        if !self.enabled {
            return Probe::Unknown;
        }
        let (dir, name) = Self::split_key(key);
        if name.is_empty() {
            return Probe::Unknown;
        }
        let mut g = self.dirs.lock().unwrap_or_else(|e| e.into_inner());
        match g.get_mut(dir) {
            Some(DirState::Listed {
                names,
                at,
                last_used,
            }) if !self.expired(*at) => {
                *last_used = Instant::now();
                if names.contains(name) {
                    Probe::Present
                } else {
                    Probe::Absent
                }
            }
            _ => Probe::Unknown,
        }
    }

    /// If the parent is unlisted, run `list` once (coalesced) and install the
    /// name set. `list` returning `NotFound` is an empty complete directory.
    pub async fn ensure_listed<F, Fut>(&self, key: &str, list: F) -> Probe
    where
        F: FnOnce(String) -> Fut,
        Fut: Future<Output = io::Result<HashSet<String>>>,
    {
        if !self.enabled {
            return Probe::Unknown;
        }
        let (dir, name) = Self::split_key(key);
        if name.is_empty() {
            return Probe::Unknown;
        }
        let mut list = Some(list);
        loop {
            if let p @ (Probe::Present | Probe::Absent) = self.probe(key) {
                return p;
            }

            let mut we_list = false;
            let wait = {
                let mut g = self.dirs.lock().unwrap_or_else(|e| e.into_inner());
                self.evict_if_needed(&mut g);
                match g.get(dir) {
                    Some(DirState::Listed { at, .. }) if !self.expired(*at) => None,
                    Some(DirState::Inflight { notify, .. }) => {
                        // Subscribe before the mutex is released so a listing
                        // that finishes in the gap cannot notify nobody.
                        Some(Arc::clone(notify).notified_owned())
                    }
                    _ => {
                        g.insert(
                            dir.into(),
                            DirState::Inflight {
                                notify: Arc::new(Notify::new()),
                                pending_insert: HashSet::new(),
                                pending_remove: HashSet::new(),
                            },
                        );
                        we_list = true;
                        None
                    }
                }
            };
            if let Some(notified) = wait {
                notified.await;
                continue;
            }
            if !we_list {
                return self.probe(key);
            }

            self.lists.fetch_add(1, Ordering::Relaxed);
            let list = list.take().expect("list once");
            let listed = match list(dir.to_string()).await {
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(HashSet::new()),
                other => other,
            };
            let notify = {
                let mut g = self.dirs.lock().unwrap_or_else(|e| e.into_inner());
                let pending = match g.remove(dir) {
                    Some(DirState::Inflight {
                        notify,
                        pending_insert,
                        pending_remove,
                    }) => Some((notify, pending_insert, pending_remove)),
                    other => {
                        if let Some(st) = other {
                            g.insert(dir.into(), st);
                        }
                        None
                    }
                };
                match (listed, pending) {
                    (Ok(names), Some((notify, inserts, removes)))
                        if names.len() <= MAX_DIR_NAMES =>
                    {
                        let mut names: HashSet<Box<str>> =
                            names.into_iter().map(|s| s.into_boxed_str()).collect();
                        names.extend(inserts);
                        for r in removes {
                            names.remove(&r);
                        }
                        let now = Instant::now();
                        g.insert(
                            dir.into(),
                            DirState::Listed {
                                names,
                                at: now,
                                last_used: now,
                            },
                        );
                        Some(notify)
                    }
                    (_, Some((notify, _, _))) => Some(notify),
                    _ => None,
                }
            };
            if let Some(n) = notify {
                n.notify_waiters();
            }
            return self.probe(key);
        }
    }

    /// A local PUT/COPY published `key`. Only mutates an already-complete
    /// listing — it must not invent completeness from a single insert.
    pub fn remember(&self, key: &str) {
        if !self.enabled {
            return;
        }
        let (dir, name) = Self::split_key(key);
        if name.is_empty() {
            return;
        }
        let mut g = self.dirs.lock().unwrap_or_else(|e| e.into_inner());
        match g.get_mut(dir) {
            Some(DirState::Listed {
                names, last_used, ..
            }) => {
                *last_used = Instant::now();
                names.insert(name.into());
            }
            Some(DirState::Inflight {
                pending_insert,
                pending_remove,
                ..
            }) => {
                pending_remove.remove(name);
                pending_insert.insert(name.into());
            }
            None => {}
        }
    }

    /// A local DELETE of `key`. Same completeness rule as [`ExistenceIndex::remember`].
    pub fn forget(&self, key: &str) {
        if !self.enabled {
            return;
        }
        let (dir, name) = Self::split_key(key);
        if name.is_empty() {
            return;
        }
        let mut g = self.dirs.lock().unwrap_or_else(|e| e.into_inner());
        match g.get_mut(dir) {
            Some(DirState::Listed {
                names, last_used, ..
            }) => {
                *last_used = Instant::now();
                names.remove(name);
            }
            Some(DirState::Inflight {
                pending_insert,
                pending_remove,
                ..
            }) => {
                pending_insert.remove(name);
                pending_remove.insert(name.into());
            }
            None => {}
        }
    }

    fn expired(&self, at: Instant) -> bool {
        self.ttl.is_some_and(|ttl| at.elapsed() >= ttl)
    }

    fn evict_if_needed(&self, g: &mut HashMap<Box<str>, DirState>) {
        if let Some(ttl) = self.ttl {
            g.retain(|_, st| match st {
                DirState::Listed { at, .. } => at.elapsed() < ttl,
                DirState::Inflight { .. } => true,
            });
        }
        while g.len() >= MAX_DIRS {
            let victim = g
                .iter()
                .filter_map(|(k, st)| match st {
                    DirState::Listed { last_used, .. } => Some((k.clone(), *last_used)),
                    DirState::Inflight { .. } => None,
                })
                .min_by_key(|(_, used)| *used)
                .map(|(k, _)| k);
            match victim {
                Some(k) => {
                    g.remove(&k);
                }
                None => break,
            }
        }
    }
}

fn parse_bool_env(name: &str) -> Option<bool> {
    let s = std::env::var(name).ok()?;
    if s.is_empty() {
        return None;
    }
    match s.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
impl ExistenceIndex {
    pub fn seed_listed(&self, dir: &str, names: &[&str]) {
        let mut g = self.dirs.lock().unwrap();
        let now = Instant::now();
        g.insert(
            dir.into(),
            DirState::Listed {
                names: names.iter().map(|s| (*s).into()).collect(),
                at: now,
                last_used: now,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn split_root_and_nested() {
        assert_eq!(ExistenceIndex::split_key("abc"), ("", "abc"));
        assert_eq!(ExistenceIndex::split_key("/abc"), ("", "abc"));
        assert_eq!(ExistenceIndex::split_key("pre/abc"), ("pre", "abc"));
        assert_eq!(ExistenceIndex::split_key("a/b/c"), ("a/b", "c"));
        assert_eq!(ExistenceIndex::split_key("pre/"), ("", "pre"));
    }

    #[test]
    fn disabled_never_answers() {
        let idx = ExistenceIndex::disabled();
        idx.seed_listed("", &["a"]);
        assert_eq!(idx.probe("a"), Probe::Unknown);
        assert_eq!(idx.probe("b"), Probe::Unknown);
    }

    #[test]
    fn listed_dir_404s_unknown_leaves() {
        let idx = ExistenceIndex::new(true, None);
        idx.seed_listed("pre", &["hit"]);
        assert_eq!(idx.probe("pre/hit"), Probe::Present);
        assert_eq!(idx.probe("pre/miss"), Probe::Absent);
        assert_eq!(idx.probe("other/x"), Probe::Unknown);
    }

    #[test]
    fn remember_only_mutates_a_complete_listing() {
        let idx = ExistenceIndex::new(true, None);
        idx.remember("pre/new");
        assert_eq!(idx.probe("pre/new"), Probe::Unknown);
        assert_eq!(idx.probe("pre/other"), Probe::Unknown);
        idx.seed_listed("pre", &["old"]);
        idx.remember("pre/new");
        assert_eq!(idx.probe("pre/new"), Probe::Present);
        assert_eq!(idx.probe("pre/old"), Probe::Present);
        assert_eq!(idx.probe("pre/gone"), Probe::Absent);
        idx.forget("pre/old");
        assert_eq!(idx.probe("pre/old"), Probe::Absent);
        assert_eq!(idx.probe("pre/new"), Probe::Present);
    }

    #[tokio::test]
    async fn empty_list_makes_every_leaf_absent() {
        let idx = ExistenceIndex::new(true, None);
        let p = idx
            .ensure_listed("pre/a", |dir| async move {
                assert_eq!(dir, "pre");
                Ok(HashSet::new())
            })
            .await;
        assert_eq!(p, Probe::Absent);
        assert_eq!(idx.probe("pre/b"), Probe::Absent);
        assert_eq!(idx.lists(), 1);
    }

    #[tokio::test]
    async fn list_not_found_is_an_empty_complete_dir() {
        let idx = ExistenceIndex::new(true, None);
        let p = idx
            .ensure_listed("missing/x", |_dir| async {
                Err(io::Error::new(io::ErrorKind::NotFound, "no dir"))
            })
            .await;
        assert_eq!(p, Probe::Absent);
        assert_eq!(idx.probe("missing/y"), Probe::Absent);
    }

    #[tokio::test]
    async fn list_error_leaves_the_directory_unknown() {
        let idx = ExistenceIndex::new(true, None);
        let p = idx
            .ensure_listed("pre/a", |_dir| async { Err(io::Error::other("smb down")) })
            .await;
        assert_eq!(p, Probe::Unknown);
        assert_eq!(idx.probe("pre/a"), Probe::Unknown);
    }

    #[tokio::test]
    async fn concurrent_misses_share_one_list() {
        let idx = Arc::new(ExistenceIndex::new(true, None));
        let lists = Arc::new(AtomicUsize::new(0));
        let start = Arc::new(tokio::sync::Barrier::new(8));
        let mut joins = Vec::new();
        for i in 0..8 {
            let idx = Arc::clone(&idx);
            let lists = Arc::clone(&lists);
            let start = Arc::clone(&start);
            joins.push(tokio::spawn(async move {
                start.wait().await;
                idx.ensure_listed(&format!("d/{i}"), {
                    let lists = Arc::clone(&lists);
                    move |_dir| {
                        let lists = Arc::clone(&lists);
                        async move {
                            lists.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(20)).await;
                            Ok(HashSet::from(["only".into()]))
                        }
                    }
                })
                .await
            }));
        }
        let mut absent = 0;
        let mut present = 0;
        for j in joins {
            match j.await.unwrap() {
                Probe::Absent => absent += 1,
                Probe::Present => present += 1,
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(
            lists.load(Ordering::SeqCst),
            1,
            "one list for the directory"
        );
        assert_eq!(idx.lists(), 1);
        // d/0..7 are not "only"
        assert_eq!(absent, 8);
        assert_eq!(present, 0);
        assert_eq!(idx.probe("d/only"), Probe::Present);
    }

    #[tokio::test]
    async fn remember_during_list_is_merged_into_the_installed_set() {
        let idx = Arc::new(ExistenceIndex::new(true, None));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let (go_tx, go_rx) = tokio::sync::oneshot::channel::<()>();
        let idx_list = Arc::clone(&idx);
        let join = tokio::spawn(async move {
            idx_list
                .ensure_listed("d/old", move |_dir| async move {
                    let _ = started_tx.send(());
                    let _ = go_rx.await;
                    Ok(HashSet::from(["old".into()]))
                })
                .await
        });
        started_rx.await.unwrap();
        idx.remember("d/new");
        idx.forget("d/old");
        let _ = go_tx.send(());
        let p = join.await.unwrap();
        assert_eq!(p, Probe::Absent, "d/old was forgotten during the list");
        assert_eq!(idx.probe("d/new"), Probe::Present);
        assert_eq!(idx.probe("d/old"), Probe::Absent);
    }

    #[tokio::test]
    async fn ttl_expires_completeness() {
        let idx = ExistenceIndex::new(true, Some(Duration::from_millis(30)));
        idx.seed_listed("p", &["a"]);
        assert_eq!(idx.probe("p/miss"), Probe::Absent);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(idx.probe("p/miss"), Probe::Unknown);
    }
}
