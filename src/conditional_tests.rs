//! Stateful wire tests: independent proxy instances, one SMB namespace. Unlike
//! scripted replies this server enforces exclusive opens and replacement rules.
use crate::s3::router::AppState;
use crate::smb::{condition::WriteCondition, ops::ShareSession, protocol::*};
use crate::test_support::{http_request, state};
use bytes::{Bytes, BytesMut};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[derive(Default)]
struct File {
    data: Vec<u8>,
    time: u64,
    flushed: bool,
}
struct Handle {
    file: u64,
    session: u64,
    exclusive: bool,
    delete: bool,
}
#[derive(Default)]
struct Nas {
    next: u64,
    names: HashMap<String, u64>,
    files: HashMap<u64, File>,
    handles: HashMap<u64, Handle>,
    publications: usize,
    fail_rename: bool,
    fail_destination_stat: bool,
    disconnect_on_rename: bool,
}
fn u32_at(b: &[u8], n: usize) -> u32 {
    u32::from_le_bytes(b[n..n + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], n: usize) -> u64 {
    u64::from_le_bytes(b[n..n + 8].try_into().unwrap())
}
fn utf16(b: &[u8]) -> String {
    String::from_utf16(
        &b.as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect::<Vec<_>>(),
    )
    .unwrap()
    .to_uppercase()
}
fn id_bytes(id: u64) -> [u8; 16] {
    let mut b = [0; 16];
    b[..8].copy_from_slice(&id.to_le_bytes());
    b
}

impl Nas {
    fn id(&mut self) -> u64 {
        self.next += 1;
        self.next
    }
    fn request(
        &mut self,
        session: u64,
        command: u16,
        body: &[u8],
        related: &mut u64,
    ) -> (u32, Vec<u8>) {
        match self.operation(session, command, body, related) {
            Ok(b) => (0, b),
            Err(status) => (status, vec![9, 0, 0, 0, 0, 0, 0, 0]),
        }
    }
    fn operation(
        &mut self,
        session: u64,
        command: u16,
        b: &[u8],
        related: &mut u64,
    ) -> Result<Vec<u8>, u32> {
        if command == Command::Create as u16 {
            let start = u16::from_le_bytes(b[44..46].try_into().unwrap()) as usize - 64;
            let len = u16::from_le_bytes(b[46..48].try_into().unwrap()) as usize;
            let name = utf16(&b[start..start + len]);
            if self.fail_destination_stat
                && name.starts_with("STRICT\\")
                && u32_at(b, 24) == DesiredAccess::ReadAttributes as u32
            {
                return Err(0xC0000022);
            }
            let disposition = u32_at(b, 36);
            let file = match self.names.get(&name) {
                Some(id) => *id,
                None if disposition == CreateDisposition::Open as u32 => return Err(0xC0000034),
                None => {
                    let id = self.id();
                    self.names.insert(name, id);
                    // Deliberately fixed/coarse time: consecutive equal-size
                    // writes must not accidentally get the same ETag.
                    self.files.insert(
                        id,
                        File {
                            time: 133000000000000000,
                            ..File::default()
                        },
                    );
                    id
                }
            };
            let exclusive = u32_at(b, 32) == 0;
            if self
                .handles
                .values()
                .any(|h| h.file == file && (h.exclusive || exclusive))
            {
                return Err(0xC0000043);
            }
            if disposition == CreateDisposition::OverwriteIf as u32 {
                self.files.get_mut(&file).unwrap().data.clear();
            }
            let handle = self.id();
            self.handles.insert(
                handle,
                Handle {
                    file,
                    session,
                    exclusive,
                    delete: u32_at(b, 40) & CreateOptions::DeleteOnClose as u32 != 0,
                },
            );
            *related = handle;
            let f = &self.files[&file];
            let mut out = vec![0; 88];
            out[..2].copy_from_slice(&89u16.to_le_bytes());
            out[24..32].copy_from_slice(&f.time.to_le_bytes());
            out[48..56].copy_from_slice(&(f.data.len() as u64).to_le_bytes());
            out[64..80].copy_from_slice(&id_bytes(handle));
            return Ok(out);
        }
        if command == Command::Ioctl as u16 {
            return Err(0xC00000BB);
        }
        let offset = match command {
            c if c == Command::Close as u16 || c == Command::Flush as u16 => 8,
            c if c == Command::QueryInfo as u16 => 24,
            _ => 16,
        };
        let handle = if b[offset..offset + 16] == [255; 16] {
            *related
        } else {
            u64_at(b, offset)
        };
        let Some(h) = self.handles.get(&handle) else {
            return Err(0xC0000008);
        };
        assert_eq!(h.session, session, "a handle crossed SMB sessions");
        let file = h.file;
        if command == Command::Close as u16 {
            let h = self.handles.remove(&handle).unwrap();
            if h.delete {
                self.names.retain(|_, id| *id != file);
            }
            return Ok(vec![0; 60]);
        }
        let f = self.files.get_mut(&file).unwrap();
        match command {
            c if c == Command::Write as u16 => {
                let offset = u64_at(b, 8) as usize;
                let len = u32_at(b, 4) as usize;
                let start = u16::from_le_bytes(b[2..4].try_into().unwrap()) as usize - 64;
                f.data.resize(f.data.len().max(offset + len), 0);
                f.data[offset..offset + len].copy_from_slice(&b[start..start + len]);
                f.flushed = false;
                let mut out = vec![0; 16];
                out[..2].copy_from_slice(&17u16.to_le_bytes());
                out[4..8].copy_from_slice(&(len as u32).to_le_bytes());
                Ok(out)
            }
            c if c == Command::Read as u16 => {
                let start = (u64_at(b, 8) as usize).min(f.data.len());
                let end = (start + u32_at(b, 4) as usize).min(f.data.len());
                let mut out = vec![0; 16];
                out[..2].copy_from_slice(&17u16.to_le_bytes());
                out[2] = 80;
                out[4..8].copy_from_slice(&((end - start) as u32).to_le_bytes());
                out.extend_from_slice(&f.data[start..end]);
                Ok(out)
            }
            c if c == Command::QueryInfo as u16 => {
                let mut out = vec![0; 64];
                out[..2].copy_from_slice(&9u16.to_le_bytes());
                out[2..4].copy_from_slice(&72u16.to_le_bytes());
                out[4..8].copy_from_slice(&56u32.to_le_bytes());
                out[24..32].copy_from_slice(&f.time.to_le_bytes());
                out[48..56].copy_from_slice(&(f.data.len() as u64).to_le_bytes());
                Ok(out)
            }
            c if c == Command::Flush as u16 => {
                f.flushed = true;
                Ok(vec![4, 0, 0, 0])
            }
            c if c == Command::SetInfo as u16 && b[3] == 4 => {
                // Emulate a server that rounds timestamps to whole seconds.
                f.time = u64_at(b, 48) / 10_000_000 * 10_000_000;
                f.flushed = false;
                Ok(vec![2, 0])
            }
            c if c == Command::SetInfo as u16 && b[3] == 10 => {
                if self.fail_rename {
                    return Err(0xC0000022);
                }
                assert!(f.flushed, "strict data must be flushed before publication");
                let lock = self
                    .handles
                    .values()
                    .find(|h| h.session == session && h.exclusive)
                    .expect("publication has no server lock");
                assert!(
                    self.files[&lock.file].flushed,
                    "version reservation must be durable first"
                );
                let len = u32_at(b, 48) as usize;
                let name = utf16(&b[52..52 + len]);
                if b[32] == 0 && self.names.contains_key(&name) {
                    return Err(0xC0000035);
                }
                self.names.retain(|_, id| *id != file);
                self.names.insert(name, file);
                self.publications += 1;
                Ok(vec![2, 0])
            }
            _ => panic!("unexpected SMB command {command}, body={b:?}"),
        }
    }
}

async fn serve(mut stream: TcpStream, nas: Arc<Mutex<Nas>>, session: u64) {
    'frames: while let Ok(len) = stream.read_u32().await {
        let mut frame = vec![0; len as usize];
        if stream.read_exact(&mut frame).await.is_err() {
            break;
        }
        let parts = parse_compound_response(&Bytes::from(frame));
        let mut response = BytesMut::new();
        let mut related = 0;
        for (index, (mut h, body)) in parts.iter().cloned().enumerate() {
            if h.command == Command::SetInfo as u16 && body[3] == 10 {
                let mut backend = nas.lock().unwrap();
                if backend.disconnect_on_rename {
                    backend.disconnect_on_rename = false;
                    break 'frames;
                }
            }
            let (status, body) =
                nas.lock()
                    .unwrap()
                    .request(session, h.command, &body, &mut related);
            h.flags = 1;
            h.status = status;
            h.credits = 64;
            let padded = (64 + body.len()).next_multiple_of(8);
            h.next_command = if index + 1 == parts.len() {
                0
            } else {
                padded as u32
            };
            h.encode(&mut response);
            response.extend_from_slice(&body);
            if h.next_command != 0 {
                response.resize(response.len() + padded - 64 - body.len(), 0);
            }
        }
        if stream.write_u32(response.len() as u32).await.is_err()
            || stream.write_all(&response).await.is_err()
        {
            break;
        }
    }
    nas.lock()
        .unwrap()
        .handles
        .retain(|_, h| h.session != session);
}

async fn instance(nas: Arc<Mutex<Nas>>, session: u64) -> Arc<AppState> {
    let (mut state, stream) = state().await;
    state.object_cache = Arc::new(crate::s3::object_cache::ObjectCache::new(
        true, 1024, 1024, 64,
    ));
    state.existence = Arc::new(crate::s3::existence::ExistenceIndex::new(true, None));
    state.existence.seed_listed("strict", &[]);
    state.share = Arc::new(
        (*state.share)
            .clone()
            .with_strict_prefixes("strict/")
            .unwrap(),
    );
    tokio::spawn(serve(stream, nas, session));
    Arc::new(state)
}
async fn request(
    state: Arc<AppState>,
    method: &str,
    path: &str,
    headers: &str,
    body: &[u8],
) -> String {
    let mut request = format!("{method} /audit/{path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n",body.len()).into_bytes();
    request.extend_from_slice(body);
    String::from_utf8(http_request(state, &request).await).unwrap()
}
fn status(response: &str) -> &str {
    response.split_whitespace().nth(1).unwrap()
}
fn etag(response: &str) -> String {
    response
        .lines()
        .find_map(|line| line.strip_prefix("etag: "))
        .unwrap()
        .trim()
        .to_owned()
}

#[tokio::test]
async fn conditional_http_writes_have_one_winner_across_instances_and_no_async_ack() {
    let nas = Arc::new(Mutex::new(Nas::default()));
    let a = instance(nas.clone(), 1).await;
    let b = instance(nas.clone(), 2).await;
    let (first, second) = tokio::join!(
        request(
            a.clone(),
            "PUT",
            "strict/key",
            "If-None-Match: *\r\n",
            b"aaaa"
        ),
        request(
            b.clone(),
            "PUT",
            "strict/key",
            "If-None-Match: *\r\n",
            b"bbbb"
        ),
    );
    assert_eq!(
        [status(&first), status(&second)]
            .iter()
            .filter(|&&s| s == "200")
            .count(),
        1,
        "{first}\n{second}"
    );
    assert_eq!(
        [status(&first), status(&second)]
            .iter()
            .filter(|&&s| s == "412")
            .count(),
        1
    );
    assert!(a.writeback.pending_meta("strict/key").await.is_none());
    assert!(b.writeback.pending_meta("strict/key").await.is_none());
    let original = if status(&first) == "200" {
        etag(&first)
    } else {
        etag(&second)
    };
    let headers = format!("If-Match: {original}\r\n");
    let (first, second) = tokio::join!(
        request(a.clone(), "PUT", "strict/key", &headers, b"cccc"),
        request(b.clone(), "PUT", "strict/key", &headers, b"dddd"),
    );
    assert_eq!(
        [status(&first), status(&second)]
            .iter()
            .filter(|&&s| s == "200")
            .count(),
        1,
        "{first}\n{second}"
    );
    assert_eq!(
        [status(&first), status(&second)]
            .iter()
            .filter(|&&s| s == "412")
            .count(),
        1
    );
    let changed = if status(&first) == "200" {
        etag(&first)
    } else {
        etag(&second)
    };
    assert_ne!(original, changed);
    assert_eq!(
        etag(&request(a.clone(), "HEAD", "strict/key", "", b"").await),
        changed
    );
    assert_eq!(nas.lock().unwrap().publications, 2);
    assert_eq!(
        status(&request(a.clone(), "PUT", "strict/missing", &headers, b"data").await),
        "404"
    );
    assert_eq!(
        status(&request(a.clone(), "DELETE", "strict/key", "", b"").await),
        "204"
    );
    let recreated = request(
        b.clone(),
        "PUT",
        "strict/key",
        "If-None-Match: *\r\n",
        b"eeee",
    )
    .await;
    assert_eq!(status(&recreated), "200");
    assert_ne!(
        etag(&recreated),
        changed,
        "delete must not reset the version sequence"
    );
    assert_eq!(
        status(&request(a, "PUT", "strict/key", &headers, b"ffff").await),
        "412"
    );
}

#[tokio::test]
async fn ordinary_put_still_acknowledges_without_any_backend_request() {
    let (mut state, mut stream) = state().await;
    state.share = Arc::new(
        (*state.share)
            .clone()
            .with_strict_prefixes("strict/")
            .unwrap(),
    );
    let state = Arc::new(state);
    let response = request(state.clone(), "PUT", "cache/key", "", b"data").await;
    assert_eq!(status(&response), "200");
    assert!(response.contains("x-spiceio-write: ASYNC"));
    assert!(state.writeback.pending_meta("cache/key").await.is_some());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), stream.read_u8())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn conditional_streaming_copy_and_assembly_share_the_publication_check() {
    let nas = Arc::new(Mutex::new(Nas::default()));
    let a = instance(nas.clone(), 1).await;
    let b = instance(nas, 2).await;
    let share: &ShareSession = &a.share;
    let initial = share
        .put_object_conditional("strict/dest", b"old", &WriteCondition::Absent)
        .await
        .unwrap();
    // Stage a body, then replace its destination through another instance.
    let mut wal = share.open_wal_write("strict/dest").await.unwrap();
    wal.write(b"streamed replacement").await.unwrap();
    b.share
        .put_object_atomic("strict/dest", b"new")
        .await
        .unwrap();
    assert!(
        wal.commit_conditional(share, &WriteCondition::Match(initial.etag))
            .await
            .is_err()
    );
    share
        .put_object_atomic("strict/source", b"source")
        .await
        .unwrap();
    assert!(
        share
            .copy_object_conditional("strict/source", "strict/dest", &WriteCondition::Absent)
            .await
            .is_err()
    );
    // Use the same immutable source as a multipart part; assembly must check
    // the destination after streaming, just like CopyObject and PutObject.
    assert!(
        share
            .assemble_parts_conditional(
                "strict/dest",
                &[("strict\\source", 6)],
                &WriteCondition::Absent
            )
            .await
            .is_err()
    );
    assert_eq!(
        share
            .get_object_compound("strict/dest", 64)
            .await
            .unwrap()
            .1
            .as_ref(),
        b"new"
    );
}

#[tokio::test]
async fn strict_reads_never_create_version_records() {
    let nas = Arc::new(Mutex::new(Nas::default()));
    let a = instance(nas.clone(), 1).await;
    let records = || {
        nas.lock()
            .unwrap()
            .names
            .keys()
            .filter(|name| name.starts_with(".SPICEIO-LOCKS\\"))
            .count()
    };
    let share: &ShareSession = &a.share;
    for key in ["strict/missing-1", "strict/missing-2"] {
        let error = share.head_object(key).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        let error = share.get_object_compound(key, 64).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }
    assert_eq!(
        records(),
        0,
        "a GET/HEAD miss must not create a lock record"
    );
    share
        .put_object_conditional("strict/key", b"data", &WriteCondition::Absent)
        .await
        .unwrap();
    assert_eq!(records(), 1);
    // An existing record is still taken (and released) by reads.
    assert_eq!(
        share
            .get_object_compound("strict/key", 64)
            .await
            .unwrap()
            .1
            .as_ref(),
        b"data"
    );
    share.head_object("strict/missing-3").await.unwrap_err();
    assert_eq!(records(), 1);
}

#[tokio::test]
async fn unlocked_read_miss_rechecks_for_a_peer_first_strict_publication() {
    let nas = Arc::new(Mutex::new(Nas::default()));
    let a = instance(nas.clone(), 1).await;
    let record = format!(
        ".SPICEIO-LOCKS\\{}",
        crate::crypto::hex_encode(&crate::crypto::sha256(b"STRICT\\KEY")).to_uppercase()
    );
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let result = a
        .share
        .strict_read("strict\\key", || {
            let call = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (nas, record, released) = (nas.clone(), record.clone(), released.clone());
            async move {
                if call > 0 {
                    // The retry must wait until the peer's publication releases the lock.
                    assert!(released.load(std::sync::atomic::Ordering::SeqCst));
                    return Ok("published");
                }
                // Between the absent-record check and this lookup, a peer
                // takes the first lock record for a pre-existing object and is
                // mid-rename, so this lookup sees the name missing.
                let handle = {
                    let mut backend = nas.lock().unwrap();
                    let file = backend.id();
                    backend.names.insert(record, file);
                    backend.files.insert(file, File::default());
                    let handle = backend.id();
                    backend.handles.insert(
                        handle,
                        Handle {
                            file,
                            session: 99,
                            exclusive: true,
                            delete: false,
                        },
                    );
                    handle
                };
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    released.store(true, std::sync::atomic::Ordering::SeqCst);
                    nas.lock().unwrap().handles.remove(&handle);
                });
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "renaming",
                ))
            }
        })
        .await
        .unwrap();
    assert_eq!(result, "published");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    // A miss with the record still absent is authoritative: no second lookup.
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let error = a
        .share
        .strict_read("strict\\other", || {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async { Err::<(), _>(std::io::Error::new(std::io::ErrorKind::NotFound, "gone")) }
        })
        .await
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn failed_stat_and_corrupt_version_record_never_publish() {
    let nas = Arc::new(Mutex::new(Nas::default()));
    let a = instance(nas.clone(), 1).await;
    expect_status(
        &request(a.clone(), "PUT", "strict/key", "", b"old").await,
        "200",
    );
    nas.lock().unwrap().fail_destination_stat = true;
    expect_status(
        &request(
            a.clone(),
            "PUT",
            "strict/key",
            "If-None-Match: *\r\n",
            b"new",
        )
        .await,
        "403",
    );
    {
        let mut backend = nas.lock().unwrap();
        backend.fail_destination_stat = false;
        let id = *backend
            .names
            .iter()
            .find(|(name, id)| {
                name.starts_with(".SPICEIO-LOCKS\\") && backend.files[id].data.len() == 48
            })
            .unwrap()
            .1;
        backend.files.get_mut(&id).unwrap().data[10] ^= 1;
    }
    expect_status(
        &request(a.clone(), "PUT", "strict/key", "", b"new").await,
        "500",
    );
    assert_eq!(nas.lock().unwrap().publications, 1);
    assert_eq!(
        a.share
            .get_object_compound("strict/key", 64)
            .await
            .unwrap()
            .1
            .as_ref(),
        b"old"
    );
}

fn expect_status(response: &str, expected: &str) {
    assert_eq!(status(response), expected, "{response}");
}

#[tokio::test]
async fn lost_lock_connection_never_retries_publication_on_a_new_session() {
    let nas = Arc::new(Mutex::new(Nas::default()));
    let a = instance(nas.clone(), 1).await;
    let b = instance(nas.clone(), 2).await;
    a.share
        .put_object_atomic("strict/key", b"old")
        .await
        .unwrap();
    nas.lock().unwrap().disconnect_on_rename = true;
    let error = a
        .share
        .put_object_conditional("strict/key", b"new", &WriteCondition::Match("*".into()))
        .await
        .unwrap_err();
    assert_eq!(
        error.get_ref().unwrap().downcast_ref(),
        Some(&crate::smb::condition::ConditionFailure::Conflict)
    );
    assert_eq!(nas.lock().unwrap().publications, 1);
    assert_eq!(
        b.share
            .get_object_compound("strict/key", 64)
            .await
            .unwrap()
            .1
            .as_ref(),
        b"old"
    );
    // The dead connection's exclusive open is gone, so a peer can proceed.
    b.share
        .put_object_atomic("strict/key", b"peer")
        .await
        .unwrap();
    assert_eq!(nas.lock().unwrap().publications, 2);
}

#[tokio::test]
async fn http_copy_and_multipart_conditions_reach_the_backend_commit() {
    let nas = Arc::new(Mutex::new(Nas::default()));
    let a = instance(nas.clone(), 1).await;
    let b = instance(nas, 2).await;
    a.share
        .put_object_atomic("strict/source", b"parts")
        .await
        .unwrap();
    let old = a
        .share
        .put_object_atomic("strict/dest", b"old")
        .await
        .unwrap();
    let copy_headers = "x-amz-copy-source: /audit/strict/source\r\nIf-None-Match: *\r\n";
    expect_status(
        &request(b.clone(), "PUT", "strict/dest", copy_headers, b"").await,
        "412",
    );
    let id = a.multipart.create("strict/dest").await;
    a.multipart
        .put_part(&id, 1, 5, "part-etag".into(), "strict\\source".into())
        .await
        .unwrap();
    let path = format!("strict/dest?uploadId={id}");
    let complete = b"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>part-etag</ETag></Part></CompleteMultipartUpload>";
    expect_status(
        &request(a.clone(), "POST", &path, "If-None-Match: *\r\n", complete).await,
        "412",
    );
    assert!(a.multipart.get(&id).await.is_some());
    let condition = format!("If-Match: \"{}\"\r\n", old.etag);
    expect_status(
        &request(a.clone(), "POST", &path, &condition, complete).await,
        "200",
    );
    assert!(a.multipart.get(&id).await.is_none());
    let response = request(b, "GET", "strict/dest", "", b"").await;
    expect_status(&response, "200");
    assert!(response.ends_with("parts"), "{response}");
}
