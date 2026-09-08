//! Loopback SMB fixtures and regression tests. Authentication is bypassed only in test builds.
use crate::s3::{
    multipart::MultipartStore, object_cache::ObjectCache, router::AppState, spill::Spill,
    writeback::WriteBack,
};
use crate::smb::{
    client::{SmbClient, SmbConfig},
    ops::ShareSession,
    pool::SmbPool,
    protocol::*,
};
use bytes::{BufMut, Bytes};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub(crate) fn config() -> SmbConfig {
    SmbConfig {
        server: "127.0.0.1".into(),
        port: 1,
        username: "audit".into(),
        password: String::new(),
        domain: String::new(),
        workstation: "audit".into(),
        max_io_size: 65536,
    }
}
pub(crate) async fn pair() -> (Arc<SmbClient>, TcpStream) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (c, s) = tokio::join!(TcpStream::connect(l.local_addr().unwrap()), l.accept());
    (SmbClient::test_from_stream(c.unwrap()), s.unwrap().0)
}
pub(crate) async fn state() -> (AppState, TcpStream) {
    let (c, s) = pair().await;
    let share = Arc::new(ShareSession::test_from_pool(SmbPool::test_from_client(c)));
    (
        AppState {
            smb_slots: share.admission(),
            client_inflight: share.client_inflight(),
            share,
            bucket: "audit".into(),
            region: "us-east-1".into(),
            multipart: MultipartStore::new(),
            listings: Default::default(),
            object_cache: Arc::new(ObjectCache::new(false, 1024, 1024, 64)),
            writeback: Arc::new(WriteBack::new(true, 1024)),
        },
        s,
    )
}
pub(crate) async fn read_frame(s: &mut TcpStream) -> Vec<u8> {
    let mut len = [0; 4];
    s.read_exact(&mut len).await.unwrap();
    let mut b = vec![0; u32::from_be_bytes(len) as usize];
    s.read_exact(&mut b).await.unwrap();
    b
}
pub(crate) async fn error_reply(s: &mut TcpStream, request: &[u8], status: u32) {
    let mut h = Header::decode(request).unwrap();
    h.next_command = 0;
    h.status = status;
    h.flags = 1;
    let b = build_request(&h, |b| b.extend_from_slice(&[9, 0, 0, 0, 0, 0, 0, 0]));
    s.write_all(&b).await.unwrap();
}
fn read_reply(message_id: u64, data: &[u8]) -> Vec<u8> {
    let mut h = Header::new(Command::Read, message_id);
    h.flags = 1;
    build_request(&h, |b| {
        b.put_u16_le(17);
        b.put_u8(80);
        b.put_u8(0);
        b.put_u32_le(data.len() as u32);
        b.put_u32_le(0);
        b.put_u32_le(0);
        b.extend_from_slice(data);
    })
    .to_vec()
}
#[tokio::test]
async fn regression_cancelled_read_must_not_return_previous_objects_bytes() {
    let (c, mut server) = pair().await;
    let first = {
        let c = c.clone();
        tokio::spawn(async move { c.read(1, &[1; 16], 0, 4).await })
    };
    let request = read_frame(&mut server).await;
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    assert!(c.is_poisoned());
    let id = Header::decode(&request).unwrap().message_id;
    server.write_all(&read_reply(id, b"AAAA")).await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(1), c.read(1, &[2; 16], 0, 4))
        .await
        .unwrap();
    assert!(result.is_err(), "an outstanding reply must never be reused");
    assert_eq!(c.inflight(), 0);
}

pub(crate) struct TempDir(pub std::path::PathBuf);
impl TempDir {
    pub(crate) fn new(name: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "spiceio-audit-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn regression_revalidation_must_preserve_unflushed_journal() {
    let dir = TempDir::new("journal-loss");
    let spill = Arc::new(Spill::open(&dir.0, "audit".into(), 1024, 1024).unwrap());
    spill.put("key", "new-etag", 2, b"new body", true).unwrap();
    let peer = ObjectCache::new(false, 1024, 1024, 64).with_spill(spill.clone());
    assert!(peer.lookup_etag("key", "old-backend-etag").await.is_none());
    let (replay, _) = spill.scan_dirty(Duration::ZERO);
    println!(
        "journal entries available for recovery after revalidation: {}",
        replay.len()
    );
    assert_eq!(
        replay.len(),
        1,
        "a read deleted the sole recoverable acknowledged write"
    );
}

#[tokio::test]
async fn regression_pending_get_must_serve_pending_body_after_l1_eviction() {
    let dir = TempDir::new("stale-pending");
    let spill = Arc::new(Spill::open(&dir.0, "audit".into(), 1024, 1024).unwrap());
    spill.put("key", "old", 1, b"old!", false).unwrap();
    let cache = ObjectCache::new(false, 4, 4, 1).with_spill(spill);
    let wb = WriteBack::new(true, 1024);
    assert!(
        wb.enqueue("key", "new", 2, Bytes::from_static(b"new!"))
            .await
    );
    cache.insert("key", "new", 2, Bytes::from_static(b"new!"));
    cache.insert("other", "x", 2, Bytes::from_static(b"xxxx"));
    assert!(wb.pending_meta("key").await.is_some());
    let body = wb.pending_object("key").await.unwrap().body;
    println!("pending lookup after eviction returned {:?}", body);
    assert_eq!(
        body.as_ref(),
        b"new!",
        "pending metadata does not validate the cache version"
    );
}

#[test]
fn regression_recovery_scan_loads_one_generation_at_a_time() {
    let dir = TempDir::new("scan-size");
    let mib = 1024 * 1024;
    let spill = Spill::open(&dir.0, "audit".into(), mib, mib).unwrap();
    let body = vec![42; mib as usize];
    for i in 0..16 {
        spill.put(&format!("key-{i}"), "e", 1, &body, true).unwrap();
    }
    let (entries, _) = spill.scan_dirty(Duration::ZERO);
    assert_eq!(entries.len(), 16);
    // Scanning returns only descriptors. The body is read and verified on
    // demand, and a generation replaced after scanning must not be replayed.
    spill
        .put(&entries[0].key, "new", 2, b"replacement", true)
        .unwrap();
    assert!(spill.load_dirty(&entries[0]).is_none());
    for entry in &entries[1..] {
        assert_eq!(spill.load_dirty(entry).unwrap().body.as_ref(), body);
    }
}

// Control: the internal range over-read is a performance finding. Hyper's
// encoder bounds the wire body, so do not report it as excess bytes on HTTP.
#[tokio::test]
async fn regression_control_hyper_caps_oversized_streaming_body_on_wire() {
    use crate::s3::body::SpiceioBody;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let svc = hyper::service::service_fn(|_| async {
            let (body, tx) = SpiceioBody::channel(1);
            tx.send(Ok(Bytes::from_static(b"bcdefgh"))).await.unwrap();
            drop(tx);
            Ok::<_, std::convert::Infallible>(
                http::Response::builder()
                    .header("Content-Length", "2")
                    .body(body)
                    .unwrap(),
            )
        });
        crate::http::connection_builder(Duration::from_secs(1))
            .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
            .await
            .unwrap();
    });
    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    server.await.unwrap();
    let at = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    println!("Hyper caps oversized body on wire to {:?}", &response[at..]);
    assert_eq!(&response[at..], b"bc");
}

#[tokio::test]
async fn mismatched_reply_identity_poisons_the_connection() {
    for wrong_command in [false, true] {
        let (client, mut server) = pair().await;
        let read = tokio::spawn({
            let client = client.clone();
            async move { client.read(1, &[1; 16], 0, 4).await }
        });
        let request = read_frame(&mut server).await;
        let id = Header::decode(&request).unwrap().message_id;
        let mut reply = read_reply(id + u64::from(!wrong_command), b"data");
        if wrong_command {
            reply[16..18].copy_from_slice(&(Command::Write as u16).to_le_bytes());
        }
        server.write_all(&reply).await.unwrap();
        assert_eq!(
            read.await.unwrap().unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert!(client.is_poisoned());
    }
}

#[tokio::test]
async fn cancelling_a_waiter_preserves_the_active_exchange() {
    let (client, mut server) = pair().await;
    let read = tokio::spawn({
        let client = client.clone();
        async move { client.read(1, &[1; 16], 0, 4).await }
    });
    let request = read_frame(&mut server).await;
    let waiting = tokio::spawn({
        let client = client.clone();
        async move { client.read(1, &[2; 16], 0, 4).await }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while client.inflight() < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    waiting.abort();
    assert!(waiting.await.unwrap_err().is_cancelled());
    assert!(!client.is_poisoned());
    server
        .write_all(&read_reply(
            Header::decode(&request).unwrap().message_id,
            b"data",
        ))
        .await
        .unwrap();
    assert_eq!(read.await.unwrap().unwrap().as_ref(), b"data");
    assert_eq!(client.inflight(), 0);
    assert!(!client.is_poisoned());
}

#[tokio::test]
async fn duplicate_pipeline_read_response_is_not_a_second_completion() {
    let (client, mut server) = pair().await;
    let read = tokio::spawn({
        let client = client.clone();
        async move { client.pipelined_read(1, &[1; 16], 0, 4, 2, 8).await }
    });
    let first = read_frame(&mut server).await;
    let _second = read_frame(&mut server).await;
    let reply = read_reply(Header::decode(&first).unwrap().message_id, b"data");
    server.write_all(&reply).await.unwrap();
    server.write_all(&reply).await.unwrap();
    assert_eq!(
        read.await.unwrap().unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
    assert!(client.is_poisoned());
}

#[test]
fn cache_fills_share_an_aggregate_memory_limit() {
    let cache = ObjectCache::new(false, 10, 10, 10);
    let fill = cache.reserve_fill(6).unwrap();
    assert!(cache.reserve_fill(6).is_none());
    let small = cache.reserve_fill(4).unwrap();
    assert!(cache.reserve_fill(1).is_none());
    drop(fill);
    assert!(cache.reserve_fill(6).is_some());
    drop(small);
    assert!(cache.reserve_fill(10).is_some());
}

pub(crate) async fn http_request(state: Arc<AppState>, request: &[u8]) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let service = hyper::service::service_fn(move |request| {
            let state = Arc::clone(&state);
            async move {
                Ok::<_, std::convert::Infallible>(
                    crate::s3::router::handle_request(request, &state).await,
                )
            }
        });
        crate::http::connection_builder(Duration::from_secs(1))
            .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
            .await
            .unwrap();
    });
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(request).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    server.await.unwrap();
    response
}

#[tokio::test]
async fn failed_write_through_put_preserves_an_acknowledged_predecessor() {
    let (mut state, mut server) = state().await;
    state.writeback = Arc::new(WriteBack::new(true, 4));
    state
        .writeback
        .enqueue("key", "old", 1, Bytes::from_static(b"old!"))
        .await;
    let state = Arc::new(state);
    let backend = tokio::spawn(async move {
        let request = read_frame(&mut server).await;
        error_reply(&mut server, &request, 0xC0000022).await;
    });
    let response = http_request(Arc::clone(&state),
        b"PUT /audit/key HTTP/1.1\r\nHost: localhost\r\nContent-Length: 8\r\nConnection: close\r\n\r\nnew-body").await;
    backend.await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 403"));
    assert_eq!(
        state
            .writeback
            .pending_object("key")
            .await
            .unwrap()
            .body
            .as_ref(),
        b"old!"
    );
}

#[tokio::test]
async fn conditional_put_does_not_treat_a_failed_stat_as_absence() {
    let (state, mut server) = state().await;
    let state = Arc::new(state);
    let backend = tokio::spawn(async move {
        let request = read_frame(&mut server).await;
        error_reply(&mut server, &request, 0xC0000022).await;
    });
    let response = http_request(Arc::clone(&state),
        b"PUT /audit/key HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nIf-None-Match: *\r\nConnection: close\r\n\r\n").await;
    backend.await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 403"));
    assert!(state.writeback.pending_object("key").await.is_none());
}
