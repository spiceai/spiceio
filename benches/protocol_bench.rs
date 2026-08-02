use bytes::{Bytes, BytesMut};
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use spiceio::smb::protocol::*;

fn bench_header_encode(c: &mut Criterion) {
    let hdr = Header::new(Command::Create, 42);
    c.bench_function("header_encode", |b| {
        b.iter(|| {
            let mut buf = BytesMut::with_capacity(64);
            black_box(&hdr).encode(&mut buf);
            buf
        })
    });
}

fn bench_header_decode(c: &mut Criterion) {
    let hdr = Header::new(Command::Read, 99);
    let mut buf = BytesMut::with_capacity(64);
    hdr.encode(&mut buf);
    let bytes = buf.freeze();
    c.bench_function("header_decode", |b| {
        b.iter(|| Header::decode(black_box(&bytes)))
    });
}

fn bench_encode_create_request(c: &mut Criterion) {
    c.bench_function("encode_create_request", |b| {
        b.iter(|| {
            let mut buf = BytesMut::with_capacity(256);
            encode_create_request(
                &mut buf,
                black_box("sccache\\us-east-1\\bucket\\abcdef1234567890"),
                0x80000000,
                0x00000001,
                0x00000001,
                0x00000040,
            );
            buf
        })
    });
}

fn bench_encode_read_request(c: &mut Criterion) {
    let file_id = [1u8; 16];
    c.bench_function("encode_read_request", |b| {
        b.iter(|| {
            let mut buf = BytesMut::with_capacity(64);
            encode_read_request(&mut buf, black_box(&file_id), 0, 131072, 0);
            buf
        })
    });
}

fn bench_encode_write_request(c: &mut Criterion) {
    let file_id = [1u8; 16];
    let mut group = c.benchmark_group("encode_write_request");
    for size in [64, 1024, 65536, 131072] {
        let data = vec![0u8; size];
        group.bench_with_input(
            criterion::BenchmarkId::from_parameter(size),
            &data,
            |b, d| {
                b.iter(|| {
                    let mut buf = BytesMut::with_capacity(64 + d.len());
                    encode_write_request(&mut buf, black_box(&file_id), 0, black_box(d));
                    buf
                })
            },
        );
    }
    group.finish();
}

fn bench_decode_create_response(c: &mut Criterion) {
    let mut body = vec![0u8; 88];
    body[24..32].copy_from_slice(&100u64.to_le_bytes());
    body[48..56].copy_from_slice(&4096u64.to_le_bytes());
    body[64..80].copy_from_slice(&[1u8; 16]);
    c.bench_function("decode_create_response", |b| {
        b.iter(|| decode_create_response(black_box(&body)))
    });
}

fn bench_decode_read_response_bytes(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_read_response_bytes");
    for size in [64, 1024, 65536] {
        let data_offset = (SMB2_HEADER_SIZE + 16) as u16;
        let mut body = vec![0u8; 16 + size];
        body[2..4].copy_from_slice(&data_offset.to_le_bytes());
        body[4..8].copy_from_slice(&(size as u32).to_le_bytes());
        let body = Bytes::from(body);
        group.bench_with_input(
            criterion::BenchmarkId::from_parameter(size),
            &body,
            |b, body| b.iter(|| decode_read_response_bytes(black_box(body))),
        );
    }
    group.finish();
}

fn bench_build_request(c: &mut Criterion) {
    let file_id = [1u8; 16];
    c.bench_function("build_request_close", |b| {
        b.iter(|| {
            let hdr = Header::new(Command::Close, 0);
            build_request(&hdr, |buf| {
                encode_close_request(buf, black_box(&file_id));
            })
        })
    });
}

fn bench_encode_set_info_rename(c: &mut Criterion) {
    let file_id = [0u8; 16];
    let mut group = c.benchmark_group("encode_set_info_rename");
    let paths: Vec<(&str, String)> = vec![
        ("short_5", "a\\b\\c".into()),
        (
            "typical_40",
            "sccache\\us-east-1\\bucket\\abcdef1234567890".into(),
        ),
        ("long_255", "a".repeat(255)),
    ];
    for (label, path) in &paths {
        group.bench_with_input(
            criterion::BenchmarkId::from_parameter(label),
            path,
            |b, p| {
                b.iter(|| {
                    let mut buf = BytesMut::with_capacity(128 + p.len() * 2);
                    encode_set_info_rename(&mut buf, black_box(&file_id), black_box(p), true);
                    buf
                })
            },
        );
    }
    group.finish();
}

// ── Parser benches for new public API ────────────────────────────────────────

/// Bench parsing of a compound response (chained SMB2 messages in one frame).
/// Compound responses are the wire format for create+read+close and similar
/// batched operations — relevant CPU cost when the S3 layer issues compounds.
fn bench_parse_compound_response(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_compound_response");
    // Body size of 16 bytes is representative of close/create-response payloads.
    let body_len = 16usize;
    let entry_size = SMB2_HEADER_SIZE + body_len;
    for n in [2usize, 4, 8] {
        let mut data = vec![0u8; entry_size * n];
        for i in 0..n {
            let mut hdr = Header::new(Command::Create, i as u64);
            hdr.next_command = if i + 1 < n { entry_size as u32 } else { 0 };
            let mut buf = BytesMut::with_capacity(SMB2_HEADER_SIZE);
            hdr.encode(&mut buf);
            let start = i * entry_size;
            data[start..start + SMB2_HEADER_SIZE].copy_from_slice(&buf);
            for b in &mut data[start + SMB2_HEADER_SIZE..start + entry_size] {
                *b = 0xAB;
            }
        }
        let data = Bytes::from(data);
        group.bench_with_input(
            criterion::BenchmarkId::from_parameter(n),
            &data,
            |b, data| b.iter(|| parse_compound_response(black_box(data))),
        );
    }
    group.finish();
}

/// Build one framed SMB2 read response message (header + read response body +
/// data) ready for `Header::decode` + `decode_read_response_from_msg`.
fn build_read_response_msg(msg_id: u64, data_len: usize) -> Vec<u8> {
    let body_len = 16 + data_len;
    let mut msg = vec![0u8; SMB2_HEADER_SIZE + body_len];

    let mut hdr_buf = BytesMut::with_capacity(SMB2_HEADER_SIZE);
    let mut hdr = Header::new(Command::Read, msg_id);
    hdr.status = 0;
    hdr.encode(&mut hdr_buf);
    msg[..SMB2_HEADER_SIZE].copy_from_slice(&hdr_buf);

    let body = &mut msg[SMB2_HEADER_SIZE..];
    // StructureSize = 17
    body[0..2].copy_from_slice(&17u16.to_le_bytes());
    // DataOffset (from start of SMB2 message)
    let data_offset = (SMB2_HEADER_SIZE + 16) as u16;
    body[2..4].copy_from_slice(&data_offset.to_le_bytes());
    // DataLength
    body[4..8].copy_from_slice(&(data_len as u32).to_le_bytes());
    // Remaining 8 bytes (DataRemaining + Flags) stay zero. Data bytes stay zero.
    msg
}

/// Bench the zero-copy `decode_read_response_from_msg` path — the inner loop
/// of GetObject streaming once the wire bytes are in. Slicing the payload out
/// of the owned frame instead of copying the body out first saves ~4 MiB of
/// memcpy per 64-deep 64 KiB batch.
fn bench_pipelined_read_decode_zerocopy(c: &mut Criterion) {
    let mut group = c.benchmark_group("pipelined_read_decode_zerocopy");
    let cases = [(8usize, 65536usize), (64, 65536), (64, 8192)];
    for (depth, chunk_size) in cases {
        let base_msg_id = 1_000u64;
        let messages: Vec<Vec<u8>> = (0..depth)
            .map(|i| build_read_response_msg(base_msg_id + i as u64, chunk_size))
            .collect();
        group.throughput(criterion::Throughput::Bytes((depth * chunk_size) as u64));
        group.bench_with_input(
            criterion::BenchmarkId::from_parameter(format!("d{depth}_c{chunk_size}")),
            &messages,
            |b, messages| {
                b.iter(|| {
                    let n = messages.len();
                    let mut slots: Vec<Option<Bytes>> = (0..n).map(|_| None).collect();
                    for msg in messages.iter() {
                        let header = Header::decode(black_box(msg)).unwrap();
                        let slot = header.message_id.wrapping_sub(base_msg_id) as usize;
                        // Clone to simulate ownership transfer from the read
                        // path — the production code reads directly into a
                        // fresh Vec each response.
                        slots[slot] = decode_read_response_from_msg(msg.clone());
                    }
                    slots
                });
            },
        );
    }
    group.finish();
}

/// Bench the CPU-bound per-batch work of `pipelined_write`: header construction
/// (with credit charge), `encode_write_request`, and `build_request` framing.
/// This is the inner loop of WAL pipelined writes before any I/O happens.
fn bench_pipelined_write_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("pipelined_write_encode");
    let file_id = [1u8; 16];
    // (depth, chunk_size) — depth=64 matches WRITE_PIPELINE_DEPTH in ops.rs.
    let cases = [(8usize, 65536usize), (64, 65536), (64, 1024 * 1024)];
    for (depth, chunk_size) in cases {
        let chunk = vec![0u8; chunk_size];
        group.throughput(criterion::Throughput::Bytes((depth * chunk_size) as u64));
        group.bench_with_input(
            criterion::BenchmarkId::from_parameter(format!("d{depth}_c{chunk_size}")),
            &chunk,
            |b, chunk| {
                b.iter(|| {
                    let mut packets = Vec::with_capacity(depth);
                    let mut offset = 0u64;
                    for i in 0..depth {
                        let mut hdr = Header::new(Command::Write, i as u64)
                            .with_credit_charge(chunk.len() as u32);
                        hdr.tree_id = 42;
                        hdr.session_id = 0xdead_beef;
                        let packet = build_request(&hdr, |buf| {
                            encode_write_request(buf, &file_id, offset, black_box(chunk));
                        });
                        packets.push(packet);
                        offset += chunk.len() as u64;
                    }
                    packets
                });
            },
        );
    }
    group.finish();
}

/// Bench the coalesced equivalent: build all packets directly into a single
/// `BytesMut`, the way `pipelined_write` does post-optimization. Comparable
/// to `bench_pipelined_write_encode` — captures the win from eliminating
/// per-packet allocations and from a single contiguous buffer.
fn bench_pipelined_write_encode_coalesced(c: &mut Criterion) {
    use bytes::BufMut;
    let mut group = c.benchmark_group("pipelined_write_encode_coalesced");
    let file_id = [1u8; 16];
    let cases = [(8usize, 65536usize), (64, 65536), (64, 1024 * 1024)];
    const WRITE_REQUEST_FIXED: usize = 48;
    for (depth, chunk_size) in cases {
        let chunk = vec![0u8; chunk_size];
        group.throughput(criterion::Throughput::Bytes((depth * chunk_size) as u64));
        group.bench_with_input(
            criterion::BenchmarkId::from_parameter(format!("d{depth}_c{chunk_size}")),
            &chunk,
            |b, chunk| {
                b.iter(|| {
                    let total_bytes =
                        depth * (4 + SMB2_HEADER_SIZE + WRITE_REQUEST_FIXED + chunk.len());
                    let mut buf = BytesMut::with_capacity(total_bytes);
                    let mut offset = 0u64;
                    for i in 0..depth {
                        let mut hdr = Header::new(Command::Write, i as u64)
                            .with_credit_charge(chunk.len() as u32);
                        hdr.tree_id = 42;
                        hdr.session_id = 0xdead_beef;
                        let packet_total = SMB2_HEADER_SIZE + WRITE_REQUEST_FIXED + chunk.len();
                        buf.put_u32((packet_total as u32) & 0x00FF_FFFF);
                        hdr.encode(&mut buf);
                        encode_write_request(&mut buf, &file_id, offset, black_box(chunk));
                        offset += chunk.len() as u64;
                    }
                    buf
                });
            },
        );
    }
    group.finish();
}

fn bench_parse_directory_entries(c: &mut Criterion) {
    // Build 50 entries
    let mut data = Vec::new();
    for i in 0..50 {
        let name = format!("file_{i:04}.txt");
        let name_utf16: Vec<u8> = name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let entry_size = 104 + name_utf16.len();
        let padded = entry_size + (8 - entry_size % 8) % 8;

        let start = data.len();
        data.resize(start + padded, 0);
        let entry = &mut data[start..];

        // next_entry_offset (0 for last)
        if i < 49 {
            entry[0..4].copy_from_slice(&(padded as u32).to_le_bytes());
        }
        entry[40..48].copy_from_slice(&((i * 1024) as u64).to_le_bytes());
        entry[56..60].copy_from_slice(&0x20u32.to_le_bytes());
        entry[60..64].copy_from_slice(&(name_utf16.len() as u32).to_le_bytes());
        entry[104..104 + name_utf16.len()].copy_from_slice(&name_utf16);
    }

    c.bench_function("parse_directory_entries_50", |b| {
        b.iter(|| parse_directory_entries(black_box(&data)))
    });
}

criterion_group!(
    benches,
    bench_header_encode,
    bench_header_decode,
    bench_encode_create_request,
    bench_encode_read_request,
    bench_encode_write_request,
    bench_encode_set_info_rename,
    bench_decode_create_response,
    bench_decode_read_response_bytes,
    bench_build_request,
    bench_parse_compound_response,
    bench_pipelined_read_decode_zerocopy,
    bench_pipelined_write_encode,
    bench_pipelined_write_encode_coalesced,
    bench_parse_directory_entries,
);
criterion_main!(benches);
