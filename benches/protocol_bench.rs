use bytes::BytesMut;
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
            encode_read_request(&mut buf, black_box(&file_id), 0, 131072);
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

fn bench_decode_read_response(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_read_response");
    for size in [64, 1024, 65536] {
        let data_offset = (SMB2_HEADER_SIZE + 16) as u16;
        let mut body = vec![0u8; 16 + size];
        body[2..4].copy_from_slice(&data_offset.to_le_bytes());
        body[4..8].copy_from_slice(&(size as u32).to_le_bytes());
        group.bench_with_input(
            criterion::BenchmarkId::from_parameter(size),
            &body,
            |b, body| b.iter(|| decode_read_response(black_box(body))),
        );
    }
    group.finish();
}

fn bench_decode_read_response_owned(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_read_response_owned");
    for size in [64, 1024, 65536] {
        let data_offset = (SMB2_HEADER_SIZE + 16) as u16;
        let mut body = vec![0u8; 16 + size];
        body[2..4].copy_from_slice(&data_offset.to_le_bytes());
        body[4..8].copy_from_slice(&(size as u32).to_le_bytes());
        group.bench_with_input(
            criterion::BenchmarkId::from_parameter(size),
            &body,
            |b, body| b.iter(|| decode_read_response_owned(black_box(body.clone()))),
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
    bench_decode_read_response,
    bench_decode_read_response_owned,
    bench_build_request,
    bench_parse_directory_entries,
);
criterion_main!(benches);
