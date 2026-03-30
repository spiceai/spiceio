use bytes::BytesMut;
use criterion::{Criterion, black_box, criterion_group, criterion_main};

use spiceio::smb::protocol::*;

fn bench_header_encode(c: &mut Criterion) {
    let hdr = Header::new(Command::Create, 42);
    let mut buf = BytesMut::with_capacity(64);

    c.bench_function("header/encode", |b| {
        b.iter(|| {
            buf.clear();
            black_box(&hdr).encode(&mut buf);
        })
    });
}

fn bench_header_decode(c: &mut Criterion) {
    let hdr = Header::new(Command::Create, 42);
    let mut buf = BytesMut::with_capacity(64);
    hdr.encode(&mut buf);
    let bytes = buf.freeze();

    c.bench_function("header/decode", |b| {
        b.iter(|| Header::decode(black_box(&bytes)))
    });
}

fn bench_frame_packet(c: &mut Criterion) {
    let hdr = Header::new(Command::Write, 100);
    let body = vec![0u8; 256];

    c.bench_function("frame_packet/256B_body", |b| {
        b.iter(|| frame_packet(black_box(&hdr), black_box(&body)))
    });
}

fn bench_build_request(c: &mut Criterion) {
    let file_id = [0u8; 16];

    c.bench_function("build_request/create", |b| {
        b.iter(|| {
            let hdr = Header::new(Command::Create, 1);
            build_request(&hdr, |buf| {
                encode_create_request(
                    buf,
                    black_box("test\\path\\file.txt"),
                    DesiredAccess::GenericWrite as u32,
                    ShareAccess::Read as u32,
                    CreateDisposition::OverwriteIf as u32,
                    CreateOptions::NonDirectoryFile as u32,
                );
            })
        })
    });

    c.bench_function("build_request/write_64KB", |b| {
        let data = vec![0u8; 65536];
        b.iter(|| {
            let hdr = Header::new(Command::Write, 1);
            build_request(&hdr, |buf| {
                encode_write_request(buf, black_box(&file_id), 0, black_box(&data));
            })
        })
    });

    c.bench_function("build_request/read", |b| {
        b.iter(|| {
            let hdr = Header::new(Command::Read, 1);
            build_request(&hdr, |buf| {
                encode_read_request(buf, black_box(&file_id), 0, 65536);
            })
        })
    });

    c.bench_function("build_request/close", |b| {
        b.iter(|| {
            let hdr = Header::new(Command::Close, 1);
            build_request(&hdr, |buf| {
                encode_close_request(buf, black_box(&file_id));
            })
        })
    });
}

fn bench_decode_responses(c: &mut Criterion) {
    // Build a minimal valid Create response (88 bytes)
    let mut create_resp = vec![0u8; 88];
    create_resp[0] = 89; // StructureSize low byte
    create_resp[64..80].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

    c.bench_function("decode/create_response", |b| {
        b.iter(|| decode_create_response(black_box(&create_resp)))
    });

    // Build a minimal valid Write response (16 bytes)
    let mut write_resp = vec![0u8; 16];
    write_resp[0] = 17; // StructureSize
    write_resp[4..8].copy_from_slice(&1024u32.to_le_bytes());

    c.bench_function("decode/write_response", |b| {
        b.iter(|| decode_write_response(black_box(&write_resp)))
    });

    // Build a read response with 1KB data
    let mut read_resp = vec![0u8; 17 + 1024];
    read_resp[0] = 17; // StructureSize
    read_resp[2] = (SMB2_HEADER_SIZE + 17) as u8; // DataOffset
    read_resp[4..8].copy_from_slice(&1024u32.to_le_bytes()); // DataLength

    c.bench_function("decode/read_response_1KB", |b| {
        b.iter(|| decode_read_response(black_box(&read_resp)))
    });
}

fn bench_parse_directory_entries(c: &mut Criterion) {
    // Build synthetic directory entries
    let mut data = Vec::new();
    for i in 0..20 {
        let name = format!("file_{i:03}.txt");
        let name_utf16: Vec<u8> = name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let entry_len = 104 + name_utf16.len();
        let padded = (entry_len + 7) & !7;

        let mut entry = vec![0u8; padded];
        if i < 19 {
            entry[0..4].copy_from_slice(&(padded as u32).to_le_bytes());
        }
        entry[60..64].copy_from_slice(&(name_utf16.len() as u32).to_le_bytes());
        entry[96..100].copy_from_slice(&1024u32.to_le_bytes());
        entry[104..104 + name_utf16.len()].copy_from_slice(&name_utf16);
        data.extend_from_slice(&entry);
    }

    c.bench_function("parse_directory_entries/20_files", |b| {
        b.iter(|| parse_directory_entries(black_box(&data)))
    });
}

fn bench_nt_status(c: &mut Criterion) {
    c.bench_function("NtStatus/from_u32_known", |b| {
        b.iter(|| NtStatus::from_u32(black_box(0xC000_0034)))
    });
    c.bench_function("NtStatus/from_u32_unknown", |b| {
        b.iter(|| NtStatus::from_u32(black_box(0xC000_FFFF)))
    });
}

criterion_group!(
    benches,
    bench_header_encode,
    bench_header_decode,
    bench_frame_packet,
    bench_build_request,
    bench_decode_responses,
    bench_parse_directory_entries,
    bench_nt_status,
);
criterion_main!(benches);
