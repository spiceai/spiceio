use criterion::{Criterion, black_box, criterion_group, criterion_main};

use spiceio::crypto;

fn bench_md4(c: &mut Criterion) {
    let data_64 = vec![0xab_u8; 64];
    let data_1k = vec![0xab_u8; 1024];

    c.bench_function("md4/64B", |b| {
        b.iter(|| black_box(crypto::md4(black_box(&data_64))))
    });
    c.bench_function("md4/1KB", |b| {
        b.iter(|| black_box(crypto::md4(black_box(&data_1k))))
    });
}

fn bench_sha256(c: &mut Criterion) {
    let data_64 = vec![0xab_u8; 64];
    let data_1k = vec![0xab_u8; 1024];
    let data_64k = vec![0xab_u8; 65536];

    c.bench_function("sha256/64B", |b| {
        b.iter(|| black_box(crypto::sha256(black_box(&data_64))))
    });
    c.bench_function("sha256/1KB", |b| {
        b.iter(|| black_box(crypto::sha256(black_box(&data_1k))))
    });
    c.bench_function("sha256/64KB", |b| {
        b.iter(|| black_box(crypto::sha256(black_box(&data_64k))))
    });
}

fn bench_hmac_md5(c: &mut Criterion) {
    let key = [0x0b_u8; 16];
    let data_64 = vec![0xab_u8; 64];
    let data_1k = vec![0xab_u8; 1024];

    c.bench_function("hmac_md5/64B", |b| {
        b.iter(|| black_box(crypto::hmac_md5(black_box(&key), black_box(&data_64))))
    });
    c.bench_function("hmac_md5/1KB", |b| {
        b.iter(|| black_box(crypto::hmac_md5(black_box(&key), black_box(&data_1k))))
    });
}

fn bench_hmac_sha256(c: &mut Criterion) {
    let key = [0x0b_u8; 32];
    let data_64 = vec![0xab_u8; 64];
    let data_1k = vec![0xab_u8; 1024];

    c.bench_function("hmac_sha256/64B", |b| {
        b.iter(|| black_box(crypto::hmac_sha256(black_box(&key), black_box(&data_64))))
    });
    c.bench_function("hmac_sha256/1KB", |b| {
        b.iter(|| black_box(crypto::hmac_sha256(black_box(&key), black_box(&data_1k))))
    });
}

fn bench_hex_encode(c: &mut Criterion) {
    let data_16 = [0xab_u8; 16];
    let data_32 = [0xab_u8; 32];

    c.bench_function("hex_encode/16B", |b| {
        b.iter(|| black_box(crypto::hex_encode(black_box(&data_16))))
    });
    c.bench_function("hex_encode/32B", |b| {
        b.iter(|| black_box(crypto::hex_encode(black_box(&data_32))))
    });
}

criterion_group!(
    benches,
    bench_md4,
    bench_sha256,
    bench_hmac_md5,
    bench_hmac_sha256,
    bench_hex_encode,
);
criterion_main!(benches);
