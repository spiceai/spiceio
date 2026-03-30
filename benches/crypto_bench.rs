use criterion::{Criterion, black_box, criterion_group, criterion_main};
use spiceio::crypto;

fn bench_md4(c: &mut Criterion) {
    let data = vec![0u8; 64];
    c.bench_function("md4_64B", |b| b.iter(|| crypto::md4(black_box(&data))));
}

fn bench_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256");
    for size in [64, 1024, 65536] {
        let data = vec![0u8; size];
        group.bench_with_input(
            criterion::BenchmarkId::from_parameter(size),
            &data,
            |b, d| b.iter(|| crypto::sha256(black_box(d))),
        );
    }
    group.finish();
}

fn bench_sha512(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha512");
    for size in [64, 1024, 65536] {
        let data = vec![0u8; size];
        group.bench_with_input(
            criterion::BenchmarkId::from_parameter(size),
            &data,
            |b, d| b.iter(|| crypto::sha512(black_box(d))),
        );
    }
    group.finish();
}

fn bench_hmac_md5(c: &mut Criterion) {
    let key = [0u8; 16];
    let data = vec![0u8; 64];
    c.bench_function("hmac_md5_64B", |b| {
        b.iter(|| crypto::hmac_md5(black_box(&key), black_box(&data)))
    });
}

fn bench_hmac_sha256(c: &mut Criterion) {
    let key = [0u8; 32];
    let data = vec![0u8; 64];
    c.bench_function("hmac_sha256_64B", |b| {
        b.iter(|| crypto::hmac_sha256(black_box(&key), black_box(&data)))
    });
}

fn bench_aes128_cmac(c: &mut Criterion) {
    let key = [0u8; 16];
    let mut group = c.benchmark_group("aes128_cmac");
    for size in [64, 256, 1024] {
        let data = vec![0u8; size];
        group.bench_with_input(
            criterion::BenchmarkId::from_parameter(size),
            &data,
            |b, d| b.iter(|| crypto::aes128_cmac(black_box(&key), black_box(d))),
        );
    }
    group.finish();
}

fn bench_hex_encode(c: &mut Criterion) {
    let data = [0xABu8; 32];
    c.bench_function("hex_encode_32B", |b| {
        b.iter(|| crypto::hex_encode(black_box(&data)))
    });
}

criterion_group!(
    benches,
    bench_md4,
    bench_sha256,
    bench_sha512,
    bench_hmac_md5,
    bench_hmac_sha256,
    bench_aes128_cmac,
    bench_hex_encode,
);
criterion_main!(benches);
