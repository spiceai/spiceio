use criterion::{Criterion, black_box, criterion_group, criterion_main};
use spiceio::s3::headers::{RangeSpec, parse_http_date, parse_range};
use spiceio::s3::xml::{
    XmlWriter, epoch_to_http_date, epoch_to_iso8601, extract_element, extract_sections,
};

// ── XML builder ──────────────────────────────────────────────────────────

fn bench_xml_writer_list_response(c: &mut Criterion) {
    // Simulate building a ListObjectsV2 response with 100 objects
    c.bench_function("xml_list_100_objects", |b| {
        b.iter(|| {
            let mut w = XmlWriter::new();
            w.declaration();
            w.open_ns(
                "ListBucketResult",
                "http://s3.amazonaws.com/doc/2006-03-01/",
            );
            w.element("Name", "mybucket");
            w.element("Prefix", "sccache/us-east-1/");
            w.element("KeyCount", "100");
            w.element("MaxKeys", "1000");
            w.element("IsTruncated", "false");
            for i in 0..100 {
                w.open("Contents");
                w.element("Key", &format!("sccache/us-east-1/cache/{i:016x}.bin"));
                w.element("LastModified", "2024-01-15T12:30:45.000Z");
                w.element("ETag", &format!("\"{i:016x}\""));
                w.element("Size", "32768");
                w.element("StorageClass", "STANDARD");
                w.close("Contents");
            }
            w.close("ListBucketResult");
            black_box(w.finish())
        })
    });
}

fn bench_xml_escape_heavy(c: &mut Criterion) {
    let nasty = "a&b<c>d\"e'f&g<h>i\"j'k";
    c.bench_function("xml_element_escape_heavy", |b| {
        b.iter(|| {
            let mut w = XmlWriter::new();
            w.element("Key", black_box(nasty));
            w.finish()
        })
    });
}

fn bench_extract_element(c: &mut Criterion) {
    let xml = "<Root><Key>my/very/long/path/to/some/object.bin</Key><Other>x</Other></Root>";
    c.bench_function("extract_element", |b| {
        b.iter(|| extract_element(black_box(xml), "Key"))
    });
}

fn bench_extract_sections_delete(c: &mut Criterion) {
    // Simulate a multi-delete request with 50 keys
    let mut xml = String::from("<Delete><Quiet>true</Quiet>");
    for i in 0..50 {
        xml.push_str(&format!(
            "<Object><Key>prefix/file_{i:04}.txt</Key></Object>"
        ));
    }
    xml.push_str("</Delete>");

    c.bench_function("extract_sections_50_keys", |b| {
        b.iter(|| extract_sections(black_box(&xml), "<Key>", "</Key>"))
    });
}

// ── Date formatting / parsing ────────────────────────────────────────────

fn bench_epoch_to_iso8601(c: &mut Criterion) {
    c.bench_function("epoch_to_iso8601", |b| {
        b.iter(|| epoch_to_iso8601(black_box(1705321845)))
    });
}

fn bench_epoch_to_http_date(c: &mut Criterion) {
    c.bench_function("epoch_to_http_date", |b| {
        b.iter(|| epoch_to_http_date(black_box(1705321845)))
    });
}

fn bench_parse_http_date_rfc7231(c: &mut Criterion) {
    c.bench_function("parse_http_date_rfc7231", |b| {
        b.iter(|| parse_http_date(black_box("Mon, 15 Jan 2024 12:30:45 GMT")))
    });
}

fn bench_parse_http_date_iso8601(c: &mut Criterion) {
    c.bench_function("parse_http_date_iso8601", |b| {
        b.iter(|| parse_http_date(black_box("2024-01-15T12:30:45.000Z")))
    });
}

// ── Range parsing ────────────────────────────────────────────────────────

fn bench_parse_range(c: &mut Criterion) {
    c.bench_function("parse_range", |b| {
        b.iter(|| parse_range(black_box("bytes=0-65535")))
    });
}

fn bench_range_resolve(c: &mut Criterion) {
    let spec = RangeSpec {
        start: Some(1024),
        end: Some(65535),
    };
    c.bench_function("range_resolve", |b| {
        b.iter(|| black_box(&spec).resolve(black_box(1048576)))
    });
}

criterion_group!(
    benches,
    bench_xml_writer_list_response,
    bench_xml_escape_heavy,
    bench_extract_element,
    bench_extract_sections_delete,
    bench_epoch_to_iso8601,
    bench_epoch_to_http_date,
    bench_parse_http_date_rfc7231,
    bench_parse_http_date_iso8601,
    bench_parse_range,
    bench_range_resolve,
);
criterion_main!(benches);
