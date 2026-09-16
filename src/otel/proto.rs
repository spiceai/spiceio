//! Hand-rolled OTLP protobuf encoder for `ExportMetricsServiceRequest`.
//!
//! Spice Cloud apps ingest OTLP/gRPC (`MetricsService/Export`). The subset we
//! emit — resource attributes, gauges, monotonic delta sums, explicit
//! histograms — is small enough to encode without `prost`/`tonic`, which would
//! dominate this crate's dependency tree.

use super::metrics::{DURATION_BOUNDS_US, Hist, RuntimeGauges, Series, Snapshot};

const WIRE_VARINT: u32 = 0;
const WIRE_FIXED64: u32 = 1;
const WIRE_LEN: u32 = 2;

/// OTLP `AggregationTemporality.DELTA`.
const TEMPORALITY_DELTA: u64 = 1;

/// gRPC service path Spice Cloud (and OSS) register for OTEL ingest.
pub const GRPC_PATH: &str = "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export";

pub struct Resource {
    pub service_name: String,
    pub service_version: String,
    pub instance_id: String,
    /// Hostname of the machine running this process. Becomes a dimension
    /// column on every ingested metric (`machine`).
    pub machine: String,
    pub share: String,
}

struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(1024),
        }
    }

    fn tag(&mut self, field: u32, wire: u32) {
        self.varint(u64::from((field << 3) | wire));
    }

    fn varint(&mut self, mut v: u64) {
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            self.buf.push(b);
            if v == 0 {
                break;
            }
        }
    }

    fn bytes(&mut self, field: u32, data: &[u8]) {
        self.tag(field, WIRE_LEN);
        self.varint(data.len() as u64);
        self.buf.extend_from_slice(data);
    }

    fn string(&mut self, field: u32, s: &str) {
        self.bytes(field, s.as_bytes());
    }

    fn message(&mut self, field: u32, build: impl FnOnce(&mut Encoder)) {
        let mut inner = Encoder::new();
        build(&mut inner);
        self.bytes(field, &inner.buf);
    }

    fn uint64(&mut self, field: u32, v: u64) {
        self.tag(field, WIRE_VARINT);
        self.varint(v);
    }

    fn bool(&mut self, field: u32, v: bool) {
        self.uint64(field, u64::from(v));
    }

    fn fixed64(&mut self, field: u32, v: u64) {
        self.tag(field, WIRE_FIXED64);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn sfixed64(&mut self, field: u32, v: i64) {
        self.fixed64(field, v as u64);
    }

    fn double(&mut self, field: u32, v: f64) {
        self.fixed64(field, v.to_bits());
    }

    /// Packed repeated `fixed64` (proto3 default packing for that type).
    ///
    /// `HistogramDataPoint.bucket_counts` is `fixed64` in the OTLP that Spice
    /// Cloud / the OSS runtime decode (`opentelemetry-proto` 0.32,
    /// `#[prost(fixed64, repeated, tag = "6")]`). Packed varints are rejected
    /// with `invalid wire type: Varint (expected SixtyFourBit)`.
    fn packed_fixed64(&mut self, field: u32, values: &[u64]) {
        if values.is_empty() {
            return;
        }
        self.tag(field, WIRE_LEN);
        self.varint((values.len() * 8) as u64);
        for v in values {
            self.buf.extend_from_slice(&v.to_le_bytes());
        }
    }

    fn packed_double(&mut self, field: u32, values: &[f64]) {
        if values.is_empty() {
            return;
        }
        self.tag(field, WIRE_LEN);
        self.varint((values.len() * 8) as u64);
        for v in values {
            self.buf.extend_from_slice(&v.to_le_bytes());
        }
    }

    fn kv_string(&mut self, field: u32, key: &str, value: &str) {
        self.message(field, |e| {
            e.string(1, key);
            // AnyValue.string_value = 1
            e.message(2, |e| e.string(1, value));
        });
    }
}

/// Identity is repeated on the data point. Spice Cloud merges resource
/// attributes into columns, but putting them on the point too means a
/// consumer that ignores Resource still gets `machine` and instance id.
fn point_attrs(e: &mut Encoder, field: u32, resource: &Resource, extra: &[(&str, &str)]) {
    e.kv_string(field, "machine", &resource.machine);
    e.kv_string(field, "service.instance.id", &resource.instance_id);
    for &(k, v) in extra {
        e.kv_string(field, k, v);
    }
}

struct Emit<'a> {
    resource: &'a Resource,
    start: u64,
    time: u64,
}

impl Emit<'_> {
    fn instrument(
        &self,
        e: &mut Encoder,
        name: &str,
        description: &str,
        unit: &str,
        data_field: u32,
        build: impl FnOnce(&mut Encoder),
    ) {
        e.message(2, |e| {
            e.string(1, name);
            if !description.is_empty() {
                e.string(2, description);
            }
            if !unit.is_empty() {
                e.string(3, unit);
            }
            e.message(data_field, build);
        });
    }

    fn number_point(&self, e: &mut Encoder, extra: &[(&str, &str)], value: u64) {
        e.message(1, |e| {
            e.fixed64(2, self.start);
            e.fixed64(3, self.time);
            e.sfixed64(6, value as i64);
            point_attrs(e, 7, self.resource, extra);
        });
    }

    fn gauge(&self, e: &mut Encoder, name: &str, description: &str, unit: &str, value: u64) {
        self.instrument(e, name, description, unit, 5, |e| {
            self.number_point(e, &[], value);
        });
    }

    fn opt_gauge(
        &self,
        e: &mut Encoder,
        name: &str,
        description: &str,
        unit: &str,
        value: Option<u64>,
    ) {
        if let Some(v) = value {
            self.gauge(e, name, description, unit, v);
        }
    }

    fn sum(
        &self,
        e: &mut Encoder,
        name: &str,
        description: &str,
        unit: &str,
        value: u64,
        attrs: &[(&str, &str)],
    ) {
        self.instrument(e, name, description, unit, 7, |e| {
            self.number_point(e, attrs, value);
            e.uint64(2, TEMPORALITY_DELTA);
            e.bool(3, true);
        });
    }

    fn histogram(
        &self,
        e: &mut Encoder,
        name: &str,
        description: &str,
        h: &Hist,
        attrs: &[(&str, &str)],
    ) {
        if h.count == 0 {
            return;
        }
        self.instrument(e, name, description, "us", 9, |e| {
            e.message(1, |e| {
                e.fixed64(2, self.start);
                e.fixed64(3, self.time);
                // HistogramDataPoint.count / bucket_counts are protobuf
                // `fixed64` in the OTLP the Spice runtime ingests
                // (`opentelemetry-proto` 0.32). Encoding them as uint64
                // varints is what Cloud rejected as
                // `invalid wire type: Varint (expected SixtyFourBit)`.
                e.fixed64(4, h.count);
                e.double(5, h.sum as f64);
                e.packed_fixed64(6, &h.buckets);
                e.packed_double(7, DURATION_BOUNDS_US);
                point_attrs(e, 9, self.resource, attrs);
                e.double(11, h.min as f64);
                e.double(12, h.max as f64);
            });
            e.uint64(2, TEMPORALITY_DELTA);
        });
    }

    fn series(&self, e: &mut Encoder, method: &str, status: u16, s: &Series) {
        if s.requests == 0 {
            return;
        }
        let status_s = status.to_string();
        let attrs = [("method", method), ("status", status_s.as_str())];
        self.sum(
            e,
            "spiceio_http_requests",
            "S3 requests completed in the interval",
            "1",
            s.requests,
            &attrs,
        );
        if s.req_bytes > 0 {
            self.sum(
                e,
                "spiceio_http_request_bytes",
                "Request body bytes declared on completed requests",
                "By",
                s.req_bytes,
                &attrs,
            );
        }
        if s.resp_bytes > 0 {
            self.sum(
                e,
                "spiceio_http_response_bytes",
                "Response body bytes streamed to the client",
                "By",
                s.resp_bytes,
                &attrs,
            );
        }
        self.histogram(
            e,
            "spiceio_http_duration_us",
            "End-to-end request time, microseconds",
            &s.duration,
            &attrs,
        );
        self.histogram(
            e,
            "spiceio_http_head_duration_us",
            "Time to response head, microseconds",
            &s.head,
            &attrs,
        );
    }

    fn gauges(&self, e: &mut Encoder, g: &RuntimeGauges) {
        self.gauge(
            e,
            "spiceio_uptime_seconds",
            "Process uptime",
            "s",
            g.uptime.as_secs(),
        );
        self.gauge(
            e,
            "spiceio_cache_hits",
            "In-memory object-cache hits (cumulative)",
            "1",
            g.cache_hits,
        );
        self.gauge(
            e,
            "spiceio_cache_misses",
            "In-memory object-cache misses (cumulative)",
            "1",
            g.cache_misses,
        );
        self.gauge(
            e,
            "spiceio_cache_hit_bytes",
            "Bytes served from the in-memory cache (cumulative)",
            "By",
            g.cache_hit_bytes,
        );
        self.gauge(
            e,
            "spiceio_cache_bytes",
            "Bytes currently resident in the in-memory cache",
            "By",
            g.cache_bytes,
        );
        self.gauge(
            e,
            "spiceio_cache_entries",
            "Entries currently in the in-memory cache",
            "1",
            g.cache_entries,
        );
        self.gauge(
            e,
            "spiceio_smb_inflight",
            "Client requests currently holding an SMB admission slot",
            "1",
            g.smb_inflight,
        );
        self.opt_gauge(
            e,
            "spiceio_spill_hits",
            "Disk-spill hits (cumulative)",
            "1",
            g.spill_hits,
        );
        self.opt_gauge(
            e,
            "spiceio_spill_misses",
            "Disk-spill misses (cumulative)",
            "1",
            g.spill_misses,
        );
        self.opt_gauge(
            e,
            "spiceio_spill_hit_bytes",
            "Bytes served from the disk spill (cumulative)",
            "By",
            g.spill_hit_bytes,
        );
        self.opt_gauge(
            e,
            "spiceio_writeback_pending",
            "Acknowledged writes not yet on the NAS",
            "1",
            g.writeback_pending,
        );
        self.opt_gauge(
            e,
            "spiceio_writeback_pending_bytes",
            "Bytes of acknowledged writes not yet on the NAS",
            "By",
            g.writeback_pending_bytes,
        );
        self.opt_gauge(
            e,
            "spiceio_writeback_accepted",
            "Writes acknowledged from memory (cumulative)",
            "1",
            g.writeback_accepted,
        );
        self.opt_gauge(
            e,
            "spiceio_writeback_flushed",
            "Write-back flushes that reached the NAS (cumulative)",
            "1",
            g.writeback_flushed,
        );
        self.gauge(
            e,
            "spiceio_existence_absents",
            "GET/HEAD 404s answered from the directory existence index (cumulative)",
            "1",
            g.existence_absents,
        );
        self.gauge(
            e,
            "spiceio_existence_lists",
            "Directory listings performed to fill the existence index (cumulative)",
            "1",
            g.existence_lists,
        );
    }
}

/// Encode an `ExportMetricsServiceRequest` (field 1 = repeated ResourceMetrics).
pub fn encode(resource: &Resource, snap: &Snapshot) -> Vec<u8> {
    let emit = Emit {
        resource,
        start: snap.start_unix_nano,
        time: snap.time_unix_nano,
    };
    let mut e = Encoder::new();
    e.message(1, |e| {
        // ResourceMetrics.resource = 1
        e.message(1, |e| {
            // Resource.attributes = 1
            e.kv_string(1, "service.name", &resource.service_name);
            e.kv_string(1, "service.version", &resource.service_version);
            e.kv_string(1, "service.instance.id", &resource.instance_id);
            e.kv_string(1, "machine", &resource.machine);
            e.kv_string(1, "spiceio.share", &resource.share);
        });
        // ResourceMetrics.scope_metrics = 2
        e.message(2, |e| {
            // ScopeMetrics.scope = 1
            e.message(1, |e| {
                e.string(1, "spiceio");
                e.string(2, env!("CARGO_PKG_VERSION"));
            });
            for ((method, status), s) in &snap.series {
                emit.series(e, method, *status, s);
            }
            emit.gauges(e, &snap.gauges);
        });
    });
    e.buf
}

/// Wrap a protobuf message in a gRPC data frame (no compression).
pub fn grpc_frame(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + msg.len());
    out.push(0);
    out.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    out.extend_from_slice(msg);
    out
}

/// Strip the 5-byte gRPC frame prefix. Tests and the mock server use this.
#[cfg(test)]
pub fn unframe(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 5 {
        return None;
    }
    let len = u32::from_be_bytes(frame[1..5].try_into().ok()?) as usize;
    let rest = &frame[5..];
    (rest.len() >= len).then_some(&rest[..len])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otel::metrics::{Registry, RuntimeGauges};

    fn resource() -> Resource {
        Resource {
            service_name: "spiceio".into(),
            service_version: "0.0.0".into(),
            instance_id: "inst-1".into(),
            machine: "mac.example".into(),
            share: "files".into(),
        }
    }

    #[test]
    fn frame_round_trip() {
        let msg = b"hello";
        let frame = grpc_frame(msg);
        assert_eq!(frame[0], 0);
        assert_eq!(&frame[1..5], &5u32.to_be_bytes());
        assert_eq!(unframe(&frame), Some(msg.as_slice()));
    }

    #[test]
    fn payload_carries_metric_name_machine_and_instance() {
        let mut r = Registry::new();
        r.record("GET", 200, 0, 64, 1500, 1500);
        r.record("GET", 404, 0, 0, 80, 80);
        let snap = r.snapshot(RuntimeGauges::default());
        let bytes = encode(&resource(), &snap);
        let text = String::from_utf8_lossy(&bytes);
        for needle in [
            "spiceio_uptime_seconds",
            "spiceio_http_requests",
            "spiceio_http_duration_us",
            "machine",
            "mac.example",
            "service.instance.id",
            "inst-1",
            "spiceio.share",
            "files",
            "404",
        ] {
            assert!(
                text.contains(needle),
                "encoded payload missing {needle:?}: {text:?}"
            );
        }
    }

    #[test]
    fn histogram_count_and_buckets_are_fixed64() {
        let mut r = Registry::new();
        r.record("GET", 200, 0, 64, 1500, 1500);
        r.record("GET", 200, 0, 32, 80, 90);
        let bytes = encode(&resource(), &r.snapshot(RuntimeGauges::default()));
        let metric = named_metric(&bytes, "spiceio_http_duration_us").expect("duration histogram");
        let point = histogram_points(metric)
            .into_iter()
            .next()
            .expect("data point");
        let count = fixed64_field(point, 4).expect("count as fixed64, not uint64 varint");
        assert_eq!(count, 2);
        let packed = len_field(point, 6).expect("bucket_counts packed");
        assert_eq!(
            packed.len(),
            (DURATION_BOUNDS_US.len() + 1) * 8,
            "bucket_counts must be packed fixed64 (n*8 bytes), not packed varints"
        );
        let buckets = packed_fixed64s(packed).expect("packed fixed64 buckets");
        assert_eq!(buckets.len(), DURATION_BOUNDS_US.len() + 1);
        assert_eq!(buckets.iter().sum::<u64>(), count);
    }

    #[test]
    fn http_series_points_include_status_and_are_unique() {
        let mut r = Registry::new();
        r.record("GET", 200, 0, 64, 100, 150);
        r.record("GET", 404, 0, 16, 80, 90);
        r.record("PUT", 200, 10, 0, 200, 300);
        let bytes = encode(&resource(), &r.snapshot(RuntimeGauges::default()));
        let mut seen = std::collections::HashSet::new();
        let mut http_with_status = 0;
        for metric in metrics(&bytes) {
            let name = string_field(metric, 1).unwrap_or("");
            for point in data_points(metric) {
                let attrs = kv_strings(point, if is_histogram(metric) { 9 } else { 7 });
                if name.starts_with("spiceio_http_") {
                    assert!(
                        attrs.iter().any(|(k, _)| k == "status"),
                        "{name} data point missing status: {attrs:?}"
                    );
                    http_with_status += 1;
                }
                let mut parts: Vec<String> =
                    attrs.iter().map(|(k, v)| format!("{k}={v}")).collect();
                parts.sort();
                let id = format!("{name}|{}", parts.join(","));
                assert!(seen.insert(id.clone()), "duplicate OTLP identity {id}");
            }
        }
        assert!(
            http_with_status >= 6,
            "expected status-labeled GET/200, GET/404, PUT/200 points, got {http_with_status}"
        );
    }

    fn read_varint(buf: &[u8], i: &mut usize) -> Option<u64> {
        let mut v = 0u64;
        let mut shift = 0;
        while *i < buf.len() {
            let b = buf[*i];
            *i += 1;
            v |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Some(v);
            }
            shift += 7;
            if shift >= 64 {
                return None;
            }
        }
        None
    }

    fn fields(buf: &[u8]) -> Vec<(u32, u32, &[u8], Option<u64>)> {
        let mut i = 0;
        let mut out = Vec::new();
        while i < buf.len() {
            let Some(tag) = read_varint(buf, &mut i) else {
                break;
            };
            let num = (tag >> 3) as u32;
            let wire = (tag & 7) as u32;
            match wire {
                WIRE_VARINT => {
                    let start = i;
                    let Some(v) = read_varint(buf, &mut i) else {
                        break;
                    };
                    out.push((num, wire, &buf[start..i], Some(v)));
                }
                WIRE_FIXED64 => {
                    if i + 8 > buf.len() {
                        break;
                    }
                    let start = i;
                    i += 8;
                    out.push((num, wire, &buf[start..i], None));
                }
                WIRE_LEN => {
                    let Some(len) = read_varint(buf, &mut i) else {
                        break;
                    };
                    let len = len as usize;
                    if i + len > buf.len() {
                        break;
                    }
                    let start = i;
                    i += len;
                    out.push((num, wire, &buf[start..i], None));
                }
                5 => {
                    if i + 4 > buf.len() {
                        break;
                    }
                    i += 4;
                }
                _ => break,
            }
        }
        out
    }

    fn messages(buf: &[u8], field: u32) -> Vec<&[u8]> {
        fields(buf)
            .into_iter()
            .filter(|(n, w, _, _)| *n == field && *w == WIRE_LEN)
            .map(|(_, _, bytes, _)| bytes)
            .collect()
    }

    fn metrics(buf: &[u8]) -> Vec<&[u8]> {
        let Some(rm) = messages(buf, 1).into_iter().next() else {
            return Vec::new();
        };
        let Some(sm) = messages(rm, 2).into_iter().next() else {
            return Vec::new();
        };
        messages(sm, 2)
    }

    fn named_metric<'a>(buf: &'a [u8], name: &str) -> Option<&'a [u8]> {
        metrics(buf)
            .into_iter()
            .find(|m| string_field(m, 1) == Some(name))
    }

    fn string_field(buf: &[u8], field: u32) -> Option<&str> {
        fields(buf).into_iter().find_map(|(n, w, bytes, _)| {
            (n == field && w == WIRE_LEN)
                .then(|| std::str::from_utf8(bytes).ok())
                .flatten()
        })
    }

    fn fixed64_field(buf: &[u8], field: u32) -> Option<u64> {
        fields(buf)
            .into_iter()
            .find_map(|(n, w, bytes, _)| (n == field && w == WIRE_FIXED64).then_some(bytes))
            .and_then(|bytes| Some(u64::from_le_bytes(bytes.try_into().ok()?)))
    }

    fn packed_fixed64s(buf: &[u8]) -> Option<Vec<u64>> {
        if !buf.len().is_multiple_of(8) {
            return None;
        }
        Some(
            buf.as_chunks::<8>()
                .0
                .iter()
                .map(|c| u64::from_le_bytes(*c))
                .collect(),
        )
    }

    fn len_field(buf: &[u8], field: u32) -> Option<&[u8]> {
        fields(buf)
            .into_iter()
            .find_map(|(n, w, bytes, _)| (n == field && w == WIRE_LEN).then_some(bytes))
    }

    fn is_histogram(metric: &[u8]) -> bool {
        !messages(metric, 9).is_empty()
    }

    fn histogram_points(metric: &[u8]) -> Vec<&[u8]> {
        messages(metric, 9)
            .into_iter()
            .flat_map(|h| messages(h, 1))
            .collect()
    }

    fn data_points(metric: &[u8]) -> Vec<&[u8]> {
        let hist = histogram_points(metric);
        if !hist.is_empty() {
            return hist;
        }
        messages(metric, 7)
            .into_iter()
            .chain(messages(metric, 5))
            .flat_map(|d| messages(d, 1))
            .collect()
    }

    fn kv_strings(buf: &[u8], field: u32) -> Vec<(String, String)> {
        messages(buf, field)
            .into_iter()
            .filter_map(|kv| {
                let key = string_field(kv, 1)?.to_string();
                let value_msg = messages(kv, 2).into_iter().next()?;
                let value = string_field(value_msg, 1)?.to_string();
                Some((key, value))
            })
            .collect()
    }
}
