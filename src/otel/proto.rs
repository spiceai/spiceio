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
        let req_attrs = [("method", method), ("status", status_s.as_str())];
        let method_attrs = [("method", method)];
        self.sum(
            e,
            "spiceio_http_requests",
            "S3 requests completed in the interval",
            "1",
            s.requests,
            &req_attrs,
        );
        if s.req_bytes > 0 {
            self.sum(
                e,
                "spiceio_http_request_bytes",
                "Request body bytes declared on completed requests",
                "By",
                s.req_bytes,
                &method_attrs,
            );
        }
        if s.resp_bytes > 0 {
            self.sum(
                e,
                "spiceio_http_response_bytes",
                "Response body bytes streamed to the client",
                "By",
                s.resp_bytes,
                &method_attrs,
            );
        }
        self.histogram(
            e,
            "spiceio_http_duration_us",
            "End-to-end request time, microseconds",
            &s.duration,
            &method_attrs,
        );
        self.histogram(
            e,
            "spiceio_http_head_duration_us",
            "Time to response head, microseconds",
            &s.head,
            &method_attrs,
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
        ] {
            assert!(
                text.contains(needle),
                "encoded payload missing {needle:?}: {text:?}"
            );
        }
    }
}
