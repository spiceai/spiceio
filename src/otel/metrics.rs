//! In-process performance metrics.
//!
//! Request-path recording takes a mutex for a few integer adds — the same
//! work the access log already does when it is on, and a single atomic load
//! when the exporter is off. Snapshotting takes the interval so a failed
//! export can merge it back rather than drop it.

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Upper bounds for `spiceio_http_duration_us` / `spiceio_http_head_duration_us`.
/// Cache hits land in the first few; NAS misses in the middle; a stalled
/// backend fills the +Inf bucket.
pub const DURATION_BOUNDS_US: &[f64] = &[
    100.0,
    250.0,
    500.0,
    1_000.0,
    2_500.0,
    5_000.0,
    10_000.0,
    25_000.0,
    50_000.0,
    100_000.0,
    250_000.0,
    500_000.0,
    1_000_000.0,
    2_500_000.0,
    5_000_000.0,
    10_000_000.0,
];

const BUCKETS: usize = DURATION_BOUNDS_US.len() + 1;

#[derive(Default)]
pub(crate) struct Hist {
    pub(crate) count: u64,
    pub(crate) sum: u64,
    pub(crate) min: u64,
    pub(crate) max: u64,
    pub(crate) buckets: [u64; BUCKETS],
}

impl Hist {
    fn observe(&mut self, v: u64) {
        self.count += 1;
        self.sum = self.sum.saturating_add(v);
        if self.count == 1 {
            self.min = v;
            self.max = v;
        } else {
            self.min = self.min.min(v);
            self.max = self.max.max(v);
        }
        let i = DURATION_BOUNDS_US
            .iter()
            .position(|&b| v as f64 <= b)
            .unwrap_or(DURATION_BOUNDS_US.len());
        self.buckets[i] += 1;
    }

    fn merge(&mut self, other: Self) {
        if other.count == 0 {
            return;
        }
        if self.count == 0 {
            *self = other;
            return;
        }
        self.count = self.count.saturating_add(other.count);
        self.sum = self.sum.saturating_add(other.sum);
        self.min = self.min.min(other.min);
        self.max = self.max.max(other.max);
        for (slot, c) in self.buckets.iter_mut().zip(other.buckets) {
            *slot = slot.saturating_add(c);
        }
    }
}

#[derive(Default)]
pub(crate) struct Series {
    pub(crate) requests: u64,
    pub(crate) req_bytes: u64,
    pub(crate) resp_bytes: u64,
    pub(crate) duration: Hist,
    pub(crate) head: Hist,
}

impl Series {
    fn merge(&mut self, other: Self) {
        self.requests = self.requests.saturating_add(other.requests);
        self.req_bytes = self.req_bytes.saturating_add(other.req_bytes);
        self.resp_bytes = self.resp_bytes.saturating_add(other.resp_bytes);
        self.duration.merge(other.duration);
        self.head.merge(other.head);
    }
}

/// One interval of request counters plus runtime gauges, ready to encode.
pub struct Snapshot {
    pub(crate) series: HashMap<(&'static str, u16), Series>,
    pub(crate) gauges: RuntimeGauges,
    pub(crate) start_unix_nano: u64,
    pub(crate) time_unix_nano: u64,
    interval_start: Instant,
}

/// Runtime gauges sampled at export time (not interval-delta).
#[derive(Default)]
pub struct RuntimeGauges {
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_hit_bytes: u64,
    pub cache_bytes: u64,
    pub cache_entries: u64,
    pub spill_hits: Option<u64>,
    pub spill_misses: Option<u64>,
    pub spill_hit_bytes: Option<u64>,
    pub writeback_pending: Option<u64>,
    pub writeback_pending_bytes: Option<u64>,
    pub writeback_accepted: Option<u64>,
    pub writeback_flushed: Option<u64>,
    pub smb_inflight: u64,
    pub uptime: Duration,
}

pub struct Registry {
    started: Instant,
    interval_start: Instant,
    by_key: HashMap<(&'static str, u16), Series>,
}

impl Registry {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            started: now,
            interval_start: now,
            by_key: HashMap::new(),
        }
    }

    pub fn record(
        &mut self,
        method: &str,
        status: u16,
        req_bytes: u64,
        resp_bytes: u64,
        head_us: u64,
        total_us: u64,
    ) {
        let method = normalize_method(method);
        let e = self.by_key.entry((method, status)).or_default();
        e.requests += 1;
        e.req_bytes = e.req_bytes.saturating_add(req_bytes);
        e.resp_bytes = e.resp_bytes.saturating_add(resp_bytes);
        e.duration.observe(total_us);
        e.head.observe(head_us);
    }

    /// Take the current interval. On a failed export, [`Registry::restore`]
    /// the returned snapshot so the next push includes it.
    pub fn snapshot(&mut self, mut gauges: RuntimeGauges) -> Snapshot {
        gauges.uptime = self.started.elapsed();
        let time = unix_nano();
        let start = time.saturating_sub(self.interval_start.elapsed().as_nanos() as u64);
        let interval_start = self.interval_start;
        self.interval_start = Instant::now();
        Snapshot {
            series: std::mem::take(&mut self.by_key),
            gauges,
            start_unix_nano: start,
            time_unix_nano: time,
            interval_start,
        }
    }

    pub fn restore(&mut self, snap: Snapshot) {
        for (key, series) in snap.series {
            self.by_key.entry(key).or_default().merge(series);
        }
        // Cover the failed window plus anything recorded since.
        self.interval_start = self.interval_start.min(snap.interval_start);
    }
}

fn normalize_method(m: &str) -> &'static str {
    match m {
        "GET" => "GET",
        "PUT" => "PUT",
        "HEAD" => "HEAD",
        "DELETE" => "DELETE",
        "POST" => "POST",
        _ => "OTHER",
    }
}

fn unix_nano() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_bucket_inclusive_upper() {
        let mut h = Hist::default();
        h.observe(100); // first bound
        h.observe(101); // next
        h.observe(10_000_001); // +Inf
        assert_eq!(h.count, 3);
        assert_eq!(h.buckets[0], 1);
        assert_eq!(h.buckets[1], 1);
        assert_eq!(h.buckets[BUCKETS - 1], 1);
    }

    #[test]
    fn snapshot_emits_labeled_sums_and_resets() {
        let mut r = Registry::new();
        r.record("GET", 200, 0, 64, 100, 150);
        r.record("GET", 200, 0, 32, 80, 90);
        r.record("PUT", 200, 10, 0, 200, 300);
        let snap = r.snapshot(RuntimeGauges {
            cache_hits: 4,
            ..RuntimeGauges::default()
        });
        let get = snap.series.get(&("GET", 200)).expect("GET/200 series");
        assert_eq!(get.requests, 2);
        assert_eq!(get.resp_bytes, 96);
        assert_eq!(get.duration.count, 2);
        assert_eq!(get.head.count, 2);
        let put = snap.series.get(&("PUT", 200)).expect("PUT/200 series");
        assert_eq!(put.requests, 1);
        assert_eq!(put.req_bytes, 10);
        assert_eq!(snap.gauges.cache_hits, 4);
        let snap2 = r.snapshot(RuntimeGauges::default());
        assert!(snap2.series.is_empty());
    }

    #[test]
    fn restore_replays_a_failed_interval() {
        let mut r = Registry::new();
        r.record("GET", 200, 0, 1, 10, 20);
        let snap = r.snapshot(RuntimeGauges::default());
        r.restore(snap);
        r.record("GET", 200, 0, 1, 10, 20);
        let snap = r.snapshot(RuntimeGauges::default());
        let get = snap.series.get(&("GET", 200)).expect("GET/200 series");
        assert_eq!(get.requests, 2);
        assert_eq!(get.resp_bytes, 2);
        assert_eq!(get.duration.count, 2);
        assert_eq!(get.duration.sum, 40);
        assert_eq!(get.head.count, 2);
        assert_eq!(get.head.sum, 20);
        // Histograms share the (method, status) key; a lossy restore that
        // keyed them on method alone would leave a leftover status-0 series.
        assert!(!snap.series.contains_key(&("GET", 0)));
    }
}
