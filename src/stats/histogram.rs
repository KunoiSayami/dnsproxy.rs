//! A fixed-size latency histogram with the bucket edges `dnsstat.py` uses,
//! so records written by this crate merge with the ones it wrote.

use std::time::Duration;

use super::json::Value;

/// Bucket upper bounds in milliseconds, identical to `EDGES_MS` in
/// `dnsstat.py`. Changing them makes records unmergeable with older ones.
pub const EDGES_MS: [f64; 33] = [
    1.0, 2.0, 3.0, 5.0, 7.0, 10.0, 15.0, 20.0, 30.0, 40.0, 50.0, 70.0, 100.0, 125.0, 150.0, 175.0,
    200.0, 250.0, 300.0, 350.0, 400.0, 450.0, 500.0, 600.0, 700.0, 800.0, 1000.0, 1250.0, 1500.0,
    2000.0, 3000.0, 5000.0, 10000.0,
];

/// One bucket per edge, plus one for anything above the last edge.
const BUCKETS: usize = EDGES_MS.len() + 1;

/// Count, sum, max, and bucket counts of latency samples. Unlike
/// `dnsstat.py`'s `Lat`, it keeps no samples, so its size is fixed however
/// many queries an interval sees; the percentiles it writes are interpolated
/// from the buckets, as `dnsstat.py summary` does when merging.
#[derive(Clone, Debug, PartialEq)]
pub struct LatencyHistogram {
    n: u64,
    sum_ms: f64,
    max_ms: f64,
    buckets: [u64; BUCKETS],
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self {
            n: 0,
            sum_ms: 0.0,
            max_ms: 0.0,
            buckets: [0; BUCKETS],
        }
    }
}

impl LatencyHistogram {
    /// Adds one sample.
    pub fn record(&mut self, latency: Duration) {
        let ms = latency.as_secs_f64() * 1000.0;
        self.n += 1;
        self.sum_ms += ms;
        self.max_ms = self.max_ms.max(ms);
        // Python's `bisect_left(EDGES_MS, ms)`: the first edge >= ms.
        self.buckets[EDGES_MS.partition_point(|&edge| edge < ms)] += 1;
    }

    /// Adds every sample of `other`.
    pub fn merge(&mut self, other: &Self) {
        self.n += other.n;
        self.sum_ms += other.sum_ms;
        self.max_ms = self.max_ms.max(other.max_ms);
        for (mine, theirs) in self.buckets.iter_mut().zip(&other.buckets) {
            *mine += theirs;
        }
    }

    /// The number of samples.
    pub fn len(&self) -> u64 {
        self.n
    }

    /// Whether no sample has been recorded.
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// The `q` quantile in milliseconds, interpolated linearly within its
    /// bucket. A port of `MLat.pct` in `dnsstat.py`.
    pub fn quantile_ms(&self, q: f64) -> Option<f64> {
        if self.n == 0 {
            return None;
        }
        let target = q * self.n as f64;
        let mut cumulative = 0.0;
        for (i, &count) in self.buckets.iter().enumerate() {
            let count = count as f64;
            if count > 0.0 && cumulative + count >= target {
                let lo = if i > 0 { EDGES_MS[i - 1] } else { 0.0 };
                let hi = EDGES_MS.get(i).copied().unwrap_or(self.max_ms);
                return Some((lo + (hi - lo) * (target - cumulative) / count).min(self.max_ms));
            }
            cumulative += count;
        }
        Some(self.max_ms)
    }

    /// The `{"n", "sum", "max", "p50", "p90", "p99", "hist"}` object
    /// `dnsstat.py` writes for a latency series.
    pub fn to_json(&self) -> Value {
        let pct = |q| self.quantile_ms(q).map_or(Value::Null, Value::Float);
        Value::object([
            ("n", Value::Int(self.n)),
            ("sum", Value::Float(self.sum_ms)),
            ("max", Value::Float(self.max_ms)),
            ("p50", pct(0.5)),
            ("p90", pct(0.9)),
            ("p99", pct(0.99)),
            (
                "hist",
                Value::Array(self.buckets.iter().map(|&c| Value::Int(c)).collect()),
            ),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_match_python_bisect_left() {
        let mut h = LatencyHistogram::default();
        // On an edge goes into that edge's bucket; just above, the next.
        h.record(Duration::from_millis(1));
        h.record(Duration::from_micros(1001));
        h.record(Duration::from_secs(10));
        h.record(Duration::from_secs(11));
        assert_eq!(h.buckets[0], 1);
        assert_eq!(h.buckets[1], 1);
        assert_eq!(h.buckets[32], 1);
        assert_eq!(h.buckets[33], 1);
        assert_eq!(h.len(), 4);
    }

    #[test]
    fn quantiles_interpolate_within_buckets() {
        let mut h = LatencyHistogram::default();
        for _ in 0..100 {
            h.record(Duration::from_millis(40)); // bucket (30, 40]
        }
        let p50 = h.quantile_ms(0.5).unwrap();
        assert!((30.0..=40.0).contains(&p50), "{p50}");
        assert_eq!(LatencyHistogram::default().quantile_ms(0.5), None);
    }

    #[test]
    fn merge_adds_everything() {
        let mut a = LatencyHistogram::default();
        a.record(Duration::from_millis(5));
        let mut b = LatencyHistogram::default();
        b.record(Duration::from_millis(500));
        a.merge(&b);
        assert_eq!(a.len(), 2);
        assert_eq!(a.max_ms, 500.0);
        assert!((a.sum_ms - 505.0).abs() < 1e-9);
    }
}
