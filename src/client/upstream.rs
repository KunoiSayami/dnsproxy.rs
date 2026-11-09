//! An upstream DNS server reachable over DoH/DoH3, DoT, DoQ, or plain
//! DNS-over-UDP/TCP, unifying [`DohUpstream`], [`DotUpstream`],
//! [`DoqUpstream`], [`PlainUdpUpstream`], and [`PlainTcpUpstream`] behind one
//! type so [`crate::client::upstream_config::UpstreamConfig`] can mix all of them.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "stats")]
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use hickory_proto::op::Message;

#[cfg(feature = "dnscrypt")]
use crate::client::dnscrypt::DnsCryptUpstream;
use crate::client::doh::DohUpstream;
#[cfg(feature = "doq")]
use crate::client::doq::DoqUpstream;
#[cfg(feature = "dot")]
use crate::client::dot::DotUpstream;
use crate::client::plain_tcp::PlainTcpUpstream;
use crate::client::plain_udp::PlainUdpUpstream;
use crate::error::DohError;
#[cfg(feature = "stats")]
use crate::stats::UpstreamCounters;
#[cfg(feature = "stats")]
use crate::stats::label::{error_kind, upstream_label};

/// A configured upstream DNS server, over DoH/DoH3, DoT, DoQ, DNSCrypt,
/// plain UDP, or plain TCP.
pub enum Upstream {
    Doh(Arc<DohUpstream>),
    #[cfg(feature = "dot")]
    Dot(Arc<DotUpstream>),
    #[cfg(feature = "doq")]
    Doq(Arc<DoqUpstream>),
    #[cfg(feature = "dnscrypt")]
    DnsCrypt(Arc<DnsCryptUpstream>),
    PlainUdp(Arc<PlainUdpUpstream>),
    PlainTcp(Arc<PlainTcpUpstream>),
}

impl Upstream {
    pub fn address(&self) -> &str {
        match self {
            Upstream::Doh(u) => u.address(),
            #[cfg(feature = "dot")]
            Upstream::Dot(u) => u.address(),
            #[cfg(feature = "doq")]
            Upstream::Doq(u) => u.address(),
            #[cfg(feature = "dnscrypt")]
            Upstream::DnsCrypt(u) => u.address(),
            Upstream::PlainUdp(u) => u.address(),
            Upstream::PlainTcp(u) => u.address(),
        }
    }

    /// The transport this upstream uses, for stats: `"udp"` (plain UDP,
    /// DoQ, DoH over HTTP/3, DNSCrypt) or `"tcp"` (plain TCP, DoT, DoH over
    /// HTTP/2 or 1.1).
    pub fn transport(&self) -> &'static str {
        match self {
            Upstream::Doh(u) => u.transport(),
            #[cfg(feature = "dot")]
            Upstream::Dot(_) => "tcp",
            #[cfg(feature = "doq")]
            Upstream::Doq(_) => "udp",
            #[cfg(feature = "dnscrypt")]
            Upstream::DnsCrypt(_) => "udp",
            Upstream::PlainUdp(_) => "udp",
            Upstream::PlainTcp(_) => "tcp",
        }
    }

    pub async fn exchange(&self, req: &Message) -> Result<Message, DohError> {
        match self {
            Upstream::Doh(u) => u.exchange(req).await,
            #[cfg(feature = "dot")]
            Upstream::Dot(u) => u.exchange(req).await,
            #[cfg(feature = "doq")]
            Upstream::Doq(u) => u.exchange(req).await,
            #[cfg(feature = "dnscrypt")]
            Upstream::DnsCrypt(u) => u.exchange(req).await,
            Upstream::PlainUdp(u) => u.exchange(req).await,
            Upstream::PlainTcp(u) => u.exchange(req).await,
        }
    }
}

/// Tracks a rolling average exchange latency for one upstream, used by
/// [`crate::client::upstream_config::UpstreamMode::LoadBalance`] to weight
/// upstreams by how fast they've recently answered.
///
/// Go dnsproxy (`proxy/exchange.go`'s `upstreamRTTStats`) keeps a lifetime
/// mean instead. This uses an exponential moving average on purpose: with a
/// lifetime mean, a long-running proxy barely moves a dead upstream's
/// average (after a million 50 ms samples, each 10 s failure penalty adds
/// about 10 µs), so it keeps being tried first and every query waits out the
/// timeout. The EMA sinks it after one failure and lets it recover after a
/// handful of successes.
///
/// It also keeps, from successful exchanges only, a smoothed latency and its
/// mean deviation, as TCP does for its retransmit timeout (RFC 6298). Load
/// balance uses these to decide when an answer is overdue and the next
/// upstream should be started; see [`Self::overdue_after`].
///
/// One tracker is shared per distinct upstream (matching the `Arc<Upstream>`
/// interning done during parsing), so the same server ages a single average
/// no matter how many domain rules reference it.
#[derive(Default)]
pub struct LatencyTracker {
    /// Exponential moving average latency in microseconds, failures counted
    /// as [`FAILURE_PENALTY`], or `u64::MAX` while no exchange has completed
    /// yet.
    avg_micros: AtomicU64,
    /// RFC 6298's SRTT (high 32 bits) and RTTVAR (low 32 bits) over
    /// successful exchanges, in microseconds, or `u64::MAX` while none has
    /// succeeded. Packed so the pair always updates together.
    spread: AtomicU64,
}

/// Weight given to the newest sample in the exponential moving average.
const EMA_ALPHA: f64 = 0.3;

/// RFC 6298's weights for the newest sample in SRTT and RTTVAR.
const SRTT_ALPHA: f64 = 1.0 / 8.0;
const RTTVAR_BETA: f64 = 1.0 / 4.0;

/// RFC 6298's K: an answer is overdue after SRTT + K × RTTVAR.
const RTTVAR_K: u32 = 4;

/// Largest sample [`LatencyTracker::spread`] holds, in microseconds (about
/// 71 minutes); one less than `u32::MAX` so a packed pair can never equal
/// the `u64::MAX` "no sample" marker.
const SPREAD_MAX_MICROS: u64 = u32::MAX as u64 - 1;

/// Latency recorded for a failed exchange, however long it actually took,
/// so a failing upstream sinks in load-balance mode instead of keeping its
/// good average. Go records a fixed value too
/// (`updateRTT(u.Address(), defaultTimeout)`), but 10 s; half that lets a
/// briefly failing upstream recover in about half the queries, while one
/// failure still cuts a fast upstream's share to a few percent.
pub const FAILURE_PENALTY: Duration = Duration::from_secs(5);

impl LatencyTracker {
    pub fn new() -> Self {
        Self {
            avg_micros: AtomicU64::new(u64::MAX),
            spread: AtomicU64::new(u64::MAX),
        }
    }

    /// Records how long a successful exchange with this upstream took.
    pub fn record(&self, elapsed: Duration) {
        self.record_average(elapsed);
        self.record_spread(elapsed);
    }

    /// Records a failed exchange as [`FAILURE_PENALTY`] in the average only.
    /// Folding the penalty into the deviation too would make one failure
    /// hold [`Self::overdue_after`] near the penalty for dozens of queries.
    pub fn record_failure(&self) {
        self.record_average(FAILURE_PENALTY);
    }

    fn record_average(&self, elapsed: Duration) {
        let sample = elapsed.as_micros().min(u64::MAX as u128) as u64;
        self.avg_micros
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |prev| {
                Some(if prev == u64::MAX {
                    sample
                } else {
                    let prev = prev as f64;
                    let sample = sample as f64;
                    (EMA_ALPHA * sample + (1.0 - EMA_ALPHA) * prev).round() as u64
                })
            })
            .ok();
    }

    fn record_spread(&self, elapsed: Duration) {
        let sample = elapsed.as_micros().min(u128::from(SPREAD_MAX_MICROS)) as f64;
        self.spread
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |prev| {
                let (srtt, rttvar) = match unpack_spread(prev) {
                    None => (sample, sample / 2.0),
                    Some((srtt, rttvar)) => (
                        (1.0 - SRTT_ALPHA) * srtt + SRTT_ALPHA * sample,
                        (1.0 - RTTVAR_BETA) * rttvar + RTTVAR_BETA * (srtt - sample).abs(),
                    ),
                };
                Some((srtt.round() as u64) << 32 | rttvar.round() as u64)
            })
            .ok();
    }

    /// The current average latency, or `None` if no exchange has completed
    /// yet (i.e. this upstream is untested).
    pub fn average(&self) -> Option<Duration> {
        match self.avg_micros.load(Ordering::Relaxed) {
            u64::MAX => None,
            micros => Some(Duration::from_micros(micros)),
        }
    }

    /// How long after sending a query its answer is overdue: SRTT + 4 ×
    /// RTTVAR over successful exchanges, RFC 6298's retransmit timeout
    /// without its 1 s floor. A steady upstream is overdue soon after its
    /// usual time, a noisy one gets more slack, and failures don't count.
    /// `None` until an exchange has succeeded.
    pub fn overdue_after(&self) -> Option<Duration> {
        unpack_spread(self.spread.load(Ordering::Relaxed)).map(|(srtt, rttvar)| {
            Duration::from_micros((srtt + f64::from(RTTVAR_K) * rttvar).round() as u64)
        })
    }
}

/// Splits [`LatencyTracker::spread`] into SRTT and RTTVAR, in microseconds.
fn unpack_spread(packed: u64) -> Option<(f64, f64)> {
    (packed != u64::MAX).then(|| ((packed >> 32) as f64, (packed & u64::from(u32::MAX)) as f64))
}

/// An [`Upstream`] paired with the latency history used to rank it in
/// [`crate::client::upstream_config::UpstreamMode::LoadBalance`].
pub struct TrackedUpstream {
    upstream: Arc<Upstream>,
    latency: LatencyTracker,
    /// The stats label, as `dnsstat.py` writes it; see
    /// `crate::stats::label::upstream_label`.
    #[cfg(feature = "stats")]
    label: Arc<str>,
    /// Exchange counters since the stats were last taken.
    #[cfg(feature = "stats")]
    counters: Mutex<UpstreamCounters>,
}

impl TrackedUpstream {
    /// Wraps `upstream`. With the `stats` feature, it's labelled from its
    /// (redacted) address; prefer `with_label` with the configured address
    /// string, which keeps an `h3://` scheme that the address normalizes
    /// away.
    #[cfg(feature = "stats")]
    pub fn new(upstream: Arc<Upstream>) -> Self {
        let label = upstream_label(upstream.address());
        Self::with_label(upstream, label)
    }

    /// Wraps `upstream`.
    #[cfg(not(feature = "stats"))]
    pub fn new(upstream: Arc<Upstream>) -> Self {
        Self {
            upstream,
            latency: LatencyTracker::new(),
        }
    }

    /// Wraps `upstream` under the stats label `label`.
    #[cfg(feature = "stats")]
    pub fn with_label(upstream: Arc<Upstream>, label: String) -> Self {
        Self {
            upstream,
            latency: LatencyTracker::new(),
            label: label.into(),
            counters: Mutex::new(UpstreamCounters::default()),
        }
    }

    /// The stats label.
    #[cfg(feature = "stats")]
    pub fn label(&self) -> &Arc<str> {
        &self.label
    }

    /// Returns the exchange counters accumulated since the last call and
    /// resets them.
    #[cfg(feature = "stats")]
    pub fn take_counters(&self) -> UpstreamCounters {
        std::mem::take(&mut *self.counters())
    }

    #[cfg(feature = "stats")]
    fn counters(&self) -> std::sync::MutexGuard<'_, UpstreamCounters> {
        // Counters stay usable even if a panic poisoned the lock.
        self.counters.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn upstream(&self) -> &Arc<Upstream> {
        &self.upstream
    }

    pub fn latency(&self) -> &LatencyTracker {
        &self.latency
    }

    pub fn address(&self) -> &str {
        self.upstream.address()
    }

    /// Exchanges `req` with the wrapped upstream, recording how long it took
    /// on success, or [`FAILURE_PENALTY`] on failure.
    ///
    /// A future dropped before completing (e.g. a cancelled query) records
    /// nothing.
    pub async fn exchange(&self, req: &Message) -> Result<Message, DohError> {
        let start = Instant::now();
        #[cfg(feature = "stats")]
        self.counters().record_sent();
        let result = self.upstream.exchange(req).await;
        let elapsed = start.elapsed();
        match result {
            Ok(_) => self.latency.record(elapsed),
            Err(_) => self.latency.record_failure(),
        }
        #[cfg(feature = "stats")]
        {
            let transport = self.upstream.transport();
            match &result {
                Ok(_) => self.counters().record_ok(transport, elapsed),
                Err(e) => self.counters().record_err(transport, error_kind(e)),
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use std::str::FromStr;

    #[tokio::test]
    async fn failed_exchange_records_failure_penalty() {
        // Nothing answers on this socket's port once it's dropped, so the
        // exchange fails (refused or timed out).
        let addr = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let tracked = TrackedUpstream::new(Arc::new(Upstream::PlainUdp(Arc::new(
            PlainUdpUpstream::new(addr, Some(Duration::from_millis(200))),
        ))));

        let mut req = Message::new(1, MessageType::Query, OpCode::Query);
        req.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        assert!(tracked.exchange(&req).await.is_err());
        assert_eq!(tracked.latency().average(), Some(FAILURE_PENALTY));
        assert_eq!(tracked.latency().overdue_after(), None);
    }

    #[test]
    fn overdue_after_follows_rfc_6298() {
        let tracker = LatencyTracker::new();
        assert_eq!(tracker.overdue_after(), None);

        // First sample R: SRTT = R, RTTVAR = R/2, so R + 4 × R/2 = 3R.
        tracker.record(Duration::from_millis(30));
        assert_eq!(tracker.overdue_after(), Some(Duration::from_millis(90)));

        // A steady upstream's RTTVAR decays, so it's overdue sooner.
        for _ in 0..40 {
            tracker.record(Duration::from_millis(30));
        }
        let steady = tracker.overdue_after().unwrap();
        assert!(steady < Duration::from_millis(31), "{steady:?}");

        // A noisy one gets more slack than twice its average.
        let noisy = LatencyTracker::new();
        for _ in 0..10 {
            for ms in [30, 30, 30, 70] {
                noisy.record(Duration::from_millis(ms));
            }
        }
        let slack = noisy.overdue_after().unwrap();
        let twice_avg = noisy.average().unwrap() * 2;
        assert!(
            slack > twice_avg + Duration::from_millis(15),
            "{slack:?} vs {twice_avg:?}"
        );
    }

    #[test]
    fn failures_move_the_average_but_not_overdue_after() {
        let tracker = LatencyTracker::new();
        for _ in 0..20 {
            tracker.record(Duration::from_millis(30));
        }
        let before = tracker.overdue_after();

        tracker.record_failure();
        assert!(tracker.average().unwrap() > Duration::from_secs(1));
        assert_eq!(tracker.overdue_after(), before);

        // Nor does the first success after it inflate the deviation, as it
        // would if measured against the penalty-laden average.
        tracker.record(Duration::from_millis(30));
        assert!(tracker.overdue_after().unwrap() < Duration::from_millis(40));
    }
}
