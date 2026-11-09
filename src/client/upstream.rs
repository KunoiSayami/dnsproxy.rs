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
/// One tracker is shared per distinct upstream (matching the `Arc<Upstream>`
/// interning done during parsing), so the same server ages a single average
/// no matter how many domain rules reference it.
#[derive(Default)]
pub struct LatencyTracker {
    /// Exponential moving average latency in microseconds, or `u64::MAX`
    /// while no exchange has completed yet.
    avg_micros: AtomicU64,
}

/// Weight given to the newest sample in the exponential moving average.
const EMA_ALPHA: f64 = 0.3;

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
        }
    }

    /// Records how long an exchange with this upstream took.
    pub fn record(&self, elapsed: Duration) {
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

    /// The current average latency, or `None` if no exchange has completed
    /// yet (i.e. this upstream is untested).
    pub fn average(&self) -> Option<Duration> {
        match self.avg_micros.load(Ordering::Relaxed) {
            u64::MAX => None,
            micros => Some(Duration::from_micros(micros)),
        }
    }
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
        self.latency.record(match result {
            Ok(_) => elapsed,
            Err(_) => FAILURE_PENALTY,
        });
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
    }
}
