//! An upstream DNS server reachable over DoH/DoH3, DoT, DoQ, or plain
//! DNS-over-UDP/TCP, unifying [`DohUpstream`], [`DotUpstream`],
//! [`DoqUpstream`], [`PlainUdpUpstream`], and [`PlainTcpUpstream`] behind one
//! type so [`crate::client::upstream_config::UpstreamConfig`] can mix all of them.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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
/// [`crate::client::upstream_config::UpstreamMode::LoadBalance`] to prefer
/// the upstream that has recently answered fastest. Mirrors the exponential
/// moving average Go dnsproxy keeps per upstream for its load-balance mode
/// (`proxy/upstream_lbalgorithm.go`'s `rttEma`).
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

/// Weight given to the newest sample in the exponential moving average;
/// matches Go dnsproxy's smoothing factor.
const EMA_ALPHA: f64 = 0.3;

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
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |prev| {
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
}

impl TrackedUpstream {
    pub fn new(upstream: Arc<Upstream>) -> Self {
        Self {
            upstream,
            latency: LatencyTracker::new(),
        }
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
    /// on success.
    pub async fn exchange(&self, req: &Message) -> Result<Message, DohError> {
        let start = Instant::now();
        let result = self.upstream.exchange(req).await;
        if result.is_ok() {
            self.latency.record(start.elapsed());
        }
        result
    }
}
