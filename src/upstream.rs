//! An upstream DNS server reachable over DoH/DoH3, DoT, or plain
//! DNS-over-UDP/TCP, unifying [`DohUpstream`], [`DotUpstream`],
//! [`PlainUdpUpstream`], and [`PlainTcpUpstream`] behind one type so
//! [`crate::upstream_config::UpstreamConfig`] can mix all of them.

use std::sync::Arc;

use hickory_proto::op::Message;

use crate::doh::DohUpstream;
#[cfg(feature = "dot")]
use crate::dot::DotUpstream;
use crate::error::DohError;
use crate::plain_tcp::PlainTcpUpstream;
use crate::plain_udp::PlainUdpUpstream;

/// A configured upstream DNS server, over DoH/DoH3, DoT, plain UDP, or plain
/// TCP.
pub enum Upstream {
    Doh(Arc<DohUpstream>),
    #[cfg(feature = "dot")]
    Dot(Arc<DotUpstream>),
    PlainUdp(Arc<PlainUdpUpstream>),
    PlainTcp(Arc<PlainTcpUpstream>),
}

impl Upstream {
    pub fn address(&self) -> &str {
        match self {
            Upstream::Doh(u) => u.address(),
            #[cfg(feature = "dot")]
            Upstream::Dot(u) => u.address(),
            Upstream::PlainUdp(u) => u.address(),
            Upstream::PlainTcp(u) => u.address(),
        }
    }

    pub async fn exchange(&self, req: &Message) -> Result<Message, DohError> {
        match self {
            Upstream::Doh(u) => u.exchange(req).await,
            #[cfg(feature = "dot")]
            Upstream::Dot(u) => u.exchange(req).await,
            Upstream::PlainUdp(u) => u.exchange(req).await,
            Upstream::PlainTcp(u) => u.exchange(req).await,
        }
    }
}
