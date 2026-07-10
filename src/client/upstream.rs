//! An upstream DNS server reachable over DoH/DoH3, DoT, DoQ, or plain
//! DNS-over-UDP/TCP, unifying [`DohUpstream`], [`DotUpstream`],
//! [`DoqUpstream`], [`PlainUdpUpstream`], and [`PlainTcpUpstream`] behind one
//! type so [`crate::client::upstream_config::UpstreamConfig`] can mix all of them.

use std::sync::Arc;

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
