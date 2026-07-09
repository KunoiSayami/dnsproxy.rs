//! An upstream DNS server reachable over either DoH/DoH3 or plain
//! DNS-over-UDP, unifying [`DohUpstream`] and [`PlainUdpUpstream`] behind one
//! type so [`crate::upstream_config::UpstreamConfig`] can mix both kinds.

use std::sync::Arc;

use hickory_proto::op::Message;

use crate::doh::DohUpstream;
use crate::error::DohError;
use crate::plain_udp::PlainUdpUpstream;

/// A configured upstream DNS server, over DoH/DoH3 or plain UDP.
pub enum Upstream {
    Doh(Arc<DohUpstream>),
    PlainUdp(Arc<PlainUdpUpstream>),
}

impl Upstream {
    pub fn address(&self) -> &str {
        match self {
            Upstream::Doh(u) => u.address(),
            Upstream::PlainUdp(u) => u.address(),
        }
    }

    pub async fn exchange(&self, req: &Message) -> Result<Message, DohError> {
        match self {
            Upstream::Doh(u) => u.exchange(req).await,
            Upstream::PlainUdp(u) => u.exchange(req).await,
        }
    }
}
