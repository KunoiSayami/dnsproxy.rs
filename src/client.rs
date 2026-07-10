//! DNS upstream client implementations: dialing and querying upstream
//! resolvers over DoH, DoT, DoQ, and plain DNS-over-UDP/TCP.

pub mod bootstrap;
#[cfg(feature = "dnscrypt")]
pub mod dnscrypt;
pub mod doh;
#[cfg(feature = "http3")]
pub mod doh3;
#[cfg(feature = "doq")]
pub mod doq;
#[cfg(feature = "dot")]
pub mod dot;
pub mod plain_tcp;
pub mod plain_udp;
pub mod upstream;
pub mod upstream_config;
pub mod upstream_url;
pub mod wire;

#[cfg(feature = "dnscrypt")]
pub use dnscrypt::DnsCryptUpstream;
pub use doh::DohUpstream;
#[cfg(feature = "doq")]
pub use doq::DoqUpstream;
#[cfg(feature = "dot")]
pub use dot::DotUpstream;
pub use plain_tcp::PlainTcpUpstream;
pub use plain_udp::PlainUdpUpstream;
pub use upstream::Upstream;
pub use upstream_config::UpstreamConfig;
pub use upstream_url::parse_upstream;
