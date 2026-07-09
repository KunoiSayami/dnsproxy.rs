//! A DNS upstream client, ported from AdGuard dnsproxy's Go implementation
//! (`upstream/`). Supports DoH (RFC 8484), DoT (RFC 7858, behind the `dot`
//! feature), and plain DNS-over-UDP/TCP.
//!
//! For DoH, HTTP/1.1 and HTTP/2 are supported always; HTTP/3 is available
//! behind the `http3` feature and races a QUIC handshake against TLS to
//! decide whether to prefer it, matching the Go client's probing behavior.

pub mod bootstrap;
pub mod cache;
pub mod doh;
#[cfg(feature = "http3")]
pub mod doh3;
#[cfg(feature = "dot")]
pub mod dot;
pub mod error;
pub mod options;
pub mod plain_tcp;
pub mod plain_udp;
pub mod server;
pub mod upstream;
pub mod upstream_config;
pub mod upstream_url;
pub mod wire;

pub use cache::{Cache, CacheOptions};
pub use doh::DohUpstream;
#[cfg(feature = "dot")]
pub use dot::DotUpstream;
pub use error::DohError;
pub use options::{HttpVersion, Options};
pub use plain_tcp::PlainTcpUpstream;
pub use plain_udp::PlainUdpUpstream;
pub use server::{Handler, serve, serve_all};
pub use upstream::Upstream;
pub use upstream_config::UpstreamConfig;
pub use upstream_url::parse_upstream;
