//! A DNS upstream client, ported from AdGuard dnsproxy's Go implementation
//! (`upstream/`). Supports DoH (RFC 8484), DoT (RFC 7858, behind the `dot`
//! feature), DoQ (RFC 9250, behind the `doq` feature), and plain
//! DNS-over-UDP/TCP.
//!
//! For DoH, HTTP/1.1 and HTTP/2 are supported always; HTTP/3 is available
//! behind the `http3` feature and races a QUIC handshake against TLS to
//! decide whether to prefer it, matching the Go client's probing behavior.

pub mod cache;
pub mod client;
pub mod error;
pub mod listener;
pub mod options;

pub use cache::{Cache, CacheOptions};
#[cfg(feature = "dnscrypt")]
pub use client::DnsCryptUpstream;
pub use client::DohUpstream;
#[cfg(feature = "doq")]
pub use client::DoqUpstream;
#[cfg(feature = "dot")]
pub use client::DotUpstream;
pub use client::{
    PlainTcpUpstream, PlainUdpUpstream, TrackedUpstream, Upstream, UpstreamConfig, UpstreamMode,
    parse_upstream,
};
pub use error::DohError;
#[cfg(feature = "doh-server")]
pub use listener::Credentials;
pub use listener::{Handler, serve, serve_all};
pub use options::{HttpVersion, Options};
