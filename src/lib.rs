//! A DNS-over-HTTPS (RFC 8484) upstream client, ported from AdGuard
//! dnsproxy's Go implementation (`upstream/doh.go`).
//!
//! Supports HTTP/1.1 and HTTP/2 always; HTTP/3 is available behind the
//! `http3` feature and races a QUIC handshake against TLS to decide whether
//! to prefer it, matching the Go client's probing behavior.

pub mod bootstrap;
pub mod cache;
pub mod doh;
#[cfg(feature = "http3")]
pub mod doh3;
pub mod error;
pub mod options;
pub mod server;
pub mod wire;

pub use cache::{Cache, CacheOptions};
pub use doh::DohUpstream;
pub use error::DohError;
pub use options::{HttpVersion, Options};
pub use server::{Handler, serve, serve_all};
