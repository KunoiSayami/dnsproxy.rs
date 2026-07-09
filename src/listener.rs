//! DNS server/listener implementations: accepting incoming queries over
//! plain DNS-over-UDP/TCP, DoT, DoQ, DoH, and DoH3.

#[cfg(feature = "doh-server")]
pub mod doh;
#[cfg(feature = "http3-server")]
pub mod doh3;
#[cfg(feature = "doh-server")]
pub mod doh_auth;
#[cfg(feature = "doq-server")]
pub mod doq;
#[cfg(feature = "dot-server")]
pub mod dot;
pub mod io;
#[cfg(any(feature = "doq-server", feature = "dot-server", feature = "doh-server"))]
pub mod tls_config;

#[cfg(feature = "doh-server")]
pub use doh_auth::Credentials;
pub use io::{Handler, serve, serve_all};
