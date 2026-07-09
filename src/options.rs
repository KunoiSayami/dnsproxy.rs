use std::sync::Arc;
use std::time::Duration;

use crate::client::bootstrap::Resolver;

/// HTTP protocol versions the DoH client may negotiate, doubling as the ALPN
/// values advertised during the TLS handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpVersion {
    Http11,
    Http2,
    Http3,
}

impl HttpVersion {
    pub fn alpn(self) -> &'static str {
        match self {
            HttpVersion::Http11 => "http/1.1",
            HttpVersion::Http2 => "h2",
            HttpVersion::Http3 => "h3",
        }
    }
}

/// Default HTTP versions used when a caller doesn't specify any: HTTP/1.1
/// and HTTP/2, matching the Go default (`DefaultHTTPVersions`).
pub fn default_http_versions() -> Vec<HttpVersion> {
    vec![HttpVersion::Http11, HttpVersion::Http2]
}

/// Configuration for a DoH [`crate::client::doh::DohUpstream`].
pub struct Options {
    /// Resolver used to bootstrap the DoH server's hostname. Defaults to the
    /// system resolver if `None`.
    pub bootstrap: Option<Arc<dyn Resolver>>,

    /// HTTP versions this upstream is allowed to negotiate. Empty means
    /// [`default_http_versions`].
    pub http_versions: Vec<HttpVersion>,

    /// Overall timeout for exchanges, bootstrap lookups, and H3 probes. `None`
    /// disables the timeout.
    pub timeout: Option<Duration>,

    /// Disables TLS certificate verification. Dangerous; mirrors
    /// `InsecureSkipVerify`.
    pub insecure_skip_verify: bool,

    /// Prefer IPv6 addresses when the bootstrap resolves multiple families.
    pub prefer_ipv6: bool,

    /// HTTP Basic Auth credentials (username, password) sent with every
    /// request, e.g. as parsed from a `https://user:pass@host/path` upstream.
    pub basic_auth: Option<(String, String)>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            bootstrap: None,
            http_versions: Vec::new(),
            timeout: Some(Duration::from_secs(10)),
            insecure_skip_verify: false,
            prefer_ipv6: false,
            basic_auth: None,
        }
    }
}

impl Options {
    pub fn resolved_http_versions(&self) -> Vec<HttpVersion> {
        if self.http_versions.is_empty() {
            default_http_versions()
        } else {
            self.http_versions.clone()
        }
    }
}
