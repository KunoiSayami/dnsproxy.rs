use thiserror::Error;

#[derive(Debug, Error)]
pub enum DohError {
    #[error("bootstrapping upstream: {0}")]
    Bootstrap(String),

    #[error("packing dns message: {0}")]
    Pack(#[from] hickory_proto::error::ProtoError),

    #[error("http request failed: {0}")]
    Http(String),

    #[error("unexpected status {status} from {addr}")]
    UnexpectedStatus { status: u16, addr: String },

    #[error("unexpected non-zero id in response: {0}")]
    NonZeroId(u16),

    #[error("validating response: {0}")]
    InvalidResponse(String),

    #[error("timeout exceeded: {0:?}")]
    Timeout(std::time::Duration),

    #[error("no http versions supported by this upstream")]
    NoSupportedVersions,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[cfg(feature = "http3")]
    #[error("quic error: {0}")]
    Quic(String),
}

impl DohError {
    /// Mirrors `dnsOverHTTPS.shouldRetry`: timeouts and QUIC 0-RTT rejections
    /// are worth retrying with a freshly created client.
    pub fn should_retry(&self) -> bool {
        match self {
            DohError::Timeout(_) => true,
            #[cfg(feature = "http3")]
            DohError::Quic(msg) => msg.contains("0-RTT") || msg.contains("retry"),
            _ => false,
        }
    }
}
