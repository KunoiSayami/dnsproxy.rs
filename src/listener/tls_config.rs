//! Loads a production `rustls::ServerConfig` from a PEM certificate chain
//! and private key on disk, shared by the DoQ, DoT, DoH, and DoH3 listeners.
//! Mirrors the certificate-loading half of Go's `proxy.Config.TLSConfig`.

use std::path::Path;

use tokio_rustls::rustls::ServerConfig;

use crate::error::DohError;

/// Reads a PEM certificate chain and private key from `cert_path`/`key_path`
/// and builds a `ServerConfig` with no client authentication, setting
/// `alpn_protocols` to `alpn`.
pub fn load_server_tls_config(
    cert_path: &Path,
    key_path: &Path,
    alpn: Vec<Vec<u8>>,
) -> Result<ServerConfig, DohError> {
    let cert_file = std::fs::read(cert_path)?;
    let certs = rustls_pemfile::certs(&mut cert_file.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| DohError::Http(format!("reading {}: {e}", cert_path.display())))?;
    if certs.is_empty() {
        return Err(DohError::Http(format!(
            "no certificates found in {}",
            cert_path.display()
        )));
    }

    let key_file = std::fs::read(key_path)?;
    let key = rustls_pemfile::private_key(&mut key_file.as_slice())
        .map_err(|e| DohError::Http(format!("reading {}: {e}", key_path.display())))?
        .ok_or_else(|| DohError::Http(format!("no private key found in {}", key_path.display())))?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| DohError::Http(format!("building tls config: {e}")))?;
    config.alpn_protocols = alpn;
    Ok(config)
}
