//! Generates a DNSCrypt resolver's key material: a provider Ed25519 signing
//! keypair and a resolver X25519 keypair, from which a signed certificate
//! and the `sdns://` stamp advertising it can be built. Mirrors Go's
//! `dnscrypt.GenerateResolverConfig`/`ResolverConfig.NewCert`/
//! `ResolverConfig.CreateStamp` (from the external `AdguardTeam/dnscrypt`
//! library, which has no Rust equivalent), used by `dnscrypt-proxy`-style
//! tooling to bootstrap a new resolver.

use std::net::SocketAddr;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use crypto_box::SecretKey;
use crypto_box::aead::rand_core::OsRng;
use ed25519_dalek::SigningKey;

use crate::client::dnscrypt::crypto;

/// Default certificate validity window: about one year, matching a
/// reasonable default for a long-lived certificate (this crate doesn't
/// implement rotation, so operators wanting shorter-lived certs should
/// regenerate manually).
pub const DEFAULT_CERT_TTL_SECS: u32 = 365 * 24 * 60 * 60;

/// A DNSCrypt resolver's key material: enough to sign certificates and
/// build the `sdns://` stamp clients use to find this resolver.
pub struct ResolverConfig {
    pub provider_name: String,
    pub provider_signing_key: SigningKey,
    pub resolver_secret_key: SecretKey,
}

impl ResolverConfig {
    /// Generates a fresh provider signing keypair and resolver X25519
    /// keypair for `provider_name`.
    pub fn generate(provider_name: &str) -> Self {
        Self {
            provider_name: provider_name.to_owned(),
            provider_signing_key: SigningKey::generate(&mut OsRng),
            resolver_secret_key: SecretKey::generate(&mut OsRng),
        }
    }

    /// Signs and returns a new certificate's raw bytes (the value to serve
    /// as the provider name's TXT record), valid from `ts_start` to
    /// `ts_end` (Unix timestamps). `client_magic` is the first 8 bytes
    /// clients must present in a query for it to be considered addressed to
    /// this certificate; distinct certificates from the same provider
    /// should use distinct client magics.
    pub fn certificate(
        &self,
        client_magic: &[u8; 8],
        serial: u32,
        ts_start: u32,
        ts_end: u32,
    ) -> Vec<u8> {
        let resolver_public_key = *self.resolver_secret_key.public_key().as_bytes();
        crypto::sign_certificate(
            &self.provider_signing_key,
            &resolver_public_key,
            client_magic,
            serial,
            ts_start,
            ts_end,
        )
    }

    /// Builds the `sdns://` stamp advertising this resolver at `addr`,
    /// the inverse of `stamp::parse_dnscrypt_stamp`.
    pub fn stamp(&self, addr: SocketAddr) -> String {
        let provider_public_key = self.provider_signing_key.verifying_key().to_bytes();
        build_stamp(addr, &provider_public_key, &self.provider_name)
    }
}

/// Encodes a DNSCrypt `sdns://` stamp, the inverse of
/// `stamp::parse_dnscrypt_stamp`.
pub(crate) fn build_stamp(
    addr: SocketAddr,
    provider_public_key: &[u8; 32],
    provider_name: &str,
) -> String {
    let mut bytes = Vec::new();
    bytes.push(0x01u8); // DNSCrypt protocol type
    bytes.extend_from_slice(&[0u8; 8]); // properties

    let addr_str = addr.to_string();
    bytes.push(addr_str.len() as u8);
    bytes.extend_from_slice(addr_str.as_bytes());

    bytes.push(provider_public_key.len() as u8);
    bytes.extend_from_slice(provider_public_key);

    bytes.push(provider_name.len() as u8);
    bytes.extend_from_slice(provider_name.as_bytes());

    format!("sdns://{}", URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::dnscrypt::stamp::parse_dnscrypt_stamp;

    #[test]
    fn generate_signs_a_verifiable_certificate() {
        let config = ResolverConfig::generate("2.dnscrypt.example.org");
        let client_magic = *b"TESTMAGC";
        let cert_bytes = config.certificate(&client_magic, 1, 0, u32::MAX);

        let provider_public_key = config.provider_signing_key.verifying_key().to_bytes();
        let certs = crypto::parse_certificates(&[cert_bytes], &provider_public_key).unwrap();

        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].client_magic, client_magic);
        assert_eq!(certs[0].serial, 1);
        assert_eq!(
            certs[0].resolver_public_key,
            *config.resolver_secret_key.public_key().as_bytes()
        );
    }

    #[test]
    fn stamp_round_trips_through_parser() {
        let config = ResolverConfig::generate("2.dnscrypt.example.org");
        let addr: SocketAddr = "203.0.113.1:443".parse().unwrap();
        let stamp_url = config.stamp(addr);

        let parsed = parse_dnscrypt_stamp(&stamp_url).unwrap();
        assert_eq!(parsed.addr, addr);
        assert_eq!(parsed.provider_name, "2.dnscrypt.example.org");
        assert_eq!(
            parsed.provider_public_key,
            config.provider_signing_key.verifying_key().to_bytes()
        );
    }
}
