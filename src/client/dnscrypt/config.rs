//! Saves/loads a [`ResolverConfig`]'s key material to/from a small
//! `key = value` text file, so `--dnscrypt-generate-config` can persist keys
//! for a later `--dnscrypt-config` run without putting secret key material
//! on the command line or in shell history.

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use crypto_box::SecretKey;
use ed25519_dalek::SigningKey;

use crate::client::dnscrypt::keygen::ResolverConfig;

const KEY_PROVIDER_NAME: &str = "provider_name";
const KEY_PROVIDER_SIGNING_KEY: &str = "provider_signing_key";
const KEY_RESOLVER_SECRET_KEY: &str = "resolver_secret_key";

/// Serializes `config`'s key material to `key = value` lines and writes them
/// to `path`.
pub fn save(path: &Path, config: &ResolverConfig) -> Result<(), String> {
    let text = format!(
        "{KEY_PROVIDER_NAME} = {}\n{KEY_PROVIDER_SIGNING_KEY} = {}\n{KEY_RESOLVER_SECRET_KEY} = {}\n",
        config.provider_name,
        BASE64.encode(config.provider_signing_key.to_bytes()),
        BASE64.encode(config.resolver_secret_key.to_bytes()),
    );
    std::fs::write(path, text).map_err(|e| format!("writing {}: {e}", path.display()))
}

/// Loads a [`ResolverConfig`] previously written by [`save`].
pub fn load(path: &Path) -> Result<ResolverConfig, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;

    let mut provider_name = None;
    let mut provider_signing_key = None;
    let mut resolver_secret_key = None;

    for (idx, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("{}:{}: expected \"key = value\"", path.display(), idx + 1))?;
        let (key, value) = (key.trim(), value.trim());

        match key {
            KEY_PROVIDER_NAME => provider_name = Some(value.to_owned()),
            KEY_PROVIDER_SIGNING_KEY => {
                provider_signing_key = Some(decode_signing_key(value).map_err(|e| {
                    format!(
                        "{}:{}: {KEY_PROVIDER_SIGNING_KEY}: {e}",
                        path.display(),
                        idx + 1
                    )
                })?);
            }
            KEY_RESOLVER_SECRET_KEY => {
                resolver_secret_key = Some(decode_secret_key(value).map_err(|e| {
                    format!(
                        "{}:{}: {KEY_RESOLVER_SECRET_KEY}: {e}",
                        path.display(),
                        idx + 1
                    )
                })?);
            }
            other => {
                return Err(format!(
                    "{}:{}: unknown key {other:?}",
                    path.display(),
                    idx + 1
                ));
            }
        }
    }

    Ok(ResolverConfig {
        provider_name: provider_name
            .ok_or_else(|| format!("{}: missing {KEY_PROVIDER_NAME}", path.display()))?,
        provider_signing_key: provider_signing_key
            .ok_or_else(|| format!("{}: missing {KEY_PROVIDER_SIGNING_KEY}", path.display()))?,
        resolver_secret_key: resolver_secret_key
            .ok_or_else(|| format!("{}: missing {KEY_RESOLVER_SECRET_KEY}", path.display()))?,
    })
}

fn decode_signing_key(value: &str) -> Result<SigningKey, String> {
    let bytes = BASE64
        .decode(value)
        .map_err(|e| format!("invalid base64: {e}"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("expected 32 bytes, got {}", v.len()))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn decode_secret_key(value: &str) -> Result<SecretKey, String> {
    let bytes = BASE64
        .decode(value)
        .map_err(|e| format!("invalid base64: {e}"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("expected 32 bytes, got {}", v.len()))?;
    Ok(SecretKey::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_a_file() {
        let dir = std::env::temp_dir().join(format!("dnscrypt-config-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("dnscrypt.conf");

        let config = ResolverConfig::generate("2.dnscrypt.example.org");
        save(&path, &config).unwrap();

        let loaded = load(&path).unwrap();
        assert_eq!(loaded.provider_name, config.provider_name);
        assert_eq!(
            loaded.provider_signing_key.to_bytes(),
            config.provider_signing_key.to_bytes()
        );
        assert_eq!(
            loaded.resolver_secret_key.to_bytes(),
            config.resolver_secret_key.to_bytes()
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_missing_fields() {
        let dir =
            std::env::temp_dir().join(format!("dnscrypt-config-test2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("dnscrypt.conf");
        std::fs::write(&path, "provider_name = example.org\n").unwrap();

        let Err(err) = load(&path) else {
            panic!("expected an error for a config missing required fields");
        };
        assert!(err.contains("missing"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_malformed_line() {
        let dir =
            std::env::temp_dir().join(format!("dnscrypt-config-test3-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("dnscrypt.conf");
        std::fs::write(&path, "not a valid line\n").unwrap();

        let Err(err) = load(&path) else {
            panic!("expected an error for a malformed line");
        };
        assert!(err.contains("expected"));

        std::fs::remove_dir_all(&dir).ok();
    }
}
