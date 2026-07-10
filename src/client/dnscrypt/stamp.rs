//! Parses `sdns://` DNS stamps for the DNSCrypt protocol, per the format at
//! <https://dnscrypt.info/stamps-specifications>. Only the DNSCrypt stamp
//! type (`0x01`) is supported; other stamp types (DoH, DoT, DoQ, plain) are
//! handled by this crate's own upstream schemes instead.

use std::net::{IpAddr, SocketAddr};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Stamp protocol type byte identifying a DNSCrypt stamp.
const STAMP_PROTO_TYPE_DNSCRYPT: u8 = 0x01;

/// Default port for DNSCrypt servers when the stamp's address omits one.
const DEFAULT_PORT_DNSCRYPT: u16 = 443;

/// A parsed DNSCrypt `sdns://` stamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsCryptStamp {
    /// The DNSCrypt server's address. Always a literal IP per the stamp
    /// spec, so no bootstrap resolution is needed to dial it.
    pub addr: SocketAddr,

    /// The provider's long-term Ed25519 public key, used to verify the
    /// resolver certificate fetched at connection time.
    pub provider_public_key: [u8; 32],

    /// The provider name, queried as a TXT record to fetch the resolver
    /// certificate.
    pub provider_name: String,
}

/// Reads a length-prefixed segment (1 byte length, then that many bytes)
/// from `buf` at `pos`, advancing `pos` past it. Per the stamp spec, if the
/// length byte's high bit (0x80) is set, another length-prefixed segment
/// follows immediately and should be appended (used for very long strings);
/// none of DNSCrypt's fields need this in practice, but it's handled for
/// spec compliance.
fn read_lp(buf: &[u8], pos: &mut usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let len_byte = *buf
            .get(*pos)
            .ok_or_else(|| "truncated stamp: missing length byte".to_owned())?;
        *pos += 1;

        let len = (len_byte & 0x7f) as usize;
        let end = pos
            .checked_add(len)
            .ok_or_else(|| "truncated stamp: length overflow".to_owned())?;
        let seg = buf
            .get(*pos..end)
            .ok_or_else(|| "truncated stamp: segment exceeds buffer".to_owned())?;
        out.extend_from_slice(seg);
        *pos = end;

        if len_byte & 0x80 == 0 {
            break;
        }
    }
    Ok(out)
}

/// Parses `addr` (an `sdns://...` URL) into a [`DnsCryptStamp`].
pub fn parse_dnscrypt_stamp(addr: &str) -> Result<DnsCryptStamp, String> {
    let payload = addr
        .strip_prefix("sdns://")
        .ok_or_else(|| format!("stamp {addr:?} must start with \"sdns://\""))?;

    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| format!("invalid stamp {addr:?}: {e}"))?;

    let mut pos = 0usize;

    let proto = *bytes
        .first()
        .ok_or_else(|| format!("stamp {addr:?} is empty"))?;
    pos += 1;
    if proto != STAMP_PROTO_TYPE_DNSCRYPT {
        return Err(format!(
            "stamp {addr:?} has unsupported protocol type {proto:#04x}; only DNSCrypt (0x01) is supported"
        ));
    }

    // 8 bytes of little-endian properties bitflags (DNSSEC/no-log/no-filter
    // hints); not enforced here.
    pos = pos
        .checked_add(8)
        .filter(|&end| end <= bytes.len())
        .ok_or_else(|| format!("stamp {addr:?} is truncated in properties"))?;

    let addr_str = String::from_utf8(read_lp(&bytes, &mut pos)?)
        .map_err(|e| format!("stamp {addr:?} has invalid address: {e}"))?;
    let provider_pk_bytes = read_lp(&bytes, &mut pos)?;
    let provider_name = String::from_utf8(read_lp(&bytes, &mut pos)?)
        .map_err(|e| format!("stamp {addr:?} has invalid provider name: {e}"))?;

    let provider_public_key: [u8; 32] = provider_pk_bytes.try_into().map_err(|v: Vec<u8>| {
        format!(
            "stamp {addr:?} has a {}-byte provider public key; expected 32",
            v.len()
        )
    })?;

    let sock_addr = parse_stamp_addr(&addr_str)
        .ok_or_else(|| format!("stamp {addr:?} has invalid server address {addr_str:?}"))?;

    Ok(DnsCryptStamp {
        addr: sock_addr,
        provider_public_key,
        provider_name,
    })
}

/// Parses a stamp's `host:port` (or bare `host`) address string into a
/// [`SocketAddr`], defaulting to [`DEFAULT_PORT_DNSCRYPT`] when no port is
/// given. Bracketed IPv6 hosts (`[::1]:443`) are supported. The host must be
/// a literal IP, matching the stamp spec (DNSCrypt stamps never carry a
/// hostname needing separate resolution here).
fn parse_stamp_addr(s: &str) -> Option<SocketAddr> {
    if let Ok(sock_addr) = s.parse::<SocketAddr>() {
        return Some(sock_addr);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, DEFAULT_PORT_DNSCRYPT));
    }
    if let Some(inner) = s.strip_prefix('[')
        && let Some((host, rest)) = inner.split_once(']')
        && let Ok(ip) = host.parse::<IpAddr>()
    {
        return match rest.strip_prefix(':') {
            Some(port_str) => port_str
                .parse::<u16>()
                .ok()
                .map(|port| SocketAddr::new(ip, port)),
            None if rest.is_empty() => Some(SocketAddr::new(ip, DEFAULT_PORT_DNSCRYPT)),
            None => None,
        };
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // AdGuard DNS's public DNSCrypt stamp, taken from dnsproxy's Go test
    // suite (upstream/dnscrypt_internal_test.go).
    const ADGUARD_STAMP: &str = "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20";

    #[test]
    fn parses_adguard_stamp() {
        let stamp = parse_dnscrypt_stamp(ADGUARD_STAMP).unwrap();
        assert_eq!(stamp.addr, "94.140.14.14:5443".parse().unwrap());
        assert_eq!(stamp.provider_name, "2.dnscrypt.default.ns1.adguard.com");
        assert_eq!(stamp.provider_public_key.len(), 32);
    }

    #[test]
    fn rejects_missing_scheme() {
        assert!(parse_dnscrypt_stamp("AQMAAAAA").is_err());
    }

    #[test]
    fn rejects_non_dnscrypt_proto() {
        // Protocol byte 0x00 = plain, not DNSCrypt.
        let bytes = [0x00u8];
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        let err = parse_dnscrypt_stamp(&format!("sdns://{encoded}")).unwrap_err();
        assert!(err.contains("unsupported protocol type"));
    }

    #[test]
    fn rejects_truncated_stamp() {
        let err = parse_dnscrypt_stamp("sdns://AQ").unwrap_err();
        assert!(err.contains("truncated"));
    }

    #[test]
    fn rejects_invalid_base64() {
        assert!(parse_dnscrypt_stamp("sdns://not!valid!base64!!!").is_err());
    }

    #[test]
    fn parse_stamp_addr_defaults_port() {
        assert_eq!(
            parse_stamp_addr("94.140.14.14"),
            Some("94.140.14.14:443".parse().unwrap())
        );
    }

    #[test]
    fn parse_stamp_addr_bracketed_ipv6() {
        assert_eq!(
            parse_stamp_addr("[::1]:5443"),
            Some("[::1]:5443".parse().unwrap())
        );
        assert_eq!(
            parse_stamp_addr("[::1]"),
            Some("[::1]:443".parse().unwrap())
        );
    }

    #[test]
    fn parse_stamp_addr_rejects_hostname() {
        assert_eq!(parse_stamp_addr("dns.example.com:443"), None);
    }
}
