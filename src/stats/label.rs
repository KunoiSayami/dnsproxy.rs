//! Upstream labels and error kinds as `dnsstat.py` writes them, so per-
//! upstream records from both line up.

use crate::error::DohError;

/// The stats label for a configured upstream address: `scheme://host:port`,
/// with the scheme's default port filled in and no path (often secret) or
/// userinfo, or `host:port` for plain UDP. A port of `label()` in
/// `dnsstat.py`, except that it also drops userinfo, which that version
/// would have written out.
pub fn upstream_label(addr: &str) -> String {
    let Some((scheme, rest)) = addr
        .split_once("://")
        .filter(|(scheme, rest)| is_word(scheme) && !rest.starts_with('/'))
    else {
        return if ends_with_port(addr) {
            addr.to_owned()
        } else {
            format!("{addr}:53")
        };
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);

    if scheme == "udp" {
        return if host.contains(':') {
            host.to_owned()
        } else {
            format!("{host}:53")
        };
    }
    let default_port = match scheme {
        "https" | "h3" => Some(443),
        "tls" | "quic" => Some(853),
        "tcp" => Some(53),
        _ => None,
    };
    match default_port {
        Some(port) if !ends_with_port(host) => format!("{scheme}://{host}:{port}"),
        _ => format!("{scheme}://{host}"),
    }
}

/// Python's `\w+`, for ASCII input.
fn is_word(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Python's `re.search(r":\d+$", s)`.
fn ends_with_port(s: &str) -> bool {
    s.rsplit_once(':')
        .is_some_and(|(_, port)| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))
}

/// Classifies an upstream error into the kinds `dnsstat.py`'s `error_kind`
/// derives from Go's log lines: `timeout`, `dial`, `conn`, `tls`, `http`,
/// or `other`. (`canceled` never occurs: abandoned attempts run to
/// completion.)
pub fn error_kind(err: &DohError) -> &'static str {
    match err {
        DohError::Timeout(_) => return "timeout",
        DohError::UnexpectedStatus { .. } => return "http",
        DohError::Bootstrap(_) => return "dial",
        _ => {}
    }
    let s = err.to_string().to_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| s.contains(n));
    if has(&["timeout", "timed out", "deadline exceeded"]) {
        "timeout"
    } else if has(&["no addresses", "dial", "no route", "refused", "unreachable"]) {
        "dial"
    } else if has(&["eof", "reset", "broken pipe", "closed"]) {
        "conn"
    } else if has(&["tls", "certificate", "x509"]) {
        "tls"
    } else if has(&["status code", "http"]) {
        "http"
    } else {
        "other"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_match_dnsstat_py() {
        for (addr, label) in [
            (
                "h3://diana.example:8443/s3cr3t/dns-query",
                "h3://diana.example:8443",
            ),
            ("https://dns.google/dns-query", "https://dns.google:443"),
            ("https://u:p@doh.example/x", "https://doh.example:443"),
            ("tls://1.1.1.1", "tls://1.1.1.1:853"),
            ("quic://dns.example:8853", "quic://dns.example:8853"),
            ("tcp://8.8.8.8", "tcp://8.8.8.8:53"),
            ("udp://1.1.1.1", "1.1.1.1:53"),
            ("udp://1.1.1.1:5353", "1.1.1.1:5353"),
            ("1.1.1.1", "1.1.1.1:53"),
            ("1.1.1.1:53", "1.1.1.1:53"),
            ("sdns://AQcAAAAAAAAA", "sdns://AQcAAAAAAAAA"),
        ] {
            assert_eq!(upstream_label(addr), label, "{addr}");
        }
    }

    #[test]
    fn classifies_errors() {
        use std::time::Duration;
        assert_eq!(
            error_kind(&DohError::Timeout(Duration::from_secs(1))),
            "timeout"
        );
        assert_eq!(
            error_kind(&DohError::UnexpectedStatus {
                status: 502,
                addr: "x".into()
            }),
            "http"
        );
        let refused = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        assert_eq!(error_kind(&DohError::Io(refused)), "dial");
        assert_eq!(
            error_kind(&DohError::Http(
                "tls handshake failed: bad certificate".into()
            )),
            "tls"
        );
        assert_eq!(
            error_kind(&DohError::InvalidResponse("mismatched name".into())),
            "other"
        );
    }
}
