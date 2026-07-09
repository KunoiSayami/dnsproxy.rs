//! Parses a single upstream address string into an [`Upstream`], mirroring
//! the relevant subset of `AddressToUpstream`/`urlToUpstream` in Go's
//! `upstream/upstream.go`: `https://`/`h3://` for DoH/DoH3, `tls://` for DoT
//! (behind the `dot` feature), and `udp://`/`tcp://` (or a bare
//! `host[:port]` with no scheme, which defaults to `udp://` just as in Go)
//! for plain DNS-over-UDP/TCP.

use std::net::SocketAddr;
use std::sync::Arc;

use hyper::Uri;

use crate::doh::DohUpstream;
#[cfg(feature = "dot")]
use crate::dot::DotUpstream;
use crate::options::{HttpVersion, Options};
use crate::plain_tcp::PlainTcpUpstream;
use crate::plain_udp::PlainUdpUpstream;
use crate::upstream::Upstream;

/// Default port for plain DNS, matching Go's `defaultPortPlain`.
const DEFAULT_PORT_PLAIN: u16 = 53;

/// Splits `user:pass@` userinfo out of a `scheme://user:pass@host/path` URL,
/// since [`Uri`] treats the whole authority as opaque and won't parse it for
/// us. Returns the credentials (if any) and the URL with userinfo removed.
fn extract_userinfo(url: &str) -> Result<(Option<(String, String)>, String), String> {
    let (scheme_sep, rest) = url
        .split_once("://")
        .ok_or_else(|| "upstream must be an absolute URL".to_owned())?;

    let Some(at) = rest.rfind('@') else {
        return Ok((None, url.to_owned()));
    };
    let (userinfo, host_and_path) = rest.split_at(at);
    let host_and_path = &host_and_path[1..]; // skip '@'

    let (user, pass) = userinfo
        .split_once(':')
        .ok_or_else(|| "userinfo in upstream must be user:pass".to_owned())?;

    Ok((
        Some((user.to_owned(), pass.to_owned())),
        format!("{scheme_sep}://{host_and_path}"),
    ))
}

/// Parses `addr` (e.g. `https://dns.google/dns-query` or
/// `h3://1.1.1.1:443/dns-query`) into a [`DohUpstream`], applying `base_opts`
/// as a template. `h3://` forces HTTP/3-only, matching Go's `h3` scheme
/// handling in `urlToUpstream`.
pub fn parse_upstream(addr: &str, base_opts: &Options) -> Result<Arc<DohUpstream>, String> {
    let (scheme, _) = addr
        .split_once("://")
        .ok_or_else(|| format!("upstream {addr:?} must be an absolute URL"))?;

    let http_versions = match scheme {
        "https" => None,
        "h3" => Some(vec![HttpVersion::Http3]),
        other => return Err(format!("unsupported upstream scheme {other:?} in {addr:?}")),
    };

    let (basic_auth, stripped) = extract_userinfo(addr)?;
    // `h3://` isn't a URI scheme `Uri` understands as carrying a host, so
    // normalize it to `https://` for parsing purposes only; the scheme
    // itself was already consumed above to pick `http_versions`.
    let normalized = if scheme == "h3" {
        format!("https://{}", &stripped[stripped.find("://").unwrap() + 3..])
    } else {
        stripped
    };

    let uri: Uri = normalized
        .parse()
        .map_err(|e| format!("invalid upstream {addr:?}: {e}"))?;

    let host = uri
        .host()
        .ok_or_else(|| format!("upstream {addr:?} must include a host"))?
        .to_owned();
    let path = uri.path().to_owned();
    let port = uri.port_u16();

    let opts = Options {
        http_versions: http_versions.unwrap_or_else(|| base_opts.http_versions.clone()),
        basic_auth,
        bootstrap: base_opts.bootstrap.clone(),
        timeout: base_opts.timeout,
        insecure_skip_verify: base_opts.insecure_skip_verify,
        prefer_ipv6: base_opts.prefer_ipv6,
    };

    Ok(Arc::new(DohUpstream::new(&host, port, &path, opts)))
}

/// Builds a new [`Options`] from `base`'s fields relevant to non-DoH
/// transports (no `http_versions`/`basic_auth`), since [`Options`] isn't
/// `Clone`.
fn clone_opts(base: &Options) -> Options {
    Options {
        bootstrap: base.bootstrap.clone(),
        http_versions: Vec::new(),
        timeout: base.timeout,
        insecure_skip_verify: base.insecure_skip_verify,
        prefer_ipv6: base.prefer_ipv6,
        basic_auth: None,
    }
}

/// Splits a `host[:port]` authority (no scheme) into a host and an optional
/// port, for schemes whose upstream may be a bootstrap-resolved hostname
/// rather than a literal IP (`tcp://`, `tls://`). Bracketed IPv6 hosts
/// (`[::1]:853`) are supported.
fn split_host_port(rest: &str) -> Result<(String, Option<u16>), String> {
    if let Some(stripped) = rest.strip_prefix('[') {
        let (host, after) = stripped
            .split_once(']')
            .ok_or_else(|| format!("invalid host {rest:?}: unterminated \"[\""))?;
        let port = match after.strip_prefix(':') {
            Some(p) => Some(
                p.parse::<u16>()
                    .map_err(|e| format!("invalid port in {rest:?}: {e}"))?,
            ),
            None if after.is_empty() => None,
            None => return Err(format!("invalid host {rest:?}")),
        };
        return Ok((host.to_owned(), port));
    }

    match rest.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            let port = port
                .parse::<u16>()
                .map_err(|e| format!("invalid port in {rest:?}: {e}"))?;
            Ok((host.to_owned(), Some(port)))
        }
        _ => Ok((rest.to_owned(), None)),
    }
}

/// Parses `addr` into an [`Upstream`], extending [`parse_upstream`] with
/// `udp://host[:port]` (or a bare `host[:port]`/`host`, which defaults to
/// `udp://` just as in Go's `AddressToUpstream`) for plain DNS-over-UDP,
/// `tcp://host[:port]` for plain DNS-over-TCP, and `tls://host[:port]` for
/// DoT (behind the `dot` feature). `udp://` upstreams must use a literal IP
/// host, since this crate has no separate bootstrap step for them; `tcp://`
/// and `tls://` may use a hostname.
pub fn parse_any_upstream(addr: &str, base_opts: &Options) -> Result<Upstream, String> {
    let (scheme, rest) = match addr.split_once("://") {
        Some((scheme, rest)) => (scheme, rest),
        None => ("udp", addr),
    };

    match scheme {
        "udp" => {
            let sock_addr = if let Ok(sock_addr) = rest.parse::<SocketAddr>() {
                sock_addr
            } else if let Ok(ip) = rest.parse::<std::net::IpAddr>() {
                SocketAddr::new(ip, DEFAULT_PORT_PLAIN)
            } else {
                return Err(format!(
                    "plain upstream {addr:?} must use a literal IP host"
                ));
            };

            Ok(Upstream::PlainUdp(Arc::new(PlainUdpUpstream::new(
                sock_addr,
                base_opts.timeout,
            ))))
        }
        "tcp" => {
            let (host, port) = split_host_port(rest)?;
            Ok(Upstream::PlainTcp(Arc::new(PlainTcpUpstream::new(
                &host,
                port,
                clone_opts(base_opts),
            ))))
        }
        #[cfg(feature = "dot")]
        "tls" => {
            let (host, port) = split_host_port(rest)?;
            Ok(Upstream::Dot(Arc::new(DotUpstream::new(
                &host,
                port,
                clone_opts(base_opts),
            ))))
        }
        _ => Ok(Upstream::Doh(parse_upstream(addr, base_opts)?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_https_upstream() {
        let u = parse_upstream("https://dns.google/dns-query", &Options::default()).unwrap();
        assert_eq!(u.address(), "https://dns.google:443/dns-query");
    }

    #[test]
    fn parses_h3_upstream_with_port() {
        let u = parse_upstream("h3://1.1.1.1:443/dns-query", &Options::default()).unwrap();
        assert_eq!(u.address(), "https://1.1.1.1:443/dns-query");
    }

    #[test]
    fn rejects_unsupported_scheme() {
        assert!(parse_upstream("tls://1.1.1.1", &Options::default()).is_err());
    }

    #[test]
    fn parses_userinfo() {
        let u = parse_upstream(
            "https://user:pass@dns.google/dns-query",
            &Options::default(),
        )
        .unwrap();
        assert_eq!(u.address(), "https://dns.google:443/dns-query");
    }

    #[test]
    fn parses_udp_scheme_upstream() {
        let u = parse_any_upstream("udp://127.0.0.1:53", &Options::default()).unwrap();
        assert_eq!(u.address(), "udp://127.0.0.1:53");
    }

    #[test]
    fn bare_address_defaults_to_udp() {
        let u = parse_any_upstream("127.0.0.1", &Options::default()).unwrap();
        assert_eq!(u.address(), "udp://127.0.0.1:53");
    }

    #[test]
    fn bare_address_with_port_defaults_to_udp() {
        let u = parse_any_upstream("127.0.0.1:5353", &Options::default()).unwrap();
        assert_eq!(u.address(), "udp://127.0.0.1:5353");
    }

    #[test]
    fn plain_upstream_rejects_hostname() {
        assert!(parse_any_upstream("udp://dns.google", &Options::default()).is_err());
    }

    #[test]
    fn any_upstream_still_parses_doh() {
        let u = parse_any_upstream("https://dns.google/dns-query", &Options::default()).unwrap();
        assert_eq!(u.address(), "https://dns.google:443/dns-query");
    }

    #[test]
    fn parses_tcp_scheme_upstream_with_hostname() {
        let u = parse_any_upstream("tcp://dns.google:53", &Options::default()).unwrap();
        assert_eq!(u.address(), "tcp://dns.google:53");
    }

    #[test]
    fn parses_tcp_scheme_upstream_default_port() {
        let u = parse_any_upstream("tcp://127.0.0.1", &Options::default()).unwrap();
        assert_eq!(u.address(), "tcp://127.0.0.1:53");
    }

    #[cfg(feature = "dot")]
    #[test]
    fn parses_tls_scheme_upstream() {
        let u = parse_any_upstream("tls://dns.google", &Options::default()).unwrap();
        assert_eq!(u.address(), "tls://dns.google:853");
    }

    #[cfg(feature = "dot")]
    #[test]
    fn parses_tls_scheme_upstream_with_port() {
        let u = parse_any_upstream("tls://1.1.1.1:853", &Options::default()).unwrap();
        assert_eq!(u.address(), "tls://1.1.1.1:853");
    }

    #[test]
    fn parses_bracketed_ipv6_host() {
        let u = parse_any_upstream("tcp://[::1]:530", &Options::default()).unwrap();
        assert_eq!(u.address(), "tcp://[::1]:530");
    }
}
