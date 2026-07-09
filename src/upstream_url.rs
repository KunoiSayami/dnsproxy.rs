//! Parses a single upstream address string into an [`Upstream`], mirroring
//! the relevant subset of `AddressToUpstream`/`urlToUpstream` in Go's
//! `upstream/upstream.go`: `https://`/`h3://` for DoH/DoH3, and `udp://` (or
//! a bare `host[:port]` with no scheme, which defaults to `udp://` just as in
//! Go) for plain DNS-over-UDP. `tcp://` isn't implemented, since this crate
//! has no plain DNS-over-TCP client.

use std::net::SocketAddr;
use std::sync::Arc;

use hyper::Uri;

use crate::doh::DohUpstream;
use crate::options::{HttpVersion, Options};
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

/// Parses `addr` into an [`Upstream`], extending [`parse_upstream`] with
/// `udp://host[:port]` (or a bare `host[:port]`/`host`, which defaults to
/// `udp://` just as in Go's `AddressToUpstream`) for plain DNS-over-UDP.
/// Plain upstreams must use a literal IP host, since this crate has no
/// separate bootstrap step for them.
pub fn parse_any_upstream(addr: &str, base_opts: &Options) -> Result<Upstream, String> {
    let (scheme, rest) = match addr.split_once("://") {
        Some((scheme, rest)) => (scheme, rest),
        None => ("udp", addr),
    };

    if scheme != "udp" {
        return Ok(Upstream::Doh(parse_upstream(addr, base_opts)?));
    }

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
}
