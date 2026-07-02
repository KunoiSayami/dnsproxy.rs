use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use hyper::Uri;

use doh_upstream::{DohUpstream, HttpVersion, Options};

pub fn init_log(verbose: u8, default_level: &str) {
    use tracing_subscriber::{EnvFilter, fmt};

    let mut filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));

    if verbose < 4 {
        filter = filter
            .add_directive("h2::proto=warn".parse().unwrap())
            .add_directive("rustls::client=warn".parse().unwrap())
            .add_directive("rustls_platform_verifier=warn".parse().unwrap());
    }
    if verbose < 3 {
        filter = filter
            .add_directive("h2::codec=warn".parse().unwrap())
            .add_directive("hpack=warn".parse().unwrap())
            .add_directive("h2::client=warn".parse().unwrap());
    }
    if verbose < 2 {
        filter = filter
            .add_directive("hyper_util::client=warn".parse().unwrap())
            .add_directive("h2::frame=warn".parse().unwrap());
    }
    if verbose < 1 {
        filter = filter.add_directive("reqwest::connect=warn".parse().unwrap());
    }

    let builder = fmt().with_env_filter(filter);
    if std::env::var_os("JOURNAL_STREAM").is_some() {
        builder.without_time().init();
    } else {
        builder.init();
    }
}

/// A minimal standalone DNS-over-HTTPS forwarding proxy.
#[derive(Parser)]
struct Args {
    /// Address to listen on for plain DNS (UDP and TCP).
    #[arg(long, default_value = "127.0.0.1:53")]
    listen: SocketAddr,

    /// Upstream DoH server, e.g. https://dns.google/dns-query. May include
    /// HTTP Basic Auth credentials as userinfo, e.g.
    /// https://user:pass@example.com/dns-query.
    #[arg(long)]
    upstream: String,

    /// Overall timeout for exchanges, bootstrap lookups, and H3 probes, in seconds.
    #[arg(long, default_value_t = 10)]
    timeout: u64,

    /// Disable TLS certificate verification. Dangerous.
    #[arg(long)]
    insecure: bool,

    /// Prefer IPv6 addresses when the bootstrap resolves multiple families.
    #[arg(long)]
    prefer_ipv6: bool,

    /// Allow HTTP/3, in addition to HTTP/1.1 and HTTP/2.
    #[cfg(feature = "http3")]
    #[arg(long)]
    http3: bool,

    /// Increase logging verbosity (repeatable), unmuting noisier dependency
    /// targets (h2, hpack, hyper_util) at each step.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Default log level, used when RUST_LOG is unset.
    #[arg(long, default_value = "info")]
    log_level: String,
}

/// Splits `user:pass@` userinfo out of a `scheme://user:pass@host/path` URL,
/// since `http::Uri` treats the whole authority as opaque and won't parse it
/// for us. Returns the credentials (if any) and the URL with userinfo removed.
fn extract_userinfo(
    url: &str,
) -> Result<(Option<(String, String)>, String), Box<dyn std::error::Error>> {
    let (scheme_sep, rest) = url
        .split_once("://")
        .ok_or("--upstream must be an absolute URL")?;

    let Some(at) = rest.rfind('@') else {
        return Ok((None, url.to_owned()));
    };
    let (userinfo, host_and_path) = rest.split_at(at);
    let host_and_path = &host_and_path[1..]; // skip '@'

    let (user, pass) = userinfo
        .split_once(':')
        .ok_or("userinfo in --upstream must be user:pass")?;

    Ok((
        Some((user.to_owned(), pass.to_owned())),
        format!("{scheme_sep}://{host_and_path}"),
    ))
}

#[cfg(test)]
mod tests {
    use super::extract_userinfo;

    #[test]
    fn no_userinfo() {
        let (auth, url) = extract_userinfo("https://example.com/dns-query").unwrap();
        assert_eq!(auth, None);
        assert_eq!(url, "https://example.com/dns-query");
    }

    #[test]
    fn userinfo_with_at_in_password() {
        let (auth, url) = extract_userinfo("https://user:p@ss@example.com/dns-query").unwrap();
        assert_eq!(auth, Some(("user".to_owned(), "p@ss".to_owned())));
        assert_eq!(url, "https://example.com/dns-query");
    }

    #[test]
    fn userinfo_without_colon_is_rejected() {
        assert!(extract_userinfo("https://baduser@example.com/dns-query").is_err());
    }

    #[test]
    fn missing_scheme_separator_is_rejected() {
        assert!(extract_userinfo("example.com/dns-query").is_err());
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    init_log(args.verbose, &args.log_level);

    // rustls needs a process-wide CryptoProvider installed before any TLS
    // connection is made; the lib crate leaves this to its consumer.
    tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("no CryptoProvider installed yet");

    let (basic_auth, stripped_upstream) = extract_userinfo(&args.upstream)?;
    let upstream_uri: Uri = stripped_upstream
        .parse()
        .map_err(|e| format!("invalid --upstream: {e}"))?;

    let host = upstream_uri
        .host()
        .ok_or("--upstream must include a host")?
        .to_owned();
    let path = upstream_uri.path().to_owned();

    #[cfg_attr(not(feature = "http3"), allow(unused_mut))]
    let mut http_versions = vec![HttpVersion::Http11, HttpVersion::Http2];
    #[cfg(feature = "http3")]
    if args.http3 {
        http_versions.push(HttpVersion::Http3);
    }

    let opts = Options {
        http_versions,
        timeout: Some(Duration::from_secs(args.timeout)),
        insecure_skip_verify: args.insecure,
        prefer_ipv6: args.prefer_ipv6,
        basic_auth,
        ..Default::default()
    };

    let upstream = Arc::new(DohUpstream::new(
        &host,
        upstream_uri.port_u16(),
        &path,
        opts,
    ));
    tracing::info!(listen = %args.listen, upstream = %upstream.address(), "forwarding");

    let handler = upstream.into_handler();
    doh_upstream::serve(args.listen, handler).await?;

    // `serve` spawns its listeners and returns once bound; block forever so
    // the process keeps running them.
    std::future::pending::<()>().await;
    Ok(())
}
