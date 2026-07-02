use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;

use doh_upstream::bootstrap::{ParallelResolver, PlainResolver};
use doh_upstream::{Cache, CacheOptions, HttpVersion, Options, UpstreamConfig};

#[cfg(all(feature = "crypto-ring", feature = "crypto-aws-lc-rs"))]
compile_error!(
    "features \"crypto-ring\" and \"crypto-aws-lc-rs\" are mutually exclusive; enable exactly one"
);
#[cfg(not(any(feature = "crypto-ring", feature = "crypto-aws-lc-rs")))]
compile_error!("exactly one of \"crypto-ring\" or \"crypto-aws-lc-rs\" must be enabled");

/// Installs the process-wide rustls `CryptoProvider` selected at compile
/// time via the `crypto-ring`/`crypto-aws-lc-rs` features. rustls needs this
/// installed before any TLS connection is made; the lib crate leaves this to
/// its consumer.
fn install_crypto_provider() {
    #[cfg(feature = "crypto-ring")]
    let provider = tokio_rustls::rustls::crypto::ring::default_provider();
    #[cfg(feature = "crypto-aws-lc-rs")]
    let provider = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider();

    provider
        .install_default()
        .expect("no CryptoProvider installed yet");
}

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
            .add_directive("h2::hpack=warn".parse().unwrap())
            .add_directive("h2::client=warn".parse().unwrap());
    }
    if verbose < 2 {
        filter = filter
            .add_directive("hyper_util::client=warn".parse().unwrap())
            .add_directive("hickory_proto=warn".parse().unwrap())
            .add_directive("rustls=warn".parse().unwrap())
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
    /// Address to listen on for plain DNS (UDP and TCP). May be repeated to
    /// bind multiple addresses, e.g. --listen 0.0.0.0:53 --listen [::]:53.
    #[arg(long, conflicts_with = "port")]
    listen: Vec<SocketAddr>,

    /// Listen on this port for plain DNS (UDP and TCP), on both the IPv4 and
    /// IPv6 wildcard addresses (0.0.0.0 and [::]). Shorthand for
    /// --listen 0.0.0.0:<port> --listen [::]:<port>.
    #[arg(long, conflicts_with = "listen")]
    port: Option<u16>,

    /// Path to an upstream config file, one rule per line. A line is either
    /// a plain upstream (the default, used for anything not matched by a
    /// domain rule) or `[/domain1/.../domainN/]upstream1 upstream2 ...` to
    /// reserve upstreams for those domains and their subdomains, tried in
    /// order on failure. Upstreams are DoH URLs, e.g.
    /// https://dns.google/dns-query or h3://1.1.1.1/dns-query (HTTP/3-only),
    /// optionally with HTTP Basic Auth userinfo
    /// (https://user:pass@example.com/dns-query). Blank lines and lines
    /// starting with # are ignored.
    #[arg(long)]
    upstream_file: PathBuf,

    /// Overall timeout for exchanges, bootstrap lookups, and H3 probes, in seconds.
    #[arg(long, default_value_t = 10)]
    timeout: u64,

    /// Plain DNS server(s) used to resolve upstream hostnames, e.g.
    /// --bootstrap 1.1.1.1 --bootstrap [2606:4700:4700::1111]:53. Port
    /// defaults to 53 if omitted. May be repeated; queried in parallel, with
    /// the first successful, non-empty result used. Defaults to the system
    /// resolver if omitted.
    #[arg(long, value_parser = parse_bootstrap_addr)]
    bootstrap: Vec<SocketAddr>,

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

    /// Cache upstream responses in memory.
    #[arg(long)]
    cache: bool,

    /// Maximum number of cached responses.
    #[arg(long, default_value_t = 1000)]
    cache_size: usize,

    /// Floor applied to a cached response's TTL, in seconds.
    #[arg(long, default_value_t = 0)]
    cache_min_ttl: u64,

    /// Ceiling applied to a cached response's TTL, in seconds. 0 means
    /// unbounded.
    #[arg(long, default_value_t = 0)]
    cache_max_ttl: u64,
}

/// Parses a `--bootstrap` value as a `SocketAddr`, defaulting the port to 53
/// when omitted (e.g. `1.1.1.1` or `2606:4700:4700::1111`, in addition to
/// `1.1.1.1:53` or `[2606:4700:4700::1111]:53`).
fn parse_bootstrap_addr(s: &str) -> Result<SocketAddr, String> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    Err(format!("invalid bootstrap address: {s}"))
}

impl Args {
    /// Resolves the effective set of addresses to listen on: `--listen`
    /// verbatim (possibly repeated), `--port` expanded to the IPv4 and IPv6
    /// wildcard addresses, or the default of `127.0.0.1:53` when neither was
    /// given.
    fn listen_addrs(&self) -> Vec<SocketAddr> {
        if let Some(port) = self.port {
            return vec![
                SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), port),
                SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), port),
            ];
        }
        if !self.listen.is_empty() {
            return self.listen.clone();
        }
        vec![SocketAddr::from(([127, 0, 0, 1], 53))]
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    init_log(args.verbose, &args.log_level);

    install_crypto_provider();

    #[cfg_attr(not(feature = "http3"), allow(unused_mut))]
    let mut http_versions = vec![HttpVersion::Http11, HttpVersion::Http2];
    #[cfg(feature = "http3")]
    if args.http3 {
        http_versions.push(HttpVersion::Http3);
    }

    let timeout = Some(Duration::from_secs(args.timeout));
    let bootstrap = (!args.bootstrap.is_empty()).then(|| {
        let resolvers = args
            .bootstrap
            .iter()
            .map(|addr| Arc::new(PlainResolver::new(*addr, timeout)) as Arc<_>)
            .collect();
        Arc::new(ParallelResolver(resolvers)) as Arc<_>
    });

    let base_opts = Options {
        bootstrap,
        http_versions,
        timeout,
        insecure_skip_verify: args.insecure,
        prefer_ipv6: args.prefer_ipv6,
        ..Default::default()
    };

    let upstream_text = std::fs::read_to_string(&args.upstream_file)
        .map_err(|e| format!("reading {}: {e}", args.upstream_file.display()))?;
    let lines: Vec<&str> = upstream_text.lines().collect();
    let upstream_config = UpstreamConfig::parse(&lines, &base_opts).map_err(|errs| {
        let joined = errs
            .iter()
            .map(|(idx, e)| format!("line {}: {e}", idx + 1))
            .collect::<Vec<_>>()
            .join("; ");
        format!("parsing {}: {joined}", args.upstream_file.display())
    })?;

    let listen_addrs = args.listen_addrs();
    tracing::info!(listen = ?listen_addrs, upstream_file = %args.upstream_file.display(), "forwarding");

    let mut handler = Arc::new(upstream_config).into_handler();
    if args.cache {
        let cache_opts = CacheOptions {
            size: NonZeroUsize::new(args.cache_size).ok_or("--cache-size must be nonzero")?,
            min_ttl: Duration::from_secs(args.cache_min_ttl),
            max_ttl: (args.cache_max_ttl > 0).then(|| Duration::from_secs(args.cache_max_ttl)),
        };
        tracing::info!(size = args.cache_size, "caching enabled");
        handler = Arc::new(Cache::new(cache_opts)).into_handler(handler);
    }
    doh_upstream::serve_all(&listen_addrs, handler).await?;

    // `serve` spawns its listeners and returns once bound; block forever so
    // the process keeps running them.
    std::future::pending::<()>().await;
    Ok(())
}
