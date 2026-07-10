use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, ValueEnum};

use doh_upstream::client::bootstrap::{DohResolver, ParallelResolver, PlainResolver, Resolver};
use doh_upstream::{
    Cache, CacheOptions, HttpVersion, Options, UpstreamConfig, UpstreamMode, parse_upstream,
};

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

pub fn init_log(verbose: u8, default_level: &str, no_timestamp: bool) {
    use tracing_subscriber::{EnvFilter, fmt};

    let mut filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));

    if verbose < 5 {
        filter = filter.add_directive("quinn_proto::connection=warn".parse().unwrap());
    }

    if verbose < 4 {
        filter = filter
            .add_directive("h2::proto=warn".parse().unwrap())
            .add_directive("rustls::client=warn".parse().unwrap())
            .add_directive("quinn_proto=warn".parse().unwrap())
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
    if no_timestamp || std::env::var_os("JOURNAL_STREAM").is_some() {
        builder.without_time().init();
    } else {
        builder.init();
    }
}

/// CLI-facing mirror of [`UpstreamMode`], needed because `clap::ValueEnum`
/// can't be derived on a type from another module without also deriving
/// `Clone`/`Copy` there in a way that fits clap's expectations.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum UpstreamModeArg {
    Ordered,
    RoundRobin,
    LoadBalance,
}

impl From<UpstreamModeArg> for UpstreamMode {
    fn from(mode: UpstreamModeArg) -> Self {
        match mode {
            UpstreamModeArg::Ordered => UpstreamMode::Ordered,
            UpstreamModeArg::RoundRobin => UpstreamMode::RoundRobin,
            UpstreamModeArg::LoadBalance => UpstreamMode::LoadBalance,
        }
    }
}

/// A minimal standalone DNS-over-HTTPS forwarding proxy.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Address to listen on for plain DNS (UDP and TCP). May be repeated to
    /// bind multiple addresses, e.g. --listen 0.0.0.0:53 --listen [::]:53.
    #[arg(long, conflicts_with = "port")]
    listen: Vec<SocketAddr>,

    /// Listen on this port for plain DNS (UDP and TCP), on both the IPv4 and
    /// IPv6 wildcard addresses (0.0.0.0 and [::]). Shorthand for
    /// --listen 0.0.0.0:<port> --listen [::]:<port>.
    #[arg(long, conflicts_with = "listen", short = 'p')]
    port: Option<u16>,

    /// Upstream rule, same syntax as one line of --upstream-file: a plain
    /// upstream (the default, used for anything not matched by a domain
    /// rule) or `[/domain1/.../domainN/]upstream1 upstream2 ...` to reserve
    /// upstreams for those domains and their subdomains, tried in order on
    /// failure. Upstreams are DoH URLs, e.g. https://dns.google/dns-query or
    /// h3://1.1.1.1/dns-query (HTTP/3-only), optionally with HTTP Basic Auth
    /// userinfo (https://user:pass@example.com/dns-query); or a plain
    /// DNS-over-UDP address with a literal IP host, e.g. udp://127.0.0.1:53
    /// or bare 127.0.0.1:53 (port defaults to 53), useful for routing
    /// reverse-DNS (in-addr.arpa/ip6.arpa) rules to a local resolver like
    /// dnsmasq that knows real DHCP lease hostnames. If the value names an
    /// existing file instead, it's read as an upstream config file (same
    /// syntax as --upstream-file). May be repeated; combined with the rules
    /// from --upstream-file, if given. At least one of --upstream or
    /// --upstream-file is required.
    #[arg(short = 'u', long = "upstream")]
    upstreams: Vec<String>,

    /// Path to an upstream config file, one rule per line; see --upstream
    /// for the line syntax. Blank lines and lines starting with # are
    /// ignored.
    #[arg(long)]
    upstream_file: Option<PathBuf>,

    /// Overall timeout for exchanges, bootstrap lookups, and H3 probes, in seconds.
    #[arg(long, default_value_t = 10)]
    timeout: u64,

    /// How to order the upstreams within a rule before trying them:
    /// "ordered" always prefers the first-configured upstream, falling back
    /// to later ones only on failure; "round-robin" rotates the starting
    /// upstream on each query; "load-balance" prefers whichever upstream has
    /// answered fastest recently, so traffic drifts toward the quicker
    /// server over time.
    #[arg(long, value_enum, default_value_t = UpstreamModeArg::Ordered)]
    upstream_mode: UpstreamModeArg,

    /// Server(s) used to resolve upstream hostnames: a plain DNS address
    /// (e.g. --bootstrap 1.1.1.1, port defaults to 53) or a DoH/DoH3 URL
    /// with a literal IP host (e.g. --bootstrap https://1.1.1.1/dns-query
    /// or --bootstrap h3://1.1.1.1/dns-query). May be repeated; queried in
    /// parallel, with the first successful, non-empty result used. Defaults
    /// to the system resolver if omitted.
    #[arg(long = "bootstrap", short = 'b')]
    bootstrap: Vec<String>,

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

    /// Disable timestamps in log output, e.g. when the log collector already
    /// adds its own (always implied under systemd's journal).
    #[arg(long)]
    no_timestamp: bool,

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

    /// Upstream for reverse-DNS (PTR) queries targeting private-use address
    /// ranges (RFC 1918/6303: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
    /// 127.0.0.0/8, 169.254.0.0/16, and their IPv6 equivalents), same syntax
    /// as one --upstream value. Takes precedence over --upstream/
    /// --upstream-file rules for those ranges. Useful for pointing at a
    /// local resolver like dnsmasq that knows real DHCP lease hostnames,
    /// e.g. --private-upstream udp://127.0.0.1:53.
    #[arg(long)]
    private_upstream: Option<String>,

    /// Address to listen on for DNS-over-QUIC (RFC 9250). May be repeated.
    /// Requires --tls-cert and --tls-key.
    #[cfg(feature = "doq-server")]
    #[arg(long, conflicts_with = "quic_port")]
    quic_listen: Vec<SocketAddr>,

    /// Listen on this port for DNS-over-QUIC, on both the IPv4 and IPv6
    /// wildcard addresses. Shorthand for --quic-listen 0.0.0.0:<port>
    /// --quic-listen [::]:<port>.
    #[cfg(feature = "doq-server")]
    #[arg(long, conflicts_with = "quic_listen")]
    quic_port: Option<u16>,

    /// Address to listen on for DNS-over-TLS (RFC 7858). May be repeated.
    /// Requires --tls-cert and --tls-key.
    #[cfg(feature = "dot-server")]
    #[arg(long, conflicts_with = "tls_port")]
    tls_listen: Vec<SocketAddr>,

    /// Listen on this port for DNS-over-TLS, on both the IPv4 and IPv6
    /// wildcard addresses. Shorthand for --tls-listen 0.0.0.0:<port>
    /// --tls-listen [::]:<port>.
    #[cfg(feature = "dot-server")]
    #[arg(long, conflicts_with = "tls_listen")]
    tls_port: Option<u16>,

    /// Address to listen on for DNS-over-HTTPS (RFC 8484). May be repeated.
    /// Also serves HTTP/3, on the same addresses, if the http3-server
    /// feature is enabled. Requires --tls-cert and --tls-key.
    #[cfg(feature = "doh-server")]
    #[arg(long, conflicts_with = "https_port")]
    https_listen: Vec<SocketAddr>,

    /// Listen on this port for DNS-over-HTTPS, on both the IPv4 and IPv6
    /// wildcard addresses. Shorthand for --https-listen 0.0.0.0:<port>
    /// --https-listen [::]:<port>.
    #[cfg(feature = "doh-server")]
    #[arg(long, conflicts_with = "https_listen")]
    https_port: Option<u16>,

    /// TLS certificate chain (PEM), for any of --quic-listen/--quic-port,
    /// --tls-listen/--tls-port, or --https-listen/--https-port. Shared by
    /// all enabled listeners.
    #[cfg(any(feature = "doq-server", feature = "dot-server", feature = "doh-server"))]
    #[arg(long, requires = "listener_tls_key")]
    listener_tls_cert: Option<PathBuf>,

    /// TLS private key (PEM), paired with --listener-tls-cert.
    #[cfg(any(feature = "doq-server", feature = "dot-server", feature = "doh-server"))]
    #[arg(long = "tls-key", requires = "listener_tls_cert")]
    listener_tls_key: Option<PathBuf>,

    /// Require HTTP Basic Auth on the DoH/DoH3 listeners, in `user:password`
    /// form. May be repeated to allow multiple credentials; any one
    /// matching pair authenticates a request. Combined with the credentials
    /// from --doh-auth-file, if given. If neither is given, the DoH/DoH3
    /// listeners accept unauthenticated requests.
    #[cfg(feature = "doh-server")]
    #[arg(long = "doh-auth")]
    doh_auth: Vec<String>,

    /// Path to a file of `user:password` credentials for the DoH/DoH3
    /// listeners, one per line; see --doh-auth for the line syntax. Blank
    /// lines and lines starting with # are ignored.
    #[cfg(feature = "doh-server")]
    #[arg(long)]
    doh_auth_file: Option<PathBuf>,

    /// Address to listen on for DNSCrypt (both UDP and TCP). May be
    /// repeated. Requires --dnscrypt-config.
    #[cfg(feature = "dnscrypt-server")]
    #[arg(long, conflicts_with = "dnscrypt_port")]
    dnscrypt_listen: Vec<SocketAddr>,

    /// Listen on this port for DNSCrypt, on both the IPv4 and IPv6 wildcard
    /// addresses. Shorthand for --dnscrypt-listen 0.0.0.0:<port>
    /// --dnscrypt-listen [::]:<port>.
    #[cfg(feature = "dnscrypt-server")]
    #[arg(long, conflicts_with = "dnscrypt_listen")]
    dnscrypt_port: Option<u16>,

    /// Path to a DNSCrypt resolver config file (provider name and signing
    /// keys), as written by --dnscrypt-generate-config. Required to enable
    /// --dnscrypt-listen/--dnscrypt-port.
    #[cfg(feature = "dnscrypt-server")]
    #[arg(long)]
    dnscrypt_config: Option<PathBuf>,

    /// Generates a new DNSCrypt resolver config (provider signing key and
    /// resolver keypair) for --dnscrypt-provider-name, writes it to this
    /// path, prints the resulting sdns:// stamp for clients to use, and
    /// exits without starting any listener.
    #[cfg(feature = "dnscrypt-server")]
    #[arg(long, requires = "dnscrypt_provider_name")]
    dnscrypt_generate_config: Option<PathBuf>,

    /// Provider name for --dnscrypt-generate-config, e.g.
    /// 2.dnscrypt-cert.example.org.
    #[cfg(feature = "dnscrypt-server")]
    #[arg(long)]
    dnscrypt_provider_name: Option<String>,
}

/// The standard reverse-DNS zones for RFC 1918 private and RFC 6303
/// special-use address ranges, mirroring the zones `hickory_proto`'s
/// `usage` module documents for the same ranges.
const PRIVATE_REVERSE_ZONES: &[&str] = &[
    // RFC 1918 IPv4 private-use ranges.
    "10.in-addr.arpa",
    "16.172.in-addr.arpa",
    "17.172.in-addr.arpa",
    "18.172.in-addr.arpa",
    "19.172.in-addr.arpa",
    "20.172.in-addr.arpa",
    "21.172.in-addr.arpa",
    "22.172.in-addr.arpa",
    "23.172.in-addr.arpa",
    "24.172.in-addr.arpa",
    "25.172.in-addr.arpa",
    "26.172.in-addr.arpa",
    "27.172.in-addr.arpa",
    "28.172.in-addr.arpa",
    "29.172.in-addr.arpa",
    "30.172.in-addr.arpa",
    "31.172.in-addr.arpa",
    "168.192.in-addr.arpa",
    // RFC 6303 special-use ranges.
    "127.in-addr.arpa",
    "254.169.in-addr.arpa",
    "c.f.ip6.arpa",
    "d.f.ip6.arpa",
    "8.e.f.ip6.arpa",
    "9.e.f.ip6.arpa",
    "a.e.f.ip6.arpa",
    "b.e.f.ip6.arpa",
    "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
];

/// Builds a single `[/zone1/.../zoneN/]upstream` config line routing every
/// private-use reverse-DNS zone to `upstream`.
fn private_upstream_line(upstream: &str) -> String {
    let zones = PRIVATE_REVERSE_ZONES.join("/");
    format!("[/{zones}/]{upstream}")
}

/// Builds the [`Resolver`] for one `--bootstrap` value: a DoH/DoH3 URL
/// (`https://`/`h3://`, with a literal IP host, since it has no bootstrap
/// resolver of its own) or a plain DNS address, defaulting its port to 53
/// when omitted (e.g. `1.1.1.1` or `2606:4700:4700::1111`, in addition to
/// `1.1.1.1:53` or `[2606:4700:4700::1111]:53`).
fn parse_bootstrap(s: &str, doh_opts: &Options) -> Result<Arc<dyn Resolver>, String> {
    if s.contains("://") {
        let upstream = parse_upstream(s, doh_opts)?;
        if upstream.host().parse::<std::net::IpAddr>().is_err() {
            return Err(format!(
                "bootstrap {s:?} must use a literal IP host, not a hostname"
            ));
        }
        return Ok(Arc::new(DohResolver(upstream)));
    }

    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(Arc::new(PlainResolver::new(addr, doh_opts.timeout)));
    }
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        return Ok(Arc::new(PlainResolver::new(
            SocketAddr::new(ip, 53),
            doh_opts.timeout,
        )));
    }
    Err(format!("invalid bootstrap address: {s}"))
}

/// Expands a `--*-listen`/`--*-port` flag pair into the effective set of
/// addresses to listen on: `listen` verbatim (possibly repeated), or `port`
/// expanded to the IPv4 and IPv6 wildcard addresses. Empty (rather than
/// defaulting to any address) when neither was given, since these listeners
/// are opt-in unlike the always-on plain DNS listener.
#[cfg(any(
    feature = "doq-server",
    feature = "dot-server",
    feature = "doh-server",
    feature = "dnscrypt-server"
))]
fn expand_listen(listen: &[SocketAddr], port: Option<u16>) -> Vec<SocketAddr> {
    if let Some(port) = port {
        return vec![
            SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), port),
            SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), port),
        ];
    }
    listen.to_vec()
}

impl Args {
    /// Resolves the effective set of addresses to listen on: `--listen`
    /// verbatim (possibly repeated), `--port` expanded to the IPv4 and IPv6
    /// wildcard addresses, or the default of `127.0.0.1:53` when neither was
    /// given and no secure listener (`--quic-listen`/`--quic-port`,
    /// `--tls-listen`/`--tls-port`, `--https-listen`/`--https-port`) is
    /// enabled either, in which case the plain DNS listener is skipped
    /// unless explicitly requested.
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
        if self.secure_listener_enabled() {
            return Vec::new();
        }
        vec![SocketAddr::from(([127, 0, 0, 1], 53))]
    }

    /// Whether any of the secure listeners (DoQ, DoT, DoH/DoH3, DNSCrypt)
    /// were requested via `--*-listen` or `--*-port`.
    #[cfg_attr(
        not(any(
            feature = "doq-server",
            feature = "dot-server",
            feature = "doh-server",
            feature = "dnscrypt-server"
        )),
        allow(clippy::unused_self)
    )]
    fn secure_listener_enabled(&self) -> bool {
        #[cfg(feature = "doq-server")]
        let quic = !self.quic_listen.is_empty() || self.quic_port.is_some();
        #[cfg(not(feature = "doq-server"))]
        let quic = false;

        #[cfg(feature = "dot-server")]
        let tls = !self.tls_listen.is_empty() || self.tls_port.is_some();
        #[cfg(not(feature = "dot-server"))]
        let tls = false;

        #[cfg(feature = "doh-server")]
        let https = !self.https_listen.is_empty() || self.https_port.is_some();
        #[cfg(not(feature = "doh-server"))]
        let https = false;

        #[cfg(feature = "dnscrypt-server")]
        let dnscrypt = !self.dnscrypt_listen.is_empty() || self.dnscrypt_port.is_some();
        #[cfg(not(feature = "dnscrypt-server"))]
        let dnscrypt = false;

        quic || tls || https || dnscrypt
    }
}

#[cfg(feature = "dnscrypt-server")]
fn run_dnscrypt_generate_config(path: &std::path::Path, provider_name: &str) -> Result<(), String> {
    let config = doh_upstream::client::dnscrypt::keygen::ResolverConfig::generate(provider_name);
    doh_upstream::client::dnscrypt::config::save(path, &config)?;

    println!("Wrote DNSCrypt resolver config to {}", path.display());
    println!(
        "Stamp (replace the host:port with your public address before distributing to clients):"
    );
    println!("{}", config.stamp("0.0.0.0:443".parse().unwrap()));
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    #[cfg(feature = "dnscrypt-server")]
    if let Some(path) = &args.dnscrypt_generate_config {
        let provider_name = args
            .dnscrypt_provider_name
            .as_ref()
            .ok_or("--dnscrypt-provider-name is required with --dnscrypt-generate-config")?;
        run_dnscrypt_generate_config(path, provider_name)?;
        return Ok(());
    }

    init_log(args.verbose, &args.log_level, args.no_timestamp);

    tracing::info!(
        upstream = ?args.upstreams,
        upstream_file = ?args.upstream_file,
        bootstrap = ?args.bootstrap,
        private_upstream = ?args.private_upstream,
        insecure = args.insecure,
        prefer_ipv6 = args.prefer_ipv6,
        cache = args.cache,
        timeout = args.timeout,
        "startup config"
    );

    install_crypto_provider();

    #[cfg_attr(not(feature = "http3"), allow(unused_mut))]
    let mut http_versions = vec![HttpVersion::Http11, HttpVersion::Http2];
    #[cfg(feature = "http3")]
    if args.http3 {
        http_versions.push(HttpVersion::Http3);
    }

    let timeout = Some(Duration::from_secs(args.timeout));
    let bootstrap_opts = Options {
        http_versions: http_versions.clone(),
        timeout,
        insecure_skip_verify: args.insecure,
        prefer_ipv6: args.prefer_ipv6,
        ..Default::default()
    };
    let bootstrap = (!args.bootstrap.is_empty())
        .then(|| {
            let resolvers = args
                .bootstrap
                .iter()
                .map(|s| parse_bootstrap(s, &bootstrap_opts))
                .collect::<Result<Vec<_>, _>>()?;
            Ok::<_, String>(Arc::new(ParallelResolver(resolvers)) as Arc<dyn Resolver>)
        })
        .transpose()?;

    let base_opts = Options {
        bootstrap,
        http_versions,
        timeout,
        insecure_skip_verify: args.insecure,
        prefer_ipv6: args.prefer_ipv6,
        ..Default::default()
    };

    if args.upstreams.is_empty() && args.upstream_file.is_none() {
        return Err("at least one of --upstream or --upstream-file is required".into());
    }

    let upstream_file_text = args
        .upstream_file
        .as_ref()
        .map(|path| {
            std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))
        })
        .transpose()?;
    let upstream_arg_text = args
        .upstreams
        .iter()
        .map(|s| {
            let path = std::path::Path::new(s);
            if path.is_file() {
                std::fs::read_to_string(path).map_err(|e| format!("reading {s}: {e}"))
            } else {
                Ok(s.clone())
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    let private_upstream_line = args.private_upstream.as_deref().map(private_upstream_line);
    let lines: Vec<&str> = private_upstream_line
        .iter()
        .map(String::as_str)
        .chain(upstream_arg_text.iter().flat_map(|text| text.lines()))
        .chain(upstream_file_text.iter().flat_map(|text| text.lines()))
        .collect();
    let upstream_config =
        UpstreamConfig::parse_with_mode(&lines, &base_opts, args.upstream_mode.into()).map_err(
            |errs| {
                let joined = errs
                    .iter()
                    .map(|(idx, e)| format!("line {}: {e}", idx + 1))
                    .collect::<Vec<_>>()
                    .join("; ");
                format!("parsing upstreams: {joined}")
            },
        )?;

    #[cfg(feature = "doh-server")]
    let doh_credentials = {
        let doh_auth_file_text = args
            .doh_auth_file
            .as_ref()
            .map(|path| {
                std::fs::read_to_string(path)
                    .map_err(|e| format!("reading {}: {e}", path.display()))
            })
            .transpose()?;
        let pairs = args
            .doh_auth
            .iter()
            .map(String::as_str)
            .chain(
                doh_auth_file_text
                    .iter()
                    .flat_map(|text| text.lines())
                    .map(str::trim)
                    .filter(|line| !line.is_empty() && !line.starts_with('#')),
            )
            .map(doh_upstream::Credentials::parse_pair)
            .collect::<Result<Vec<_>, _>>()?;
        Arc::new(doh_upstream::Credentials::new(pairs))
    };

    let listen_addrs = args.listen_addrs();
    tracing::info!(listen = ?listen_addrs, upstream_file = ?args.upstream_file, "forwarding");

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
    doh_upstream::serve_all(&listen_addrs, handler.clone()).await?;

    #[cfg(any(feature = "doq-server", feature = "dot-server", feature = "doh-server"))]
    {
        let quic_addrs = {
            #[cfg(feature = "doq-server")]
            {
                expand_listen(&args.quic_listen, args.quic_port)
            }
            #[cfg(not(feature = "doq-server"))]
            {
                Vec::<SocketAddr>::new()
            }
        };
        let tls_addrs = {
            #[cfg(feature = "dot-server")]
            {
                expand_listen(&args.tls_listen, args.tls_port)
            }
            #[cfg(not(feature = "dot-server"))]
            {
                Vec::<SocketAddr>::new()
            }
        };
        let https_addrs = {
            #[cfg(feature = "doh-server")]
            {
                expand_listen(&args.https_listen, args.https_port)
            }
            #[cfg(not(feature = "doh-server"))]
            {
                Vec::<SocketAddr>::new()
            }
        };

        if !quic_addrs.is_empty() || !tls_addrs.is_empty() || !https_addrs.is_empty() {
            let cert = args.listener_tls_cert.as_ref().ok_or(
                "--tls-cert is required to enable any of --quic-listen/--tls-listen/--https-listen",
            )?;
            let key = args
                .listener_tls_key
                .as_ref()
                .ok_or("--tls-key is required")?;

            #[cfg(feature = "doq-server")]
            if !quic_addrs.is_empty() {
                let tls_config = doh_upstream::listener::tls_config::load_server_tls_config(
                    cert,
                    key,
                    vec![doh_upstream::listener::doq::DOQ_ALPN.to_vec()],
                )?;
                tracing::info!(listen = ?quic_addrs, "doq listening");
                doh_upstream::listener::doq::serve_all(
                    &quic_addrs,
                    Arc::new(tls_config),
                    handler.clone(),
                )
                .await?;
            }

            #[cfg(feature = "dot-server")]
            if !tls_addrs.is_empty() {
                let tls_config =
                    doh_upstream::listener::tls_config::load_server_tls_config(cert, key, vec![])?;
                tracing::info!(listen = ?tls_addrs, "dot listening");
                doh_upstream::listener::dot::serve_all(
                    &tls_addrs,
                    Arc::new(tls_config),
                    handler.clone(),
                )
                .await?;
            }

            #[cfg(feature = "doh-server")]
            if !https_addrs.is_empty() {
                #[cfg_attr(not(feature = "http3-server"), allow(unused_mut))]
                let mut alpn: Vec<Vec<u8>> = doh_upstream::listener::doh::DOH_ALPN
                    .iter()
                    .map(|p| p.to_vec())
                    .collect();
                #[cfg(feature = "http3-server")]
                alpn.extend(
                    doh_upstream::listener::doh3::DOH3_ALPN
                        .iter()
                        .map(|p| p.to_vec()),
                );
                let tls_config =
                    doh_upstream::listener::tls_config::load_server_tls_config(cert, key, alpn)?;
                let tls_config = Arc::new(tls_config);
                tracing::info!(listen = ?https_addrs, "doh listening");
                doh_upstream::listener::doh::serve_all(
                    &https_addrs,
                    Arc::clone(&tls_config),
                    handler.clone(),
                    Arc::clone(&doh_credentials),
                )
                .await?;

                #[cfg(feature = "http3-server")]
                {
                    tracing::info!(listen = ?https_addrs, "doh3 listening");
                    doh_upstream::listener::doh3::serve_all(
                        &https_addrs,
                        tls_config,
                        handler.clone(),
                        Arc::clone(&doh_credentials),
                    )
                    .await?;
                }
            }
        }
    }

    #[cfg(feature = "dnscrypt-server")]
    {
        let dnscrypt_addrs = expand_listen(&args.dnscrypt_listen, args.dnscrypt_port);
        if !dnscrypt_addrs.is_empty() {
            let config_path = args.dnscrypt_config.as_ref().ok_or(
                "--dnscrypt-config is required to enable --dnscrypt-listen/--dnscrypt-port",
            )?;
            let resolver_config = doh_upstream::client::dnscrypt::config::load(config_path)?;

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0);
            let cert_ttl = doh_upstream::client::dnscrypt::keygen::DEFAULT_CERT_TTL_SECS;
            let server_config = doh_upstream::listener::dnscrypt::DnsCryptServerConfig::new(
                resolver_config.resolver_secret_key,
                &resolver_config.provider_signing_key,
                resolver_config.provider_name,
                *b"DNSC\0\0\0\0",
                1,
                now,
                now.saturating_add(cert_ttl),
            );

            tracing::info!(listen = ?dnscrypt_addrs, "dnscrypt listening");
            doh_upstream::listener::dnscrypt::serve_all(
                &dnscrypt_addrs,
                &dnscrypt_addrs,
                Arc::new(server_config),
                handler.clone(),
            )
            .await?;
        }
    }

    // `serve` spawns its listeners and returns once bound; block forever so
    // the process keeps running them.
    std::future::pending::<()>().await;
    Ok(())
}
