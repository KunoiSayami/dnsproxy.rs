# doh-upstream

A DNS upstream client for Rust, ported from [AdGuard dnsproxy](https://github.com/AdguardTeam/dnsproxy)'s
Go implementation. Started as a DNS-over-HTTPS ([RFC 8484](https://www.rfc-editor.org/rfc/rfc8484))
client (`upstream/doh.go`) and has grown to cover DoT, DoH3, DoQ, and plain
DNS-over-UDP/TCP.

HTTP/1.1 and HTTP/2 are supported unconditionally; HTTP/3 is available behind
the `http3` feature and races a QUIC handshake against TLS to decide whether
to prefer it, matching the Go client's probing behavior. DNS-over-TLS is
available behind the `dot` feature, and DNS-over-QUIC behind the `doq`
feature.

## Features

- DNS message exchange over DoH using `hyper` (HTTP/1.1 / HTTP/2) and
  optionally `quinn`/`h3` (HTTP/3)
- DNS-over-TLS (`tls://`, RFC 7858), behind the `dot` feature
- DNS-over-QUIC (`quic://`, RFC 9250), behind the `doq` feature
- Plain DNS-over-UDP (`udp://`) and DNS-over-TCP (`tcp://`)
- Configurable bootstrap resolver for resolving the upstream server's
  hostname
- Automatic retry with a fresh client on retryable errors (timeouts, QUIC
  0-RTT rejection)
- Optional HTTP Basic Auth credentials sent with every DoH upstream request
- A minimal plain-DNS server (`serve`/`serve_all`) that forwards UDP/TCP
  queries to any async handler, so a `DohUpstream` can be turned into a
  local DNS-to-DoH proxy with `into_handler`, listening on one or more
  addresses at once
- An optional in-memory response cache (`Cache`), keyed by question name,
  type, and class, with configurable TTL floor/ceiling and an LRU eviction
  policy
- Domain-scoped upstream routing (`UpstreamConfig`), parsing an AdGuard
  dnsproxy-style upstream list — including `[/domain1/.../domainN/]upstream1
  upstream2 ...` rules — with hierarchical suffix matching and in-order
  fallback across an upstream rule's servers, mixing any of the supported
  transports

## Standalone binary

The crate also builds a `doh-upstream` binary: a minimal standalone
DNS-over-HTTPS forwarding proxy.

```sh
echo 'https://dns.google/dns-query' > upstreams.txt
doh-upstream --upstream-file upstreams.txt --port 53
```

Domain-scoped routing, with fallback across upstreams tried in order:

```
# default upstream, used for anything not matched below
https://dns.google/dns-query

# reserved for example.com and its subdomains; tries 1.1.1.1 first
[/example.com/]https://1.1.1.1/dns-query h3://1.0.0.1/dns-query
```

Useful flags:

| Flag | Description |
|---|---|
| `--listen <addr>` | Address to listen on for plain DNS (UDP+TCP). Repeatable. |
| `--port <port>` | Shorthand for listening on the IPv4 and IPv6 wildcard addresses on this port. |
| `--upstream-file <path>` | Path to an upstream config file (see above). Upstreams may be DoH URLs (`https://`, or `h3://` for HTTP/3-only, optionally with HTTP Basic Auth as `user:pass@host`), `tls://host[:port]` for DoT (requires the `dot` feature), `quic://host[:port]` for DoQ (requires the `doq` feature), `tcp://host[:port]` for plain DNS-over-TCP, or `udp://host[:port]`/a bare `host[:port]` for plain DNS-over-UDP. |
| `--timeout <secs>` | Overall timeout for exchanges, bootstrap lookups, and H3 probes (default `10`). |
| `--bootstrap <addr>` | Server used to resolve upstream hostnames: a plain DNS address, e.g. `1.1.1.1` or `[2606:4700:4700::1111]:53` (port defaults to `53`), or a DoH/DoH3 URL with a literal IP host, e.g. `https://1.1.1.1/dns-query` (`h3://` requires `--http3`). Repeatable; queried in parallel. Defaults to the system resolver. |
| `--insecure` | Disable TLS certificate verification. |
| `--prefer-ipv6` | Prefer IPv6 addresses when the bootstrap resolves multiple families. |
| `--http3` | Allow HTTP/3, in addition to HTTP/1.1 and HTTP/2 (requires the `http3` feature). |
| `-v`, `--verbose` | Increase logging verbosity (repeatable). |
| `--log-level <level>` | Default log level when `RUST_LOG` is unset (default `info`). |
| `--cache` | Cache upstream responses in memory. |
| `--cache-size <n>` | Maximum number of cached responses (default `1000`). |
| `--cache-min-ttl <secs>` | Floor applied to a cached response's TTL (default `0`). |
| `--cache-max-ttl <secs>` | Ceiling applied to a cached response's TTL; `0` means unbounded (default `0`). |

Run `doh-upstream --help` for the full list.

## Usage

```rust
use doh_upstream::{DohUpstream, Options};

let upstream = DohUpstream::new("dns.google", None, "/dns-query", Options::default());
let response = upstream.exchange(&query_message).await?;
```

To run it as a local plain-DNS proxy:

```rust
use std::sync::Arc;
use doh_upstream::{serve, DohUpstream, Options};

let upstream = Arc::new(DohUpstream::new("dns.google", None, "/dns-query", Options::default()));
serve("127.0.0.1:5353".parse()?, upstream.into_handler()).await?;
```

## Cargo features

| Feature | Default | Description |
|---|---|---|
| `http3` | yes | Enables HTTP/3 support via `quinn`, `h3`, and `h3-quinn` |
| `dot` | yes | Enables DNS-over-TLS (`tls://`) support |
| `doq` | yes | Enables DNS-over-QUIC (`quic://`) support via `quinn` |
| `crypto-ring` | yes | Uses `ring` as rustls's crypto backend: pure Rust, no C toolchain, smaller binary |
| `crypto-aws-lc-rs` | no | Uses `aws-lc-rs` instead: adds FIPS validation and post-quantum key exchange support, at the cost of a C/assembly build step and a larger binary |

Exactly one of `crypto-ring`/`crypto-aws-lc-rs` must be enabled; the build
fails at compile time otherwise. To switch backends:

```sh
cargo build --release --no-default-features --features http3,crypto-aws-lc-rs
```

## Building

```sh
cargo check
cargo test
```

### Cross-compiling

To build a static `aarch64-unknown-linux-musl` binary, install the target and
an `aarch64-linux-musl-gcc` cross-toolchain, then build with `--release`:

```sh
rustup target add aarch64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
```

The linker for that target is configured in [.cargo/config.toml](.cargo/config.toml).

## License

AGPL-3.0-only. See the `license` field in [Cargo.toml](Cargo.toml).
