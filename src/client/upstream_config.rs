//! Parses an AdGuard dnsproxy-style upstream config file: one rule per line,
//! either a plain upstream (the default) or a domain-scoped rule of the form
//! `[/domain1/.../domainN/]upstream1 upstream2 ...`. Mirrors the core
//! matching behavior of `ParseUpstreamsConfig`/`UpstreamConfig` in Go's
//! `proxy/upstreams.go` — hierarchical suffix matching, where a query for
//! `mail.host.com` falls back to a rule registered for `host.com` if no more
//! specific rule exists. Does not implement Go's `*.domain` (subdomain-only)
//! or `[/domain/]#` (exclusion) syntax.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use hickory_proto::op::Message;
use rand::seq::SliceRandom;

use crate::client::upstream::TrackedUpstream;
use crate::client::upstream_url::parse_any_upstream;
use crate::error::DohError;
use crate::listener::io::Handler;
use crate::options::Options;

/// A separator between labels of a domain name.
const LABEL_SEP: char = '.';

/// How [`UpstreamConfig`] orders the upstreams for a query before trying
/// them in sequence. Mirrors Go dnsproxy's `UpstreamMode` (`proxy/proxy.go`):
/// `UpstreamModeLoadBalance` picks by recent latency, while the plain
/// default mode always tries upstreams in configured order. Round-robin has
/// no direct Go equivalent but is offered here as a simpler alternative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UpstreamMode {
    /// Always try upstreams in the order they were configured. This is the
    /// default: the first upstream in a rule is preferred, and later ones
    /// are only used as failover.
    #[default]
    Ordered,

    /// Rotate the starting upstream for each query, cycling through the
    /// group in order.
    RoundRobin,

    /// Try the upstream with the lowest recent average latency first,
    /// falling back through the rest in ascending latency order. Untested
    /// upstreams (no completed exchange yet) are treated as fastest and
    /// tried in random order ahead of any measured ones, so every upstream
    /// gets a chance to be measured.
    LoadBalance,
}

/// One domain rule's or the default group's upstreams, plus the state
/// [`UpstreamMode::RoundRobin`] needs to rotate the starting point across
/// calls.
#[derive(Default)]
struct UpstreamGroup {
    upstreams: Vec<Arc<TrackedUpstream>>,
    round_robin_cursor: AtomicUsize,
}

impl UpstreamGroup {
    fn push(&mut self, upstream: Arc<TrackedUpstream>) {
        self.upstreams.push(upstream);
    }

    /// Returns this group's upstreams ordered per `mode`.
    fn ordered(&self, mode: UpstreamMode) -> Vec<Arc<TrackedUpstream>> {
        match mode {
            UpstreamMode::Ordered => self.upstreams.clone(),
            UpstreamMode::RoundRobin => {
                let len = self.upstreams.len();
                if len == 0 {
                    return Vec::new();
                }
                let start = self.round_robin_cursor.fetch_add(1, Ordering::Relaxed) % len;
                self.upstreams[start..]
                    .iter()
                    .chain(&self.upstreams[..start])
                    .cloned()
                    .collect()
            }
            UpstreamMode::LoadBalance => {
                let mut tested: Vec<Arc<TrackedUpstream>> = Vec::new();
                let mut untested: Vec<Arc<TrackedUpstream>> = Vec::new();
                for u in &self.upstreams {
                    if u.latency().average().is_some() {
                        tested.push(Arc::clone(u));
                    } else {
                        untested.push(Arc::clone(u));
                    }
                }
                tested.sort_by_key(|u| u.latency().average());
                untested.shuffle(&mut rand::rng());
                untested.extend(tested);
                untested
            }
        }
    }
}

/// Maps domain names to the upstreams that should handle queries for them,
/// falling back to [`Self::default_upstreams`] for anything unmatched.
pub struct UpstreamConfig {
    /// Rules keyed by lowercased, dot-terminated domain (e.g. `"host.com."`),
    /// tried in order on failure.
    domain_upstreams: HashMap<Box<str>, UpstreamGroup>,

    /// Upstreams used for queries that don't match any domain rule.
    default_upstreams: UpstreamGroup,

    /// How each group's upstreams are ordered before being tried.
    mode: UpstreamMode,
}

impl UpstreamConfig {
    /// Parses `lines` (as read from an upstream config file) into an
    /// [`UpstreamConfig`]. Blank lines and lines starting with `#` are
    /// skipped. Returns every parse error found, tagged with the 0-based line
    /// index, rather than stopping at the first one.
    pub fn parse(lines: &[&str], base_opts: &Options) -> Result<Self, Vec<(usize, String)>> {
        Self::parse_with_mode(lines, base_opts, UpstreamMode::default())
    }

    /// Like [`Self::parse`], but selects how upstreams within each group are
    /// ordered before being tried; see [`UpstreamMode`].
    pub fn parse_with_mode(
        lines: &[&str],
        base_opts: &Options,
        mode: UpstreamMode,
    ) -> Result<Self, Vec<(usize, String)>> {
        // Dedupes identical upstream strings within one file, so a domain
        // list that repeats the same fallback server doesn't create a fresh
        // client (and connection pool) per line. Sharing the Arc also means
        // the same server's latency history is shared across every rule
        // that references it.
        let mut upstream_index: HashMap<String, Arc<TrackedUpstream>> = HashMap::new();
        let mut domain_upstreams: HashMap<Box<str>, UpstreamGroup> = HashMap::new();
        let mut default_upstreams = UpstreamGroup::default();
        let mut errors = Vec::new();

        for (idx, line) in lines.iter().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let (upstream_strs, domains) = match split_config_line(line) {
                Ok(v) => v,
                Err(e) => {
                    errors.push((idx, e));
                    continue;
                }
            };

            for u in &upstream_strs {
                let upstream = match upstream_index.get(u.as_str()) {
                    Some(existing) => Arc::clone(existing),
                    None => match parse_any_upstream(u, base_opts) {
                        Ok(built) => {
                            let built = Arc::new(TrackedUpstream::new(Arc::new(built)));
                            upstream_index.insert(u.clone(), Arc::clone(&built));
                            built
                        }
                        Err(e) => {
                            errors.push((idx, format!("upstream {u:?}: {e}")));
                            continue;
                        }
                    },
                };

                if domains.is_empty() {
                    default_upstreams.push(upstream);
                } else {
                    for domain in &domains {
                        domain_upstreams
                            .entry(domain.as_str().into())
                            .or_default()
                            .push(Arc::clone(&upstream));
                    }
                }
            }
        }

        if !errors.is_empty() {
            return Err(errors);
        }

        Ok(Self {
            domain_upstreams,
            default_upstreams,
            mode,
        })
    }

    /// Returns the upstreams that should handle a query for `fqdn`,
    /// preferring the most specific matching domain rule and falling back to
    /// [`Self::default_upstreams`] if none match, ordered per this config's
    /// [`UpstreamMode`]. Mirrors `UpstreamConfig.getUpstreamsForDomain`.
    pub fn upstreams_for(&self, fqdn: &str) -> Vec<Arc<TrackedUpstream>> {
        let group = self.group_for(fqdn);
        group.ordered(self.mode)
    }

    fn group_for(&self, fqdn: &str) -> &UpstreamGroup {
        if self.domain_upstreams.is_empty() {
            return &self.default_upstreams;
        }

        let lower = fqdn.to_ascii_lowercase();
        let mut suffix = lower.as_str();
        loop {
            if let Some(group) = self.domain_upstreams.get(suffix) {
                return group;
            }
            match suffix.split_once(LABEL_SEP) {
                Some((_, rest)) if !rest.is_empty() => suffix = rest,
                _ => break,
            }
        }

        &self.default_upstreams
    }

    /// Builds a [`Handler`] that looks up the upstreams for each query's
    /// name and tries them in order, returning the first successful
    /// response. If every upstream for a query fails, the last error is
    /// returned.
    pub fn into_handler(self: Arc<Self>) -> Handler {
        Arc::new(move |req: Message| {
            let config = Arc::clone(&self);
            Box::pin(async move { config.exchange(&req).await })
        })
    }

    async fn exchange(&self, req: &Message) -> Result<Message, DohError> {
        let name = req
            .queries
            .first()
            .map(|q| q.name().to_ascii())
            .unwrap_or_default();
        let upstreams = self.upstreams_for(&name);

        let mut last_err = None;
        for upstream in upstreams {
            match upstream.exchange(req).await {
                Ok(resp) => return Ok(resp),
                Err(e) => last_err = Some(e),
            }
        }

        Err(last_err.unwrap_or(DohError::Bootstrap(format!(
            "no upstreams configured for {name:?}"
        ))))
    }
}

/// Splits one config line into its upstream address(es) and the domains it's
/// reserved for (empty when the line is a plain default-upstream line).
/// Mirrors `splitConfigLine` in Go's `proxy/upstreams.go`, minus the `#`
/// exclusion marker and `*.` wildcard handling.
fn split_config_line(line: &str) -> Result<(Vec<String>, Vec<String>), String> {
    let Some(rest) = line.strip_prefix("[/") else {
        return Ok((vec![line.to_owned()], Vec::new()));
    };

    let Some((domains_part, upstreams_part)) = rest.split_once("/]") else {
        return Err("wrong upstream format: missing closing \"/]\"".to_owned());
    };
    if upstreams_part.is_empty() {
        return Err("wrong upstream format: no upstreams after \"/]\"".to_owned());
    }

    let mut domains = Vec::new();
    for host in domains_part.split('/') {
        if host.is_empty() {
            return Err("wrong upstream format: empty domain in rule".to_owned());
        }
        domains.push(format!("{}{LABEL_SEP}", host.to_ascii_lowercase()));
    }

    let upstreams = upstreams_part
        .split_whitespace()
        .map(str::to_owned)
        .collect();

    Ok((upstreams, domains))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn opts() -> Options {
        Options::default()
    }

    #[test]
    fn plain_line_is_default_upstream() {
        let cfg = UpstreamConfig::parse(&["https://dns.google/dns-query"], &opts()).unwrap();
        assert_eq!(cfg.default_upstreams.upstreams.len(), 1);
        assert_eq!(cfg.upstreams_for("example.com.").len(), 1);
    }

    #[test]
    fn domain_rule_matches_subdomains() {
        let cfg =
            UpstreamConfig::parse(&["[/example.com/]https://1.1.1.1/dns-query"], &opts()).unwrap();

        assert_eq!(
            cfg.upstreams_for("mail.example.com.")[0].address(),
            "https://1.1.1.1:443/dns-query"
        );
        assert_eq!(
            cfg.upstreams_for("example.com.")[0].address(),
            "https://1.1.1.1:443/dns-query"
        );
    }

    #[test]
    fn more_specific_domain_wins() {
        let cfg = UpstreamConfig::parse(
            &[
                "[/host.com/]https://1.1.1.1/dns-query",
                "[/www.host.com/]https://2.2.2.2/dns-query",
                "https://3.3.3.3/dns-query",
            ],
            &opts(),
        )
        .unwrap();

        assert_eq!(
            cfg.upstreams_for("www.host.com.")[0].address(),
            "https://2.2.2.2:443/dns-query"
        );
        assert_eq!(
            cfg.upstreams_for("mail.host.com.")[0].address(),
            "https://1.1.1.1:443/dns-query"
        );
        assert_eq!(
            cfg.upstreams_for("unrelated.example.")[0].address(),
            "https://3.3.3.3:443/dns-query"
        );
    }

    #[test]
    fn multiple_upstreams_on_one_rule_preserve_order() {
        let cfg = UpstreamConfig::parse(
            &["[/example.com/]https://1.1.1.1/dns-query https://2.2.2.2/dns-query"],
            &opts(),
        )
        .unwrap();

        let ups = cfg.upstreams_for("example.com.");
        assert_eq!(ups.len(), 2);
        assert_eq!(ups[0].address(), "https://1.1.1.1:443/dns-query");
        assert_eq!(ups[1].address(), "https://2.2.2.2:443/dns-query");
    }

    #[test]
    fn plain_udp_rule_can_be_mixed_with_doh() {
        let cfg = UpstreamConfig::parse(
            &[
                "[/7.168.192.in-addr.arpa/]127.0.0.1:53",
                "https://1.1.1.1/dns-query",
            ],
            &opts(),
        )
        .unwrap();

        assert_eq!(
            cfg.upstreams_for("163.7.168.192.in-addr.arpa.")[0].address(),
            "udp://127.0.0.1:53"
        );
        assert_eq!(
            cfg.upstreams_for("example.com.")[0].address(),
            "https://1.1.1.1:443/dns-query"
        );
    }

    #[test]
    fn duplicate_upstream_strings_are_deduplicated() {
        let cfg = UpstreamConfig::parse(
            &[
                "[/a.com/]https://1.1.1.1/dns-query",
                "[/b.com/]https://1.1.1.1/dns-query",
            ],
            &opts(),
        )
        .unwrap();

        assert!(Arc::ptr_eq(
            &cfg.upstreams_for("a.com.")[0],
            &cfg.upstreams_for("b.com.")[0]
        ));
    }

    #[test]
    fn blank_and_comment_lines_are_skipped() {
        let cfg = UpstreamConfig::parse(&["", "# comment", "https://1.1.1.1/dns-query"], &opts())
            .unwrap();
        assert_eq!(cfg.default_upstreams.upstreams.len(), 1);
    }

    #[test]
    fn missing_closing_bracket_is_reported() {
        let result = UpstreamConfig::parse(&["[/example.com/https://1.1.1.1/dns-query"], &opts());
        let Err(errs) = result else {
            panic!("expected a parse error");
        };
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].0, 0);
    }

    #[test]
    fn empty_domain_segment_is_rejected() {
        let result = UpstreamConfig::parse(&["[//]https://1.1.1.1/dns-query"], &opts());
        let Err(errs) = result else {
            panic!("expected a parse error");
        };
        assert_eq!(errs.len(), 1);
    }

    #[test]
    fn no_domain_rules_returns_default_directly() {
        let cfg = UpstreamConfig::parse(&["https://1.1.1.1/dns-query"], &opts()).unwrap();
        assert_eq!(cfg.upstreams_for("anything.example.").len(), 1);
    }

    #[test]
    fn round_robin_rotates_starting_upstream() {
        let cfg = UpstreamConfig::parse_with_mode(
            &["[/example.com/]https://1.1.1.1/dns-query https://2.2.2.2/dns-query https://3.3.3.3/dns-query"],
            &opts(),
            UpstreamMode::RoundRobin,
        )
        .unwrap();

        let first: Vec<String> = cfg
            .upstreams_for("example.com.")
            .iter()
            .map(|u| u.address().to_owned())
            .collect();
        let second: Vec<String> = cfg
            .upstreams_for("example.com.")
            .iter()
            .map(|u| u.address().to_owned())
            .collect();
        let third: Vec<String> = cfg
            .upstreams_for("example.com.")
            .iter()
            .map(|u| u.address().to_owned())
            .collect();

        assert_eq!(first[0], "https://1.1.1.1:443/dns-query");
        assert_eq!(second[0], "https://2.2.2.2:443/dns-query");
        assert_eq!(third[0], "https://3.3.3.3:443/dns-query");
        // Every rotation still contains the full set, just reordered.
        for group in [&first, &second, &third] {
            assert_eq!(group.len(), 3);
        }
    }

    #[test]
    fn load_balance_prefers_lower_latency_upstream() {
        let cfg = UpstreamConfig::parse_with_mode(
            &["[/example.com/]https://1.1.1.1/dns-query https://2.2.2.2/dns-query"],
            &opts(),
            UpstreamMode::LoadBalance,
        )
        .unwrap();

        let group = cfg.upstreams_for("example.com.");
        let slow = group
            .iter()
            .find(|u| u.address().contains("1.1.1.1"))
            .unwrap();
        let fast = group
            .iter()
            .find(|u| u.address().contains("2.2.2.2"))
            .unwrap();
        slow.latency().record(Duration::from_millis(50));
        fast.latency().record(Duration::from_millis(5));

        let ordered = cfg.upstreams_for("example.com.");
        assert_eq!(ordered[0].address(), "https://2.2.2.2:443/dns-query");
        assert_eq!(ordered[1].address(), "https://1.1.1.1:443/dns-query");
    }

    #[test]
    fn load_balance_tries_untested_upstreams_before_measured_ones() {
        let cfg = UpstreamConfig::parse_with_mode(
            &["[/example.com/]https://1.1.1.1/dns-query https://2.2.2.2/dns-query"],
            &opts(),
            UpstreamMode::LoadBalance,
        )
        .unwrap();

        let group = cfg.upstreams_for("example.com.");
        let tested = group
            .iter()
            .find(|u| u.address().contains("1.1.1.1"))
            .unwrap();
        tested.latency().record(Duration::from_millis(5));

        let ordered = cfg.upstreams_for("example.com.");
        assert_eq!(ordered[0].address(), "https://2.2.2.2:443/dns-query");
        assert_eq!(ordered[1].address(), "https://1.1.1.1:443/dns-query");
    }
}
