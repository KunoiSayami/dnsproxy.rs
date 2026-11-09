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
use std::time::Duration;

use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use hickory_proto::op::Message;
use rand::seq::SliceRandom;
use tokio::time::{Instant, sleep_until};

use crate::client::upstream::TrackedUpstream;
use crate::client::upstream_url::{parse_any_upstream, redact_url};
use crate::error::DohError;
use crate::listener::io::Handler;
use crate::options::Options;
#[cfg(feature = "stats")]
use crate::stats::label::upstream_label;
#[cfg(feature = "stats")]
use crate::stats::{Role, RoleCollector, Source, set_source};

/// A separator between labels of a domain name.
const LABEL_SEP: char = '.';

/// How [`UpstreamConfig`] orders the upstreams for a query before trying
/// them in sequence. Mirrors Go dnsproxy's `UpstreamMode` (`proxy/proxy.go`):
/// `UpstreamModeLoadBalance` picks at random weighted by recent latency,
/// while the plain default mode always tries upstreams in configured order. Round-robin has
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

    /// Order upstreams by a weighted random draw without replacement, each
    /// weighted by the inverse of its recent average latency, so traffic
    /// spreads in proportion to speed and slower upstreams keep getting
    /// re-measured. A failed exchange counts as a
    /// [`crate::client::upstream::FAILURE_PENALTY`] sample, so a failing
    /// upstream sinks to the back. Untested upstreams (no exchange recorded
    /// yet) go first, in random order. Mirrors Go's `exchangeUpstreams` and
    /// `calcWeights` (`proxy/exchange.go`), whose default weight of 1 for an
    /// untested upstream likewise outranks any measured one.
    ///
    /// Unlike Go, attempts are hedged rather than strictly sequential: if
    /// the upstream being tried hasn't answered within [`hedge_delay`]
    /// (about twice its average latency), the next one is started alongside
    /// it, and whichever answers first wins. A silently failing upstream
    /// then costs a short delay instead of the full `--timeout`.
    LoadBalance,

    /// Send each query to every upstream in the group at once and use the
    /// first successful answer. Mirrors Go's `UpstreamModeParallel`
    /// (`upstream.ExchangeParallel`): the best latency, at the cost of
    /// multiplying upstream traffic by the group's size.
    Parallel,
}

/// Lower bound for [`hedge_delay`], so an upstream that usually answers in
/// a few milliseconds isn't hedged on ordinary jitter.
const HEDGE_DELAY_MIN: Duration = Duration::from_millis(50);

/// Upper bound for [`hedge_delay`], and the delay for an upstream with no
/// measurements yet: well inside the few seconds a stub resolver or browser
/// waits before giving up on a query.
const HEDGE_DELAY_MAX: Duration = Duration::from_secs(1);

/// How long [`UpstreamMode::LoadBalance`] waits for `upstream` to answer
/// before also starting the next one: twice its average latency, clamped to
/// [`HEDGE_DELAY_MIN`]..=[`HEDGE_DELAY_MAX`].
fn hedge_delay(upstream: &TrackedUpstream) -> Duration {
    upstream.latency().average().map_or(HEDGE_DELAY_MAX, |avg| {
        avg.saturating_mul(2)
            .clamp(HEDGE_DELAY_MIN, HEDGE_DELAY_MAX)
    })
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
            UpstreamMode::Ordered | UpstreamMode::Parallel => self.upstreams.clone(),
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
                let mut rng = rand::rng();
                let mut tested: Vec<(f64, Arc<TrackedUpstream>)> = Vec::new();
                let mut untested: Vec<Arc<TrackedUpstream>> = Vec::new();
                for u in &self.upstreams {
                    match u.latency().average() {
                        Some(avg) => tested.push((weighted_draw_key(avg, &mut rng), Arc::clone(u))),
                        None => untested.push(Arc::clone(u)),
                    }
                }
                tested.sort_by(|(a, _), (b, _)| a.total_cmp(b));
                untested.shuffle(&mut rng);
                untested.extend(tested.into_iter().map(|(_, u)| u));
                untested
            }
        }
    }
}

/// A random sort key for one upstream in a weighted draw without
/// replacement with weight `1 / avg`: sorting ascending by these keys gives
/// the same order distribution as repeatedly drawing an upstream with
/// probability proportional to its weight among those left, as Go's
/// `sampleuv.Weighted.Take` does. Each key is an exponentially distributed
/// "arrival time" with rate `1 / avg`, i.e. `-ln(U) * avg`; this stays
/// accurate however small the weights get, unlike the `U^(1/w)` form.
fn weighted_draw_key(avg: Duration, rng: &mut impl rand::RngExt) -> f64 {
    // `random` is in [0, 1); flip it to (0, 1] so `ln` stays finite.
    let u: f64 = 1.0 - rng.random::<f64>();
    -u.ln() * avg.as_secs_f64()
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

    /// Upstreams to try, all at once, when every upstream for a query has
    /// failed; see [`Self::with_fallback`].
    fallback: Option<Box<UpstreamConfig>>,
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
                            #[cfg(feature = "stats")]
                            let built =
                                TrackedUpstream::with_label(Arc::new(built), upstream_label(u));
                            #[cfg(not(feature = "stats"))]
                            let built = TrackedUpstream::new(Arc::new(built));
                            let built = Arc::new(built);
                            upstream_index.insert(u.clone(), Arc::clone(&built));
                            built
                        }
                        Err(e) => {
                            errors.push((idx, format!("upstream {:?}: {e}", redact_url(u))));
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
            fallback: None,
        })
    }

    /// Every distinct upstream in this config, with how it's used: `default`
    /// if any plain line uses it, else `domain`, and `fallback` for the
    /// upstreams of [`Self::with_fallback`]. For [`crate::stats::Stats`].
    #[cfg(feature = "stats")]
    pub fn upstreams_with_roles(&self) -> Vec<(Arc<TrackedUpstream>, Role)> {
        let mut roles = RoleCollector::default();
        for upstream in &self.default_upstreams.upstreams {
            roles.add(upstream, Role::Default);
        }
        for group in self.domain_upstreams.values() {
            for upstream in &group.upstreams {
                roles.add(upstream, Role::Domain);
            }
        }
        if let Some(fallback) = &self.fallback {
            for (upstream, _) in fallback.upstreams_with_roles() {
                roles.add(&upstream, Role::Fallback);
            }
        }
        roles.finish()
    }

    /// Sets the fallback upstreams, mirroring Go's `Config.Fallbacks`: when
    /// every upstream for a query has failed, the query is sent to all of
    /// `fallback`'s upstreams for that name at once (Go's
    /// `upstream.ExchangeParallel`), whatever `fallback`'s own mode, and the
    /// first answer is used. Not used when no upstream matched the name in
    /// the first place. `fallback`'s own fallback, if any, is ignored.
    pub fn with_fallback(mut self, mut fallback: UpstreamConfig) -> Self {
        fallback.mode = UpstreamMode::Parallel;
        fallback.fallback = None;
        self.fallback = Some(Box::new(fallback));
        self
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
        if upstreams.is_empty() {
            return Err(DohError::Bootstrap(format!(
                "no upstreams configured for {name:?}"
            )));
        }

        let err = match self.exchange_with(upstreams, req).await {
            Ok(resp) => return Ok(resp),
            Err(e) => e,
        };
        let Some(fallback) = &self.fallback else {
            return Err(err);
        };
        let fallback_upstreams = fallback.upstreams_for(&name);
        if fallback_upstreams.is_empty() {
            return Err(err);
        }
        tracing::debug!(error = %err, "upstreams failed; using fallback");
        fallback.exchange_with(fallback_upstreams, req).await
    }

    /// Exchanges `req` with `upstreams` (non-empty, as ordered by
    /// [`Self::upstreams_for`]) per this config's mode.
    async fn exchange_with(
        &self,
        upstreams: Vec<Arc<TrackedUpstream>>,
        req: &Message,
    ) -> Result<Message, DohError> {
        match self.mode {
            UpstreamMode::Ordered | UpstreamMode::RoundRobin => {
                let mut last_err = None;
                for upstream in upstreams {
                    match upstream.exchange(req).await {
                        Ok(resp) => {
                            note_answered_by(&upstream);
                            return Ok(resp);
                        }
                        Err(e) => last_err = Some(e),
                    }
                }
                Err(last_err.expect("at least one upstream was tried"))
            }
            UpstreamMode::LoadBalance => race(upstreams, req, hedge_delay).await,
            UpstreamMode::Parallel => race(upstreams, req, |_| Duration::ZERO).await,
        }
    }
}

/// Redacts every upstream address in one config line (or `--upstream`
/// value) with [`redact_url`], keeping any `[/domain/]` prefix, so the line
/// can be logged without leaking credentials or secret paths.
pub fn redact_rule(line: &str) -> String {
    let (prefix, upstreams) = match line.strip_prefix("[/").and_then(|r| r.split_once("/]")) {
        Some((domains, upstreams)) => (format!("[/{domains}/]"), upstreams),
        None => (String::new(), line),
    };
    let redacted: Vec<String> = upstreams.split_whitespace().map(redact_url).collect();
    format!("{prefix}{}", redacted.join(" "))
}

/// Records `upstream` as what answered the query being handled, for the
/// stats; does nothing without the `stats` feature.
fn note_answered_by(upstream: &TrackedUpstream) {
    #[cfg(feature = "stats")]
    set_source(Source::Upstream(Arc::clone(upstream.label())));
    #[cfg(not(feature = "stats"))]
    let _ = upstream;
}

/// Tries `upstreams` in order, starting each one after the previous attempt
/// fails or after `hedge_delay(previous)` passes without an answer, whichever
/// comes first, and returns the first successful answer. A zero delay starts
/// them all at once. Returns the last error if every attempt fails.
///
/// Attempts still in flight when one succeeds aren't cancelled: they finish
/// in a background task, as Go's `ExchangeParallel` goroutines do, so each
/// upstream's latency is still recorded. In particular, an upstream that was
/// hedged around because it stopped answering still records its failure
/// penalty, rather than keeping a good average and being tried first again.
async fn race(
    upstreams: Vec<Arc<TrackedUpstream>>,
    req: &Message,
    hedge_delay: fn(&TrackedUpstream) -> Duration,
) -> Result<Message, DohError> {
    let req = Arc::new(req.clone());
    let mut waiting = upstreams.into_iter();
    let mut running = FuturesUnordered::new();
    let mut last_err = None;
    // When to start the next waiting upstream if nothing has answered.
    let mut next_start: Option<Instant> = None;
    let mut start_next = true;

    loop {
        while start_next {
            start_next = false;
            next_start = None;
            let Some(upstream) = waiting.next() else {
                break;
            };
            if !running.is_empty() {
                tracing::debug!(addr = %upstream.address(), "hedging query to next upstream");
            }
            let delay = hedge_delay(&upstream);
            let req = Arc::clone(&req);
            running.push(async move {
                let result = upstream.exchange(&req).await;
                (upstream, result)
            });
            if delay.is_zero() {
                start_next = true;
            } else {
                next_start = Some(Instant::now() + delay);
            }
        }

        if running.is_empty() {
            return Err(last_err.expect("at least one upstream was tried"));
        }

        tokio::select! {
            Some((upstream, result)) = running.next() => match result {
                Ok(resp) => {
                    // Set here, in the query's own task: losers finishing
                    // in the background task below can't overwrite it.
                    note_answered_by(&upstream);
                    if !running.is_empty() {
                        tokio::spawn(async move { while running.next().await.is_some() {} });
                    }
                    return Ok(resp);
                }
                Err(e) => {
                    last_err = Some(e);
                    start_next = true;
                }
            },
            () = sleep_until(next_start.unwrap_or_else(Instant::now)), if next_start.is_some() => {
                start_next = true;
            }
        }
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

    /// Counts, over `draws` orderings, how often each address came first.
    fn first_pick_shares(cfg: &UpstreamConfig, fqdn: &str, draws: usize) -> HashMap<String, f64> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for _ in 0..draws {
            let first = cfg.upstreams_for(fqdn)[0].address().to_owned();
            *counts.entry(first).or_default() += 1;
        }
        counts
            .into_iter()
            .map(|(addr, n)| (addr, n as f64 / draws as f64))
            .collect()
    }

    #[test]
    fn load_balance_spreads_load_by_inverse_latency() {
        let cfg = UpstreamConfig::parse_with_mode(
            &["[/example.com/]https://1.1.1.1/dns-query https://2.2.2.2/dns-query https://3.3.3.3/dns-query"],
            &opts(),
            UpstreamMode::LoadBalance,
        )
        .unwrap();
        // Weights 1/10 : 1/40 : 1/120 = 12 : 3 : 1, so the first pick
        // should split 75% / 18.75% / 6.25% (cngz1 sees ~73/19/7 under Go).
        for (ip, ms) in [("1.1.1.1", 10), ("2.2.2.2", 40), ("3.3.3.3", 120)] {
            cfg.upstreams_for("example.com.")
                .iter()
                .find(|u| u.address().contains(ip))
                .unwrap()
                .latency()
                .record(Duration::from_millis(ms));
        }

        let shares = first_pick_shares(&cfg, "example.com.", 40_000);
        for (addr, expected) in [
            ("https://1.1.1.1:443/dns-query", 0.75),
            ("https://2.2.2.2:443/dns-query", 0.1875),
            ("https://3.3.3.3:443/dns-query", 0.0625),
        ] {
            let got = shares.get(addr).copied().unwrap_or(0.0);
            // ~5 standard deviations at 40k draws.
            assert!(
                (got - expected).abs() < 0.012,
                "{addr}: {got} vs {expected}"
            );
        }
    }

    #[test]
    fn load_balance_sinks_a_failing_upstream_and_lets_it_recover() {
        let cfg = UpstreamConfig::parse_with_mode(
            &["[/example.com/]https://1.1.1.1/dns-query https://2.2.2.2/dns-query"],
            &opts(),
            UpstreamMode::LoadBalance,
        )
        .unwrap();
        let group = cfg.upstreams_for("example.com.");
        let flaky = group
            .iter()
            .find(|u| u.address().contains("1.1.1.1"))
            .unwrap();
        let steady = group
            .iter()
            .find(|u| u.address().contains("2.2.2.2"))
            .unwrap();
        flaky.latency().record(Duration::from_millis(5));
        steady.latency().record(Duration::from_millis(50));
        let flaky_addr = flaky.address().to_owned();

        // Faster, so first ~91% of the time (weights 1/5 : 1/50).
        let before = first_pick_shares(&cfg, "example.com.", 10_000)[&flaky_addr];
        assert!(before > 0.85, "{before}");

        // One failure: average ≈ 0.3 * 5 s + 0.7 * 5 ms ≈ 1.5 s, so first
        // only ~3% of the time.
        flaky
            .latency()
            .record(crate::client::upstream::FAILURE_PENALTY);
        let after_failure = first_pick_shares(&cfg, "example.com.", 10_000)
            .get(&flaky_addr)
            .copied()
            .unwrap_or(0.0);
        assert!(after_failure < 0.04, "{after_failure}");

        // Each success shrinks the excess by 0.7: ten bring it level with
        // the 50 ms upstream (≈ 47 ms), eighteen nearly back to 5 ms
        // (≈ 7 ms, first ~87% of the time).
        for _ in 0..10 {
            flaky.latency().record(Duration::from_millis(5));
        }
        let level = first_pick_shares(&cfg, "example.com.", 10_000)[&flaky_addr];
        assert!((0.45..0.6).contains(&level), "{level}");
        for _ in 0..8 {
            flaky.latency().record(Duration::from_millis(5));
        }
        let recovered = first_pick_shares(&cfg, "example.com.", 10_000)[&flaky_addr];
        assert!(recovered > 0.82, "{recovered}");
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

    #[test]
    fn redact_rule_keeps_domains_and_redacts_upstreams() {
        assert_eq!(
            redact_rule(
                "[/example.com/test.org/]h3://a.example/s3cr3t https://u:p@b.example/dns-query"
            ),
            "[/example.com/test.org/]h3://a.example/<redacted> https://b.example/dns-query"
        );
        assert_eq!(
            redact_rule("https://u:p@c.example/s3cr3t"),
            "https://c.example/<redacted>"
        );
    }

    #[test]
    fn parse_errors_hide_secret_paths() {
        let errs = UpstreamConfig::parse(&["[/example.com/]ftp://u:p@h/s3cr3t"], &opts())
            .err()
            .unwrap();
        assert_eq!(errs.len(), 1);
        assert!(!errs[0].1.contains("s3cr3t"), "{}", errs[0].1);
        assert!(!errs[0].1.contains("u:p"), "{}", errs[0].1);
    }

    /// A local UDP DNS server that echoes each query back as a response
    /// after `delay`, or never answers if `delay` is `None`. Returns its
    /// address and a count of queries received.
    async fn udp_server(delay: Option<Duration>) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
        use hickory_proto::op::MessageType;
        use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
                counter.fetch_add(1, Ordering::SeqCst);
                let Some(delay) = delay else { continue };
                let mut resp = Message::from_bytes(&buf[..len]).unwrap();
                resp.metadata.message_type = MessageType::Response;
                let socket = Arc::clone(&socket);
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = socket.send_to(&resp.to_bytes().unwrap(), peer).await;
                });
            }
        });
        (addr, hits)
    }

    /// An address nothing listens on, so a connected UDP socket gets
    /// "connection refused" right away.
    fn closed_udp_port() -> std::net::SocketAddr {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    }

    fn query() -> Message {
        use hickory_proto::op::{MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RecordType};
        use std::str::FromStr;

        let mut msg = Message::new(7, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        msg
    }

    fn udp_config(
        addrs: &[std::net::SocketAddr],
        mode: UpstreamMode,
        timeout: Duration,
    ) -> UpstreamConfig {
        let upstreams: Vec<String> = addrs.iter().map(|a| format!("udp://{a}")).collect();
        let line = format!("[/example.com/]{}", upstreams.join(" "));
        let opts = Options {
            timeout: Some(timeout),
            ..Default::default()
        };
        UpstreamConfig::parse_with_mode(&[line.as_str()], &opts, mode).unwrap()
    }

    fn tracked(cfg: &UpstreamConfig, addr: std::net::SocketAddr) -> Arc<TrackedUpstream> {
        cfg.upstreams_for("example.com.")
            .into_iter()
            .find(|u| u.address() == format!("udp://{addr}"))
            .unwrap()
    }

    #[tokio::test]
    async fn parallel_queries_every_upstream_and_returns_the_first_answer() {
        let (slow, slow_hits) = udp_server(Some(Duration::from_millis(500))).await;
        let (fast, fast_hits) = udp_server(Some(Duration::from_millis(10))).await;
        let cfg = udp_config(
            &[slow, fast],
            UpstreamMode::Parallel,
            Duration::from_secs(2),
        );

        let start = std::time::Instant::now();
        let resp = cfg.exchange(&query()).await.unwrap();
        assert_eq!(resp.metadata.id, 7);
        assert!(
            start.elapsed() < Duration::from_millis(300),
            "{:?}",
            start.elapsed()
        );
        assert_eq!(slow_hits.load(Ordering::SeqCst), 1);
        assert_eq!(fast_hits.load(Ordering::SeqCst), 1);

        // The slow upstream's attempt finishes in the background and is
        // recorded as a success, not a failure.
        tokio::time::sleep(Duration::from_millis(700)).await;
        let slow_avg = tracked(&cfg, slow).latency().average().unwrap();
        assert!(slow_avg < Duration::from_secs(1), "{slow_avg:?}");
    }

    #[tokio::test]
    async fn parallel_fails_only_once_every_upstream_has_failed() {
        let (a, _) = udp_server(None).await;
        let (b, _) = udp_server(None).await;
        let cfg = udp_config(&[a, b], UpstreamMode::Parallel, Duration::from_millis(200));

        let start = std::time::Instant::now();
        assert!(cfg.exchange(&query()).await.is_err());
        // Concurrent, so one timeout's worth, not two.
        assert!(
            start.elapsed() < Duration::from_millis(350),
            "{:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn load_balance_hedges_around_a_silent_upstream() {
        let (silent, silent_hits) = udp_server(None).await;
        let (answering, _) = udp_server(Some(Duration::from_millis(10))).await;
        let cfg = udp_config(
            &[silent, answering],
            UpstreamMode::LoadBalance,
            Duration::from_millis(500),
        );
        // The silent one looks fastest, so it's drawn first ~99.99% of the
        // time and hedged after the 50 ms minimum.
        let silent_tracked = tracked(&cfg, silent);
        silent_tracked.latency().record(Duration::from_millis(1));
        tracked(&cfg, answering)
            .latency()
            .record(Duration::from_secs(10));

        let start = std::time::Instant::now();
        let resp = cfg.exchange(&query()).await.unwrap();
        assert_eq!(resp.metadata.id, 7);
        // Without hedging this would wait out the 500 ms timeout.
        assert!(
            start.elapsed() < Duration::from_millis(300),
            "{:?}",
            start.elapsed()
        );
        assert_eq!(silent_hits.load(Ordering::SeqCst), 1);

        // The abandoned attempt still times out in the background and
        // records the failure penalty, so the silent upstream sinks.
        tokio::time::sleep(Duration::from_millis(700)).await;
        let avg = silent_tracked.latency().average().unwrap();
        assert!(avg > Duration::from_secs(1), "{avg:?}");
    }

    #[tokio::test]
    async fn load_balance_starts_the_next_upstream_as_soon_as_one_fails() {
        let refused = closed_udp_port();
        let (answering, _) = udp_server(Some(Duration::from_millis(5))).await;
        let cfg = udp_config(
            &[refused, answering],
            UpstreamMode::LoadBalance,
            Duration::from_secs(2),
        );
        // Untested, so the refused upstream goes first, with the maximum
        // 1 s hedge delay; only an immediate failover answers sooner.
        tracked(&cfg, answering)
            .latency()
            .record(Duration::from_millis(5));

        let start = std::time::Instant::now();
        cfg.exchange(&query()).await.unwrap();
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "{:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn load_balance_does_not_hedge_quick_answers() {
        let (a, a_hits) = udp_server(Some(Duration::from_millis(5))).await;
        let (b, b_hits) = udp_server(Some(Duration::from_millis(5))).await;
        let cfg = udp_config(&[a, b], UpstreamMode::LoadBalance, Duration::from_secs(2));
        tracked(&cfg, a).latency().record(Duration::from_millis(5));
        tracked(&cfg, b).latency().record(Duration::from_millis(5));

        cfg.exchange(&query()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let total = a_hits.load(Ordering::SeqCst) + b_hits.load(Ordering::SeqCst);
        assert_eq!(total, 1);
    }

    fn udp_line(domains: &str, addrs: &[std::net::SocketAddr]) -> String {
        let upstreams: Vec<String> = addrs.iter().map(|a| format!("udp://{a}")).collect();
        format!("{domains}{}", upstreams.join(" "))
    }

    fn udp_opts() -> Options {
        Options {
            timeout: Some(Duration::from_millis(500)),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn fallback_answers_when_every_upstream_fails() {
        let refused = closed_udp_port();
        let (fb_a, a_hits) = udp_server(Some(Duration::from_millis(5))).await;
        let (fb_b, b_hits) = udp_server(Some(Duration::from_millis(5))).await;
        let fallback = UpstreamConfig::parse(
            &[udp_line("[/example.com/]", &[fb_a, fb_b]).as_str()],
            &udp_opts(),
        )
        .unwrap();
        let cfg = UpstreamConfig::parse(
            &[udp_line("[/example.com/]", &[refused]).as_str()],
            &udp_opts(),
        )
        .unwrap()
        .with_fallback(fallback);

        let resp = cfg.exchange(&query()).await.unwrap();
        assert_eq!(resp.metadata.id, 7);
        // Queried in parallel, like Go's ExchangeParallel.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(a_hits.load(Ordering::SeqCst), 1);
        assert_eq!(b_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn fallback_is_not_used_while_an_upstream_answers() {
        let refused = closed_udp_port();
        let (answering, _) = udp_server(Some(Duration::from_millis(5))).await;
        let (fb, fb_hits) = udp_server(Some(Duration::from_millis(5))).await;
        let fallback = UpstreamConfig::parse(&[udp_line("", &[fb]).as_str()], &udp_opts()).unwrap();
        let cfg = UpstreamConfig::parse(
            &[udp_line("[/example.com/]", &[refused, answering]).as_str()],
            &udp_opts(),
        )
        .unwrap()
        .with_fallback(fallback);

        cfg.exchange(&query()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(fb_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn fallback_is_not_used_when_no_upstream_matches() {
        let (other, _) = udp_server(Some(Duration::from_millis(5))).await;
        let (fb, fb_hits) = udp_server(Some(Duration::from_millis(5))).await;
        let fallback = UpstreamConfig::parse(&[udp_line("", &[fb]).as_str()], &udp_opts()).unwrap();
        // Only a rule for another domain, and no default upstream.
        let cfg =
            UpstreamConfig::parse(&[udp_line("[/other.org/]", &[other]).as_str()], &udp_opts())
                .unwrap()
                .with_fallback(fallback);

        assert!(cfg.exchange(&query()).await.is_err());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(fb_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn fails_when_upstreams_and_fallback_all_fail() {
        let fallback =
            UpstreamConfig::parse(&[udp_line("", &[closed_udp_port()]).as_str()], &udp_opts())
                .unwrap();
        let cfg =
            UpstreamConfig::parse(&[udp_line("", &[closed_udp_port()]).as_str()], &udp_opts())
                .unwrap()
                .with_fallback(fallback);

        assert!(cfg.exchange(&query()).await.is_err());
    }
}
