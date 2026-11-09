//! Built-in query statistics, replacing the `dnsstat.py` log-scraping
//! wrapper used with Go dnsproxy: counters are kept in memory and every
//! interval one JSON line is appended to `<dir>/<YYYY-MM-DD>.jsonl`, in the
//! same schema `dnsstat.py` writes, so `dnsstat.py summary` reads both and
//! merges old and new records.
//!
//! Like `dnsstat.py`, it never stores query names or client addresses. The
//! `clients` field is always 0, since handlers never see client addresses.

pub mod clock;
pub mod histogram;
pub mod json;
pub mod label;

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::fs::{DirBuilder, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;

use crate::client::upstream::TrackedUpstream;
use crate::listener::io::Handler;
use clock::LocalTime;
use histogram::LatencyHistogram;
use json::Value;

tokio::task_local! {
    /// Who answered the query being handled, set by whichever layer
    /// produced the response and read by [`Stats::wrap`], which scopes it.
    static ANSWERED_BY: RefCell<Option<Source>>;
}

/// What answered a query: the `answered_by` key in a stats record.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    /// The response cache.
    Cache,
    /// A hosts file (`--hosts-files`). A new key: Go's log gave
    /// `dnsstat.py` no way to tell these apart.
    Hosts,
    /// No upstream (or fallback) answered; the client got SERVFAIL.
    Error,
    /// Nothing reported a source (the handler isn't an
    /// [`crate::UpstreamConfig`], for instance).
    Unknown,
    /// An upstream or fallback, by its stats label.
    Upstream(Arc<str>),
}

impl Source {
    fn as_str(&self) -> &str {
        match self {
            Self::Cache => "cache",
            Self::Hosts => "hosts",
            Self::Error => "error",
            Self::Unknown => "unknown",
            Self::Upstream(label) => label,
        }
    }
}

/// Records `source` as what answered the query being handled. Does nothing
/// outside a [`Stats::wrap`] scope (stats disabled, or a spawned task).
pub(crate) fn set_source(source: Source) {
    let _ = ANSWERED_BY.try_with(|cell| *cell.borrow_mut() = Some(source));
}

/// How an upstream is configured, the `role` field of a stats record.
/// Ordered by precedence: an upstream used both as a default and for a
/// domain rule is reported as `default`, as in `dnsstat.py`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    /// Used for queries matching no domain rule.
    Default,
    /// Used only by `[/domain/]` rules.
    Domain,
    /// A `--fallback` upstream.
    Fallback,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Domain => "domain",
            Self::Fallback => "fallback",
        }
    }
}

/// One upstream's exchange counters for one interval.
#[derive(Clone, Debug, Default)]
pub struct UpstreamCounters {
    sent: u64,
    ok: u64,
    err: u64,
    proto: BTreeMap<&'static str, u64>,
    errors: BTreeMap<&'static str, u64>,
    latency: LatencyHistogram,
}

impl UpstreamCounters {
    pub(crate) fn record_sent(&mut self) {
        self.sent += 1;
    }

    pub(crate) fn record_ok(&mut self, transport: &'static str, latency: Duration) {
        self.ok += 1;
        *self.proto.entry(transport).or_default() += 1;
        self.latency.record(latency);
    }

    pub(crate) fn record_err(&mut self, transport: &'static str, kind: &'static str) {
        self.err += 1;
        *self.proto.entry(transport).or_default() += 1;
        *self.errors.entry(kind).or_default() += 1;
    }

    /// Exchanges started.
    pub fn sent(&self) -> u64 {
        self.sent
    }

    /// Exchanges that succeeded.
    pub fn ok(&self) -> u64 {
        self.ok
    }

    /// Exchanges that failed.
    pub fn err(&self) -> u64 {
        self.err
    }

    /// Latency of the successful exchanges.
    pub fn latency(&self) -> &LatencyHistogram {
        &self.latency
    }

    fn merge(&mut self, other: &Self) {
        self.sent += other.sent;
        self.ok += other.ok;
        self.err += other.err;
        for (k, v) in &other.proto {
            *self.proto.entry(k).or_default() += v;
        }
        for (k, v) in &other.errors {
            *self.errors.entry(k).or_default() += v;
        }
        self.latency.merge(&other.latency);
    }

    fn to_json(&self, role: Role) -> Value {
        let mut entries = vec![
            ("role", Value::String(role.as_str().to_owned())),
            ("sent", Value::Int(self.sent)),
            ("ok", Value::Int(self.ok)),
            ("err", Value::Int(self.err)),
            (
                "proto",
                Value::counts(self.proto.iter().map(|(k, v)| (k, *v))),
            ),
            (
                "errors",
                Value::counts(self.errors.iter().map(|(k, v)| (k, *v))),
            ),
        ];
        if !self.latency.is_empty() {
            entries.push(("latency", self.latency.to_json()));
            entries.push(("latency_method", Value::String("exact".to_owned())));
        }
        Value::object(entries)
    }
}

/// Query counters for the current interval.
struct Interval {
    start: SystemTime,
    queries: u64,
    proto: BTreeMap<&'static str, u64>,
    qtype: BTreeMap<Cow<'static, str>, u64>,
    rcode: BTreeMap<Cow<'static, str>, u64>,
    answered: BTreeMap<Source, u64>,
    latency_all: LatencyHistogram,
    latency: BTreeMap<Source, LatencyHistogram>,
}

impl Interval {
    fn new(start: SystemTime) -> Self {
        Self {
            start,
            queries: 0,
            proto: BTreeMap::new(),
            qtype: BTreeMap::new(),
            rcode: BTreeMap::new(),
            answered: BTreeMap::new(),
            latency_all: LatencyHistogram::default(),
            latency: BTreeMap::new(),
        }
    }
}

/// Collects query and upstream statistics and writes one record per
/// interval; see the module docs.
pub struct Stats {
    dir: PathBuf,
    interval: Duration,
    keep_days: u32,
    upstreams: Vec<(Arc<TrackedUpstream>, Role)>,
    current: Mutex<Interval>,
}

impl Stats {
    /// Creates the collector, writing to `dir` (created with mode 0700 if
    /// missing) every `interval`, deleting daily files older than
    /// `keep_days`. `upstreams` are the upstreams whose counters each record
    /// includes, typically [`crate::UpstreamConfig::upstreams_with_roles`].
    pub fn new(
        dir: PathBuf,
        interval: Duration,
        keep_days: u32,
        upstreams: Vec<(Arc<TrackedUpstream>, Role)>,
    ) -> std::io::Result<Self> {
        let mut builder = DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(&dir)?;
        Ok(Self {
            dir,
            interval: interval.max(Duration::from_secs(1)),
            keep_days,
            upstreams,
            current: Mutex::new(Interval::new(SystemTime::now())),
        })
    }

    /// Wraps `handler` to count every query it handles under the listener
    /// transport `proto` (`"udp"`, `"tcp"`, `"tls"`, `"quic"`, `"https"`,
    /// `"h3"`, `"dnscrypt"`). Wrap each listener's handler separately, and
    /// outside [`crate::listener::io::with_servfail`] so SERVFAIL replies
    /// are counted.
    pub fn wrap(self: &Arc<Self>, handler: Handler, proto: &'static str) -> Handler {
        let stats = Arc::clone(self);
        Arc::new(move |req: Message| {
            let stats = Arc::clone(&stats);
            let handler = Arc::clone(&handler);
            Box::pin(async move {
                let qtype = req.queries.first().map(|q| qtype_name(q.query_type()));
                let start = Instant::now();
                let (result, source) = ANSWERED_BY
                    .scope(RefCell::new(None), async move {
                        let result = handler(req).await;
                        (result, ANSWERED_BY.with(|cell| cell.borrow_mut().take()))
                    })
                    .await;
                let source = match (&result, source) {
                    (Err(_), _) => Source::Error,
                    (Ok(_), Some(source)) => source,
                    (Ok(_), None) => Source::Unknown,
                };
                let rcode = result
                    .as_ref()
                    .ok()
                    .map(|resp| rcode_name(resp.metadata.response_code));
                stats.record_query(proto, qtype, rcode, source, start.elapsed());
                result
            })
        })
    }

    fn record_query(
        &self,
        proto: &'static str,
        qtype: Option<Cow<'static, str>>,
        rcode: Option<Cow<'static, str>>,
        source: Source,
        latency: Duration,
    ) {
        let mut cur = self.current.lock().unwrap_or_else(PoisonError::into_inner);
        cur.queries += 1;
        *cur.proto.entry(proto).or_default() += 1;
        if let Some(qtype) = qtype {
            *cur.qtype.entry(qtype).or_default() += 1;
        }
        if let Some(rcode) = rcode {
            *cur.rcode.entry(rcode).or_default() += 1;
        }
        cur.latency_all.record(latency);
        cur.latency
            .entry(source.clone())
            .or_default()
            .record(latency);
        *cur.answered.entry(source).or_default() += 1;
    }

    /// Ends the current interval at `now`, returning its record as a JSON
    /// line along with the local date of its start (the file it belongs
    /// in), and starts the next one.
    fn take_record(&self, now: SystemTime) -> (String, String) {
        let cur = std::mem::replace(
            &mut *self.current.lock().unwrap_or_else(PoisonError::into_inner),
            Interval::new(now),
        );

        // Upstreams sharing a label (e.g. the same server as an upstream and
        // a fallback) are reported together, under the highest-precedence
        // role.
        let mut upstreams: BTreeMap<Arc<str>, (Role, UpstreamCounters)> = BTreeMap::new();
        for (upstream, role) in &self.upstreams {
            let counters = upstream.take_counters();
            upstreams
                .entry(Arc::clone(upstream.label()))
                .and_modify(|(r, c)| {
                    *r = (*r).min(*role);
                    c.merge(&counters);
                })
                .or_insert((*role, counters));
        }

        let start = LocalTime::at(cur.start);
        let interval_s = now
            .duration_since(cur.start)
            .unwrap_or_default()
            .as_secs_f64();
        let mut latency = Vec::new();
        if !cur.latency_all.is_empty() {
            latency.push(("all".to_owned(), cur.latency_all.to_json()));
        }
        latency.extend(
            cur.latency
                .iter()
                .map(|(source, h)| (source.as_str().to_owned(), h.to_json())),
        );
        let roles = cur.answered.keys().filter_map(|source| match source {
            Source::Upstream(label) => {
                let role = upstreams.get(label).map_or("other", |(r, _)| r.as_str());
                Some((label.to_string(), Value::String(role.to_owned())))
            }
            _ => None,
        });

        let record = Value::object([
            ("ts", Value::String(start.iso8601())),
            (
                "interval_s",
                Value::Float((interval_s * 10.0).round() / 10.0),
            ),
            ("queries", Value::Int(cur.queries)),
            ("clients", Value::Int(0)),
            (
                "proto",
                Value::counts(cur.proto.iter().map(|(k, v)| (k, *v))),
            ),
            (
                "qtype",
                Value::counts(cur.qtype.iter().map(|(k, v)| (k, *v))),
            ),
            (
                "rcode",
                Value::counts(cur.rcode.iter().map(|(k, v)| (k, *v))),
            ),
            (
                "answered_by",
                Value::counts(cur.answered.iter().map(|(k, v)| (k.as_str(), *v))),
            ),
            ("latency", Value::Object(latency)),
            (
                "upstreams",
                Value::Object(
                    upstreams
                        .iter()
                        .filter(|(_, (_, c))| c.sent + c.ok + c.err > 0)
                        .map(|(label, (role, c))| (label.to_string(), c.to_json(*role)))
                        .collect(),
                ),
            ),
            ("roles", Value::Object(roles.collect())),
            ("h3_fallback", Value::Object(Vec::new())),
            ("diag", Value::Object(Vec::new())),
        ]);
        (start.date(), record.to_compact_string())
    }

    /// Ends the current interval and appends its record, deleting files
    /// past the retention period. A failed write is logged, never fatal.
    pub async fn flush(&self) {
        let now = SystemTime::now();
        let (date, line) = self.take_record(now);
        let dir = self.dir.clone();
        let keep_days = self.keep_days;
        let result =
            tokio::task::spawn_blocking(move || write_record(&dir, &date, &line, keep_days, now))
                .await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(error = %e, "writing stats failed"),
            Err(e) => tracing::warn!(error = %e, "writing stats failed"),
        }
    }

    /// Spawns the task that flushes a record at every multiple of the
    /// interval on the wall clock (e.g. :00, :05, ... for 300 s), as
    /// `dnsstat.py` does. The first record covers from startup to the
    /// first boundary.
    pub fn spawn_flusher(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let stats = Arc::clone(self);
        tokio::spawn(async move {
            let secs = stats.interval.as_secs().max(1);
            loop {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default();
                let next = Duration::from_secs((now.as_secs() / secs + 1) * secs);
                tokio::time::sleep(next.saturating_sub(now)).await;
                stats.flush().await;
            }
        })
    }
}

/// Appends `line` to `<dir>/<date>.jsonl` (mode 0600), then deletes daily
/// files dated more than `keep_days` before `now`.
fn write_record(
    dir: &Path,
    date: &str,
    line: &str,
    keep_days: u32,
    now: SystemTime,
) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(dir.join(format!("{date}.jsonl")))?;
    file.write_all(format!("{line}\n").as_bytes())?;

    let cutoff = now
        .checked_sub(Duration::from_secs(u64::from(keep_days) * 86_400))
        .map(|t| LocalTime::at(t).date());
    let Some(cutoff) = cutoff else {
        return Ok(());
    };
    for entry in std::fs::read_dir(dir)?.flatten() {
        let name = entry.file_name();
        let Some(stem) = name.to_str().and_then(|n| n.strip_suffix(".jsonl")) else {
            continue;
        };
        if is_date(stem) && stem < cutoff.as_str() {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    Ok(())
}

/// Whether `s` looks like `YYYY-MM-DD` (`dnsstat.py`'s `????-??-??` glob,
/// restricted to digits).
fn is_date(s: &str) -> bool {
    s.len() == 10
        && s.bytes().enumerate().all(|(i, b)| {
            if i == 4 || i == 7 {
                b == b'-'
            } else {
                b.is_ascii_digit()
            }
        })
}

/// The query type as miekg/dns (and so Go dnsproxy's log) prints it, which
/// `dnsstat.py` records, lumping names over 10 characters into `other`.
fn qtype_name(rtype: RecordType) -> Cow<'static, str> {
    let name: Cow<'static, str> = match rtype {
        RecordType::Unknown(code) => format!("TYPE{code}").into(),
        known => <&'static str>::from(known).into(),
    };
    if name.len() > 10 {
        "other".into()
    } else {
        name
    }
}

/// The response code as miekg/dns's `RcodeToString` prints it.
fn rcode_name(rcode: ResponseCode) -> Cow<'static, str> {
    let code = u16::from(rcode);
    let name = match code {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        16 => "BADSIG",
        17 => "BADKEY",
        18 => "BADTIME",
        19 => "BADMODE",
        20 => "BADNAME",
        21 => "BADALG",
        22 => "BADTRUNC",
        23 => "BADCOOKIE",
        _ => return code.to_string().into(),
    };
    name.into()
}

/// Collects `(upstream, role)` pairs, keeping each upstream once under its
/// highest-precedence role. Used by
/// [`crate::UpstreamConfig::upstreams_with_roles`].
#[derive(Default)]
pub(crate) struct RoleCollector {
    entries: Vec<(Arc<TrackedUpstream>, Role)>,
    index: HashMap<*const TrackedUpstream, usize>,
}

impl RoleCollector {
    pub(crate) fn add(&mut self, upstream: &Arc<TrackedUpstream>, role: Role) {
        match self.index.get(&Arc::as_ptr(upstream)) {
            Some(&i) => self.entries[i].1 = self.entries[i].1.min(role),
            None => {
                self.index.insert(Arc::as_ptr(upstream), self.entries.len());
                self.entries.push((Arc::clone(upstream), role));
            }
        }
    }

    pub(crate) fn finish(self) -> Vec<(Arc<TrackedUpstream>, Role)> {
        self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::Name;
    use std::str::FromStr;

    fn query(rtype: RecordType) -> Message {
        let mut msg = Message::new(1, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(Name::from_str("example.com.").unwrap(), rtype));
        msg
    }

    fn answering(source: Option<Source>, rcode: ResponseCode) -> Handler {
        Arc::new(move |req: Message| {
            let source = source.clone();
            Box::pin(async move {
                if let Some(source) = source {
                    set_source(source);
                }
                let mut resp = req.clone();
                resp.metadata.message_type = MessageType::Response;
                resp.metadata.response_code = rcode;
                Ok(resp)
            })
        })
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("doh-upstream-stats-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[tokio::test]
    async fn counts_queries_by_proto_type_rcode_and_source() {
        let dir = temp_dir("counts");
        let stats =
            Arc::new(Stats::new(dir.clone(), Duration::from_secs(300), 30, Vec::new()).unwrap());
        let label: Arc<str> = "h3://diana.example:8443".into();
        let udp = stats.wrap(
            answering(
                Some(Source::Upstream(Arc::clone(&label))),
                ResponseCode::NoError,
            ),
            "udp",
        );
        let h3 = stats.wrap(answering(Some(Source::Cache), ResponseCode::NXDomain), "h3");
        let plain = stats.wrap(answering(None, ResponseCode::ServFail), "tcp");

        udp(query(RecordType::A)).await.unwrap();
        udp(query(RecordType::AAAA)).await.unwrap();
        h3(query(RecordType::HTTPS)).await.unwrap();
        plain(query(RecordType::Unknown(65_534))).await.unwrap();

        let (_, line) = stats.take_record(SystemTime::now());
        for needle in [
            r#""queries":4"#,
            r#""clients":0"#,
            r#""proto":{"h3":1,"tcp":1,"udp":2}"#,
            r#""qtype":{"A":1,"AAAA":1,"HTTPS":1,"TYPE65534":1}"#,
            r#""rcode":{"NOERROR":2,"NXDOMAIN":1,"SERVFAIL":1}"#,
            r#""answered_by":{"cache":1,"unknown":1,"h3://diana.example:8443":2}"#,
            r#""roles":{"h3://diana.example:8443":"other"}"#,
            r#""h3_fallback":{},"diag":{}"#,
        ] {
            assert!(line.contains(needle), "missing {needle} in {line}");
        }
        assert!(line.contains(r#""latency":{"all":{"n":4,"#), "{line}");

        // The interval was reset.
        let (_, line) = stats.take_record(SystemTime::now());
        assert!(line.contains(r#""queries":0"#), "{line}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn a_failed_handler_counts_as_error() {
        let dir = temp_dir("error");
        let stats =
            Arc::new(Stats::new(dir.clone(), Duration::from_secs(300), 30, Vec::new()).unwrap());
        let failing: Handler = Arc::new(|_req: Message| {
            Box::pin(async move { Err(crate::error::DohError::Bootstrap("down".into())) })
        });
        let handler = stats.wrap(crate::listener::io::with_servfail(failing), "udp");
        handler(query(RecordType::A)).await.unwrap();

        let (_, line) = stats.take_record(SystemTime::now());
        assert!(line.contains(r#""answered_by":{"error":1}"#), "{line}");
        assert!(line.contains(r#""rcode":{"SERVFAIL":1}"#), "{line}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn flush_appends_a_line_and_prunes_old_files() {
        let dir = temp_dir("flush");
        let stats =
            Arc::new(Stats::new(dir.clone(), Duration::from_secs(300), 30, Vec::new()).unwrap());
        std::fs::write(dir.join("2000-01-01.jsonl"), "{}\n").unwrap();
        std::fs::write(dir.join("notes.txt"), "keep").unwrap();

        stats.flush().await;
        stats.flush().await;

        let today = LocalTime::at(SystemTime::now()).date();
        let text = std::fs::read_to_string(dir.join(format!("{today}.jsonl"))).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(!dir.join("2000-01-01.jsonl").exists());
        assert!(dir.join("notes.txt").exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let file_mode = std::fs::metadata(dir.join(format!("{today}.jsonl")))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(file_mode & 0o777, 0o600);
            let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode();
            assert_eq!(dir_mode & 0o777, 0o700);
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn cache_hits_count_as_answered_by_cache() {
        use hickory_proto::rr::{RData, Record, rdata::A};

        let dir = temp_dir("cache");
        let stats =
            Arc::new(Stats::new(dir.clone(), Duration::from_secs(300), 30, Vec::new()).unwrap());
        let upstream: Handler = Arc::new(|req: Message| {
            Box::pin(async move {
                let mut resp = req.clone();
                resp.metadata.message_type = MessageType::Response;
                let name = req.queries[0].name().clone();
                resp.add_answer(Record::from_rdata(name, 60, RData::A(A::new(192, 0, 2, 1))));
                set_source(Source::Upstream("udp-upstream:53".into()));
                Ok(resp)
            })
        });
        let cache = Arc::new(crate::Cache::new(crate::CacheOptions {
            size: std::num::NonZeroUsize::new(10).unwrap(),
            min_ttl: Duration::ZERO,
            max_ttl: None,
        }));
        let handler = stats.wrap(cache.into_handler(upstream), "udp");

        handler(query(RecordType::A)).await.unwrap();
        handler(query(RecordType::A)).await.unwrap();

        let (_, line) = stats.take_record(SystemTime::now());
        assert!(
            line.contains(r#""answered_by":{"cache":1,"udp-upstream:53":1}"#),
            "{line}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn names_match_miekg() {
        assert_eq!(qtype_name(RecordType::A), "A");
        assert_eq!(qtype_name(RecordType::Unknown(65_534)), "TYPE65534");
        assert_eq!(rcode_name(ResponseCode::NXDomain), "NXDOMAIN");
        assert_eq!(rcode_name(ResponseCode::ServFail), "SERVFAIL");
    }
}
