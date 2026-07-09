//! An in-memory, TTL-aware response cache, wrapping a [`crate::listener::io::Handler`]
//! so callers can add caching to any upstream without changing the query
//! handling path in `server.rs`. Mirrors the gist of `proxy/cache.go` (cache
//! by question, minimum-TTL storage, decrementing TTLs on hits) without its
//! byte-budget sizing or optimistic (stale-while-revalidate) mode.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::Message;
use hickory_proto::rr::{DNSClass, Name, Record, RecordType};
use lru::LruCache;
use tokio::sync::Mutex;

use crate::listener::io::Handler;

/// Caching options, set from `--cache-size`, `--cache-min-ttl`, and
/// `--cache-max-ttl`.
#[derive(Debug, Clone)]
pub struct CacheOptions {
    /// Maximum number of cached responses.
    pub size: NonZeroUsize,
    /// Floor applied to a response's stored TTL.
    pub min_ttl: Duration,
    /// Ceiling applied to a response's stored TTL; `None` means unbounded.
    pub max_ttl: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    name: Name,
    query_type: RecordType,
    query_class: DNSClass,
    /// The EDNS `DO` (DNSSEC OK) bit. Part of the key because a `DO=0` query
    /// yields a response stripped of RRSIG/DNSSEC records, and serving that to
    /// a `DO=1` validating client (or vice versa) produces a wrong answer.
    dnssec_ok: bool,
    /// The `CD` (Checking Disabled) header bit. A `CD=1` query may return data
    /// that failed validation upstream; it must not be served to a `CD=0`
    /// client expecting validated results.
    checking_disabled: bool,
}

struct CacheEntry {
    response: Message,
    stored_at: Instant,
    ttl: Duration,
}

/// A response cache keyed on the query's name, type, and class.
pub struct Cache {
    entries: Mutex<LruCache<CacheKey, CacheEntry>>,
    min_ttl: Duration,
    max_ttl: Option<Duration>,
}

impl Cache {
    pub fn new(opts: CacheOptions) -> Self {
        Self {
            entries: Mutex::new(LruCache::new(opts.size)),
            min_ttl: opts.min_ttl,
            max_ttl: opts.max_ttl,
        }
    }

    /// Wraps `handler` with this cache: served from cache on a fresh hit,
    /// otherwise forwarded to `handler` and stored before being returned.
    pub fn into_handler(self: Arc<Self>, handler: Handler) -> Handler {
        Arc::new(move |req: Message| {
            let cache = Arc::clone(&self);
            let handler = Arc::clone(&handler);
            Box::pin(async move {
                let key = match cache_key(&req) {
                    Some(key) => key,
                    // Not a single-question query; caching doesn't apply.
                    None => return handler(req).await,
                };

                if let Some(resp) = cache.get(&key, req.metadata.id).await {
                    return Ok(resp);
                }

                let resp = handler(req).await?;
                cache.insert(key, &resp).await;
                Ok(resp)
            })
        })
    }

    async fn get(&self, key: &CacheKey, id: u16) -> Option<Message> {
        let mut entries = self.entries.lock().await;
        let entry = entries.get(key)?;

        let elapsed = entry.stored_at.elapsed();
        if elapsed >= entry.ttl {
            entries.pop(key);
            return None;
        }

        let remaining = (entry.ttl - elapsed).as_secs() as u32;
        let mut resp = entry.response.clone();
        resp.metadata.id = id;
        for record in all_records_mut(&mut resp) {
            record.ttl = remaining;
        }
        Some(resp)
    }

    async fn insert(&self, key: CacheKey, resp: &Message) {
        let Some(ttl) = self.response_ttl(resp) else {
            return;
        };
        let entry = CacheEntry {
            response: resp.clone(),
            stored_at: Instant::now(),
            ttl,
        };
        self.entries.lock().await.put(key, entry);
    }

    /// The TTL to store a response under: the minimum TTL among its records
    /// across all sections (answer, authority, additional), clamped to
    /// `[min_ttl, max_ttl]`. Responses with no real records (e.g. NXDOMAIN/
    /// NODATA carrying only an SOA in the authority section still count that
    /// SOA; a bare response with nothing to cache returns `None`). The OPT
    /// pseudo-record is skipped, since its "TTL" field encodes EDNS flags, not
    /// a lifetime.
    fn response_ttl(&self, resp: &Message) -> Option<Duration> {
        let min_rr_ttl = cacheable_records(resp).map(|r| r.ttl).min()?;
        let mut ttl = Duration::from_secs(min_rr_ttl as u64);

        if ttl < self.min_ttl {
            ttl = self.min_ttl;
        }
        if let Some(max_ttl) = self.max_ttl
            && ttl > max_ttl
        {
            ttl = max_ttl;
        }
        Some(ttl)
    }
}

fn cache_key(req: &Message) -> Option<CacheKey> {
    if req.queries.len() != 1 {
        return None;
    }
    let q = &req.queries[0];
    Some(CacheKey {
        name: q.name().clone(),
        query_type: q.query_type(),
        query_class: q.query_class,
        dnssec_ok: req.edns.as_ref().is_some_and(|edns| edns.flags().dnssec_ok),
        checking_disabled: req.metadata.checking_disabled,
    })
}

/// Iterates the records across all three sections whose TTL is meaningful for
/// caching, skipping the OPT pseudo-record (whose TTL field carries EDNS
/// flags/version rather than a lifetime).
fn cacheable_records(msg: &Message) -> impl Iterator<Item = &Record> {
    msg.answers
        .iter()
        .chain(msg.authorities.iter())
        .chain(msg.additionals.iter())
        .filter(|r| r.record_type() != RecordType::OPT)
}

/// The mutable counterpart of [`cacheable_records`], for rewriting the
/// remaining TTL on a cache hit.
fn all_records_mut(msg: &mut Message) -> impl Iterator<Item = &mut Record> {
    msg.answers
        .iter_mut()
        .chain(msg.authorities.iter_mut())
        .chain(msg.additionals.iter_mut())
        .filter(|r| r.record_type() != RecordType::OPT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::{RData, Record, rdata::A};
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    fn query(id: u16, name: &str) -> Message {
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
        msg
    }

    fn response_with_ttl(req: &Message, ttl: u32) -> Message {
        let mut resp = req.clone();
        resp.metadata.message_type = MessageType::Response;
        resp.add_answer(Record::from_rdata(
            req.queries[0].name().clone(),
            ttl,
            RData::A(A::from(Ipv4Addr::new(1, 2, 3, 4))),
        ));
        resp
    }

    fn opts() -> CacheOptions {
        CacheOptions {
            size: NonZeroUsize::new(10).unwrap(),
            min_ttl: Duration::ZERO,
            max_ttl: None,
        }
    }

    #[tokio::test]
    async fn caches_and_serves_hit() {
        let cache = Cache::new(opts());
        let req = query(1, "example.com.");
        let resp = response_with_ttl(&req, 300);

        let key = cache_key(&req).unwrap();
        cache.insert(key.clone(), &resp).await;

        let hit = cache.get(&key, 42).await.unwrap();
        assert_eq!(hit.metadata.id, 42);
        assert!(hit.answers[0].ttl <= 300);
    }

    #[tokio::test]
    async fn min_ttl_raises_short_ttl() {
        let mut o = opts();
        o.min_ttl = Duration::from_secs(60);
        let cache = Cache::new(o);
        let req = query(1, "example.com.");
        let resp = response_with_ttl(&req, 5);

        let ttl = cache.response_ttl(&resp).unwrap();
        assert_eq!(ttl, Duration::from_secs(60));
    }

    #[tokio::test]
    async fn max_ttl_caps_long_ttl() {
        let mut o = opts();
        o.max_ttl = Some(Duration::from_secs(60));
        let cache = Cache::new(o);
        let req = query(1, "example.com.");
        let resp = response_with_ttl(&req, 3600);

        let ttl = cache.response_ttl(&resp).unwrap();
        assert_eq!(ttl, Duration::from_secs(60));
    }

    #[tokio::test]
    async fn responses_without_answers_are_not_cached() {
        let cache = Cache::new(opts());
        let req = query(1, "example.com.");
        let mut resp = req.clone();
        resp.metadata.message_type = MessageType::Response;

        assert!(cache.response_ttl(&resp).is_none());
    }

    #[tokio::test]
    async fn dnssec_ok_queries_get_a_distinct_key() {
        use hickory_proto::op::Edns;

        let plain = query(1, "example.com.");

        let mut with_do = query(1, "example.com.");
        let mut edns = Edns::new();
        edns.flags_mut().dnssec_ok = true;
        with_do.set_edns(edns);

        // Same question, differing only by the DO bit, must not collide: a
        // DO=0 answer (RRSIG-stripped) must never be served to a DO=1 client.
        assert_ne!(cache_key(&plain), cache_key(&with_do));
    }

    #[tokio::test]
    async fn checking_disabled_queries_get_a_distinct_key() {
        let plain = query(1, "example.com.");
        let mut cd = query(1, "example.com.");
        cd.metadata.checking_disabled = true;

        assert_ne!(cache_key(&plain), cache_key(&cd));
    }

    #[tokio::test]
    async fn authority_records_are_ttl_decremented_on_hit() {
        let cache = Cache::new(opts());
        let req = query(1, "example.com.");
        let mut resp = response_with_ttl(&req, 300);
        // An authority record with a longer TTL than the answer; on a hit it
        // must be rewritten to the remaining lifetime, not served verbatim.
        resp.authorities.push(Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            9999,
            RData::A(A::from(Ipv4Addr::new(5, 6, 7, 8))),
        ));

        let key = cache_key(&req).unwrap();
        cache.insert(key.clone(), &resp).await;

        let hit = cache.get(&key, 1).await.unwrap();
        assert!(hit.authorities[0].ttl <= 300);
    }

    #[tokio::test]
    async fn expired_entry_is_evicted_on_get() {
        let mut o = opts();
        o.min_ttl = Duration::ZERO;
        let cache = Cache::new(o);
        let req = query(1, "example.com.");
        let resp = response_with_ttl(&req, 0);

        let key = cache_key(&req).unwrap();
        cache.insert(key.clone(), &resp).await;

        assert!(cache.get(&key, 1).await.is_none());
    }
}
