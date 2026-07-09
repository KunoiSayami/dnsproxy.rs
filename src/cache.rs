//! An in-memory, TTL-aware response cache, wrapping a [`crate::listener::io::Handler`]
//! so callers can add caching to any upstream without changing the query
//! handling path in `server.rs`. Mirrors the gist of `proxy/cache.go` (cache
//! by question, minimum-TTL storage, decrementing TTLs on hits) without its
//! byte-budget sizing or optimistic (stale-while-revalidate) mode.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::Message;
use hickory_proto::rr::{DNSClass, Name, RecordType};
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
        for record in resp.answers.iter_mut() {
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

    /// The TTL to store a response under: the minimum TTL among its answer
    /// records, clamped to `[min_ttl, max_ttl]`. Responses with no answers
    /// (e.g. NXDOMAIN/NODATA) aren't cached, since there's no RR TTL to base
    /// an entry on.
    fn response_ttl(&self, resp: &Message) -> Option<Duration> {
        let min_rr_ttl = resp.answers.iter().map(|r| r.ttl).min()?;
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
    })
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
