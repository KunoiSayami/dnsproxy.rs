//! Answering queries from hosts files (`/etc/hosts` by default) before any
//! upstream is asked, as Go dnsproxy does by default (`hosts-file-enabled`,
//! `internal/middleware/hosts.go`): A and AAAA queries from the addresses
//! listed for a name, PTR queries from the names listed for an address.
//! Anything else, and names without an address of the queried family, go on
//! to the upstreams.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, PTR};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use crate::listener::io::Handler;

/// The hosts file read when none is configured.
pub const DEFAULT_HOSTS_FILE: &str = "/etc/hosts";

/// TTL of answers from hosts files, Go's `defaultResponseTTL`.
const HOSTS_TTL: u32 = 10;

/// Names and addresses read from hosts files.
#[derive(Debug, Default)]
pub struct Hosts {
    /// Lowercased name, without a trailing dot, to its addresses in file
    /// order.
    by_name: HashMap<String, Vec<IpAddr>>,
    /// Address to its names in file order, as written.
    by_addr: HashMap<IpAddr, Vec<String>>,
}

impl Hosts {
    /// Parses hosts file contents: one `address name [alias...]` entry per
    /// line, `#` starting a comment. Lines that don't parse (a bad address,
    /// no name) are skipped, as Go's `hostsfile.Parse` does.
    pub fn parse(text: &str) -> Self {
        let mut hosts = Self::default();
        hosts.add(text);
        hosts
    }

    /// Reads and merges every file in `paths`, in order. With `paths` empty,
    /// reads [`DEFAULT_HOSTS_FILE`], treating it as empty if it doesn't
    /// exist; an explicitly configured file that can't be read is an error,
    /// as in Go.
    pub fn load(paths: &[PathBuf]) -> Result<Self, String> {
        let mut hosts = Self::default();
        if paths.is_empty() {
            match std::fs::read_to_string(DEFAULT_HOSTS_FILE) {
                Ok(text) => hosts.add(&text),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("reading {DEFAULT_HOSTS_FILE}: {e}")),
            }
        }
        for path in paths {
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("reading {}: {e}", Path::new(path).display()))?;
            hosts.add(&text);
        }
        Ok(hosts)
    }

    fn add(&mut self, text: &str) {
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or_default();
            let mut fields = line.split_whitespace();
            let Some(addr) = fields.next().and_then(|a| a.parse::<IpAddr>().ok()) else {
                continue;
            };
            for name in fields {
                let key = name.trim_end_matches('.').to_ascii_lowercase();
                let addrs = self.by_name.entry(key).or_default();
                if !addrs.contains(&addr) {
                    addrs.push(addr);
                }
                let names = self.by_addr.entry(addr).or_default();
                if !names.iter().any(|n| n.eq_ignore_ascii_case(name)) {
                    names.push(name.to_owned());
                }
            }
        }
    }

    /// The number of distinct names.
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Whether no entries were read.
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// The addresses listed for `name` (case-insensitive, with or without a
    /// trailing dot).
    pub fn addrs_by_name(&self, name: &str) -> &[IpAddr] {
        self.by_name
            .get(&name.trim_end_matches('.').to_ascii_lowercase())
            .map_or(&[], Vec::as_slice)
    }

    /// The names listed for `addr`.
    pub fn names_by_addr(&self, addr: IpAddr) -> &[String] {
        self.by_addr.get(&addr).map_or(&[], Vec::as_slice)
    }

    /// The answer to `req` from these hosts, or `None` to pass it on. A port
    /// of Go's `resolveFromHosts`.
    pub fn answer(&self, req: &Message) -> Option<Message> {
        if req.metadata.op_code != OpCode::Query {
            return None;
        }
        let query = req.queries.first()?;
        let qname = query.name();
        let name = qname.to_ascii();
        let rdatas: Vec<RData> = match query.query_type() {
            RecordType::A => self
                .addrs_by_name(&name)
                .iter()
                .filter_map(|addr| match addr {
                    IpAddr::V4(v4) => Some(RData::A(A::from(*v4))),
                    IpAddr::V6(_) => None,
                })
                .collect(),
            RecordType::AAAA => self
                .addrs_by_name(&name)
                .iter()
                .filter_map(|addr| match addr {
                    IpAddr::V6(v6) => Some(RData::AAAA(AAAA::from(*v6))),
                    IpAddr::V4(_) => None,
                })
                .collect(),
            RecordType::PTR => {
                let addr = addr_from_reverse_name(&name)?;
                self.names_by_addr(addr)
                    .iter()
                    // `from_ascii` keeps the name as written, as Go does;
                    // `from_utf8` (for IDNs) would lowercase it.
                    .filter_map(|host| {
                        Name::from_ascii(host)
                            .or_else(|_| Name::from_utf8(host))
                            .ok()
                    })
                    .map(|mut host| {
                        host.set_fqdn(true);
                        RData::PTR(PTR(host))
                    })
                    .collect()
            }
            _ => return None,
        };
        if rdatas.is_empty() {
            return None;
        }

        let mut resp =
            Message::error_msg(req.metadata.id, req.metadata.op_code, ResponseCode::NoError);
        resp.metadata.recursion_desired = req.metadata.recursion_desired;
        resp.metadata.checking_disabled = req.metadata.checking_disabled;
        resp.metadata.recursion_available = true;
        resp.add_query(query.clone());
        for rdata in rdatas {
            resp.add_answer(Record::from_rdata(qname.clone(), HOSTS_TTL, rdata));
        }
        Some(resp)
    }

    /// Wraps `handler` to answer from these hosts first, passing on every
    /// query they can't answer.
    pub fn into_handler(self: Arc<Self>, handler: Handler) -> Handler {
        Arc::new(move |req: Message| {
            let hosts = Arc::clone(&self);
            let handler = Arc::clone(&handler);
            Box::pin(async move {
                if let Some(resp) = hosts.answer(&req) {
                    #[cfg(feature = "stats")]
                    crate::stats::set_source(crate::stats::Source::Hosts);
                    return Ok(resp);
                }
                handler(req).await
            })
        })
    }
}

/// The address a reverse-lookup name stands for: `d.c.b.a.in-addr.arpa`
/// (exactly four decimal labels) or the 32-nibble `ip6.arpa` form. Like Go's
/// `netutil.IPFromReversedAddr`, partial names yield `None`.
fn addr_from_reverse_name(name: &str) -> Option<IpAddr> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if let Some(labels) = name.strip_suffix(".in-addr.arpa") {
        let octets: Vec<u8> = labels
            .split('.')
            .map(|label| {
                // No signs or leading zeros, which `u8::from_str` accepts.
                let canonical = label == "0" || !(label.starts_with('0') || label.starts_with('+'));
                canonical.then(|| label.parse::<u8>().ok()).flatten()
            })
            .collect::<Option<_>>()?;
        let [d, c, b, a] = octets[..] else {
            return None;
        };
        return Some(IpAddr::V4(Ipv4Addr::new(a, b, c, d)));
    }
    let labels = name.strip_suffix(".ip6.arpa")?;
    let nibbles: Vec<u8> = labels
        .split('.')
        .map(|label| match label.as_bytes() {
            [c] => (*c as char).to_digit(16).map(|n| n as u8),
            _ => None,
        })
        .collect::<Option<_>>()?;
    if nibbles.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (i, pair) in nibbles.rchunks(2).enumerate() {
        // Reversed: the last label is the most significant nibble.
        bytes[i] = (pair[1] << 4) | pair[0];
    }
    Some(IpAddr::V6(Ipv6Addr::from(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, Query};

    const HOSTS: &str = "\
# comment line
127.0.0.1   localhost
::1         localhost ip6-localhost
192.0.2.10  Diana.example diana   # pinned
2001:db8::10 diana.example
192.0.2.11  triton.example.
not-an-ip   ignored.example
192.0.2.12
";

    fn query(name: &str, rtype: RecordType) -> Message {
        let mut msg = Message::new(42, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        // `from_ascii` keeps case, as a name parsed off the wire does.
        msg.add_query(Query::query(Name::from_ascii(name).unwrap(), rtype));
        msg
    }

    fn answers(resp: &Message) -> Vec<String> {
        resp.answers.iter().map(|r| r.data.to_string()).collect()
    }

    #[test]
    fn parses_names_aliases_and_comments() {
        let hosts = Hosts::parse(HOSTS);
        assert_eq!(
            hosts.addrs_by_name("DIANA.example."),
            &[
                "192.0.2.10".parse::<IpAddr>().unwrap(),
                "2001:db8::10".parse().unwrap()
            ]
        );
        assert_eq!(
            hosts.addrs_by_name("diana"),
            &["192.0.2.10".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            hosts.addrs_by_name("triton.example"),
            &["192.0.2.11".parse::<IpAddr>().unwrap()]
        );
        assert!(hosts.addrs_by_name("ignored.example").is_empty());
        assert!(hosts.addrs_by_name("pinned").is_empty());
        assert_eq!(
            hosts.names_by_addr("192.0.2.10".parse().unwrap()),
            &["Diana.example", "diana"]
        );
    }

    #[test]
    fn answers_a_and_aaaa_by_family() {
        let hosts = Hosts::parse(HOSTS);
        let resp = hosts
            .answer(&query("diana.example.", RecordType::A))
            .unwrap();
        assert_eq!(resp.metadata.id, 42);
        assert_eq!(resp.metadata.message_type, MessageType::Response);
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert!(resp.metadata.recursion_desired && resp.metadata.recursion_available);
        assert_eq!(answers(&resp), ["192.0.2.10"]);
        assert_eq!(resp.answers[0].ttl, HOSTS_TTL);

        let resp = hosts
            .answer(&query("Diana.Example.", RecordType::AAAA))
            .unwrap();
        assert_eq!(answers(&resp), ["2001:db8::10"]);
        // The answer keeps the query's spelling.
        assert_eq!(resp.answers[0].name.to_ascii(), "Diana.Example.");
    }

    #[test]
    fn passes_on_what_it_cannot_answer() {
        let hosts = Hosts::parse(HOSTS);
        // A v4-only name has no AAAA: the upstreams answer.
        assert!(
            hosts
                .answer(&query("triton.example.", RecordType::AAAA))
                .is_none()
        );
        assert!(
            hosts
                .answer(&query("unknown.example.", RecordType::A))
                .is_none()
        );
        assert!(
            hosts
                .answer(&query("diana.example.", RecordType::MX))
                .is_none()
        );
        assert!(
            hosts
                .answer(&query("10.2.0.192.in-addr.arpa.", RecordType::A))
                .is_none()
        );
    }

    #[test]
    fn answers_ptr_from_addresses() {
        let hosts = Hosts::parse(HOSTS);
        let resp = hosts
            .answer(&query("10.2.0.192.in-addr.arpa.", RecordType::PTR))
            .unwrap();
        assert_eq!(answers(&resp), ["Diana.example.", "diana."]);

        let v6 = "0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.";
        let resp = hosts.answer(&query(v6, RecordType::PTR)).unwrap();
        assert_eq!(answers(&resp), ["diana.example."]);

        assert!(
            hosts
                .answer(&query("99.2.0.192.in-addr.arpa.", RecordType::PTR))
                .is_none()
        );
    }

    #[test]
    fn reverse_names_must_be_complete() {
        assert_eq!(
            addr_from_reverse_name("4.3.2.1.in-addr.arpa."),
            Some("1.2.3.4".parse().unwrap())
        );
        assert_eq!(addr_from_reverse_name("3.2.1.in-addr.arpa."), None);
        assert_eq!(addr_from_reverse_name("04.3.2.1.in-addr.arpa."), None);
        assert_eq!(addr_from_reverse_name("256.3.2.1.in-addr.arpa."), None);
        assert_eq!(addr_from_reverse_name("1.0.ip6.arpa."), None);
        assert_eq!(addr_from_reverse_name("example.com."), None);
    }

    #[tokio::test]
    async fn handler_answers_from_hosts_and_forwards_the_rest() {
        let upstream: Handler = Arc::new(|req: Message| {
            Box::pin(async move {
                let mut resp = req.clone();
                resp.metadata.message_type = MessageType::Response;
                resp.metadata.response_code = ResponseCode::NXDomain;
                Ok(resp)
            })
        });
        let handler = Arc::new(Hosts::parse(HOSTS)).into_handler(upstream);

        let resp = handler(query("localhost.", RecordType::A)).await.unwrap();
        assert_eq!(answers(&resp), ["127.0.0.1"]);
        let resp = handler(query("example.org.", RecordType::A)).await.unwrap();
        assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
    }

    #[test]
    fn missing_explicit_file_is_an_error() {
        let err = Hosts::load(&[PathBuf::from("/nonexistent/hosts")]).unwrap_err();
        assert!(err.contains("/nonexistent/hosts"), "{err}");
    }
}
