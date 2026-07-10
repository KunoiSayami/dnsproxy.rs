//! A DNSCrypt listener: accepts encrypted queries over UDP and TCP,
//! decrypts them per the DNSCrypt v2 wire protocol
//! (`client::dnscrypt::crypto`), dispatches the decoded query to a
//! [`Handler`], and encrypts the response back. Mirrors Go's
//! `proxy/serverdnscrypt.go`, which wraps the external
//! `AdguardTeam/dnscrypt` library's `dnscrypt.Server`.
//!
//! Unlike Go's reference deployment, this listener also auto-answers TXT
//! queries for the configured provider name directly from the in-memory
//! certificate, rather than requiring the operator to wire up a separate
//! static-answer zone for it — a deliberate simplification so a DNSCrypt
//! server here is self-contained.

use std::net::SocketAddr;
use std::sync::Arc;

use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::rr::{Name, RData, Record, RecordType, rdata::TXT};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::net::{TcpListener, UdpSocket};

use crate::client::dnscrypt::crypto;
use crate::error::DohError;
use crate::listener::io::{Handler, bind_tcp, bind_udp, read_prefixed, write_prefixed};

/// Per RFC 1035 section 2.3.4, matching the plain listener's truncation
/// threshold.
const UDP_MAX_MSG_SIZE: usize = 512;
const UDP_RECV_BUF_SIZE: usize = 65535;

/// A DNSCrypt server's key material and certificate, held for the process's
/// lifetime — this crate doesn't implement certificate rotation, so a
/// long-lived validity window (e.g. a year) is expected.
pub struct DnsCryptServerConfig {
    pub resolver_secret_key: crypto_box::SecretKey,
    pub provider_name: String,
    pub client_magic: [u8; 8],
    pub cert_bytes: Vec<u8>,
}

impl DnsCryptServerConfig {
    /// Signs a new certificate from `resolver_secret_key`/`provider_signing_key`,
    /// valid from `ts_start` to `ts_end`.
    pub fn new(
        resolver_secret_key: crypto_box::SecretKey,
        provider_signing_key: &ed25519_dalek::SigningKey,
        provider_name: String,
        client_magic: [u8; 8],
        serial: u32,
        ts_start: u32,
        ts_end: u32,
    ) -> Self {
        let resolver_public_key = *resolver_secret_key.public_key().as_bytes();
        let cert_bytes = crypto::sign_certificate(
            provider_signing_key,
            &resolver_public_key,
            &client_magic,
            serial,
            ts_start,
            ts_end,
        );
        Self {
            resolver_secret_key,
            provider_name,
            client_magic,
            cert_bytes,
        }
    }
}

/// Runs a DNSCrypt listener on every address in `udp_addrs`/`tcp_addrs`,
/// dispatching every decrypted query to `handler`. Returns once every
/// listener is bound; the accept/receive loops keep running in spawned
/// tasks.
pub async fn serve_all(
    udp_addrs: &[SocketAddr],
    tcp_addrs: &[SocketAddr],
    config: Arc<DnsCryptServerConfig>,
    handler: Handler,
) -> Result<(), DohError> {
    for &addr in udp_addrs {
        serve_udp(addr, Arc::clone(&config), Arc::clone(&handler)).await?;
    }
    for &addr in tcp_addrs {
        serve_tcp(addr, Arc::clone(&config), Arc::clone(&handler)).await?;
    }
    Ok(())
}

/// Runs a DNSCrypt UDP listener on `addr`, returning the address it
/// actually bound to.
pub async fn serve_udp(
    addr: SocketAddr,
    config: Arc<DnsCryptServerConfig>,
    handler: Handler,
) -> Result<SocketAddr, DohError> {
    let socket = bind_udp(addr)?;
    let bound_addr = socket.local_addr()?;
    tracing::info!(addr = %bound_addr, "listening for dnscrypt udp queries");

    tokio::spawn(async move {
        udp_loop(socket, config, handler).await;
    });

    Ok(bound_addr)
}

/// Runs a DNSCrypt TCP listener on `addr`, returning the address it
/// actually bound to.
pub async fn serve_tcp(
    addr: SocketAddr,
    config: Arc<DnsCryptServerConfig>,
    handler: Handler,
) -> Result<SocketAddr, DohError> {
    let listener = bind_tcp(addr)?;
    let bound_addr = listener.local_addr()?;
    tracing::info!(addr = %bound_addr, "listening for dnscrypt tcp queries");

    tokio::spawn(async move {
        tcp_accept_loop(listener, config, handler).await;
    });

    Ok(bound_addr)
}

async fn udp_loop(socket: UdpSocket, config: Arc<DnsCryptServerConfig>, handler: Handler) {
    let socket = Arc::new(socket);
    let mut buf = vec![0u8; UDP_RECV_BUF_SIZE];

    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "dnscrypt udp recv failed");
                continue;
            }
        };

        let packet = buf[..len].to_vec();
        let socket = Arc::clone(&socket);
        let config = Arc::clone(&config);
        let handler = Arc::clone(&handler);

        tokio::spawn(async move {
            if let Err(e) = handle_udp_packet(&socket, &packet, peer, &config, handler).await {
                tracing::warn!(%peer, error = %e, "dnscrypt udp query failed");
            }
        });
    }
}

async fn handle_udp_packet(
    socket: &UdpSocket,
    packet: &[u8],
    peer: SocketAddr,
    config: &DnsCryptServerConfig,
    handler: Handler,
) -> Result<(), DohError> {
    match respond(packet, config, handler).await? {
        Response::Plain(mut resp) => {
            let mut bytes = resp.to_bytes()?;
            if bytes.len() > UDP_MAX_MSG_SIZE {
                resp = resp.truncate();
                bytes = resp.to_bytes()?;
            }
            socket.send_to(&bytes, peer).await?;
        }
        Response::Encrypted {
            client_public_key,
            client_nonce,
            resp_bytes,
        } => {
            let mut framed = crypto::encrypt_server_response(
                &config.resolver_secret_key,
                &client_public_key,
                &client_nonce,
                &resp_bytes,
            )?;
            if framed.len() > UDP_MAX_MSG_SIZE {
                // Signal truncation the way the plain listener does: encrypt
                // a truncated (TC=1, question-only) response instead of the
                // full one, so the client retries over TCP.
                let mut resp = Message::from_bytes(&resp_bytes)
                    .map_err(|e| DohError::InvalidResponse(format!("re-parsing response: {e}")))?;
                resp = resp.truncate();
                let truncated_bytes = resp.to_bytes()?;
                framed = crypto::encrypt_server_response(
                    &config.resolver_secret_key,
                    &client_public_key,
                    &client_nonce,
                    &truncated_bytes,
                )?;
            }
            socket.send_to(&framed, peer).await?;
        }
    }
    Ok(())
}

async fn tcp_accept_loop(
    listener: TcpListener,
    config: Arc<DnsCryptServerConfig>,
    handler: Handler,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "dnscrypt tcp accept failed");
                continue;
            }
        };
        let config = Arc::clone(&config);
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            if let Err(e) = handle_tcp_connection(stream, config, handler).await {
                tracing::warn!(%peer, error = %e, "dnscrypt tcp connection failed");
            }
        });
    }
}

async fn handle_tcp_connection(
    mut stream: tokio::net::TcpStream,
    config: Arc<DnsCryptServerConfig>,
    handler: Handler,
) -> Result<(), DohError> {
    loop {
        let packet = match read_prefixed(&mut stream).await {
            Ok(p) => p,
            Err(_) => return Ok(()),
        };

        let bytes = match respond(&packet, &config, Arc::clone(&handler)).await? {
            Response::Plain(resp) => resp.to_bytes()?,
            Response::Encrypted {
                client_public_key,
                client_nonce,
                resp_bytes,
            } => crypto::encrypt_server_response(
                &config.resolver_secret_key,
                &client_public_key,
                &client_nonce,
                &resp_bytes,
            )?,
        };
        write_prefixed(&mut stream, &bytes).await?;
    }
}

enum Response {
    /// A plain (unencrypted) response to a plain query, used for the
    /// auto-answered provider-name TXT lookup.
    Plain(Message),
    /// A decrypted-and-handled response awaiting encryption back to the
    /// client that sent it.
    Encrypted {
        client_public_key: [u8; 32],
        client_nonce: [u8; 12],
        resp_bytes: Vec<u8>,
    },
}

/// Handles one incoming packet, either a plain TXT query for the provider
/// name (answered directly from `config.cert_bytes`) or an encrypted
/// DNSCrypt query (decrypted, dispatched to `handler`, and left for the
/// caller to encrypt and send back).
async fn respond(
    packet: &[u8],
    config: &DnsCryptServerConfig,
    handler: Handler,
) -> Result<Response, DohError> {
    if let Some(resp) = try_answer_provider_txt(packet, config)? {
        return Ok(Response::Plain(resp));
    }

    let (req_bytes, client_public_key, client_nonce) =
        crypto::decrypt_query(&config.resolver_secret_key, &config.client_magic, packet)?;

    let req = Message::from_bytes(&req_bytes)
        .map_err(|e| DohError::InvalidResponse(format!("unpacking dnscrypt query: {e}")))?;

    let resp = handler(req).await?;
    let resp_bytes = resp.to_bytes()?;

    Ok(Response::Encrypted {
        client_public_key,
        client_nonce,
        resp_bytes,
    })
}

/// If `packet` parses as a plain (unencrypted) DNS query for
/// `config.provider_name`'s TXT record, returns the answer built from
/// `config.cert_bytes`. Returns `Ok(None)` for anything else (including
/// malformed packets, which fall through to being treated as an encrypted
/// query instead).
fn try_answer_provider_txt(
    packet: &[u8],
    config: &DnsCryptServerConfig,
) -> Result<Option<Message>, DohError> {
    let Ok(req) = Message::from_bytes(packet) else {
        return Ok(None);
    };
    if req.metadata.message_type != MessageType::Query {
        return Ok(None);
    }
    let Some(query) = req.queries.first() else {
        return Ok(None);
    };
    if query.query_type() != RecordType::TXT {
        return Ok(None);
    }
    let Ok(provider_name) = Name::from_ascii(&config.provider_name) else {
        return Ok(None);
    };
    if !query.name().eq_ignore_root(&provider_name) {
        return Ok(None);
    }

    let mut resp = Message::new(req.metadata.id, MessageType::Response, OpCode::Query);
    resp.add_query(query.clone());
    resp.add_answer(Record::from_rdata(
        query.name().clone(),
        60,
        RData::TXT(TXT::from_bytes(vec![&config.cert_bytes])),
    ));
    Ok(Some(resp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::dnscrypt::DnsCryptUpstream;
    use crate::client::dnscrypt::keygen::ResolverConfig;
    use crate::options::Options;
    use hickory_proto::op::Query as DnsQuery;
    use hickory_proto::rr::{Name, RecordType};
    use std::str::FromStr;
    use std::time::Duration;

    fn make_query(id: u16, name: &str) -> Message {
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        msg.add_query(DnsQuery::query(
            Name::from_str(name).unwrap(),
            RecordType::A,
        ));
        msg
    }

    fn echo_handler() -> Handler {
        Arc::new(|req: Message| {
            Box::pin(async move {
                let mut resp = req.clone();
                resp.metadata.message_type = MessageType::Response;
                Ok(resp)
            })
        })
    }

    fn server_config(
        resolver_config: &ResolverConfig,
        client_magic: [u8; 8],
    ) -> DnsCryptServerConfig {
        DnsCryptServerConfig::new(
            resolver_config.resolver_secret_key.clone(),
            &resolver_config.provider_signing_key,
            resolver_config.provider_name.clone(),
            client_magic,
            1,
            0,
            u32::MAX,
        )
    }

    #[tokio::test]
    async fn client_and_server_roundtrip_over_udp() {
        let resolver_config = ResolverConfig::generate("2.dnscrypt.test.example.");
        let config = Arc::new(server_config(&resolver_config, *b"TESTMAGC"));

        let bound = serve_udp(
            "127.0.0.1:0".parse().unwrap(),
            Arc::clone(&config),
            echo_handler(),
        )
        .await
        .unwrap();

        let stamp = resolver_config.stamp(bound);
        let upstream = DnsCryptUpstream::new(
            &stamp,
            Options {
                timeout: Some(Duration::from_secs(5)),
                ..Default::default()
            },
        )
        .unwrap();

        let req = make_query(42, "example.com.");
        let resp = upstream.exchange(&req).await.unwrap();
        assert_eq!(resp.metadata.id, 42);
        assert_eq!(resp.metadata.message_type, MessageType::Response);
    }

    #[tokio::test]
    async fn client_and_server_roundtrip_over_tcp_on_truncation() {
        let resolver_config = ResolverConfig::generate("2.dnscrypt.test.example.");
        let config = Arc::new(server_config(&resolver_config, *b"TESTMAGC"));

        // A handler that returns a response large enough to force UDP
        // truncation, so the client falls back to TCP.
        let big_handler: Handler = Arc::new(|req: Message| {
            Box::pin(async move {
                use hickory_proto::rr::{RData, Record, rdata::TXT};

                let mut resp = Message::new(req.metadata.id, MessageType::Response, OpCode::Query);
                resp.add_query(req.queries[0].clone());
                let long_string = "x".repeat(200);
                for _ in 0..10 {
                    resp.add_answer(Record::from_rdata(
                        req.queries[0].name().clone(),
                        60,
                        RData::TXT(TXT::new(vec![long_string.clone()])),
                    ));
                }
                Ok(resp)
            })
        });

        let udp_addr = serve_udp(
            "127.0.0.1:0".parse().unwrap(),
            Arc::clone(&config),
            Arc::clone(&big_handler),
        )
        .await
        .unwrap();
        serve_tcp(udp_addr, Arc::clone(&config), big_handler)
            .await
            .unwrap();

        let stamp = resolver_config.stamp(udp_addr);
        let upstream = DnsCryptUpstream::new(
            &stamp,
            Options {
                timeout: Some(Duration::from_secs(5)),
                ..Default::default()
            },
        )
        .unwrap();

        let req = make_query(7, "example.com.");
        let resp = upstream.exchange(&req).await.unwrap();
        assert_eq!(resp.metadata.id, 7);
        assert!(resp.answers.len() >= 10);
    }

    #[tokio::test]
    async fn provider_txt_query_is_auto_answered() {
        let resolver_config = ResolverConfig::generate("2.dnscrypt.test.example.");
        let config = server_config(&resolver_config, *b"TESTMAGC");

        let mut txt_query = Message::new(1, MessageType::Query, OpCode::Query);
        txt_query.add_query(DnsQuery::query(
            Name::from_str("2.dnscrypt.test.example.").unwrap(),
            RecordType::TXT,
        ));
        let packet = txt_query.to_bytes().unwrap();

        let resp = try_answer_provider_txt(&packet, &config).unwrap();
        assert!(resp.is_some());
        let resp = resp.unwrap();
        assert_eq!(resp.answers.len(), 1);
    }
}
