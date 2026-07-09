//! Plain DNS-over-TCP upstream client, mirroring the `tcp` case of Go's
//! `newPlain` in `upstream/plain.go`. Unlike [`crate::plain_udp`], this
//! supports bootstrap-resolved hostnames, since TCP has no equivalent of
//! UDP's connectionless one-shot exchange forcing a literal IP.

use std::time::Duration;

use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::client::bootstrap::{Network, Resolver, SystemResolver, resolve_dial_context};
use crate::client::wire::{format_host_port, validate_response};
use crate::error::DohError;

const DEFAULT_PORT_PLAIN: u16 = 53;

/// A plain DNS-over-TCP upstream, dialing a fresh connection per exchange.
pub struct PlainTcpUpstream {
    host: String,
    port: u16,
    addr_redacted: String,
    resolver: std::sync::Arc<dyn Resolver>,
    prefer_ipv6: bool,
    timeout: Option<Duration>,
}

impl PlainTcpUpstream {
    pub fn new(host: &str, port: Option<u16>, opts: crate::options::Options) -> Self {
        let port = port.unwrap_or(DEFAULT_PORT_PLAIN);
        Self {
            host: host.to_owned(),
            port,
            addr_redacted: format!("tcp://{}", format_host_port(host, port)),
            resolver: opts
                .bootstrap
                .unwrap_or_else(|| std::sync::Arc::new(SystemResolver)),
            prefer_ipv6: opts.prefer_ipv6,
            timeout: opts.timeout,
        }
    }

    pub fn address(&self) -> &str {
        &self.addr_redacted
    }

    /// Sends `req` to this upstream over TCP, framing it with the 2-byte
    /// big-endian length prefix required by RFC 1035 section 4.2.2, and
    /// validates the response against it.
    pub async fn exchange(&self, req: &Message) -> Result<Message, DohError> {
        let req_bytes = req.to_bytes()?;
        if req_bytes.len() > u16::MAX as usize {
            return Err(DohError::Pack(hickory_proto::ProtoError::from(
                "message too large for tcp framing",
            )));
        }

        let fut = async {
            let dial = resolve_dial_context(
                &self.host,
                self.port,
                self.timeout,
                self.resolver.as_ref(),
                self.prefer_ipv6,
            )
            .await?;

            let conn = (dial)(Network::Tcp).await?;
            let mut tcp = match conn {
                crate::client::bootstrap::Conn::Tcp(s) => s,
                crate::client::bootstrap::Conn::Udp(..) => {
                    return Err(DohError::Bootstrap("expected tcp connection".into()));
                }
            };

            let len = (req_bytes.len() as u16).to_be_bytes();
            tcp.write_all(&len).await?;
            tcp.write_all(&req_bytes).await?;

            let mut len_buf = [0u8; 2];
            tcp.read_exact(&mut len_buf).await?;
            let resp_len = u16::from_be_bytes(len_buf) as usize;

            let mut resp_buf = vec![0u8; resp_len];
            tcp.read_exact(&mut resp_buf).await?;

            let resp = Message::from_bytes(&resp_buf)
                .map_err(|e| DohError::InvalidResponse(format!("unpacking response: {e}")))?;
            validate_response(req, &resp)?;
            Ok(resp)
        };

        match self.timeout {
            Some(d) => tokio::time::timeout(d, fut)
                .await
                .map_err(|_| DohError::Timeout(d))?,
            None => fut.await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use std::str::FromStr;
    use tokio::net::TcpListener;

    fn make_query(id: u16, name: &str) -> Message {
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
        msg
    }

    async fn write_framed(stream: &mut tokio::net::TcpStream, bytes: &[u8]) {
        stream
            .write_all(&(bytes.len() as u16).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(bytes).await.unwrap();
    }

    async fn read_framed(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.unwrap();
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await.unwrap();
        buf
    }

    #[tokio::test]
    async fn exchange_roundtrips_over_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let req_bytes = read_framed(&mut stream).await;
            let req = Message::from_bytes(&req_bytes).unwrap();

            let mut resp = req.clone();
            resp.metadata.message_type = MessageType::Response;
            let bytes = resp.to_bytes().unwrap();
            write_framed(&mut stream, &bytes).await;
        });

        let upstream = PlainTcpUpstream::new(
            &addr.ip().to_string(),
            Some(addr.port()),
            crate::options::Options {
                timeout: Some(Duration::from_secs(5)),
                ..Default::default()
            },
        );
        let req = make_query(42, "example.com.");
        let resp = upstream.exchange(&req).await.unwrap();

        assert_eq!(resp.metadata.id, 42);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn exchange_rejects_mismatched_name() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let req_bytes = read_framed(&mut stream).await;
            let req = Message::from_bytes(&req_bytes).unwrap();

            let mut resp = Message::new(req.metadata.id, MessageType::Response, OpCode::Query);
            resp.add_query(Query::query(
                Name::from_str("other.com.").unwrap(),
                RecordType::A,
            ));
            let bytes = resp.to_bytes().unwrap();
            write_framed(&mut stream, &bytes).await;
        });

        let upstream = PlainTcpUpstream::new(
            &addr.ip().to_string(),
            Some(addr.port()),
            crate::options::Options {
                timeout: Some(Duration::from_secs(5)),
                ..Default::default()
            },
        );
        let req = make_query(1, "example.com.");
        let err = upstream.exchange(&req).await.unwrap_err();
        assert!(matches!(err, DohError::InvalidResponse(_)));

        server_task.await.unwrap();
    }
}
