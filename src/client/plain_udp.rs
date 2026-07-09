//! Plain DNS-over-UDP upstream client, mirroring the `udp` case of Go's
//! `newPlain` in `upstream/plain.go`. Used for upstreams that only speak
//! classic DNS, e.g. a local resolver like dnsmasq that holds DHCP lease
//! hostnames unreachable from the public DoH upstreams.

use std::net::SocketAddr;
use std::time::Duration;

use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::net::UdpSocket;

use crate::client::wire::validate_response;
use crate::error::DohError;

const MAX_MSG_SIZE: usize = 65535;

/// A plain DNS-over-UDP upstream at a fixed address.
pub struct PlainUdpUpstream {
    addr: SocketAddr,
    addr_redacted: String,
    timeout: Option<Duration>,
}

impl PlainUdpUpstream {
    pub fn new(addr: SocketAddr, timeout: Option<Duration>) -> Self {
        Self {
            addr,
            addr_redacted: format!("udp://{addr}"),
            timeout,
        }
    }

    pub fn address(&self) -> &str {
        &self.addr_redacted
    }

    /// Sends `req` to this upstream over UDP and validates the response
    /// against it, matching `dnsOverUDP.Exchange`'s question checks.
    pub async fn exchange(&self, req: &Message) -> Result<Message, DohError> {
        let req_bytes = req.to_bytes()?;

        let fut = async {
            let local = if self.addr.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let sock = UdpSocket::bind(local).await?;
            sock.connect(self.addr).await?;
            sock.send(&req_bytes).await?;

            let mut buf = [0u8; MAX_MSG_SIZE];
            let n = sock.recv(&mut buf).await?;

            let resp = Message::from_bytes(&buf[..n])
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
    use tokio::net::UdpSocket as TokioUdpSocket;

    fn make_query(id: u16, name: &str) -> Message {
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
        msg
    }

    #[tokio::test]
    async fn exchange_roundtrips_over_udp() {
        let server = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            let req = Message::from_bytes(&buf[..n]).unwrap();

            let mut resp = req.clone();
            resp.metadata.message_type = MessageType::Response;
            let bytes = resp.to_bytes().unwrap();
            server.send_to(&bytes, peer).await.unwrap();
        });

        let upstream = PlainUdpUpstream::new(server_addr, Some(Duration::from_secs(5)));
        let req = make_query(42, "example.com.");
        let resp = upstream.exchange(&req).await.unwrap();

        assert_eq!(resp.metadata.id, 42);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn exchange_rejects_mismatched_name() {
        let server = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            let req = Message::from_bytes(&buf[..n]).unwrap();

            let mut resp = Message::new(req.metadata.id, MessageType::Response, OpCode::Query);
            resp.add_query(Query::query(
                Name::from_str("other.com.").unwrap(),
                RecordType::A,
            ));
            let bytes = resp.to_bytes().unwrap();
            server.send_to(&bytes, peer).await.unwrap();
        });

        let upstream = PlainUdpUpstream::new(server_addr, Some(Duration::from_secs(5)));
        let req = make_query(1, "example.com.");
        let err = upstream.exchange(&req).await.unwrap_err();
        assert!(matches!(err, DohError::InvalidResponse(_)));

        server_task.await.unwrap();
    }
}
