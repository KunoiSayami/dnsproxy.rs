//! A DNS-over-TLS (RFC 7858) upstream client, mirroring Go's `dnsOverTLS` in
//! `upstream/tls.go`: plain DNS-over-TCP framing (2-byte length prefix) over
//! a TLS connection, dialing bootstrap-resolved addresses.

use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::bootstrap::{Network, Resolver, SystemResolver, resolve_dial_context};
use crate::doh::build_tls_config;
use crate::error::DohError;
use crate::options::Options;
use crate::wire::{format_host_port, validate_response};

const DEFAULT_PORT_DOT: u16 = 853;

/// A DNS-over-TLS upstream, dialing a fresh TLS connection per exchange.
pub struct DotUpstream {
    host: String,
    port: u16,
    addr_redacted: String,
    resolver: Arc<dyn Resolver>,
    prefer_ipv6: bool,
    timeout: Option<Duration>,
    insecure_skip_verify: bool,
}

impl DotUpstream {
    pub fn new(host: &str, port: Option<u16>, opts: Options) -> Self {
        let port = port.unwrap_or(DEFAULT_PORT_DOT);
        Self {
            host: host.to_owned(),
            port,
            addr_redacted: format!("tls://{}", format_host_port(host, port)),
            resolver: opts.bootstrap.unwrap_or_else(|| Arc::new(SystemResolver)),
            prefer_ipv6: opts.prefer_ipv6,
            timeout: opts.timeout,
            insecure_skip_verify: opts.insecure_skip_verify,
        }
    }

    pub fn address(&self) -> &str {
        &self.addr_redacted
    }

    /// Sends `req` to this upstream over TLS, framing it like plain
    /// DNS-over-TCP, and validates the response against it.
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
            let tcp = match conn {
                crate::bootstrap::Conn::Tcp(s) => s,
                crate::bootstrap::Conn::Udp(..) => {
                    return Err(DohError::Bootstrap("expected tcp connection".into()));
                }
            };

            let tls_config = build_tls_config(&self.host, self.insecure_skip_verify, vec![]);
            let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
            let name = ServerName::try_from(self.host.clone())
                .map_err(|e| DohError::Http(format!("invalid server name: {e}")))?;

            let mut tls = connector
                .connect(name, tcp)
                .await
                .map_err(|e| DohError::Http(format!("tls handshake failed: {e}")))?;

            let len = (req_bytes.len() as u16).to_be_bytes();
            tls.write_all(&len).await?;
            tls.write_all(&req_bytes).await?;

            let mut len_buf = [0u8; 2];
            tls.read_exact(&mut len_buf).await?;
            let resp_len = u16::from_be_bytes(len_buf) as usize;

            let mut resp_buf = vec![0u8; resp_len];
            tls.read_exact(&mut resp_buf).await?;

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
    use tokio_rustls::TlsAcceptor;

    fn make_query(id: u16, name: &str) -> Message {
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
        msg
    }

    fn server_tls_config() -> tokio_rustls::rustls::ServerConfig {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der = tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
            cert.signing_key.serialize_der().into(),
        );

        tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap()
    }

    #[tokio::test]
    async fn exchange_roundtrips_over_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let acceptor = TlsAcceptor::from(Arc::new(server_tls_config()));
        let server_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();

            let mut len_buf = [0u8; 2];
            tls.read_exact(&mut len_buf).await.unwrap();
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut req_buf = vec![0u8; len];
            tls.read_exact(&mut req_buf).await.unwrap();
            let req = Message::from_bytes(&req_buf).unwrap();

            let mut resp = req.clone();
            resp.metadata.message_type = MessageType::Response;
            let bytes = resp.to_bytes().unwrap();
            tls.write_all(&(bytes.len() as u16).to_be_bytes())
                .await
                .unwrap();
            tls.write_all(&bytes).await.unwrap();
        });

        let upstream = DotUpstream::new(
            "localhost",
            Some(addr.port()),
            Options {
                bootstrap: Some(Arc::new(crate::bootstrap::StaticResolver(vec![addr.ip()]))),
                timeout: Some(Duration::from_secs(5)),
                insecure_skip_verify: true,
                ..Default::default()
            },
        );
        let req = make_query(42, "example.com.");
        let resp = upstream.exchange(&req).await.unwrap();

        assert_eq!(resp.metadata.id, 42);
        server_task.await.unwrap();
    }
}
