//! A minimal plain-DNS server: accepts queries over UDP and TCP and hands
//! them to a caller-supplied async handler, mirroring the listener/framing
//! plumbing in `proxy/serverudp.go` and `proxy/servertcp.go` (minus the full
//! routing engine those files back onto `Proxy.handleDNSRequest`).

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use crate::client::wire::servfail;
use crate::error::DohError;

/// Per RFC 1035 section 2.3.4, and the historical default enforced by the Go
/// client's `dns.Conn.UDPSize` when unset.
const UDP_MAX_MSG_SIZE: usize = 512;

/// Handles a decoded query and returns the response to send back. On its
/// own, an error is only logged and the listener gives up on the query (UDP
/// sends nothing, TCP/DoT close the connection, DoH answers HTTP 400); wrap
/// the handler with [`with_servfail`] to answer SERVFAIL instead, as the Go
/// server does.
pub type Handler = Arc<
    dyn Fn(Message) -> Pin<Box<dyn Future<Output = Result<Message, DohError>> + Send>>
        + Send
        + Sync,
>;

/// Wraps `handler` so that a query it fails to resolve is answered with
/// SERVFAIL (see [`servfail`]) instead of an error, mirroring how
/// `Proxy.handleDNSRequest` answers every resolution failure. Every listener
/// sharing the wrapped handler gets the behaviour; requests a listener can't
/// decode never reach the handler and are still rejected per transport.
///
/// The error is logged here, since the listener no longer sees it. Wrap
/// outside any cache, so SERVFAIL replies aren't cached.
pub fn with_servfail(handler: Handler) -> Handler {
    Arc::new(move |req: Message| {
        let handler = Arc::clone(&handler);
        Box::pin(async move {
            // The handler consumes `req`, so build the fallback up front.
            let fallback = servfail(&req);
            match handler(req).await {
                Ok(resp) => Ok(resp),
                Err(e) => {
                    tracing::warn!(error = %e, "resolving query failed; answering servfail");
                    #[cfg(feature = "stats")]
                    crate::stats::set_source(crate::stats::Source::Error);
                    Ok(fallback)
                }
            }
        })
    })
}

/// Runs UDP and TCP listeners on `addr`, dispatching every decoded query to
/// `handler` and writing back whatever it returns. Runs until the process is
/// killed or a fatal socket error occurs; both loops are spawned and this
/// function returns once both listeners are bound.
///
/// IPv6 addresses are bound with `IPV6_V6ONLY` set, so that binding an IPv6
/// wildcard address (e.g. `[::]:53`) doesn't claim the IPv4 wildcard address
/// on platforms where dual-stack sockets are the default, and a caller can
/// bind both families on the same port via [`serve_all`].
pub async fn serve(addr: SocketAddr, handler: Handler) -> Result<(), DohError> {
    serve_split(addr, Arc::clone(&handler), handler).await
}

/// Like [`serve`], but with separate handlers for UDP and TCP queries, e.g.
/// to count them separately in the stats.
pub async fn serve_split(
    addr: SocketAddr,
    udp_handler: Handler,
    tcp_handler: Handler,
) -> Result<(), DohError> {
    let udp = bind_udp(addr)?;
    let tcp = bind_tcp(addr)?;
    tracing::info!(%addr, "listening for udp and tcp dns queries");

    crate::listener::spawn_accept_loop(async move {
        udp_loop(udp, udp_handler).await;
    });
    crate::listener::spawn_accept_loop(async move {
        tcp_loop(tcp, tcp_handler).await;
    });

    Ok(())
}

/// Runs [`serve`] on every address in `addrs`, so a caller can e.g. bind both
/// an IPv4 and an IPv6 wildcard address for the same port.
pub async fn serve_all(addrs: &[SocketAddr], handler: Handler) -> Result<(), DohError> {
    serve_all_split(addrs, Arc::clone(&handler), handler).await
}

/// Runs [`serve_split`] on every address in `addrs`.
pub async fn serve_all_split(
    addrs: &[SocketAddr],
    udp_handler: Handler,
    tcp_handler: Handler,
) -> Result<(), DohError> {
    for &addr in addrs {
        serve_split(addr, Arc::clone(&udp_handler), Arc::clone(&tcp_handler)).await?;
    }
    Ok(())
}

/// Builds a bound, non-blocking `socket2::Socket` for `addr`, setting
/// `IPV6_V6ONLY` on IPv6 sockets so IPv4 and IPv6 wildcard binds don't
/// collide.
///
/// `SO_REUSEADDR` is set on TCP sockets only, so a restart can rebind while
/// old connections sit in `TIME_WAIT`. On UDP it would let several sockets
/// share one port on Linux, so a second listener on a port already in use
/// would bind silently and steal its traffic instead of failing.
pub(crate) fn new_socket(
    addr: SocketAddr,
    ty: Type,
    protocol: Protocol,
) -> std::io::Result<Socket> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, ty, Some(protocol))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    if ty == Type::STREAM {
        socket.set_reuse_address(true)?;
    }
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// Binds a QUIC server endpoint (DoQ, DoH3) on `addr`.
///
/// `quinn::Endpoint::server` binds a plain `std::net::UdpSocket`, which for
/// `[::]` is dual-stack wherever `net.ipv6.bindv6only=0` (the Linux
/// default), so it would collide with an IPv4 wildcard bind on the same port
/// and fail with `EADDRINUSE`. This binds through [`new_socket`] instead.
#[cfg(any(feature = "doq-server", feature = "http3-server"))]
pub(crate) fn bind_quic_server(
    addr: SocketAddr,
    server_config: quinn::ServerConfig,
) -> Result<quinn::Endpoint, DohError> {
    let socket = new_socket(addr, Type::DGRAM, Protocol::UDP)?;
    let runtime =
        quinn::default_runtime().ok_or_else(|| DohError::Quic("no async runtime found".into()))?;
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket.into(),
        runtime,
    )
    .map_err(|e| DohError::Quic(e.to_string()))
}

pub(crate) fn bind_udp(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let socket = new_socket(addr, Type::DGRAM, Protocol::UDP)?;
    UdpSocket::from_std(socket.into())
}

pub(crate) fn bind_tcp(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = new_socket(addr, Type::STREAM, Protocol::TCP)?;
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

async fn udp_loop(socket: UdpSocket, handler: Handler) {
    let socket = Arc::new(socket);
    let mut buf = vec![0u8; 65535];

    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "udp recv failed");
                continue;
            }
        };

        let packet = buf[..len].to_vec();
        let socket = Arc::clone(&socket);
        let handler = Arc::clone(&handler);

        tokio::spawn(async move {
            if let Err(e) = handle_udp_packet(&socket, &packet, peer, handler).await {
                tracing::warn!(%peer, error = %e, "udp query failed");
            }
        });
    }
}

async fn handle_udp_packet(
    socket: &UdpSocket,
    packet: &[u8],
    peer: SocketAddr,
    handler: Handler,
) -> Result<(), DohError> {
    let req = Message::from_bytes(packet)
        .map_err(|e| DohError::InvalidResponse(format!("unpacking udp packet: {e}")))?;

    let mut resp = handler(req).await?;

    let mut bytes = resp.to_bytes()?;
    if bytes.len() > UDP_MAX_MSG_SIZE {
        // Truncate per RFC 1035: signal TC and drop all sections, leaving
        // just the question, so the client retries over TCP.
        resp = resp.truncate();
        bytes = resp.to_bytes()?;
    }

    socket.send_to(&bytes, peer).await?;
    Ok(())
}

async fn tcp_loop(listener: TcpListener, handler: Handler) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "tcp accept failed");
                continue;
            }
        };
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            if let Err(e) = handle_tcp_connection(stream, handler).await {
                tracing::warn!(%peer, error = %e, "tcp connection failed");
            }
        });
    }
}

async fn handle_tcp_connection(
    mut stream: tokio::net::TcpStream,
    handler: Handler,
) -> Result<(), DohError> {
    loop {
        let packet = match read_prefixed(&mut stream).await {
            Ok(p) => p,
            Err(_) => return Ok(()),
        };

        let req = Message::from_bytes(&packet)
            .map_err(|e| DohError::InvalidResponse(format!("unpacking tcp message: {e}")))?;

        let resp = handler(req).await?;
        let bytes = resp.to_bytes()?;
        write_prefixed(&mut stream, &bytes).await?;
    }
}

/// Reads a DNS message prefixed with its 2-byte big-endian length, per
/// RFC 1035 section 4.2.2. Mirrors `readPrefixed` in `proxy/servertcp.go`.
/// Generic over the stream type so it's reusable for TLS-wrapped connections
/// (e.g. a DoT listener), not just a raw `TcpStream`.
pub(crate) async fn read_prefixed<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<Vec<u8>, DohError> {
    let len = stream.read_u16().await?;
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Mirrors `writePrefixed` in `proxy/servertcp.go`. Rejects bodies that don't
/// fit the 2-byte length prefix rather than silently truncating the length
/// (which would desync the stream), matching the guard the DoQ listener
/// applies to its own framing.
pub(crate) async fn write_prefixed<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    body: &[u8],
) -> Result<(), DohError> {
    let len = u16::try_from(body.len()).map_err(|_| {
        DohError::Pack(hickory_proto::ProtoError::from(
            "response too large for 2-byte length prefix",
        ))
    })?;
    stream.write_u16(len).await?;
    stream.write_all(body).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{Name, RecordType};
    use std::str::FromStr;

    fn make_query(id: u16, name: &str) -> Message {
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
        msg
    }

    fn failing_handler() -> Handler {
        Arc::new(|_req: Message| {
            Box::pin(async move { Err(DohError::Bootstrap("all upstreams failed".into())) })
        })
    }

    fn assert_servfail(resp: &Message, id: u16) {
        assert_eq!(resp.metadata.id, id);
        assert_eq!(resp.metadata.message_type, MessageType::Response);
        assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
        assert!(resp.metadata.recursion_desired);
        assert_eq!(resp.queries.len(), 1);
        assert_eq!(
            resp.queries[0].name(),
            &Name::from_str("example.com.").unwrap()
        );
    }

    #[tokio::test]
    async fn with_servfail_passes_successful_responses_through() {
        let handler = with_servfail(Arc::new(|req: Message| {
            Box::pin(async move {
                let mut resp = req.clone();
                resp.metadata.message_type = MessageType::Response;
                Ok(resp)
            })
        }));
        let resp = handler(make_query(7, "example.com.")).await.unwrap();
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    }

    #[tokio::test]
    async fn udp_answers_servfail_when_handler_fails() {
        let server = bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(udp_loop(server, with_servfail(failing_handler())));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let req = make_query(0x4242, "example.com.");
        client
            .send_to(&req.to_bytes().unwrap(), addr)
            .await
            .unwrap();

        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.recv_from(&mut buf),
        )
        .await
        .expect("udp listener should answer instead of dropping the query")
        .unwrap();
        assert_servfail(&Message::from_bytes(&buf[..len]).unwrap(), 0x4242);
    }

    #[tokio::test]
    async fn tcp_answers_servfail_and_keeps_connection_open() {
        let server = bind_tcp("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(tcp_loop(server, with_servfail(failing_handler())));

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Two queries on one connection: a failure must not close it.
        for id in [1, 2] {
            let req = make_query(id, "example.com.");
            write_prefixed(&mut stream, &req.to_bytes().unwrap())
                .await
                .unwrap();
            let bytes = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                read_prefixed(&mut stream),
            )
            .await
            .unwrap()
            .unwrap();
            assert_servfail(&Message::from_bytes(&bytes).unwrap(), id);
        }
    }

    #[test]
    fn udp_bind_on_a_port_in_use_fails() {
        let first = new_socket("127.0.0.1:0".parse().unwrap(), Type::DGRAM, Protocol::UDP).unwrap();
        let addr = first.local_addr().unwrap().as_socket().unwrap();
        let err = new_socket(addr, Type::DGRAM, Protocol::UDP).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
    }
}
