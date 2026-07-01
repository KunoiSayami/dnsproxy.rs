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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use crate::error::DohError;

/// Per RFC 1035 section 2.3.4, and the historical default enforced by the Go
/// client's `dns.Conn.UDPSize` when unset.
const UDP_MAX_MSG_SIZE: usize = 512;

/// Handles a decoded query and returns the response to send back. Errors are
/// logged and the query is dropped (no response), matching the Go server's
/// behavior of not answering when handling fails.
pub type Handler = Arc<
    dyn Fn(Message) -> Pin<Box<dyn Future<Output = Result<Message, DohError>> + Send>>
        + Send
        + Sync,
>;

/// Runs UDP and TCP listeners on `addr`, dispatching every decoded query to
/// `handler` and writing back whatever it returns. Runs until the process is
/// killed or a fatal socket error occurs; both loops are spawned and this
/// function returns once both listeners are bound.
pub async fn serve(addr: SocketAddr, handler: Handler) -> Result<(), DohError> {
    let udp = UdpSocket::bind(addr).await?;
    let tcp = TcpListener::bind(addr).await?;

    let udp_handler = Arc::clone(&handler);
    tokio::spawn(async move {
        udp_loop(udp, udp_handler).await;
    });

    tokio::spawn(async move {
        tcp_loop(tcp, handler).await;
    });

    Ok(())
}

async fn udp_loop(socket: UdpSocket, handler: Handler) {
    let socket = Arc::new(socket);
    let mut buf = vec![0u8; 65535];

    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => continue,
        };

        let packet = buf[..len].to_vec();
        let socket = Arc::clone(&socket);
        let handler = Arc::clone(&handler);

        tokio::spawn(async move {
            let _ = handle_udp_packet(&socket, &packet, peer, handler).await;
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
        resp.set_truncated(true);
        resp.take_answers();
        resp.take_name_servers();
        resp.take_additionals();
        bytes = resp.to_bytes()?;
    }

    socket.send_to(&bytes, peer).await?;
    Ok(())
}

async fn tcp_loop(listener: TcpListener, handler: Handler) {
    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => continue,
        };
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            let _ = handle_tcp_connection(stream, handler).await;
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
async fn read_prefixed(stream: &mut tokio::net::TcpStream) -> Result<Vec<u8>, DohError> {
    let len = stream.read_u16().await?;
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Mirrors `writePrefixed` in `proxy/servertcp.go`.
async fn write_prefixed(stream: &mut tokio::net::TcpStream, body: &[u8]) -> Result<(), DohError> {
    stream.write_u16(body.len() as u16).await?;
    stream.write_all(body).await?;
    Ok(())
}
