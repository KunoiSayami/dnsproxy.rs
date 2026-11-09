//! `listener::stop_accepting` stops every listener process-wide, so it gets
//! its own test binary rather than running alongside the unit tests'
//! listeners.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use tokio::net::{TcpStream, UdpSocket};

use doh_upstream::Handler;

fn echo_handler() -> Handler {
    Arc::new(|req: Message| {
        Box::pin(async move {
            let mut resp = req.clone();
            resp.metadata.message_type = MessageType::Response;
            Ok(resp)
        })
    })
}

fn query() -> Vec<u8> {
    let mut msg = Message::new(9, MessageType::Query, OpCode::Query);
    msg.add_query(Query::query(
        Name::from_str("example.com.").unwrap(),
        RecordType::A,
    ));
    msg.to_bytes().unwrap()
}

async fn udp_answers(addr: SocketAddr) -> bool {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(&query(), addr).await.unwrap();
    let mut buf = [0u8; 512];
    tokio::time::timeout(Duration::from_millis(300), socket.recv_from(&mut buf))
        .await
        .is_ok_and(|r| r.is_ok())
}

#[tokio::test]
async fn stop_accepting_closes_listeners_but_keeps_accepted_connections() {
    // Find a free port for both UDP and TCP.
    let addr = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    doh_upstream::serve(addr, echo_handler()).await.unwrap();

    assert!(udp_answers(addr).await);
    // One exchange first, so the server has really accepted the connection
    // (a connection still in the kernel's backlog is reset when the
    // listener closes, as with any server).
    let mut established = TcpStream::connect(addr).await.unwrap();
    assert!(tcp_exchange(&mut established).await);

    doh_upstream::listener::stop_accepting();
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert!(!udp_answers(addr).await, "udp still answering");
    assert!(
        TcpStream::connect(addr).await.is_err(),
        "tcp still accepting"
    );

    // The connection accepted before the stop is still served.
    assert!(tcp_exchange(&mut established).await);
}

async fn tcp_exchange(stream: &mut TcpStream) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let q = query();
    stream
        .write_all(&(q.len() as u16).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(&q).await.unwrap();
    let Ok(Ok(len)) = tokio::time::timeout(Duration::from_secs(2), stream.read_u16()).await else {
        return false;
    };
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await.is_ok()
}
