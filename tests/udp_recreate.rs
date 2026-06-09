//! Regression test for the long-standing UDP-packet-drop race in upstream
//! `ipstack` that prompted the Quantux Labs fork.
//!
//! # The bug (pre-fork)
//!
//! Each per-flow `IpStackUdpStream` registered its sender in the dispatcher's
//! session map. On user-side drop, an `Option<oneshot::Sender<()>>` fired,
//! waking a separately-spawned task that posted the 5-tuple into a
//! `session_remove_rx` mpsc channel. The dispatcher only removed the entry
//! when the `select!` happened to pick that arm.
//!
//! Between drop and that random scheduling event, the dispatcher's
//! `device.read` arm could win one or more iterations, see `Occupied(entry)`
//! for the same 5-tuple, call `entry.get().send(packet)` on a now-closed
//! receiver, and silently drop every packet that landed in the window.
//! For chatty UDP flows (DNS resolvers, QUIC tunnels) this manifested as
//! mysterious packet loss the dev described as "haunting me for 2 years".
//!
//! # The fix (this fork)
//!
//! `process_device_read` (`src/lib.rs`) now detects `entry.get().send(packet)`
//! returning `Err`, evicts the stale slot from the lock-free `DashMap`, and
//! falls through to the new-stream path \u2014 spawning a fresh
//! `IpStackUdpStream` from the rejected packet itself. RAII `SessionGuard`
//! ensures the slot is detached on user-side drop without any async
//! indirection.
//!
//! This test exercises that exact sequence: drop a UDP stream, then inject a
//! second datagram on the same 5-tuple immediately. Pre-fork, the second
//! datagram would be lost. Post-fork, a fresh stream is accepted.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use etherparse::{IpNumber, Ipv4Header, UdpHeader};
use ipstack::{IpStack, IpStackConfig, IpStackStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const CLIENT_PORT: u16 = 50_000;
const SERVER_PORT: u16 = 53;

/// Build a serialised IPv4 + UDP packet for the test 5-tuple. The fields
/// match what `ipstack`'s parser expects: minimal IPv4 header, no options,
/// `IpNumber::UDP`, and a checksum-correct UDP header.
fn build_udp_packet(payload: &[u8]) -> Vec<u8> {
    let mut ip = Ipv4Header::new(0, 64, IpNumber::UDP, CLIENT_IP.octets(), SERVER_IP.octets()).expect("ip header");
    ip.set_payload_len(8 + payload.len()).expect("payload len");

    let udp = UdpHeader::with_ipv4_checksum(CLIENT_PORT, SERVER_PORT, &ip, payload).expect("udp checksum");

    let mut bytes = Vec::with_capacity(ip.header_len() + 8 + payload.len());
    ip.write(&mut bytes).expect("ip write");
    udp.write(&mut bytes).expect("udp write");
    bytes.extend_from_slice(payload);
    bytes
}

/// Mock TUN-like device. The ipstack worker reads from `read_rx` (we inject
/// packet bytes there) and writes to `write_buf` (drained at end-of-test).
///
/// One whole IP packet per `poll_read` matches what a real `tun_rs::AsyncDevice`
/// produces, so we don't need any framing layer here.
struct MockDevice {
    read_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    write_buf: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl AsyncRead for MockDevice {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.read_rx.poll_recv(cx) {
            Poll::Ready(Some(pkt)) => {
                let n = pkt.len().min(buf.remaining());
                buf.put_slice(&pkt[..n]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF; ipstack will idle
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for MockDevice {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        self.write_buf.lock().unwrap().push(buf.to_vec());
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_packet_after_stream_drop_creates_fresh_stream() {
    let _ = env_logger::builder().is_test(true).try_init();

    let (read_tx, read_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let write_buf = Arc::new(Mutex::new(Vec::new()));
    let device = MockDevice {
        read_rx,
        write_buf: write_buf.clone(),
    };

    let mut ipstack_config = IpStackConfig::default();
    ipstack_config.mtu(1500).expect("mtu");
    let mut ip_stack = IpStack::new(ipstack_config, device);

    // First UDP datagram: a fresh flow is accepted.
    read_tx.send(build_udp_packet(b"first")).expect("send first");

    let first_stream = match tokio::time::timeout(Duration::from_secs(2), ip_stack.accept()).await {
        Ok(Ok(IpStackStream::Udp(udp))) => udp,
        Ok(Ok(other)) => panic!("expected Udp, got {:?}", other.local_addr()),
        Ok(Err(e)) => panic!("first accept errored: {e}"),
        Err(_) => panic!("first accept timed out"),
    };
    assert_eq!(first_stream.local_addr(), SocketAddr::new(IpAddr::V4(CLIENT_IP), CLIENT_PORT));
    assert_eq!(first_stream.peer_addr(), SocketAddr::new(IpAddr::V4(SERVER_IP), SERVER_PORT));

    // Drop the stream BEFORE the next packet arrives. The user-side
    // SessionGuard fires on drop, but with the dispatcher's recreate-on-
    // send-failure path even a packet that lands DURING the drop window
    // becomes the seed for a fresh stream.
    drop(first_stream);
    // Yield once so the SessionGuard's drop has a chance to land in the
    // DashMap (the explicit sleep is unnecessary but tightens the test
    // against scheduler quirks).
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Second datagram on the same 5-tuple. Pre-fork: silently dropped.
    // Post-fork: dispatcher detects send-failure (or finds the slot
    // already evicted by the guard's Drop) and creates a fresh stream.
    read_tx.send(build_udp_packet(b"second")).expect("send second");

    let second_stream = match tokio::time::timeout(Duration::from_secs(2), ip_stack.accept()).await {
        Ok(Ok(IpStackStream::Udp(udp))) => udp,
        Ok(Ok(other)) => panic!("expected Udp, got {:?}", other.local_addr()),
        Ok(Err(e)) => panic!("second accept errored: {e}"),
        Err(_) => panic!("second accept timed out -- the UDP-drop race regressed"),
    };
    assert_eq!(second_stream.local_addr(), SocketAddr::new(IpAddr::V4(CLIENT_IP), CLIENT_PORT));
    assert_eq!(second_stream.peer_addr(), SocketAddr::new(IpAddr::V4(SERVER_IP), SERVER_PORT));

    // Cleanup: dropping ip_stack aborts the worker task.
    drop(second_stream);
    drop(ip_stack);
}

/// Tighter race variant: we inject the second datagram WITHOUT yielding
/// after dropping the first stream. This exercises the
/// recreate-on-send-failure path in `process_device_read` more directly,
/// because the SessionGuard's `DashMap::remove` likely won't have completed
/// before the dispatcher reads the second packet, so the dispatcher sees
/// `Occupied`, fails to `send`, evicts, and recreates.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_packet_during_stream_drop_window_is_not_lost() {
    let _ = env_logger::builder().is_test(true).try_init();

    let (read_tx, read_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let write_buf = Arc::new(Mutex::new(Vec::new()));
    let device = MockDevice {
        read_rx,
        write_buf: write_buf.clone(),
    };

    let mut ipstack_config = IpStackConfig::default();
    ipstack_config.mtu(1500).expect("mtu");
    let mut ip_stack = IpStack::new(ipstack_config, device);

    read_tx.send(build_udp_packet(b"a")).expect("send a");
    let stream_a = match tokio::time::timeout(Duration::from_secs(2), ip_stack.accept()).await {
        Ok(Ok(IpStackStream::Udp(udp))) => udp,
        _ => panic!("first accept failed"),
    };

    // Drop and inject the next packet immediately, no yield in between.
    drop(stream_a);
    read_tx.send(build_udp_packet(b"b")).expect("send b");

    let stream_b = match tokio::time::timeout(Duration::from_secs(2), ip_stack.accept()).await {
        Ok(Ok(IpStackStream::Udp(udp))) => udp,
        Ok(Ok(_)) => panic!("expected Udp"),
        Ok(Err(e)) => panic!("second accept errored: {e}"),
        Err(_) => panic!("second accept timed out under the tight drop->send window"),
    };
    assert_eq!(stream_b.local_addr(), SocketAddr::new(IpAddr::V4(CLIENT_IP), CLIENT_PORT));

    drop(stream_b);
    drop(ip_stack);
}
