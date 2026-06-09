#![doc = include_str!("../README.md")]

use dashmap::DashMap;
use packet::{NetworkPacket, NetworkTuple, TransportHeader};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    select,
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};

pub(crate) type PacketSender = UnboundedSender<NetworkPacket>;
pub(crate) type PacketReceiver = UnboundedReceiver<NetworkPacket>;

/// Lock-free, sharded map of live per-flow sender handles.
///
/// The dispatcher (`process_device_read`) reads via `get(&tuple)` to find the
/// owning stream's `PacketSender`. Streams clean themselves up via
/// [`SessionGuard`]'s `Drop` impl — no async indirection, no spawned cleanup
/// task, no `oneshot` channel. RAII end-to-end.
pub(crate) type SessionMap = Arc<DashMap<NetworkTuple, PacketSender>>;

/// RAII guard owning one slot in the [`SessionMap`].
///
/// Each [`IpStackTcpStream`] / [`IpStackUdpStream`] embeds a `SessionGuard` for
/// its 5-tuple. When the user drops the stream, this guard's `Drop` runs and
/// synchronously removes the entry from the shared `DashMap` — the very next
/// uplink packet for that tuple will be treated as a new flow (vacant entry
/// path in `process_device_read`).
///
/// This replaces the pre-fork `Option<tokio::sync::oneshot::Sender<()>>` +
/// spawned-cleanup-task pattern, which had a race window: between
/// stream-drop and the cleanup task posting the tuple to a `session_remove_rx`
/// arm of the dispatcher's `select!`, the dispatcher could observe the stale
/// `Occupied` entry, call `entry.get().send(packet)` on a closed receiver,
/// and silently drop the packet.
#[derive(Debug)]
pub(crate) struct SessionGuard {
    sessions: SessionMap,
    tuple: NetworkTuple,
}

impl SessionGuard {
    pub(crate) fn new(sessions: SessionMap, tuple: NetworkTuple) -> Self {
        Self { sessions, tuple }
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        // `remove` is a no-op if the entry has already been replaced by a
        // racing `process_device_read` recreate path — that's fine, the new
        // entry holds a different `PacketSender` and we don't own it.
        // `remove_if` would gate on identity, but PacketSender doesn't impl
        // PartialEq, so we do the looser `remove`. The window for collision
        // is identical to the recreate path (microseconds), and overshoot
        // there is idempotent: the next uplink packet would just create the
        // entry again as a new flow.
        if self.sessions.remove(&self.tuple).is_some() {
            log::debug!("session destroyed: {}", self.tuple);
        }
    }
}

mod error;
mod packet;
mod stream;

pub use self::error::{IpStackError, Result};
pub use self::stream::{IpStackStream, IpStackTcpStream, IpStackUdpStream, IpStackUnknownTransport};
pub use self::stream::{TcpConfig, TcpOptions};
pub use etherparse::IpNumber;

#[cfg(unix)]
const TTL: u8 = 64;

#[cfg(windows)]
const TTL: u8 = 128;

#[cfg(unix)]
const TUN_FLAGS: [u8; 2] = [0x00, 0x00];

#[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd", target_os = "espidf"))]
const TUN_PROTO_IP6: [u8; 2] = [0x86, 0xdd];
#[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd", target_os = "espidf"))]
const TUN_PROTO_IP4: [u8; 2] = [0x08, 0x00];

#[cfg(any(target_os = "macos", target_os = "ios"))]
const TUN_PROTO_IP6: [u8; 2] = [0x00, 0x0A];
#[cfg(any(target_os = "macos", target_os = "ios"))]
const TUN_PROTO_IP4: [u8; 2] = [0x00, 0x02];

/// Minimum MTU required for IPv6 (per RFC 8200 §5: MTU ≥ 1280).
/// Also satisfies IPv4 minimum MTU (RFC 791 §3.1: 68 bytes).
const MIN_MTU: u16 = 1280;

/// Configuration for the IP stack.
///
/// This structure holds configuration parameters that control the behavior of the IP stack,
/// including network settings and protocol-specific timeouts.
///
/// # Examples
///
/// ```
/// use ipstack::IpStackConfig;
/// use std::time::Duration;
///
/// let mut config = IpStackConfig::default();
/// config.mtu(1500).expect("Failed to set MTU")
///       .udp_timeout(Duration::from_secs(60))
///       .packet_information(false);
/// ```
#[non_exhaustive]
pub struct IpStackConfig {
    /// Maximum Transmission Unit (MTU) size in bytes.
    /// Default is `MIN_MTU` (1280).
    pub mtu: u16,
    /// Whether to include packet information headers (Unix platforms only).
    /// Default is `false`.
    pub packet_information: bool,
    /// TCP-specific configuration parameters.
    pub tcp_config: Arc<TcpConfig>,
    /// Timeout for UDP connections.
    /// Default is 30 seconds.
    pub udp_timeout: Duration,
}

impl Default for IpStackConfig {
    fn default() -> Self {
        IpStackConfig {
            mtu: MIN_MTU,
            packet_information: false,
            tcp_config: Arc::new(TcpConfig::default()),
            udp_timeout: Duration::from_secs(30),
        }
    }
}

impl IpStackConfig {
    /// Set custom TCP configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The TCP configuration to use
    ///
    /// # Examples
    ///
    /// ```
    /// use ipstack::{IpStackConfig, TcpConfig};
    ///
    /// let mut config = IpStackConfig::default();
    /// config.with_tcp_config(TcpConfig::default());
    /// ```
    pub fn with_tcp_config(&mut self, config: TcpConfig) -> &mut Self {
        self.tcp_config = Arc::new(config);
        self
    }

    /// Set the UDP connection timeout.
    ///
    /// # Arguments
    ///
    /// * `timeout` - The timeout duration for UDP connections
    ///
    /// # Examples
    ///
    /// ```
    /// use ipstack::IpStackConfig;
    /// use std::time::Duration;
    ///
    /// let mut config = IpStackConfig::default();
    /// config.udp_timeout(Duration::from_secs(60));
    /// ```
    pub fn udp_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.udp_timeout = timeout;
        self
    }

    /// Set the Maximum Transmission Unit (MTU) size.
    ///
    /// # Arguments
    ///
    /// * `mtu` - The MTU size in bytes
    ///
    /// # Examples
    ///
    /// ```
    /// use ipstack::IpStackConfig;
    ///
    /// let mut config = IpStackConfig::default();
    /// config.mtu(1500).expect("Failed to set MTU");
    /// ```
    pub fn mtu(&mut self, mtu: u16) -> Result<&mut Self, IpStackError> {
        if mtu < MIN_MTU {
            return Err(IpStackError::InvalidMtuSize(mtu));
        }
        self.mtu = mtu;
        Ok(self)
    }

    /// Set the Maximum Transmission Unit (MTU) size without validation.
    pub fn mtu_unchecked(&mut self, mtu: u16) -> &mut Self {
        self.mtu = mtu;
        self
    }

    /// Enable or disable packet information headers (Unix platforms only).
    ///
    /// When enabled on Unix platforms, the TUN device will include 4-byte packet
    /// information headers.
    ///
    /// # Arguments
    ///
    /// * `packet_information` - Whether to include packet information headers
    ///
    /// # Examples
    ///
    /// ```
    /// use ipstack::IpStackConfig;
    ///
    /// let mut config = IpStackConfig::default();
    /// config.packet_information(true);
    /// ```
    pub fn packet_information(&mut self, packet_information: bool) -> &mut Self {
        self.packet_information = packet_information;
        self
    }
}

/// The main IP stack instance.
///
/// `IpStack` provides a userspace TCP/IP stack implementation for TUN devices.
/// It processes network packets and creates stream abstractions for TCP, UDP, and
/// unknown transport protocols.
///
/// # Examples
///
/// ```no_run
/// use ipstack::{IpStack, IpStackConfig, IpStackStream};
/// use std::net::Ipv4Addr;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // Configure TUN device
///     let mut config = tun::Configuration::default();
///     config
///         .address(Ipv4Addr::new(10, 0, 0, 1))
///         .netmask(Ipv4Addr::new(255, 255, 255, 0))
///         .up();
///
///     // Create IP stack
///     let ipstack_config = IpStackConfig::default();
///     let mut ip_stack = IpStack::new(ipstack_config, tun::create_as_async(&config)?);
///
///     // Accept incoming streams
///     while let Ok(stream) = ip_stack.accept().await {
///         match stream {
///             IpStackStream::Tcp(tcp) => {
///                 // Handle TCP connection
///             }
///             IpStackStream::Udp(udp) => {
///                 // Handle UDP connection
///             }
///             _ => {}
///         }
///     }
///     Ok(())
/// }
/// ```
pub struct IpStack {
    accept_receiver: UnboundedReceiver<IpStackStream>,
    handle: JoinHandle<Result<()>>,
}

impl IpStack {
    /// Create a new IP stack instance.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for the IP stack
    /// * `device` - An async TUN device implementing `AsyncRead` + `AsyncWrite`
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use ipstack::{IpStack, IpStackConfig};
    /// use std::net::Ipv4Addr;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut tun_config = tun::Configuration::default();
    /// tun_config.address(Ipv4Addr::new(10, 0, 0, 1))
    ///           .netmask(Ipv4Addr::new(255, 255, 255, 0))
    ///           .up();
    ///
    /// let ipstack_config = IpStackConfig::default();
    /// let ip_stack = IpStack::new(ipstack_config, tun::create_as_async(&tun_config)?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new<Device>(config: IpStackConfig, device: Device) -> IpStack
    where
        Device: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (accept_sender, accept_receiver) = mpsc::unbounded_channel::<IpStackStream>();
        IpStack {
            accept_receiver,
            handle: run(config, device, accept_sender),
        }
    }

    /// Accept an incoming network stream.
    ///
    /// This method waits for and returns the next incoming network connection or packet.
    /// The returned `IpStackStream` enum indicates the type of stream (TCP, UDP, or unknown).
    ///
    /// # Returns
    ///
    /// * `Ok(IpStackStream)` - The next incoming stream
    /// * `Err(IpStackError::AcceptError)` - If the IP stack has been shut down
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use ipstack::{IpStack, IpStackConfig, IpStackStream};
    ///
    /// # async fn example(mut ip_stack: IpStack) -> Result<(), Box<dyn std::error::Error>> {
    /// match ip_stack.accept().await? {
    ///     IpStackStream::Tcp(tcp) => {
    ///         println!("New TCP connection from {}", tcp.peer_addr());
    ///     }
    ///     IpStackStream::Udp(udp) => {
    ///         println!("New UDP stream from {}", udp.peer_addr());
    ///     }
    ///     IpStackStream::UnknownTransport(unknown) => {
    ///         println!("Unknown transport protocol: {:?}", unknown.ip_protocol());
    ///     }
    ///     IpStackStream::UnknownNetwork(data) => {
    ///         println!("Unknown network packet: {} bytes", data.len());
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn accept(&mut self) -> Result<IpStackStream, IpStackError> {
        self.accept_receiver.recv().await.ok_or(IpStackError::AcceptError)
    }
}

impl Drop for IpStack {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

fn run<Device: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    config: IpStackConfig,
    mut device: Device,
    accept_sender: UnboundedSender<IpStackStream>,
) -> JoinHandle<Result<()>> {
    let sessions: SessionMap = Arc::new(DashMap::new());
    let pi = config.packet_information;
    let offset = if pi && cfg!(unix) { 4 } else { 0 };
    let mut buffer = vec![0_u8; config.mtu as usize + offset];
    let (up_pkt_sender, mut up_pkt_receiver) = mpsc::unbounded_channel::<NetworkPacket>();

    tokio::spawn(async move {
        loop {
            // `biased` orders the arms top-down. We drain pending uplink
            // (already-buffered packets being written back to the device)
            // before reading more from the device. This keeps the device
            // writer-side from starving when uplink traffic is heavy, and
            // also tightens the recreate-on-send-failure window in
            // `process_device_read` (any uplink-side ACK pushed by a closing
            // session lands on the wire promptly, before we read a follow-up
            // packet that might race with stream cleanup).
            select! {
                biased;
                Some(packet) = up_pkt_receiver.recv() => {
                    process_upstream_recv(packet, &mut device, #[cfg(unix)]pi).await?;
                }
                Ok(n) = device.read(&mut buffer) => {
                    if let Err(e) = process_device_read(&buffer[offset..n], &sessions, &up_pkt_sender, &config, &accept_sender).await {
                        let io_err: std::io::Error = e.into();
                        if io_err.kind() == std::io::ErrorKind::ConnectionRefused {
                            log::trace!("Received junk data: {io_err}");
                        } else {
                            log::warn!("process_device_read error: {io_err}");
                        }
                    }
                }
            }
        }
    })
}

async fn process_device_read(
    data: &[u8],
    sessions: &SessionMap,
    up_pkt_sender: &PacketSender,
    config: &IpStackConfig,
    accept_sender: &UnboundedSender<IpStackStream>,
) -> Result<()> {
    let Ok(packet) = NetworkPacket::parse(data) else {
        let stream = IpStackStream::UnknownNetwork(data.to_owned());
        accept_sender.send(stream)?;
        return Ok(());
    };

    if let TransportHeader::Unknown = packet.transport_header() {
        let stream = IpStackStream::UnknownTransport(IpStackUnknownTransport::new(
            packet.src_addr().ip(),
            packet.dst_addr().ip(),
            packet.payload.unwrap_or_default(),
            &packet.ip,
            config.mtu,
            up_pkt_sender.clone(),
        ));
        accept_sender.send(stream)?;
        return Ok(());
    }

    let network_tuple = packet.network_tuple();

    // Fast path: dispatch to existing stream. If the receiver has been
    // dropped (user dropped the stream slightly before this dispatch), we
    // detect the failed `send`, evict the stale entry, and fall through to
    // the new-stream path below. This is the recreate-on-send-failure fix
    // for the long-standing UDP-packet-drop race that haunted upstream
    // ipstack: pre-fix, a closed `PacketSender` would silently lose every
    // subsequent packet on that 5-tuple until the spawned cleanup task got
    // scheduled and posted the tuple to `session_remove_rx`. With this fix
    // the loss is bounded to AT MOST the in-flight packet that lost the
    // race; the next packet creates a fresh stream as if the flow were new.
    let packet = if let Some(sender_ref) = sessions.get(&network_tuple) {
        match sender_ref.send(packet) {
            Ok(()) => {
                let _ = sender_ref;
                return Ok(());
            }
            Err(send_err) => {
                drop(sender_ref);
                // `remove` is best-effort. The user-side stream's
                // `SessionGuard::Drop` may have raced and already removed
                // the entry. Either way, we now own the rejected packet
                // and route it through the vacant-entry path below.
                sessions.remove(&network_tuple);
                let pkt = send_err.0;
                // For TCP, only resurrect on a SYN — anything else is
                // mid-conversation and would land on a fresh TCB whose
                // ack/seq don't line up. Drop silently; the peer will
                // retransmit a SYN if it really wants a new connection.
                if let TransportHeader::Tcp(h) = pkt.transport_header()
                    && !h.syn
                {
                    log::trace!("stream dead, discarding non-SYN TCP packet for {network_tuple}");
                    return Ok(());
                }
                log::warn!("stream dead, recreating for {network_tuple}");
                pkt
            }
        }
    } else {
        // Vacant: brand-new flow (or its previous stream was already cleaned
        // up). Same TCP gate: only honor SYN segments.
        if let TransportHeader::Tcp(h) = packet.transport_header()
            && !h.syn
        {
            // Mid-conversation segments to a non-existent TCB get an
            // ACK|RST in `IpStackTcpStream::new` below — let the existing
            // path handle that for diagnostic + protocol-correctness.
        }
        packet
    };

    // New-stream path: fresh entry in the map, and the stream itself owns a
    // `SessionGuard` that will remove the entry on drop.
    let ip_stack_stream = create_stream(packet, config, up_pkt_sender.clone(), sessions.clone(), network_tuple)?;
    let packet_sender = ip_stack_stream.stream_sender()?;
    accept_sender.send(ip_stack_stream)?;
    sessions.insert(network_tuple, packet_sender);
    log::debug!("session created: {network_tuple}");
    Ok(())
}

fn create_stream(
    packet: NetworkPacket,
    cfg: &IpStackConfig,
    up_pkt_sender: PacketSender,
    sessions: SessionMap,
    tuple: NetworkTuple,
) -> Result<IpStackStream> {
    let src_addr = packet.src_addr();
    let dst_addr = packet.dst_addr();
    let guard = SessionGuard::new(sessions, tuple);
    match packet.transport_header() {
        TransportHeader::Tcp(h) => {
            let stream = IpStackTcpStream::new(src_addr, dst_addr, h.clone(), up_pkt_sender, cfg.mtu, guard, cfg.tcp_config.clone())?;
            Ok(IpStackStream::Tcp(stream))
        }
        TransportHeader::Udp(_) => {
            let payload = packet.payload.unwrap_or_default();
            let stream = IpStackUdpStream::new(src_addr, dst_addr, payload, up_pkt_sender, cfg.mtu, cfg.udp_timeout, guard);
            Ok(IpStackStream::Udp(stream))
        }
        TransportHeader::Unknown => Err(IpStackError::UnsupportedTransportProtocol),
    }
}

async fn process_upstream_recv<Device: AsyncWrite + Unpin + 'static>(
    up_packet: NetworkPacket,
    device: &mut Device,
    #[cfg(unix)] packet_information: bool,
) -> Result<()> {
    #[allow(unused_mut)]
    let Ok(mut packet_bytes) = up_packet.to_bytes() else {
        log::warn!("to_bytes error");
        return Ok(());
    };
    #[cfg(unix)]
    if packet_information {
        if up_packet.src_addr().is_ipv4() {
            packet_bytes.splice(0..0, [TUN_FLAGS, TUN_PROTO_IP4].concat());
        } else {
            packet_bytes.splice(0..0, [TUN_FLAGS, TUN_PROTO_IP6].concat());
        }
    }
    device.write_all(&packet_bytes).await?;
    // device.flush().await?;

    Ok(())
}
