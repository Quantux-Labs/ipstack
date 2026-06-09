use super::seqnum::SeqNum;
use etherparse::TcpHeader;
use std::{collections::BTreeMap, time::Duration};

pub(super) const MAX_UNACK: u32 = 1024 * 16; // 16KB
pub(super) const READ_BUFFER_SIZE: usize = 1024 * 16; // 16KB
pub(super) const MAX_COUNT_FOR_DUP_ACK: usize = 3; // Maximum number of duplicate ACKs before retransmission

/// Retransmission timeout
pub(super) const RTO: std::time::Duration = std::time::Duration::from_secs(1);

/// Maximum count of retransmissions before dropping the packet
pub(super) const MAX_RETRANSMIT_COUNT: usize = 3;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub(crate) enum TcpState {
    // Init, /* Since we always act as a server, it starts from `Listen`, so we don't use states Init & SynSent. */
    // SynSent,
    Listen = 0,
    SynReceived = 1,
    Established = 2,
    FinWait1 = 3, // act as a client, actively send a farewell packet to the other side, followed with FinWait2, TimeWait, Closed
    FinWait2 = 4,
    TimeWait = 5,
    CloseWait = 6, // act as a server, followed with LastAck, Closed
    LastAck = 7,
    Closed = 8,
}

impl TcpState {
    /// Inverse of `as u8`. Used by [`super::signals::AtomicTcpState`] to
    /// round-trip through `AtomicU8`. Panics on bad discriminants only in
    /// debug builds; the `state` cell is never written from outside this
    /// crate so a stuck unknown byte would be a bug here, not bad input.
    #[inline]
    pub(crate) fn from_u8(v: u8) -> Self {
        match v {
            0 => TcpState::Listen,
            1 => TcpState::SynReceived,
            2 => TcpState::Established,
            3 => TcpState::FinWait1,
            4 => TcpState::FinWait2,
            5 => TcpState::TimeWait,
            6 => TcpState::CloseWait,
            7 => TcpState::LastAck,
            8 => TcpState::Closed,
            other => {
                debug_assert!(false, "AtomicTcpState observed bogus discriminant {other}");
                TcpState::Closed
            }
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub(super) enum PacketType {
    WindowUpdate,
    Invalid,
    RetransmissionRequest,
    NewPacket,
    Ack,
    KeepAlive,
}

/// TCP Control Block
/// - `inflight_packets` is prerepresented bytes stream from upstream application,
///   which have been sent to the lower device but not yet acknowledged.
/// - `unordered_packets` is the bytes stream received from the lower device,
///   which can be acknowledged and extracted by `consume_unordered_packets` method
///   then can be read by upstream application via `Tcp::poll_read` method.
/// - `peer_mss` is the Maximum Segment Size advertised by the peer in their
///   SYN. RFC 9293 §3.7.1 mandates we clamp outgoing segment size to this
///   value. `None` means the peer omitted the option — RFC default is 536
///   (IPv4) but in our implementation we fall back to `mtu - hdr` (also
///   conservative on every modern network).
///
/// The TCP state machine **does NOT live here** — it lives lock-free in
/// [`super::signals::StreamSignals::state`]. That lets `poll_read` /
/// `poll_write` / `poll_shutdown` peek the state with a single Acquire load
/// instead of acquiring the `tcb` mutex (which the per-stream task holds
/// for ~all of its loop body).
#[derive(Debug, Clone)]
pub(crate) struct Tcb {
    seq: SeqNum,
    ack: SeqNum,
    mtu: u16,
    last_received_ack: SeqNum,
    send_window: u16,
    inflight_packets: BTreeMap<SeqNum, InflightPacket>,
    unordered_packets: BTreeMap<SeqNum, Vec<u8>>,
    duplicate_ack_count: usize,
    duplicate_ack_count_helper: SeqNum,
    max_unacked_bytes: u32,
    read_buffer_size: usize,
    max_count_for_dup_ack: usize,
    rto: std::time::Duration,
    max_retransmit_count: usize,
    peer_mss: Option<u16>,
}

impl Tcb {
    pub(super) fn new(
        ack: SeqNum,
        mtu: u16,
        max_unacked_bytes: u32,
        read_buffer_size: usize,
        max_count_for_dup_ack: usize,
        rto: std::time::Duration,
        max_retransmit_count: usize,
    ) -> Tcb {
        #[cfg(debug_assertions)]
        let seq = 100;
        #[cfg(not(debug_assertions))]
        let seq = rand::RngExt::random::<u32>(&mut rand::rng());
        Tcb {
            seq: seq.into(),
            ack,
            mtu,
            last_received_ack: seq.into(),
            send_window: u16::MAX,
            inflight_packets: BTreeMap::new(),
            unordered_packets: BTreeMap::new(),
            duplicate_ack_count: 0,
            duplicate_ack_count_helper: seq.into(),
            max_unacked_bytes,
            read_buffer_size,
            max_count_for_dup_ack,
            rto,
            max_retransmit_count,
            peer_mss: None,
        }
    }

    /// Calculate the maximum payload length for an outgoing TCP segment.
    ///
    /// RFC 9293 §3.7.1: outgoing segments MUST NOT exceed the peer's
    /// advertised MSS. We clamp to the minimum of three constraints:
    ///   * the peer's send window (flow control),
    ///   * the peer's MSS (if advertised in their SYN),
    ///   * `mtu - (ip_header + tcp_header)` (PMTU bound on our side).
    pub fn calculate_payload_max_len(&self, ip_header_size: usize, tcp_header_size: usize) -> usize {
        let send_window = self.get_send_window() as usize;
        let mtu = self.get_mtu() as usize;
        let local_max = mtu.saturating_sub(ip_header_size + tcp_header_size);
        let mut bound = std::cmp::min(send_window, local_max);
        if let Some(peer_mss) = self.peer_mss {
            bound = std::cmp::min(bound, peer_mss as usize);
        }
        bound
    }

    /// Set the peer's advertised MSS. Called once during SYN processing in
    /// [`super::tcp::IpStackTcpStream::new`].
    pub(super) fn set_peer_mss(&mut self, mss: u16) {
        // Reject pathological values: RFC 9293 §3.7.1 mandates a minimum
        // MSS of 1 byte but in practice 88 is the smallest sane value
        // (IPv4 minimum MTU 68 minus 20 IP header + 20 TCP header doesn't
        // make geometric sense for 1-byte payloads; we clamp to 88).
        self.peer_mss = Some(mss.max(88));
    }

    /// Drop every inflight packet without retransmitting. Called on RST
    /// receipt — the peer rejected the connection, no point keeping
    /// zombie retransmit timers alive.
    pub(super) fn clear_inflight_packets(&mut self) {
        let n = self.inflight_packets.len();
        if n > 0 {
            self.inflight_packets.clear();
            log::trace!("cleared {n} inflight packet(s) on RST");
        }
    }

    pub fn update_duplicate_ack_count(&mut self, rcvd_ack: SeqNum) {
        // If the received rcvd_ack is the same as duplicate_ack_count_helper and not all data has been acknowledged (rcvd_ack < self.seq), increment the count.
        if rcvd_ack == self.duplicate_ack_count_helper && rcvd_ack < self.seq {
            self.duplicate_ack_count = self.duplicate_ack_count.saturating_add(1);
        } else {
            self.duplicate_ack_count_helper = rcvd_ack;
            self.duplicate_ack_count = 0; // reset duplicate ACK count
        }
    }

    pub fn is_duplicate_ack_count_exceeded(&self) -> bool {
        self.duplicate_ack_count >= self.max_count_for_dup_ack
    }

    pub(super) fn add_unordered_packet(&mut self, seq: SeqNum, buf: Vec<u8>) {
        if seq < self.ack {
            log::warn!("Received packet seq {seq} < self ack {}, len = {}", self.ack, buf.len());
            return;
        }
        self.unordered_packets.insert(seq, buf);
    }
    pub(super) fn get_available_read_buffer_size(&self) -> usize {
        self.read_buffer_size.saturating_sub(self.get_unordered_packets_total_len())
    }
    #[inline]
    pub(crate) fn get_unordered_packets_total_len(&self) -> usize {
        self.unordered_packets.values().map(|p| p.len()).sum()
    }

    pub(super) fn consume_unordered_packets(&mut self, max_bytes: usize) -> Option<Vec<u8>> {
        let mut data = Vec::new();
        let mut remaining_bytes = max_bytes;

        while remaining_bytes > 0 {
            if let Some(seq) = self.unordered_packets.keys().next().copied() {
                if seq != self.ack {
                    break; // sequence number is not continuous, stop extracting
                }

                // remove and get the first packet
                let mut payload = self.unordered_packets.remove(&seq).unwrap();
                let payload_len = payload.len();

                if payload_len <= remaining_bytes {
                    // current packet can be fully extracted
                    data.extend(payload);
                    self.ack += payload_len as u32;
                    remaining_bytes -= payload_len;
                } else {
                    // current packet can only be partially extracted
                    let remaining_payload = payload.split_off(remaining_bytes);
                    data.extend_from_slice(&payload);
                    self.ack += remaining_bytes as u32;
                    self.unordered_packets.insert(self.ack, remaining_payload);
                    break;
                }
            } else {
                break; // no more packets to extract
            }
        }

        if data.is_empty() { None } else { Some(data) }
    }

    pub(super) fn increase_seq(&mut self) {
        self.seq += 1;
    }
    pub(super) fn get_seq(&self) -> SeqNum {
        self.seq
    }
    pub(super) fn increase_ack(&mut self) {
        self.ack += 1;
    }
    pub(super) fn get_ack(&self) -> SeqNum {
        self.ack
    }
    pub(super) fn get_mtu(&self) -> u16 {
        self.mtu
    }
    pub(super) fn get_last_received_ack(&self) -> SeqNum {
        self.last_received_ack
    }
    pub(super) fn update_send_window(&mut self, window: u16) {
        self.send_window = window;
    }
    pub(super) fn get_send_window(&self) -> u16 {
        self.send_window
    }
    pub(super) fn get_recv_window(&self) -> u16 {
        self.get_available_read_buffer_size().try_into().unwrap_or(u16::MAX)
    }
    // #[inline(always)]
    // pub(super) fn buffer_size(&self, payload_len: u16) -> u16 {
    //     match MAX_UNACK - self.inflight_packets.len() as u32 {
    //         // b if b.saturating_sub(payload_len as u32 + 64) != 0 => payload_len,
    //         // b if b < 128 && b >= 4 => (b / 2) as u16,
    //         // b if b < 4 => b as u16,
    //         // b => (b - 64) as u16,
    //         b if b >= payload_len as u32 * 2 && b > 0 => payload_len,
    //         b if b < 4 => b as u16,
    //         b => (b / 2) as u16,
    //     }
    // }

    pub(super) fn check_pkt_type(&self, tcp_header: &TcpHeader, payload: &[u8]) -> PacketType {
        let rcvd_ack = SeqNum(tcp_header.acknowledgment_number);
        let rcvd_seq = SeqNum(tcp_header.sequence_number);
        let rcvd_window = tcp_header.window_size;
        let len = payload.len();
        let res = if rcvd_ack > self.seq {
            PacketType::Invalid
        } else {
            match rcvd_ack.cmp(&self.get_last_received_ack()) {
                std::cmp::Ordering::Less => PacketType::Invalid,
                std::cmp::Ordering::Equal => {
                    if self.ack - 1 == rcvd_seq && payload.len() <= 1 {
                        PacketType::KeepAlive
                    } else if !payload.is_empty() {
                        PacketType::NewPacket
                    } else if self.get_send_window() == rcvd_window && self.seq != rcvd_ack && self.is_duplicate_ack_count_exceeded() {
                        PacketType::RetransmissionRequest
                    } else {
                        PacketType::WindowUpdate
                    }
                }
                std::cmp::Ordering::Greater => {
                    if payload.is_empty() {
                        PacketType::Ack
                    } else {
                        PacketType::NewPacket
                    }
                }
            }
        };
        #[rustfmt::skip]
        log::trace!("received {{ ack = {:08X?}, seq = {:08X?}, window = {rcvd_window} }}, self {{ ack = {:08X?}, seq = {:08X?}, send_window = {} }}, len = {len}, {res:?}", rcvd_ack.0, rcvd_seq.0, self.ack.0, self.seq.0, self.get_send_window());
        res
    }

    pub(super) fn add_inflight_packet(&mut self, buf: Vec<u8>) -> std::io::Result<()> {
        if buf.is_empty() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Empty payload"));
        }
        let buf_len = buf.len() as u32;
        self.inflight_packets.insert(self.seq, InflightPacket::new(self.seq, buf, self.rto));
        self.seq += buf_len;
        Ok(())
    }

    pub(super) fn update_last_received_ack(&mut self, ack: SeqNum) {
        self.last_received_ack = ack;
    }

    pub(crate) fn update_inflight_packet_queue(&mut self, ack: SeqNum) {
        match self.inflight_packets.first_key_value() {
            None => return,
            Some((&seq, _)) if ack < seq => return,
            _ => {}
        }
        if let Some(seq) = self
            .inflight_packets
            .iter()
            .find(|(_, p)| p.contains_seq_num(ack - 1))
            .map(|(&s, _)| s)
        {
            let mut inflight_packet = self.inflight_packets.remove(&seq).unwrap();
            let distance = ack.distance(inflight_packet.seq) as usize;
            if distance < inflight_packet.payload.len() {
                inflight_packet.payload.drain(0..distance);
                inflight_packet.seq = ack;
                self.inflight_packets.insert(ack, inflight_packet);
            }
        }
        self.inflight_packets.retain(|_, p| ack < p.seq + p.payload.len() as u32);
    }

    pub(crate) fn find_inflight_packet(&self, seq: SeqNum) -> Option<&InflightPacket> {
        self.inflight_packets.get(&seq)
    }

    #[must_use]
    pub(crate) fn collect_timed_out_inflight_packets(&mut self) -> Vec<InflightPacket> {
        let mut retransmit_list = Vec::new();

        self.inflight_packets.retain(|_, packet| {
            if packet.retransmit_count >= self.max_retransmit_count {
                log::warn!("Packet with seq {:?} reached max retransmit count, dropping packet", packet.seq);
                return false; // remove this packet
            }
            if packet.is_timed_out() {
                packet.retransmit_count += 1;
                packet.retransmit_timeout *= 2; // increase timeout exponentially
                packet.send_time = std::time::Instant::now();
                retransmit_list.push(packet.clone());
            }
            true // keep the packet in the inflight_packets
        });
        retransmit_list
    }

    pub(crate) fn get_inflight_packets_total_len(&self) -> usize {
        self.inflight_packets.values().map(|p| p.payload.len()).sum()
    }

    #[allow(dead_code)]
    pub(crate) fn get_all_inflight_packets(&self) -> Vec<&InflightPacket> {
        self.inflight_packets.values().collect::<Vec<_>>()
    }

    pub fn is_send_buffer_full(&self) -> bool {
        // To respect the receiver's window (remote_window) size and avoid sending too many unacknowledged packets, which may cause packet loss
        // Simplified version: min(cwnd, rwnd)
        self.seq.distance(self.get_last_received_ack()) >= self.max_unacked_bytes.min(self.get_send_window() as u32)
    }
}

#[derive(Debug, Clone)]
pub struct InflightPacket {
    pub seq: SeqNum,
    pub payload: Vec<u8>,
    pub send_time: std::time::Instant,
    pub retransmit_count: usize,
    pub retransmit_timeout: std::time::Duration, // current retransmission timeout
}

impl InflightPacket {
    fn new(seq: SeqNum, payload: Vec<u8>, rto: Duration) -> Self {
        Self {
            seq,
            payload,
            send_time: std::time::Instant::now(),
            retransmit_count: 0,
            retransmit_timeout: rto,
        }
    }
    pub(crate) fn contains_seq_num(&self, seq: SeqNum) -> bool {
        self.seq <= seq && seq < self.seq + self.payload.len() as u32
    }
    pub(crate) fn is_timed_out(&self) -> bool {
        self.send_time.elapsed() >= self.retransmit_timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_flight_packet() {
        let p = InflightPacket::new((u32::MAX - 1).into(), vec![10, 20, 30, 40, 50], RTO);

        assert!(p.contains_seq_num((u32::MAX - 1).into()));
        assert!(p.contains_seq_num(u32::MAX.into()));
        assert!(p.contains_seq_num(0.into()));
        assert!(p.contains_seq_num(1.into()));
        assert!(p.contains_seq_num(2.into()));

        assert!(!p.contains_seq_num(3.into()));
    }

    #[test]
    fn test_get_unordered_packets_with_max_bytes() {
        let mut tcb = Tcb::new(
            SeqNum(1000),
            1500,
            MAX_UNACK,
            READ_BUFFER_SIZE,
            MAX_COUNT_FOR_DUP_ACK,
            RTO,
            MAX_RETRANSMIT_COUNT,
        );

        // insert 3 consecutive packets
        tcb.add_unordered_packet(SeqNum(1000), vec![1; 500]); // seq=1000, len=500
        tcb.add_unordered_packet(SeqNum(1500), vec![2; 500]); // seq=1500, len=500
        tcb.add_unordered_packet(SeqNum(2000), vec![3; 500]); // seq=2000, len=500

        // test 1: extract up to 700 bytes
        let data = tcb.consume_unordered_packets(700).unwrap();
        assert_eq!(data.len(), 700); // extract 500 + 200
        assert_eq!(data[..500], vec![1; 500]); // the first packet
        assert_eq!(data[500..700], vec![2; 200]); // the first 200 bytes of the second packet
        assert_eq!(tcb.ack, SeqNum(1700)); // ack increased by 700
        assert_eq!(tcb.unordered_packets.len(), 2); // remaining two packets
        assert_eq!(tcb.unordered_packets.get(&SeqNum(1700)).unwrap().len(), 300); // the second packet remaining 300 bytes
        assert_eq!(tcb.unordered_packets.get(&SeqNum(2000)).unwrap().len(), 500); // the third packet unchanged

        // test 2: extract up to 800 bytes
        let data = tcb.consume_unordered_packets(800).unwrap();
        assert_eq!(data.len(), 800); // extract 300 bytes of the second packet and the third packet
        assert_eq!(data[..300], vec![2; 300]); // the remaining 300 bytes of the second packet
        assert_eq!(data[300..800], vec![3; 500]); // the third packet
        assert_eq!(tcb.ack, SeqNum(2500)); // ack increased by 800
        assert_eq!(tcb.unordered_packets.len(), 0); // no remaining packets

        // test 3: no data to extract
        let data = tcb.consume_unordered_packets(1000);
        assert!(data.is_none());
    }

    #[test]
    fn test_update_inflight_packet_queue() {
        let mut tcb = Tcb::new(
            SeqNum(1000),
            1500,
            MAX_UNACK,
            READ_BUFFER_SIZE,
            MAX_COUNT_FOR_DUP_ACK,
            RTO,
            MAX_RETRANSMIT_COUNT,
        );
        tcb.seq = SeqNum(100); // setting the initial seq

        // insert 3 consecutive packets
        tcb.add_inflight_packet(vec![1; 500]).unwrap(); // seq=100, len=500
        tcb.add_inflight_packet(vec![2; 500]).unwrap(); // seq=600, len=500
        tcb.add_inflight_packet(vec![3; 500]).unwrap(); // seq=1100, len=500

        // test 1: confirm partial packets (ack=800)
        tcb.update_inflight_packet_queue(SeqNum(800));
        assert_eq!(tcb.inflight_packets.len(), 2); // remaining two packets
        let first_packet = tcb.inflight_packets.first_key_value().unwrap().1;
        assert_eq!(first_packet.seq, SeqNum(800)); // the remaining part of the first packet
        assert_eq!(first_packet.payload.len(), 300); // remaining 300 bytes in the first packet
        let second_packet = tcb.inflight_packets.last_key_value().unwrap().1;
        assert_eq!(second_packet.seq, SeqNum(1100)); // no change in the second packet

        // test 2: confirm all packets (ack=2000)
        tcb.update_inflight_packet_queue(SeqNum(2000));
        assert_eq!(tcb.inflight_packets.len(), 0); // all packets are acknowledged
    }

    #[test]
    fn test_update_inflight_packet_queue_cumulative_ack() {
        let mut tcb = Tcb::new(
            SeqNum(1000),
            1500,
            MAX_UNACK,
            READ_BUFFER_SIZE,
            MAX_COUNT_FOR_DUP_ACK,
            RTO,
            MAX_RETRANSMIT_COUNT,
        );
        tcb.seq = SeqNum(1000);

        // Insert 3 consecutive packets
        tcb.add_inflight_packet(vec![1; 500]).unwrap(); // seq=1000, len=500
        tcb.add_inflight_packet(vec![2; 500]).unwrap(); // seq=1500, len=500
        tcb.add_inflight_packet(vec![3; 500]).unwrap(); // seq=2000, len=500

        // Emulate cumulative ACK: ack=2500
        tcb.update_inflight_packet_queue(SeqNum(2500));
        assert_eq!(tcb.inflight_packets.len(), 0); // all packets should be removed
    }

    #[test]
    fn test_retransmit_with_exponential_backoff() {
        let mut tcb = Tcb::new(
            SeqNum(1000),
            1500,
            MAX_UNACK,
            READ_BUFFER_SIZE,
            MAX_COUNT_FOR_DUP_ACK,
            RTO,
            MAX_RETRANSMIT_COUNT,
        );

        tcb.add_inflight_packet(vec![1; 500]).unwrap();

        // Simulate retransmission timeouts
        for i in 0..MAX_RETRANSMIT_COUNT {
            // Simulate a timeout for the first packet
            let timeout = tcb.inflight_packets.values().next().unwrap().retransmit_timeout + std::time::Duration::from_millis(100);
            println!("timeout: {timeout:?}");
            std::thread::sleep(timeout);

            let packets = tcb.collect_timed_out_inflight_packets();
            assert_eq!(packets.len(), 1);
            let packet = &packets[0];
            assert_eq!(packet.retransmit_count, i + 1);
            assert!(packet.retransmit_timeout > RTO);
        }

        let packets = tcb.collect_timed_out_inflight_packets();
        assert!(packets.is_empty());
        assert!(tcb.inflight_packets.is_empty());
    }
}
