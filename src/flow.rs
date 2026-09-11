//! TCP flow tracking and state machine
//!
//! Tracks TCP connections and their state for RTT measurement.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Unique identifier for a TCP flow (bidirectional)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// Lower address (by IP, then port)
    pub addr_a: SocketAddr,
    /// Higher address
    pub addr_b: SocketAddr,
}

impl FlowKey {
    /// Create a flow key from source and destination addresses.
    /// Normalizes to ensure consistent ordering regardless of direction.
    pub fn new(src: SocketAddr, dst: SocketAddr) -> Self {
        if src < dst {
            Self { addr_a: src, addr_b: dst }
        } else {
            Self { addr_a: dst, addr_b: src }
        }
    }

    /// Check if this packet is from addr_a to addr_b
    pub fn is_a_to_b(&self, src: SocketAddr) -> bool {
        src == self.addr_a
    }
}

impl std::fmt::Display for FlowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} <-> {}", self.addr_a, self.addr_b)
    }
}

/// TCP flags extracted from packet
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
}

impl TcpFlags {
    pub fn from_byte(flags: u8) -> Self {
        Self {
            fin: flags & 0x01 != 0,
            syn: flags & 0x02 != 0,
            rst: flags & 0x04 != 0,
            psh: flags & 0x08 != 0,
            ack: flags & 0x10 != 0,
        }
    }

    pub fn is_syn(&self) -> bool {
        self.syn && !self.ack
    }

    pub fn is_syn_ack(&self) -> bool {
        self.syn && self.ack
    }

    pub fn is_pure_ack(&self) -> bool {
        self.ack && !self.syn && !self.fin && !self.rst
    }
}

/// State of a TCP flow for RTT tracking
#[derive(Debug, Clone)]
pub enum FlowState {
    /// Initial SYN seen, waiting for SYN-ACK
    SynSent {
        initiator: SocketAddr,
        syn_time: Instant,
        syn_seq: u32,
    },

    /// SYN-ACK received, waiting for final ACK
    SynAckReceived {
        initiator: SocketAddr,
        syn_time: Instant,
        syn_ack_time: Instant,
        syn_ack_seq: u32,
    },

    /// Connection established, tracking data RTT
    Established {
        initiator: SocketAddr,
        handshake_rtt: Duration,
        pending_data: HashMap<u32, PendingSegment>,
    },

    /// Connection closing
    Closing,

    /// Connection closed
    Closed,
}

/// A data segment waiting for ACK
#[derive(Debug, Clone)]
pub struct PendingSegment {
    pub send_time: Instant,
    pub seq_end: u32,
    pub payload_len: u16,
}

/// Tracked TCP flow with state and RTT samples
#[derive(Debug)]
pub struct TrackedFlow {
    pub key: FlowKey,
    pub state: FlowState,
    pub rtt_samples: Vec<Duration>,
    pub last_activity: Instant,
    pub packets_seen: u64,
    pub bytes_seen: u64,
}

impl TrackedFlow {
    pub fn new(key: FlowKey, initiator: SocketAddr, syn_time: Instant, syn_seq: u32) -> Self {
        Self {
            key,
            state: FlowState::SynSent {
                initiator,
                syn_time,
                syn_seq,
            },
            rtt_samples: Vec::new(),
            last_activity: syn_time,
            packets_seen: 1,
            bytes_seen: 0,
        }
    }

    /// Process a packet and potentially extract RTT sample
    pub fn process_packet(
        &mut self,
        src: SocketAddr,
        flags: TcpFlags,
        seq: u32,
        ack: u32,
        payload_len: u16,
        timestamp: Instant,
    ) -> Option<Duration> {
        self.last_activity = timestamp;
        self.packets_seen += 1;
        self.bytes_seen += payload_len as u64;

        let mut rtt_sample = None;

        match &mut self.state {
            FlowState::SynSent { initiator, syn_time, syn_seq: _ } => {
                // Expect SYN-ACK from responder
                if flags.is_syn_ack() && src != *initiator {
                    let handshake_rtt = timestamp.saturating_duration_since(*syn_time);
                    self.state = FlowState::SynAckReceived {
                        initiator: *initiator,
                        syn_time: *syn_time,
                        syn_ack_time: timestamp,
                        syn_ack_seq: seq,
                    };
                    // SYN -> SYN-ACK is half RTT from initiator's perspective
                    // but full RTT from our observation point
                    rtt_sample = Some(handshake_rtt);
                }
            }

            FlowState::SynAckReceived { initiator, syn_time, syn_ack_time: _, syn_ack_seq: _ } => {
                // Expect ACK from initiator completing handshake
                if flags.is_pure_ack() && src == *initiator {
                    let handshake_rtt = timestamp.saturating_duration_since(*syn_time);
                    self.state = FlowState::Established {
                        initiator: *initiator,
                        handshake_rtt,
                        pending_data: HashMap::new(),
                    };
                }
            }

            FlowState::Established { pending_data, .. } => {
                if flags.rst || flags.fin {
                    self.state = FlowState::Closing;
                    return None;
                }

                // Data packet: track for ACK matching
                if payload_len > 0 {
                    let seq_end = seq.wrapping_add(payload_len as u32);
                    pending_data.insert(seq_end, PendingSegment {
                        send_time: timestamp,
                        seq_end,
                        payload_len,
                    });

                    // Limit pending segments to prevent memory growth
                    if pending_data.len() > 1000 {
                        // Remove oldest entries
                        let mut entries: Vec<_> = pending_data.iter()
                            .map(|(k, v)| (*k, v.send_time))
                            .collect();
                        entries.sort_by_key(|(_, t)| *t);
                        for (k, _) in entries.into_iter().take(500) {
                            pending_data.remove(&k);
                        }
                    }
                }

                // ACK packet: match against pending data
                if flags.ack && ack > 0 {
                    // Find the segment this ACK covers
                    let mut matched_key = None;
                    for (seq_end, segment) in pending_data.iter() {
                        // ACK covers this segment if ack >= seq_end
                        if ack >= *seq_end || (ack < 1000 && *seq_end > u32::MAX - 1000) {
                            let rtt = timestamp.saturating_duration_since(segment.send_time);
                            // Sanity check: RTT should be reasonable
                            if rtt < Duration::from_secs(30) && rtt > Duration::from_micros(10) {
                                rtt_sample = Some(rtt);
                                matched_key = Some(*seq_end);
                                break;
                            }
                        }
                    }

                    // Remove ACKed segment
                    if let Some(key) = matched_key {
                        pending_data.remove(&key);
                    }
                }
            }

            FlowState::Closing => {
                if flags.rst || (flags.fin && flags.ack) {
                    self.state = FlowState::Closed;
                }
            }

            FlowState::Closed => {}
        }

        if let Some(rtt) = rtt_sample {
            self.rtt_samples.push(rtt);
        }

        rtt_sample
    }

    /// Check if flow is still active
    pub fn is_active(&self, now: Instant, timeout: Duration) -> bool {
        !matches!(self.state, FlowState::Closed)
            && now.saturating_duration_since(self.last_activity) < timeout
    }

    /// Check if flow is established
    pub fn is_established(&self) -> bool {
        matches!(self.state, FlowState::Established { .. })
    }

    /// Get handshake RTT if available
    pub fn handshake_rtt(&self) -> Option<Duration> {
        match &self.state {
            FlowState::Established { handshake_rtt, .. } => Some(*handshake_rtt),
            _ => None,
        }
    }
}

/// Flow tracker managing multiple TCP flows
#[derive(Debug)]
pub struct FlowTracker {
    flows: HashMap<FlowKey, TrackedFlow>,
    flow_timeout: Duration,
    max_flows: usize,
}

impl FlowTracker {
    pub fn new(flow_timeout: Duration, max_flows: usize) -> Self {
        Self {
            flows: HashMap::new(),
            flow_timeout,
            max_flows,
        }
    }

    /// Process a TCP packet
    pub fn process_packet(
        &mut self,
        src: SocketAddr,
        dst: SocketAddr,
        flags: TcpFlags,
        seq: u32,
        ack: u32,
        payload_len: u16,
        timestamp: Instant,
    ) -> Option<(FlowKey, Duration)> {
        let key = FlowKey::new(src, dst);

        // New SYN - start tracking new flow
        if flags.is_syn() {
            // Check max flows limit
            if self.flows.len() >= self.max_flows {
                self.cleanup_old_flows(timestamp);
            }

            let flow = TrackedFlow::new(key, src, timestamp, seq);
            self.flows.insert(key, flow);
            return None;
        }

        // Existing flow
        if let Some(flow) = self.flows.get_mut(&key) {
            if let Some(rtt) = flow.process_packet(src, flags, seq, ack, payload_len, timestamp) {
                return Some((key, rtt));
            }
        }

        None
    }

    /// Get flow by key
    pub fn get_flow(&self, key: &FlowKey) -> Option<&TrackedFlow> {
        self.flows.get(key)
    }

    /// Get all active flows
    pub fn active_flows(&self) -> impl Iterator<Item = &TrackedFlow> {
        let now = Instant::now();
        let timeout = self.flow_timeout;
        self.flows.values().filter(move |f| f.is_active(now, timeout))
    }

    /// Clean up old/closed flows
    pub fn cleanup_old_flows(&mut self, now: Instant) {
        self.flows.retain(|_, flow| flow.is_active(now, self.flow_timeout));
    }

    /// Number of tracked flows
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, port as u8)), port)
    }

    #[test]
    fn test_flow_key_normalization() {
        let a = addr(1000);
        let b = addr(2000);

        let key1 = FlowKey::new(a, b);
        let key2 = FlowKey::new(b, a);

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_tcp_flags() {
        let syn = TcpFlags::from_byte(0x02);
        assert!(syn.is_syn());
        assert!(!syn.is_syn_ack());

        let syn_ack = TcpFlags::from_byte(0x12);
        assert!(syn_ack.is_syn_ack());

        let ack = TcpFlags::from_byte(0x10);
        assert!(ack.is_pure_ack());
    }

    #[test]
    fn test_handshake_rtt() {
        let client = addr(50000);
        let server = addr(80);
        let key = FlowKey::new(client, server);

        let mut flow = TrackedFlow::new(key, client, Instant::now(), 1000);

        // Simulate SYN-ACK after 10ms
        std::thread::sleep(Duration::from_millis(10));
        let syn_ack_flags = TcpFlags::from_byte(0x12);
        let rtt = flow.process_packet(server, syn_ack_flags, 2000, 1001, 0, Instant::now());

        assert!(rtt.is_some());
        let rtt = rtt.unwrap();
        assert!(rtt >= Duration::from_millis(9));
        assert!(rtt <= Duration::from_millis(50));
    }

    #[test]
    fn test_flow_tracker() {
        let mut tracker = FlowTracker::new(Duration::from_secs(60), 1000);

        let client = addr(50000);
        let server = addr(80);

        // SYN
        let syn_flags = TcpFlags::from_byte(0x02);
        tracker.process_packet(client, server, syn_flags, 1000, 0, 0, Instant::now());

        assert_eq!(tracker.flow_count(), 1);

        let key = FlowKey::new(client, server);
        assert!(tracker.get_flow(&key).is_some());
    }
}
