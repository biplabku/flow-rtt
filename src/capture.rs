//! Packet capture sources (live interface or pcap file)

use std::net::SocketAddr;
use std::time::Instant;

use pcap::{Capture, Active, Offline, Device};
use etherparse::{SlicedPacket, TransportSlice};

use crate::error::Error;
use crate::flow::TcpFlags;

/// Parsed TCP packet information
#[derive(Debug, Clone)]
pub struct TcpPacketInfo {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub flags: TcpFlags,
    pub seq: u32,
    pub ack: u32,
    pub payload_len: u16,
    pub timestamp: Instant,
}

/// Trait for packet sources
pub trait PacketSource {
    /// Get the next TCP packet
    fn next_tcp_packet(&mut self) -> Option<Result<TcpPacketInfo, Error>>;
}

/// Live packet capture from network interface
pub struct LiveCapture {
    capture: Capture<Active>,
}

impl LiveCapture {
    /// Open a live capture on the specified interface
    pub fn new(interface: &str) -> Result<Self, Error> {
        // Find the device
        let devices = Device::list()
            .map_err(|e| Error::CaptureOpen(e.to_string()))?;

        let device = devices.iter()
            .find(|d| d.name == interface)
            .ok_or_else(|| Error::InterfaceNotFound(interface.to_string()))?;

        let capture = Capture::from_device(device.clone())
            .map_err(|e| Error::CaptureOpen(e.to_string()))?
            .promisc(true)
            .snaplen(128) // We only need headers
            .timeout(100) // 100ms timeout
            .immediate_mode(true)
            .open()
            .map_err(|e| Error::CaptureOpen(e.to_string()))?;

        Ok(Self { capture })
    }

    /// Set BPF filter (e.g., "tcp")
    pub fn set_filter(&mut self, filter: &str) -> Result<(), Error> {
        self.capture.filter(filter, true)
            .map_err(|e| Error::FilterError(e.to_string()))
    }

    /// List available interfaces
    pub fn list_interfaces() -> Result<Vec<String>, Error> {
        let devices = Device::list()
            .map_err(|e| Error::CaptureOpen(e.to_string()))?;
        Ok(devices.into_iter().map(|d| d.name).collect())
    }
}

impl PacketSource for LiveCapture {
    fn next_tcp_packet(&mut self) -> Option<Result<TcpPacketInfo, Error>> {
        loop {
            match self.capture.next_packet() {
                Ok(packet) => {
                    let timestamp = Instant::now();
                    match parse_tcp_packet(packet.data, timestamp) {
                        Some(info) => return Some(Ok(info)),
                        None => continue, // Not a TCP packet, try next
                    }
                }
                Err(pcap::Error::TimeoutExpired) => return None,
                Err(e) => return Some(Err(Error::Capture(e.to_string()))),
            }
        }
    }
}

/// Pcap file packet source
pub struct PcapFileSource {
    capture: Capture<Offline>,
    base_time: Option<Instant>,
}

impl PcapFileSource {
    /// Open a pcap file
    pub fn new(path: &str) -> Result<Self, Error> {
        let capture = Capture::from_file(path)
            .map_err(|e| Error::PcapFile(e.to_string()))?;

        Ok(Self {
            capture,
            base_time: None,
        })
    }
}

impl PacketSource for PcapFileSource {
    fn next_tcp_packet(&mut self) -> Option<Result<TcpPacketInfo, Error>> {
        loop {
            match self.capture.next_packet() {
                Ok(packet) => {
                    // Use monotonic time for pcap replay
                    let timestamp = self.base_time.get_or_insert_with(Instant::now);
                    let timestamp = *timestamp;

                    match parse_tcp_packet(packet.data, timestamp) {
                        Some(info) => return Some(Ok(info)),
                        None => continue,
                    }
                }
                Err(pcap::Error::NoMorePackets) => return None,
                Err(e) => return Some(Err(Error::PcapFile(e.to_string()))),
            }
        }
    }
}

/// Parse a raw packet and extract TCP information
fn parse_tcp_packet(data: &[u8], timestamp: Instant) -> Option<TcpPacketInfo> {
    let packet = SlicedPacket::from_ethernet(data).ok()?;

    // Extract IP addresses using net field
    let (src_ip, dst_ip) = match packet.net {
        Some(etherparse::NetSlice::Ipv4(ipv4)) => {
            (
                std::net::IpAddr::V4(ipv4.header().source_addr()),
                std::net::IpAddr::V4(ipv4.header().destination_addr()),
            )
        }
        Some(etherparse::NetSlice::Ipv6(ipv6)) => {
            (
                std::net::IpAddr::V6(ipv6.header().source_addr()),
                std::net::IpAddr::V6(ipv6.header().destination_addr()),
            )
        }
        Some(_) => return None, // ARP or other non-IP
        None => return None,
    };

    // Extract TCP header
    let tcp = match packet.transport {
        Some(TransportSlice::Tcp(tcp)) => tcp,
        _ => return None,
    };

    let src = SocketAddr::new(src_ip, tcp.source_port());
    let dst = SocketAddr::new(dst_ip, tcp.destination_port());

    // Parse flags from the raw slice
    let flags_byte = tcp.slice()[13]; // TCP flags are at offset 13
    let flags = TcpFlags::from_byte(flags_byte);

    // Calculate payload length from packet
    let payload_len = tcp.slice().len().saturating_sub(tcp.data_offset() as usize) as u16;

    Some(TcpPacketInfo {
        src,
        dst,
        flags,
        seq: tcp.sequence_number(),
        ack: tcp.acknowledgment_number(),
        payload_len,
        timestamp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_interfaces() {
        // This should not panic
        let result = LiveCapture::list_interfaces();
        // May fail without permissions, that's ok
        if let Ok(interfaces) = result {
            println!("Found interfaces: {:?}", interfaces);
        }
    }

    #[test]
    fn test_tcp_flags_parsing() {
        let flags = TcpFlags::from_byte(0x02); // SYN
        assert!(flags.syn);
        assert!(!flags.ack);

        let flags = TcpFlags::from_byte(0x12); // SYN-ACK
        assert!(flags.syn);
        assert!(flags.ack);

        let flags = TcpFlags::from_byte(0x10); // ACK
        assert!(!flags.syn);
        assert!(flags.ack);
    }
}
