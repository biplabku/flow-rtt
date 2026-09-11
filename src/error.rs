//! Error types for flow-rtt

use std::fmt;

/// Errors that can occur during passive RTT monitoring
#[derive(Debug)]
pub enum Error {
    /// Failed to open capture device
    CaptureOpen(String),

    /// Failed to set capture filter
    FilterError(String),

    /// Packet capture error
    Capture(String),

    /// Invalid packet format
    InvalidPacket(String),

    /// Interface not found
    InterfaceNotFound(String),

    /// Permission denied (need root/CAP_NET_RAW)
    PermissionDenied(String),

    /// Pcap file error
    PcapFile(String),

    /// Channel closed
    ChannelClosed,

    /// IO error
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CaptureOpen(msg) => write!(f, "failed to open capture: {}", msg),
            Self::FilterError(msg) => write!(f, "filter error: {}", msg),
            Self::Capture(msg) => write!(f, "capture error: {}", msg),
            Self::InvalidPacket(msg) => write!(f, "invalid packet: {}", msg),
            Self::InterfaceNotFound(name) => write!(f, "interface not found: {}", name),
            Self::PermissionDenied(msg) => write!(f, "permission denied: {} (try running with sudo or CAP_NET_RAW)", msg),
            Self::PcapFile(msg) => write!(f, "pcap file error: {}", msg),
            Self::ChannelClosed => write!(f, "channel closed"),
            Self::Io(e) => write!(f, "io error: {}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<pcap::Error> for Error {
    fn from(e: pcap::Error) -> Self {
        let msg = e.to_string();
        if msg.contains("permission") || msg.contains("Operation not permitted") {
            Self::PermissionDenied(msg)
        } else {
            Self::Capture(msg)
        }
    }
}
