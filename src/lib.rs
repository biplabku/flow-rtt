//! # flow-rtt
//!
//! Passive TCP round-trip time measurement from packet capture.
//! Zero network overhead latency monitoring for production systems.
//!
//! ## Overview
//!
//! `flow-rtt` passively observes TCP traffic and extracts RTT measurements
//! without generating any network traffic. It works by:
//!
//! 1. Capturing packets on a network interface
//! 2. Tracking TCP flow state (handshake, data transfer)
//! 3. Measuring RTT from packet timestamps:
//!    - **Handshake RTT**: SYN → SYN-ACK timing
//!    - **Data RTT**: Data segment → ACK timing
//! 4. Computing percentile statistics (p50, p95, p99)
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use flow_rtt::{PassiveMonitor, MonitorConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), flow_rtt::Error> {
//!     let config = MonitorConfig::default();
//!     let mut monitor = PassiveMonitor::new("eth0", config)?;
//!
//!     // Get flow statistics
//!     while let Some(stats) = monitor.next_flow_stats().await {
//!         println!("{} -> {}: p50={:.2}ms p99={:.2}ms samples={}",
//!             stats.src, stats.dst,
//!             stats.rtt_p50_ms, stats.rtt_p99_ms,
//!             stats.sample_count);
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Use Cases
//!
//! - **Kubernetes monitoring**: Observe service-to-service latency
//! - **Production debugging**: Find slow connections without adding probes
//! - **SLA verification**: Passive RTT percentile tracking
//! - **Network forensics**: Historical latency analysis from pcap files

mod error;
pub mod flow;
pub mod stats;
mod capture;
mod monitor;

pub use error::Error;
pub use flow::{FlowKey, FlowState, TcpFlags, FlowTracker, TrackedFlow};
pub use stats::{RttStats, FlowStats};
pub use capture::{PacketSource, LiveCapture, PcapFileSource};
pub use monitor::{PassiveMonitor, MonitorConfig};

/// Result type for flow-rtt operations
pub type Result<T> = std::result::Result<T, Error>;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
