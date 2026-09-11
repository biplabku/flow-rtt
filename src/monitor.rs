//! Passive RTT monitor - main API

use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::capture::{LiveCapture, PacketSource, PcapFileSource};
use crate::error::Error;
use crate::flow::FlowTracker;
use crate::stats::FlowStats;

/// Configuration for the passive monitor
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    /// How long to keep tracking idle flows
    pub flow_timeout: Duration,

    /// Maximum number of concurrent flows to track
    pub max_flows: usize,

    /// BPF filter expression (default: "tcp")
    pub filter: String,

    /// How often to report flow statistics
    pub stats_interval: Duration,

    /// Minimum samples before reporting a flow
    pub min_samples: u64,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            flow_timeout: Duration::from_secs(60),
            max_flows: 10000,
            filter: "tcp".to_string(),
            stats_interval: Duration::from_secs(10),
            min_samples: 1,
        }
    }
}

impl MonitorConfig {
    /// Create config with custom flow timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.flow_timeout = timeout;
        self
    }

    /// Create config with custom filter
    pub fn with_filter(mut self, filter: impl Into<String>) -> Self {
        self.filter = filter.into();
        self
    }

    /// Create config with custom stats interval
    pub fn with_stats_interval(mut self, interval: Duration) -> Self {
        self.stats_interval = interval;
        self
    }
}

/// Passive TCP RTT monitor
pub struct PassiveMonitor {
    config: MonitorConfig,
    tracker: FlowTracker,
    capture: Box<dyn PacketSource + Send>,
    stats_rx: Option<mpsc::Receiver<FlowStats>>,
    stats_tx: mpsc::Sender<FlowStats>,
}

impl PassiveMonitor {
    /// Create a new passive monitor on a live interface
    pub fn new(interface: &str, config: MonitorConfig) -> Result<Self, Error> {
        let mut capture = LiveCapture::new(interface)?;
        capture.set_filter(&config.filter)?;

        let (stats_tx, stats_rx) = mpsc::channel(1000);

        Ok(Self {
            tracker: FlowTracker::new(config.flow_timeout, config.max_flows),
            capture: Box::new(capture),
            config,
            stats_rx: Some(stats_rx),
            stats_tx,
        })
    }

    /// Create a passive monitor from a pcap file
    pub fn from_pcap(path: &str, config: MonitorConfig) -> Result<Self, Error> {
        let capture = PcapFileSource::new(path)?;

        let (stats_tx, stats_rx) = mpsc::channel(1000);

        Ok(Self {
            tracker: FlowTracker::new(config.flow_timeout, config.max_flows),
            capture: Box::new(capture),
            config,
            stats_rx: Some(stats_rx),
            stats_tx,
        })
    }

    /// Get the next flow statistics (async)
    pub async fn next_flow_stats(&mut self) -> Option<FlowStats> {
        if let Some(ref mut rx) = self.stats_rx {
            rx.recv().await
        } else {
            None
        }
    }

    /// Process packets synchronously and emit stats
    pub fn process_packets(&mut self) -> Result<(), Error> {
        let mut last_report = Instant::now();

        while let Some(result) = self.capture.next_tcp_packet() {
            let packet = result?;

            self.tracker.process_packet(
                packet.src,
                packet.dst,
                packet.flags,
                packet.seq,
                packet.ack,
                packet.payload_len,
                packet.timestamp,
            );

            // Periodic stats reporting
            if last_report.elapsed() >= self.config.stats_interval {
                self.report_stats();
                last_report = Instant::now();
            }
        }

        // Final report
        self.report_stats();

        Ok(())
    }

    /// Run the monitor asynchronously
    pub async fn run(&mut self) -> Result<(), Error> {
        let config = self.config.clone();

        // Process packets in a blocking task
        let process_result = tokio::task::spawn_blocking({
            let _tracker = FlowTracker::new(config.flow_timeout, config.max_flows);
            let _filter = config.filter.clone();

            move || -> Result<Vec<FlowStats>, Error> {
                // Note: In a real implementation, we'd need to pass the capture
                // For now, return empty to show the structure
                Ok(Vec::new())
            }
        }).await;

        match process_result {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(Error::ChannelClosed),
        }
    }

    fn report_stats(&self) {
        for flow in self.tracker.active_flows() {
            if flow.rtt_samples.len() as u64 >= self.config.min_samples {
                let stats = FlowStats::from_flow(flow);
                let _ = self.stats_tx.try_send(stats);
            }
        }
    }

    /// Get current flow count
    pub fn flow_count(&self) -> usize {
        self.tracker.flow_count()
    }

    /// Get all current flow statistics
    pub fn all_flow_stats(&self) -> Vec<FlowStats> {
        self.tracker.active_flows()
            .map(FlowStats::from_flow)
            .collect()
    }

    /// Get statistics for flows with RTT data
    pub fn flows_with_rtt(&self) -> Vec<FlowStats> {
        self.tracker.active_flows()
            .filter(|f| !f.rtt_samples.is_empty())
            .map(FlowStats::from_flow)
            .collect()
    }

    /// Process a batch of packets and return stats
    pub fn process_batch(&mut self, max_packets: usize) -> Result<Vec<FlowStats>, Error> {
        let mut processed = 0;

        while processed < max_packets {
            match self.capture.next_tcp_packet() {
                Some(Ok(packet)) => {
                    self.tracker.process_packet(
                        packet.src,
                        packet.dst,
                        packet.flags,
                        packet.seq,
                        packet.ack,
                        packet.payload_len,
                        packet.timestamp,
                    );
                    processed += 1;
                }
                Some(Err(e)) => return Err(e),
                None => break,
            }
        }

        Ok(self.flows_with_rtt())
    }
}

/// Builder for PassiveMonitor
pub struct MonitorBuilder {
    interface: Option<String>,
    pcap_path: Option<String>,
    config: MonitorConfig,
}

impl MonitorBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            interface: None,
            pcap_path: None,
            config: MonitorConfig::default(),
        }
    }

    /// Set the network interface
    pub fn interface(mut self, interface: impl Into<String>) -> Self {
        self.interface = Some(interface.into());
        self
    }

    /// Set the pcap file path
    pub fn pcap_file(mut self, path: impl Into<String>) -> Self {
        self.pcap_path = Some(path.into());
        self
    }

    /// Set flow timeout
    pub fn flow_timeout(mut self, timeout: Duration) -> Self {
        self.config.flow_timeout = timeout;
        self
    }

    /// Set max flows
    pub fn max_flows(mut self, max: usize) -> Self {
        self.config.max_flows = max;
        self
    }

    /// Set BPF filter
    pub fn filter(mut self, filter: impl Into<String>) -> Self {
        self.config.filter = filter.into();
        self
    }

    /// Set stats reporting interval
    pub fn stats_interval(mut self, interval: Duration) -> Self {
        self.config.stats_interval = interval;
        self
    }

    /// Build the monitor
    pub fn build(self) -> Result<PassiveMonitor, Error> {
        if let Some(path) = self.pcap_path {
            PassiveMonitor::from_pcap(&path, self.config)
        } else if let Some(interface) = self.interface {
            PassiveMonitor::new(&interface, self.config)
        } else {
            Err(Error::CaptureOpen("No interface or pcap file specified".to_string()))
        }
    }
}

impl Default for MonitorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = MonitorConfig::default();
        assert_eq!(config.flow_timeout, Duration::from_secs(60));
        assert_eq!(config.max_flows, 10000);
        assert_eq!(config.filter, "tcp");
    }

    #[test]
    fn test_config_builder() {
        let config = MonitorConfig::default()
            .with_timeout(Duration::from_secs(120))
            .with_filter("tcp port 80");

        assert_eq!(config.flow_timeout, Duration::from_secs(120));
        assert_eq!(config.filter, "tcp port 80");
    }

    #[test]
    fn test_monitor_builder() {
        let builder = MonitorBuilder::new()
            .interface("eth0")
            .flow_timeout(Duration::from_secs(30))
            .max_flows(5000)
            .filter("tcp port 443");

        // Can't actually build without permissions
        // Just test the builder pattern works
        assert!(builder.interface.is_some());
    }
}
