//! RTT statistics computation using HDR histograms

use std::net::SocketAddr;
use std::time::Duration;

use hdrhistogram::Histogram;

use crate::flow::{FlowKey, TrackedFlow};

/// RTT statistics for a flow
#[derive(Debug, Clone)]
pub struct RttStats {
    /// Minimum RTT observed
    pub min: Duration,
    /// Maximum RTT observed
    pub max: Duration,
    /// Mean RTT
    pub mean: Duration,
    /// Median RTT (p50)
    pub p50: Duration,
    /// 95th percentile RTT
    pub p95: Duration,
    /// 99th percentile RTT
    pub p99: Duration,
    /// Number of samples
    pub sample_count: u64,
    /// Standard deviation
    pub std_dev: Duration,
}

impl RttStats {
    /// Compute statistics from RTT samples
    pub fn from_samples(samples: &[Duration]) -> Option<Self> {
        if samples.is_empty() {
            return None;
        }

        // Create histogram (microsecond precision, up to 1 hour)
        let mut hist = Histogram::<u64>::new_with_bounds(1, 3_600_000_000, 3)
            .expect("histogram creation should succeed");

        for sample in samples {
            let micros = sample.as_micros() as u64;
            if micros > 0 {
                let _ = hist.record(micros);
            }
        }

        if hist.is_empty() {
            return None;
        }

        Some(Self {
            min: Duration::from_micros(hist.min()),
            max: Duration::from_micros(hist.max()),
            mean: Duration::from_micros(hist.mean() as u64),
            p50: Duration::from_micros(hist.value_at_quantile(0.50)),
            p95: Duration::from_micros(hist.value_at_quantile(0.95)),
            p99: Duration::from_micros(hist.value_at_quantile(0.99)),
            sample_count: hist.len(),
            std_dev: Duration::from_micros(hist.stdev() as u64),
        })
    }

    /// Get p50 in milliseconds
    pub fn p50_ms(&self) -> f64 {
        self.p50.as_secs_f64() * 1000.0
    }

    /// Get p95 in milliseconds
    pub fn p95_ms(&self) -> f64 {
        self.p95.as_secs_f64() * 1000.0
    }

    /// Get p99 in milliseconds
    pub fn p99_ms(&self) -> f64 {
        self.p99.as_secs_f64() * 1000.0
    }

    /// Get mean in milliseconds
    pub fn mean_ms(&self) -> f64 {
        self.mean.as_secs_f64() * 1000.0
    }
}

/// Complete flow statistics including endpoints and RTT
#[derive(Debug, Clone)]
pub struct FlowStats {
    /// Source address (initiator)
    pub src: SocketAddr,
    /// Destination address (responder)
    pub dst: SocketAddr,
    /// Flow key
    pub key: FlowKey,
    /// Handshake RTT (SYN -> SYN-ACK)
    pub handshake_rtt_ms: Option<f64>,
    /// RTT statistics from data transfer
    pub rtt: Option<RttStats>,
    /// Number of RTT samples
    pub sample_count: u64,
    /// Packets observed
    pub packets: u64,
    /// Bytes observed
    pub bytes: u64,
    /// Convenience: p50 RTT in milliseconds
    pub rtt_p50_ms: f64,
    /// Convenience: p99 RTT in milliseconds
    pub rtt_p99_ms: f64,
}

impl FlowStats {
    /// Create flow stats from a tracked flow
    pub fn from_flow(flow: &TrackedFlow) -> Self {
        let rtt = RttStats::from_samples(&flow.rtt_samples);

        let (rtt_p50_ms, rtt_p99_ms) = rtt.as_ref()
            .map(|r| (r.p50_ms(), r.p99_ms()))
            .unwrap_or((0.0, 0.0));

        let handshake_rtt_ms = flow.handshake_rtt()
            .map(|d| d.as_secs_f64() * 1000.0);

        // Determine initiator/responder from flow state
        let (src, dst) = match &flow.state {
            crate::flow::FlowState::SynSent { initiator, .. } |
            crate::flow::FlowState::SynAckReceived { initiator, .. } |
            crate::flow::FlowState::Established { initiator, .. } => {
                (*initiator, if *initiator == flow.key.addr_a {
                    flow.key.addr_b
                } else {
                    flow.key.addr_a
                })
            }
            _ => (flow.key.addr_a, flow.key.addr_b),
        };

        Self {
            src,
            dst,
            key: flow.key,
            handshake_rtt_ms,
            rtt,
            sample_count: flow.rtt_samples.len() as u64,
            packets: flow.packets_seen,
            bytes: flow.bytes_seen,
            rtt_p50_ms,
            rtt_p99_ms,
        }
    }

    /// Check if we have meaningful RTT data
    pub fn has_rtt_data(&self) -> bool {
        self.sample_count > 0
    }
}

impl std::fmt::Display for FlowStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {}: ", self.src, self.dst)?;

        if let Some(ref rtt) = self.rtt {
            write!(f, "p50={:.2}ms p95={:.2}ms p99={:.2}ms samples={}",
                rtt.p50_ms(), rtt.p95_ms(), rtt.p99_ms(), self.sample_count)
        } else if let Some(handshake) = self.handshake_rtt_ms {
            write!(f, "handshake={:.2}ms (no data samples)", handshake)
        } else {
            write!(f, "no RTT data")
        }
    }
}

/// Aggregated statistics across multiple flows
#[derive(Debug, Clone)]
pub struct AggregateStats {
    /// Total flows observed
    pub flow_count: u64,
    /// Flows with RTT data
    pub flows_with_rtt: u64,
    /// Total RTT samples
    pub total_samples: u64,
    /// Global p50 across all flows
    pub global_p50_ms: f64,
    /// Global p99 across all flows
    pub global_p99_ms: f64,
}

impl AggregateStats {
    /// Compute aggregate statistics from multiple flow stats
    pub fn from_flows(flows: &[FlowStats]) -> Self {
        let mut all_samples = Vec::new();

        for flow in flows {
            if let Some(ref rtt) = flow.rtt {
                // We don't have raw samples here, so use the p50 as representative
                for _ in 0..flow.sample_count {
                    all_samples.push(rtt.p50);
                }
            }
        }

        let global = RttStats::from_samples(&all_samples);
        let (global_p50_ms, global_p99_ms) = global.as_ref()
            .map(|r| (r.p50_ms(), r.p99_ms()))
            .unwrap_or((0.0, 0.0));

        Self {
            flow_count: flows.len() as u64,
            flows_with_rtt: flows.iter().filter(|f| f.has_rtt_data()).count() as u64,
            total_samples: flows.iter().map(|f| f.sample_count).sum(),
            global_p50_ms,
            global_p99_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtt_stats_from_samples() {
        let samples: Vec<Duration> = (1..=100)
            .map(|i| Duration::from_millis(i))
            .collect();

        let stats = RttStats::from_samples(&samples).unwrap();

        assert_eq!(stats.sample_count, 100);
        assert!(stats.min >= Duration::from_millis(1));
        // Histogram buckets may round up slightly
        assert!(stats.max <= Duration::from_millis(110));
        assert!(stats.p50_ms() > 40.0 && stats.p50_ms() < 60.0);
        assert!(stats.p99_ms() > 90.0);
    }

    #[test]
    fn test_rtt_stats_empty() {
        let samples: Vec<Duration> = vec![];
        assert!(RttStats::from_samples(&samples).is_none());
    }

    #[test]
    fn test_rtt_stats_single_sample() {
        let samples = vec![Duration::from_millis(50)];
        let stats = RttStats::from_samples(&samples).unwrap();

        assert_eq!(stats.sample_count, 1);
        assert!((stats.p50_ms() - 50.0).abs() < 1.0);
    }
}
