# flow-rtt

[![Crates.io](https://img.shields.io/crates/v/flow-rtt.svg)](https://crates.io/crates/flow-rtt)
[![Documentation](https://docs.rs/flow-rtt/badge.svg)](https://docs.rs/flow-rtt)
[![License](https://img.shields.io/crates/l/flow-rtt.svg)](LICENSE)

Passive TCP round-trip time measurement from packet capture. Zero network overhead latency monitoring for production systems.

## Why flow-rtt?

- **Zero overhead**: Observe existing traffic, don't generate new packets
- **Production safe**: No impact on application performance
- **Percentile statistics**: p50, p95, p99 RTT out of the box
- **Library first**: Embed in your monitoring tools, not just CLI

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                      Network Traffic                             │
│   Client ──────────────────────────────────────────── Server    │
│           SYN ──────────────────────►                           │
│               ◄────────────────────── SYN-ACK                   │
│           ACK ──────────────────────►                           │
│          DATA ──────────────────────►                           │
│               ◄────────────────────── ACK                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        flow-rtt                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ Packet       │  │ Flow         │  │ RTT Statistics       │  │
│  │ Capture      │──│ Tracking     │──│ p50, p95, p99        │  │
│  │ (pcap)       │  │ (TCP state)  │  │ (hdrhistogram)       │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

flow-rtt passively observes TCP flows and extracts RTT by:

1. **Handshake RTT**: Time from SYN to SYN-ACK
2. **Data RTT**: Time from data segment to corresponding ACK

## Quick Start

**Requires `CAP_NET_RAW` or `sudo`** — pcap needs raw socket access.

```toml
[dependencies]
flow-rtt = "0.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

**Option A: Batch mode** (process N packets, return stats)

```rust
use flow_rtt::{PassiveMonitor, MonitorConfig};

fn main() -> Result<(), flow_rtt::Error> {
    let mut monitor = PassiveMonitor::new("eth0", MonitorConfig::default())?;

    // Process up to 1000 packets, return flows seen so far
    let stats = monitor.process_batch(1000)?;

    for flow in stats {
        if flow.has_rtt_data() {
            println!("{} -> {}: p50={:.2}ms p99={:.2}ms",
                flow.src, flow.dst,
                flow.rtt_p50_ms, flow.rtt_p99_ms);
        }
    }
    Ok(())
}
```

**Option B: Async streaming** (emit a FlowStats each time a flow completes)

```rust
use flow_rtt::{PassiveMonitor, MonitorConfig};

#[tokio::main]
async fn main() -> Result<(), flow_rtt::Error> {
    let mut monitor = PassiveMonitor::new("eth0", MonitorConfig::default())?;

    while let Some(flow) = monitor.next_flow_stats().await {
        if flow.has_rtt_data() {
            println!("{} -> {}: p50={:.2}ms p99={:.2}ms",
                flow.src, flow.dst,
                flow.rtt_p50_ms, flow.rtt_p99_ms);
        }
    }
    Ok(())
}
```

## Configuration

```rust
use flow_rtt::MonitorConfig;
use std::time::Duration;

let config = MonitorConfig::default()
    .with_timeout(Duration::from_secs(120))  // Flow idle timeout
    .with_filter("tcp port 443")              // BPF filter
    .with_stats_interval(Duration::from_secs(5));
```

## Use Cases

| Use Case | Description |
|----------|-------------|
| **Kubernetes monitoring** | Observe pod-to-pod latency without sidecars |
| **Service mesh** | Measure actual TCP RTT vs reported latency |
| **Database connections** | Track query response times passively |
| **Load balancer health** | Monitor backend connection quality |
| **Network forensics** | Analyze historical latency from pcap files |

## Comparison with Active Probing

| Aspect | Active (ping/multiprobe) | Passive (flow-rtt) |
|--------|--------------------------|-------------------|
| Network overhead | Generates traffic | Zero |
| What it measures | Synthetic probes | Real application traffic |
| Setup complexity | Simple | Requires capture access |
| Path coverage | Probe path only | All observed flows |

## Statistics Available

```rust
pub struct FlowStats {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub handshake_rtt_ms: Option<f64>,
    pub rtt_p50_ms: f64,
    pub rtt_p99_ms: f64,
    pub sample_count: u64,
    pub packets: u64,
    pub bytes: u64,
}
```

## Permissions

| Platform | Requirement |
|----------|-------------|
| Linux | CAP_NET_RAW or root |
| macOS | root |
| Windows | WinPcap/Npcap + Admin |

```bash
# Linux: Grant capability
sudo setcap cap_net_raw+ep ./your-binary

# Or run with sudo
sudo ./your-binary
```

## Pcap File Analysis

```rust
use flow_rtt::{PassiveMonitor, MonitorConfig};

let monitor = PassiveMonitor::from_pcap("capture.pcap", MonitorConfig::default())?;
let stats = monitor.all_flow_stats();

for flow in stats {
    println!("{}", flow);
}
```

## API Reference

### PassiveMonitor

```rust
// Live capture
PassiveMonitor::new(interface, config)

// Pcap file
PassiveMonitor::from_pcap(path, config)

// Get stats
monitor.all_flow_stats()
monitor.flows_with_rtt()
monitor.process_batch(max_packets)
```

### MonitorConfig

```rust
MonitorConfig {
    flow_timeout: Duration,    // Default: 60s
    max_flows: usize,          // Default: 10000
    filter: String,            // Default: "tcp"
    stats_interval: Duration,  // Default: 10s
    min_samples: u64,          // Default: 1
}
```

## License

MIT OR Apache-2.0
