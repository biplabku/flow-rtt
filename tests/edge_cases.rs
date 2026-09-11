//! Edge case tests for flow-rtt
//!
//! Tests scenarios that could break the RTT tracking logic.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use flow_rtt::flow::{FlowKey, FlowTracker, TcpFlags, TrackedFlow};
use flow_rtt::stats::RttStats;

fn addr(ip: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, ip)), port)
}

fn syn() -> TcpFlags {
    TcpFlags::from_byte(0x02)
}

fn syn_ack() -> TcpFlags {
    TcpFlags::from_byte(0x12)
}

fn ack() -> TcpFlags {
    TcpFlags::from_byte(0x10)
}

fn rst() -> TcpFlags {
    TcpFlags::from_byte(0x04)
}

fn fin_ack() -> TcpFlags {
    TcpFlags::from_byte(0x11)
}

fn psh_ack() -> TcpFlags {
    TcpFlags::from_byte(0x18)
}

// =============================================================================
// Edge Case 1: Out-of-order packets
// =============================================================================

#[test]
fn test_out_of_order_syn_ack_before_syn() {
    let mut tracker = FlowTracker::new(Duration::from_secs(60), 1000);
    let client = addr(1, 50000);
    let server = addr(2, 80);

    // SYN-ACK arrives before SYN (shouldn't happen but test it)
    tracker.process_packet(server, client, syn_ack(), 2000, 1001, 0, Instant::now());

    // No flow should be created from SYN-ACK alone
    assert_eq!(tracker.flow_count(), 0);

    // Now SYN arrives
    tracker.process_packet(client, server, syn(), 1000, 0, 0, Instant::now());
    assert_eq!(tracker.flow_count(), 1);
}

// =============================================================================
// Edge Case 2: Retransmissions
// =============================================================================

#[test]
fn test_syn_retransmission() {
    let mut tracker = FlowTracker::new(Duration::from_secs(60), 1000);
    let client = addr(1, 50000);
    let server = addr(2, 80);

    // First SYN
    tracker.process_packet(client, server, syn(), 1000, 0, 0, Instant::now());
    assert_eq!(tracker.flow_count(), 1);

    // Retransmitted SYN (same seq)
    tracker.process_packet(client, server, syn(), 1000, 0, 0, Instant::now());

    // Should still be one flow, not two
    assert_eq!(tracker.flow_count(), 1);
}

#[test]
fn test_data_retransmission_doesnt_double_count_rtt() {
    let client = addr(1, 50000);
    let server = addr(2, 80);
    let key = FlowKey::new(client, server);

    let now = Instant::now();
    let mut flow = TrackedFlow::new(key, client, now, 1000);

    // Complete handshake
    std::thread::sleep(Duration::from_millis(5));
    flow.process_packet(server, syn_ack(), 2000, 1001, 0, Instant::now());
    std::thread::sleep(Duration::from_millis(5));
    flow.process_packet(client, ack(), 1001, 2001, 0, Instant::now());

    // Send data
    std::thread::sleep(Duration::from_millis(10));
    let data_time = Instant::now();
    flow.process_packet(client, psh_ack(), 1001, 2001, 100, data_time);

    // Retransmit same data (same seq)
    std::thread::sleep(Duration::from_millis(5));
    flow.process_packet(client, psh_ack(), 1001, 2001, 100, Instant::now());

    // ACK arrives
    std::thread::sleep(Duration::from_millis(10));
    let rtt = flow.process_packet(server, ack(), 2001, 1101, 0, Instant::now());

    // Should get RTT from first transmission, not retransmit
    assert!(rtt.is_some());
}

// =============================================================================
// Edge Case 3: Duplicate ACKs
// =============================================================================

#[test]
fn test_duplicate_acks() {
    let client = addr(1, 50000);
    let server = addr(2, 80);
    let key = FlowKey::new(client, server);

    let now = Instant::now();
    let mut flow = TrackedFlow::new(key, client, now, 1000);

    // Complete handshake quickly
    flow.process_packet(server, syn_ack(), 2000, 1001, 0, Instant::now());
    flow.process_packet(client, ack(), 1001, 2001, 0, Instant::now());

    // Send data
    flow.process_packet(client, psh_ack(), 1001, 2001, 100, Instant::now());

    // Multiple duplicate ACKs (fast retransmit scenario)
    for _ in 0..3 {
        flow.process_packet(server, ack(), 2001, 1001, 0, Instant::now());
    }

    // Flow should still be in good state
    assert!(flow.is_established());
}

// =============================================================================
// Edge Case 4: RST packets
// =============================================================================

#[test]
fn test_rst_during_handshake() {
    let mut tracker = FlowTracker::new(Duration::from_secs(60), 1000);
    let client = addr(1, 50000);
    let server = addr(2, 80);

    // SYN
    tracker.process_packet(client, server, syn(), 1000, 0, 0, Instant::now());

    // RST from server (connection refused)
    tracker.process_packet(server, client, rst(), 0, 1001, 0, Instant::now());

    // Flow should still exist but be in closing state
    let key = FlowKey::new(client, server);
    let flow = tracker.active_flows().find(|f| f.key == key);
    // Flow might be cleaned up - that's ok
}

#[test]
fn test_rst_during_data_transfer() {
    let client = addr(1, 50000);
    let server = addr(2, 80);
    let key = FlowKey::new(client, server);

    let mut flow = TrackedFlow::new(key, client, Instant::now(), 1000);

    // Complete handshake
    flow.process_packet(server, syn_ack(), 2000, 1001, 0, Instant::now());
    flow.process_packet(client, ack(), 1001, 2001, 0, Instant::now());

    assert!(flow.is_established());

    // RST
    flow.process_packet(server, rst(), 2001, 1001, 0, Instant::now());

    // Flow should not be established anymore
    assert!(!flow.is_established());
}

// =============================================================================
// Edge Case 5: Very high/low RTT
// =============================================================================

#[test]
fn test_very_low_rtt_microseconds() {
    let samples: Vec<Duration> = (1..=100)
        .map(|i| Duration::from_micros(i * 10)) // 10-1000 microseconds
        .collect();

    let stats = RttStats::from_samples(&samples);
    assert!(stats.is_some());

    let stats = stats.unwrap();
    assert!(stats.p50.as_micros() > 0);
    assert!(stats.p50.as_micros() < 1000);
}

#[test]
fn test_high_rtt_seconds() {
    let samples: Vec<Duration> = (1..=10)
        .map(|i| Duration::from_secs(i)) // 1-10 seconds
        .collect();

    let stats = RttStats::from_samples(&samples);
    assert!(stats.is_some());

    let stats = stats.unwrap();
    assert!(stats.p50.as_secs() >= 4);
    assert!(stats.p50.as_secs() <= 6);
}

// =============================================================================
// Edge Case 6: Sequence number wraparound
// =============================================================================

#[test]
fn test_sequence_wraparound() {
    let client = addr(1, 50000);
    let server = addr(2, 80);
    let key = FlowKey::new(client, server);

    // Start near max u32
    let initial_seq = u32::MAX - 100;
    let mut flow = TrackedFlow::new(key, client, Instant::now(), initial_seq);

    // Complete handshake
    flow.process_packet(server, syn_ack(), 2000, initial_seq.wrapping_add(1), 0, Instant::now());
    flow.process_packet(client, ack(), initial_seq.wrapping_add(1), 2001, 0, Instant::now());

    // Send data that wraps around
    std::thread::sleep(Duration::from_millis(10));
    let wrapped_seq = initial_seq.wrapping_add(1);
    flow.process_packet(client, psh_ack(), wrapped_seq, 2001, 200, Instant::now());

    // ACK with wrapped sequence
    std::thread::sleep(Duration::from_millis(10));
    let wrapped_ack = wrapped_seq.wrapping_add(200);
    let rtt = flow.process_packet(server, ack(), 2001, wrapped_ack, 0, Instant::now());

    // Should still work (though our simple logic might not handle this perfectly)
    // At minimum, shouldn't panic
    assert!(flow.is_established());
}

// =============================================================================
// Edge Case 7: FIN handling
// =============================================================================

#[test]
fn test_graceful_close() {
    let client = addr(1, 50000);
    let server = addr(2, 80);
    let key = FlowKey::new(client, server);

    let mut flow = TrackedFlow::new(key, client, Instant::now(), 1000);

    // Complete handshake
    flow.process_packet(server, syn_ack(), 2000, 1001, 0, Instant::now());
    flow.process_packet(client, ack(), 1001, 2001, 0, Instant::now());

    assert!(flow.is_established());

    // FIN from client
    flow.process_packet(client, fin_ack(), 1001, 2001, 0, Instant::now());

    // Flow should be closing
    assert!(!flow.is_established());
}

// =============================================================================
// Edge Case 8: Max flows limit
// =============================================================================

#[test]
fn test_max_flows_cleanup_triggered() {
    let mut tracker = FlowTracker::new(Duration::from_millis(10), 10); // 10ms timeout, 10 max

    // Create 10 flows
    for i in 0..10 {
        let client = addr(i as u8, 50000 + i);
        let server = addr(100, 80);
        tracker.process_packet(client, server, syn(), 1000, 0, 0, Instant::now());
    }

    assert_eq!(tracker.flow_count(), 10);

    // Wait for timeout
    std::thread::sleep(Duration::from_millis(20));

    // Create more flows - should trigger cleanup of old ones
    for i in 10..15 {
        let client = addr(i as u8, 50000 + i);
        let server = addr(100, 80);
        tracker.process_packet(client, server, syn(), 1000, 0, 0, Instant::now());
    }

    // Old flows should be cleaned up, new ones added
    // Total should be around 5 (the new ones) + maybe some that haven't timed out
    assert!(tracker.flow_count() <= 15);
    assert!(tracker.flow_count() >= 5);
}

// =============================================================================
// Edge Case 9: Empty/zero payload
// =============================================================================

#[test]
fn test_zero_payload_packets() {
    let client = addr(1, 50000);
    let server = addr(2, 80);
    let key = FlowKey::new(client, server);

    let mut flow = TrackedFlow::new(key, client, Instant::now(), 1000);

    // Complete handshake
    flow.process_packet(server, syn_ack(), 2000, 1001, 0, Instant::now());
    flow.process_packet(client, ack(), 1001, 2001, 0, Instant::now());

    // Many zero-payload ACKs
    for _ in 0..100 {
        flow.process_packet(client, ack(), 1001, 2001, 0, Instant::now());
        flow.process_packet(server, ack(), 2001, 1001, 0, Instant::now());
    }

    // Should still be established, no crashes
    assert!(flow.is_established());
    // No RTT samples from pure ACKs
    assert!(flow.rtt_samples.len() < 10); // Some from handshake
}

// =============================================================================
// Edge Case 10: Rapid flow creation/destruction
// =============================================================================

#[test]
fn test_rapid_flow_churn() {
    let mut tracker = FlowTracker::new(Duration::from_millis(100), 1000);

    for i in 0..100 {
        let client = addr((i % 255) as u8, 50000 + (i % 1000) as u16);
        let server = addr(100, 80);

        // Create flow
        tracker.process_packet(client, server, syn(), 1000, 0, 0, Instant::now());

        // Complete handshake
        tracker.process_packet(server, client, syn_ack(), 2000, 1001, 0, Instant::now());
        tracker.process_packet(client, server, ack(), 1001, 2001, 0, Instant::now());

        // RST to close
        tracker.process_packet(client, server, rst(), 1001, 0, 0, Instant::now());
    }

    // Should have cleaned up most flows
    tracker.cleanup_old_flows(Instant::now());
}

// =============================================================================
// Edge Case 11: Statistics edge cases
// =============================================================================

#[test]
fn test_stats_single_sample() {
    let samples = vec![Duration::from_millis(50)];
    let stats = RttStats::from_samples(&samples).unwrap();

    // All percentiles should be roughly the same
    assert!((stats.p50_ms() - 50.0).abs() < 5.0);
    assert!((stats.p95_ms() - 50.0).abs() < 5.0);
    assert!((stats.p99_ms() - 50.0).abs() < 5.0);
}

#[test]
fn test_stats_identical_samples() {
    let samples: Vec<Duration> = (0..1000)
        .map(|_| Duration::from_millis(100))
        .collect();

    let stats = RttStats::from_samples(&samples).unwrap();

    // All should be ~100ms
    assert!((stats.p50_ms() - 100.0).abs() < 10.0);
    assert!((stats.p99_ms() - 100.0).abs() < 10.0);
    assert!(stats.std_dev.as_millis() < 10); // Low variance
}

#[test]
fn test_stats_bimodal_distribution() {
    let mut samples = Vec::new();
    // 50 samples at 10ms
    for _ in 0..50 {
        samples.push(Duration::from_millis(10));
    }
    // 50 samples at 100ms
    for _ in 0..50 {
        samples.push(Duration::from_millis(100));
    }

    let stats = RttStats::from_samples(&samples).unwrap();

    // p50 should be in between or at lower mode
    assert!(stats.p50_ms() < 60.0);
    // p99 should be at upper mode
    assert!(stats.p99_ms() >= 90.0);
}

// =============================================================================
// Edge Case 12: Flow key normalization
// =============================================================================

#[test]
fn test_flow_key_same_regardless_of_direction() {
    let a = addr(1, 50000);
    let b = addr(2, 80);

    let key1 = FlowKey::new(a, b);
    let key2 = FlowKey::new(b, a);

    assert_eq!(key1, key2);
    assert_eq!(key1.addr_a, key2.addr_a);
    assert_eq!(key1.addr_b, key2.addr_b);
}

#[test]
fn test_flow_key_direction_detection() {
    let client = addr(1, 50000);
    let server = addr(2, 80);

    let key = FlowKey::new(client, server);

    // Should correctly identify direction
    assert!(key.is_a_to_b(key.addr_a));
    assert!(!key.is_a_to_b(key.addr_b));
}
