// metrics.rs - Performance counters for gutd (BPF-only mode)
//
// Provides zero-cost performance monitoring with atomic counters.
// All operations are lock-free and designed for hot-path usage.
// In BPF-only mode, these counters track Rust-side events;
// BPF map stats are read separately via TcBpfManager::get_stats().

use std::sync::atomic::Ordering;
#[cfg(not(target_has_atomic = "64"))]
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[cfg(target_has_atomic = "64")]
type CounterInner = std::sync::atomic::AtomicU64;
#[cfg(not(target_has_atomic = "64"))]
type CounterInner = Mutex<u64>;

pub struct CounterU64 {
    inner: CounterInner,
}

impl CounterU64 {
    const fn new(value: u64) -> Self {
        #[cfg(target_has_atomic = "64")]
        {
            Self {
                inner: std::sync::atomic::AtomicU64::new(value),
            }
        }
        #[cfg(not(target_has_atomic = "64"))]
        {
            Self {
                inner: Mutex::new(value),
            }
        }
    }

    fn fetch_add(&self, value: u64, ordering: Ordering) -> u64 {
        #[cfg(target_has_atomic = "64")]
        {
            self.inner.fetch_add(value, ordering)
        }
        #[cfg(not(target_has_atomic = "64"))]
        {
            let _ = ordering;
            let mut guard = self.inner.lock().expect("counter mutex poisoned");
            let old = *guard;
            *guard = old.saturating_add(value);
            old
        }
    }

    fn load(&self, ordering: Ordering) -> u64 {
        #[cfg(target_has_atomic = "64")]
        {
            self.inner.load(ordering)
        }
        #[cfg(not(target_has_atomic = "64"))]
        {
            let _ = ordering;
            *self.inner.lock().expect("counter mutex poisoned")
        }
    }
}

/// Global performance metrics - zero-cost atomic counters
pub struct Metrics {
    // Packet counters
    pub rx_packets: CounterU64,
    pub tx_packets: CounterU64,
    pub rx_bytes: CounterU64,
    pub tx_bytes: CounterU64,
    pub rx_dropped: CounterU64,
    pub tx_dropped: CounterU64,

    // Encryption
    pub chacha_encode_count: CounterU64,
    pub chacha_decode_count: CounterU64,

    // Start time for uptime calculation
    start_time: Instant,
}

impl Metrics {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rx_packets: CounterU64::new(0),
            tx_packets: CounterU64::new(0),
            rx_bytes: CounterU64::new(0),
            tx_bytes: CounterU64::new(0),
            rx_dropped: CounterU64::new(0),
            tx_dropped: CounterU64::new(0),

            chacha_encode_count: CounterU64::new(0),
            chacha_decode_count: CounterU64::new(0),

            // Start time will be initialized when first accessed
            start_time: unsafe { std::mem::MaybeUninit::zeroed().assume_init() },
        }
    }

    /// Initialize start time (call once at startup)
    pub fn init(&mut self) {
        self.start_time = Instant::now();
    }

    /// Get uptime duration
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Record received packet (always active - cheap atomic ops)
    #[inline]
    pub fn record_rx(&self, bytes: usize) {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record transmitted packet (always active - cheap atomic ops)
    #[inline]
    pub fn record_tx(&self, bytes: usize) {
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record dropped receive packet (always active)
    #[inline]
    pub fn record_rx_drop(&self) {
        self.rx_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Record dropped transmit packet (always active)
    #[inline]
    pub fn record_tx_drop(&self) {
        self.tx_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Record `ChaCha` encryption (always active)
    #[inline]
    pub fn record_chacha_encode(&self) {
        self.chacha_encode_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record `ChaCha` decryption (always active)
    #[inline]
    pub fn record_chacha_decode(&self) {
        self.chacha_decode_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get snapshot of current metrics
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_dropped: self.rx_dropped.load(Ordering::Relaxed),
            tx_dropped: self.tx_dropped.load(Ordering::Relaxed),

            chacha_encode_count: self.chacha_encode_count.load(Ordering::Relaxed),
            chacha_decode_count: self.chacha_decode_count.load(Ordering::Relaxed),

            uptime: self.uptime(),
        }
    }

    /// Print formatted statistics
    pub fn print_stats(&self) {
        let snap = self.snapshot();
        snap.print();
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of metrics at a point in time
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,

    pub chacha_encode_count: u64,
    pub chacha_decode_count: u64,

    pub uptime: Duration,
}

#[allow(clippy::cast_precision_loss)] // Stats are approximate, precision loss acceptable
impl MetricsSnapshot {
    /// Calculate packets per second
    #[must_use]
    pub fn rx_pps(&self) -> f64 {
        self.rx_packets as f64 / self.uptime.as_secs_f64()
    }

    #[must_use]
    pub fn tx_pps(&self) -> f64 {
        self.tx_packets as f64 / self.uptime.as_secs_f64()
    }

    /// Calculate bytes per second (throughput)
    #[must_use]
    pub fn rx_bps(&self) -> f64 {
        self.rx_bytes as f64 / self.uptime.as_secs_f64()
    }

    #[must_use]
    pub fn tx_bps(&self) -> f64 {
        self.tx_bytes as f64 / self.uptime.as_secs_f64()
    }

    /// Calculate packet loss rate
    #[must_use]
    pub fn rx_loss_rate(&self) -> f64 {
        let total = self.rx_packets + self.rx_dropped;
        if total == 0 {
            0.0
        } else {
            self.rx_dropped as f64 / total as f64
        }
    }

    #[must_use]
    pub fn tx_loss_rate(&self) -> f64 {
        let total = self.tx_packets + self.tx_dropped;
        if total == 0 {
            0.0
        } else {
            self.tx_dropped as f64 / total as f64
        }
    }

    /// Print formatted statistics
    pub fn print(&self) {
        println!("=== gutd Performance Metrics ===");
        println!("Uptime: {:.2}s", self.uptime.as_secs_f64());
        println!();

        println!("--- Packets ---");
        println!(
            "  RX: {} packets ({} bytes, {:.2} pps, {:.2} Mbps)",
            self.rx_packets,
            self.rx_bytes,
            self.rx_pps(),
            self.rx_bps() * 8.0 / 1_000_000.0
        );
        println!(
            "  TX: {} packets ({} bytes, {:.2} pps, {:.2} Mbps)",
            self.tx_packets,
            self.tx_bytes,
            self.tx_pps(),
            self.tx_bps() * 8.0 / 1_000_000.0
        );
        println!(
            "  RX Dropped: {} ({:.2}%)",
            self.rx_dropped,
            self.rx_loss_rate() * 100.0
        );
        println!(
            "  TX Dropped: {} ({:.2}%)",
            self.tx_dropped,
            self.tx_loss_rate() * 100.0
        );
        println!();

        println!("--- Encryption ---");
        println!("  Encryption Encode: {}", self.chacha_encode_count);
        println!("  Encryption Decode: {}", self.chacha_decode_count);
        println!();

        println!("================================");
    }
}

/// Global metrics instance
pub static METRICS: Metrics = Metrics::new();

/// Lightweight timer for measuring operation duration.
pub struct Timer {
    start: Instant,
}

impl Timer {
    #[inline]
    #[must_use]
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    #[inline]
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_basic() {
        let m = Metrics::new();
        m.record_rx(100);
        m.record_tx(200);

        let snap = m.snapshot();
        assert_eq!(snap.rx_packets, 1);
        assert_eq!(snap.tx_packets, 1);
        assert_eq!(snap.rx_bytes, 100);
        assert_eq!(snap.tx_bytes, 200);
    }

    #[test]
    fn test_metrics_rates() {
        let m = Metrics::new();
        std::thread::sleep(Duration::from_millis(100));

        m.record_rx(1000);
        m.record_tx(2000);

        let snap = m.snapshot();
        assert!(snap.rx_pps() > 0.0);
        assert!(snap.tx_pps() > 0.0);
    }
}
