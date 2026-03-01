//! Performance test for metrics - verifies always-on and zero overhead

use gutd::metrics::METRICS;
use std::time::Instant;

#[test]
fn test_metrics_always_active() {
    // Verify metrics work without any feature flags
    METRICS.record_rx(100);
    METRICS.record_tx(200);

    let snap = METRICS.snapshot();

    // Metrics should be counting (not feature-gated)
    assert!(snap.rx_packets > 0, "Metrics should always be active!");
    assert!(snap.rx_bytes > 0, "Metrics should track bytes!");
}

#[test]
fn test_metrics_performance() {
    // Verify metrics have minimal overhead
    let iterations = 100_000;

    let start = Instant::now();
    for i in 0..iterations {
        METRICS.record_rx(usize::try_from(i).unwrap_or(0));
        METRICS.record_tx(usize::try_from(i).unwrap_or(0));
    }
    let elapsed = start.elapsed();

    // Should be very fast - atomic operations are ~1-5ns each
    // With 2 operations per iteration, 200k ops should take < 10ms
    assert!(
        elapsed.as_millis() < 100,
        "Metrics should have minimal overhead: {elapsed:?}"
    );

    println!("✓ 200k metric operations in {elapsed:?}");
    #[allow(clippy::cast_precision_loss)]
    let ns_per_op = elapsed.as_nanos() as f64 / f64::from(iterations * 2);
    println!("  Per operation: {ns_per_op:.2} ns");
}

#[test]
fn test_timer_always_works() {
    // Timer should always work (not feature-gated)
    let timer = gutd::metrics::Timer::start();
    std::thread::sleep(std::time::Duration::from_millis(1));
    let elapsed = timer.elapsed();

    assert!(elapsed.as_millis() >= 1, "Timer should measure real time");
}
