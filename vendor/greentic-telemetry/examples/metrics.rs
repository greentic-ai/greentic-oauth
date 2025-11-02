use std::time::{Duration, Instant};

use greentic_telemetry::{
    CloudCtx, TelemetryInit, init,
    metrics::{counter, histogram},
    set_context,
};

fn main() -> anyhow::Result<()> {
    init(
        TelemetryInit {
            service_name: "metrics-example",
            service_version: "0.1.0",
            deployment_env: "dev",
        },
        &["tenant", "team"],
    )?;

    set_context(CloudCtx {
        tenant: Some("alpha"),
        team: Some("observability"),
        flow: Some("metrics-demo"),
        run_id: Some("run-42"),
    });

    let request_counter = counter("example.request.count");
    let latency_histogram = histogram("example.request.duration_ms");

    for _ in 0..3 {
        let start = Instant::now();

        // Simulated work.
        std::thread::sleep(Duration::from_millis(50));

        request_counter.add(1.0);
        latency_histogram.record(start.elapsed().as_secs_f64() * 1000.0);
    }

    Ok(())
}
