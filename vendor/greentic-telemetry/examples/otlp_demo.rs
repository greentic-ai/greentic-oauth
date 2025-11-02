use std::time::{Duration, Instant};

use greentic_telemetry::{
    CloudCtx, TelemetryInit, init,
    metrics::{counter, histogram},
    prelude::*,
    set_context,
};
use tracing::info_span;

fn main() -> anyhow::Result<()> {
    init(
        TelemetryInit {
            service_name: "otlp-demo",
            service_version: "0.1.0",
            deployment_env: "dev",
        },
        &["tenant", "team"],
    )?;

    set_context(CloudCtx {
        tenant: Some("alpha"),
        team: Some("telemetry"),
        flow: Some("otlp-demo"),
        run_id: Some("run-otlp"),
    });

    let request_counter = counter("demo.request.count");
    let latency_histogram = histogram("demo.request.duration_ms");

    let span = info_span!("demo.operation");
    let _guard = span.enter();

    info!("performing work");
    let timer = Instant::now();

    std::thread::sleep(Duration::from_millis(75));

    request_counter.add(1.0);
    latency_histogram.record(timer.elapsed().as_secs_f64() * 1000.0);

    info!("operation complete");
    Ok(())
}
