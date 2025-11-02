use greentic_telemetry::{
    HostField, HostLogLevel, TelemetryInit, host_log, host_span_end, host_span_start, init,
    prelude::*,
};

fn main() -> anyhow::Result<()> {
    init(
        TelemetryInit {
            service_name: "wasm-host-demo",
            service_version: "0.1.0",
            deployment_env: "dev",
        },
        &[],
    )?;

    info!("simulating guest calls");

    let span_id = host_span_start(
        "guest-tool",
        &[HostField {
            key: "tenant",
            value: "alpha",
        }],
    );

    host_log(
        HostLogLevel::Info,
        "guest emitted info log",
        &[HostField {
            key: "tool-version",
            value: "1.2.3",
        }],
    );

    host_span_end(span_id);
    Ok(())
}
