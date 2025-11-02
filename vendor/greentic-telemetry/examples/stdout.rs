use greentic_telemetry::{CloudCtx, TelemetryInit, init, prelude::*, set_context, shutdown};

fn main() -> anyhow::Result<()> {
    init(
        TelemetryInit {
            service_name: "greentic-telemetry-example",
            service_version: "0.1.0",
            deployment_env: "dev",
        },
        &["tenant", "team", "flow", "run_id"],
    )?;

    set_context(CloudCtx {
        tenant: Some("tenant-123"),
        team: Some("platform"),
        flow: Some("stdout-demo"),
        run_id: Some("run-abc"),
    });

    info!("telemetry example started");
    debug!(hint = "add more logs", "debug level shows when enabled");
    warn!(
        tenant = "tenant-123",
        "custom field overrides are supported"
    );

    shutdown();

    Ok(())
}
