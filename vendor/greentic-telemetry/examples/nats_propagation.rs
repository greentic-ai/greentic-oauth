use std::collections::HashMap;

use greentic_telemetry::{
    Carrier, CloudCtx, TelemetryInit, extract_carrier_into_span, init, inject_carrier, prelude::*,
    set_context,
};
use tracing::info_span;

#[derive(Default)]
struct MockHeaders(HashMap<String, String>);

impl Carrier for MockHeaders {
    fn set(&mut self, key: &str, value: String) {
        self.0.insert(key.to_string(), value);
    }

    fn get(&self, key: &str) -> Option<String> {
        self.0.get(key).cloned()
    }
}

fn main() -> anyhow::Result<()> {
    init(
        TelemetryInit {
            service_name: "nats-producer",
            service_version: "0.1.0",
            deployment_env: "dev",
        },
        &["tenant", "team"],
    )?;

    set_context(CloudCtx {
        tenant: Some("alpha"),
        team: Some("platform"),
        flow: Some("nats-demo"),
        run_id: Some("run-001"),
    });

    let mut headers = MockHeaders::default();

    {
        let span = info_span!("producer");
        let _guard = span.enter();
        inject_carrier(&mut headers);
        info!(subject = "orders.created", "published message");
    }

    {
        let span = info_span!("consumer");
        extract_carrier_into_span(&headers, &span);
        let _guard = span.enter();
        info!(subject = "orders.created", "processed message");
    }

    Ok(())
}
