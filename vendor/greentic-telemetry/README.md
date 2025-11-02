# greentic-telemetry

Structured JSON logging helpers built on top of `tracing` for Greentic services.

## Quickstart

```rust
use greentic_telemetry::{init, set_context, shutdown, CloudCtx, TelemetryInit, prelude::*};

fn main() -> anyhow::Result<()> {
    init(
        TelemetryInit {
            service_name: "example-service",
            service_version: "1.0.0",
            deployment_env: "staging",
        },
        &["tenant", "team", "flow", "run_id"],
    )?;

    set_context(CloudCtx {
        tenant: Some("tenant-42"),
        team: Some("growth"),
        flow: Some("onboarding"),
        run_id: Some("run-17"),
    });

    info!("service booted");

    shutdown(); // flush OTLP batches before exiting

    Ok(())
}
```

Run the included example to view JSON output:

```bash
cargo run --example stdout
```

### Environment overview

| Variable | Description | Default |
| --- | --- | --- |
| `TELEMETRY_EXPORT` | Export mode (`json-stdout`, `otlp-grpc`, `otlp-http`) | `json-stdout` |
| `OTLP_ENDPOINT` | Collector endpoint (e.g. `http://otel-collector:4317`) | _unset_ |
| `OTLP_HEADERS` | Comma separated headers forwarded to the collector | _unset_ |
| `TELEMETRY_SAMPLING` | `parent` or `traceidratio:<ratio>` | `parent` |
| `CLOUD_PRESET` | Cloud preset (`aws`, `gcp`, `azure`, `datadog`, `loki`, `none`) | `none` |
| `PII_REDACTION_MODE` | `off`, `strict`, `allowlist` | `off` |
| `PII_ALLOWLIST_FIELDS` | Comma allowlist for PII fields (allowlist mode) | _unset_ |
| `PII_MASK_REGEXES` | Extra regex masks applied to messages & string fields | _unset_ |

When OTLP configuration fails, the crate logs a warning and keeps emitting JSON to stdout (if enabled).

### Runnable examples

```bash
cargo run --example stdout          # JSON logs to stdout
cargo run --example nats_propagation
cargo run --example wasm_host_demo
cargo run --example otlp_demo       # requires OTLP endpoint
```

## Context Propagation

Use `inject_carrier` / `extract_carrier_into_span` to round-trip span context and the Greentic cloud IDs across message boundaries:

```rust
struct Headers(HashMap<String, String>);

impl greentic_telemetry::Carrier for Headers {
    fn set(&mut self, key: &str, value: String) { self.0.insert(key.into(), value); }
    fn get(&self, key: &str) -> Option<String> { self.0.get(key).cloned() }
}

let mut headers = Headers(HashMap::new());

let span = tracing::info_span!("publish");
let _guard = span.enter();
greentic_telemetry::inject_carrier(&mut headers);

// Later, on the consumer side:
let span = tracing::info_span!("handle");
greentic_telemetry::extract_carrier_into_span(&headers, &span);
let _guard = span.enter();
```

`inject_carrier` emits W3C `traceparent` / `tracestate` headers and the `x-tenant`, `x-team`, `x-flow`, `x-run-id` identifiers. `extract_carrier_into_span` restores the span parentage and rehydrates the context so subsequent logs include the inherited IDs. If you already entered the target span, `extract_carrier` will attempt to apply the context to the current span.

### NATS propagation demo

```rust
use greentic_telemetry::{
    init, set_context, Carrier, CloudCtx, TelemetryInit, extract_carrier_into_span, inject_carrier, prelude::*,
};
use std::collections::HashMap;

#[derive(Default)]
struct Headers(HashMap<String, String>);

impl Carrier for Headers {
    fn set(&mut self, key: &str, value: String) { self.0.insert(key.to_string(), value); }
    fn get(&self, key: &str) -> Option<String> { self.0.get(key).cloned() }
}

fn main() -> anyhow::Result<()> {
    init(
        TelemetryInit {
            service_name: "nats-demo",
            service_version: "1.0.0",
            deployment_env: "prod",
        },
        &["tenant", "team"],
    )?;

    set_context(CloudCtx {
        tenant: Some("alpha"),
        team: Some("platform"),
        flow: None,
        run_id: None,
    });

    let mut headers = Headers::default();
    {
        let span = info_span!("publish");
        let _guard = span.enter();
        inject_carrier(&mut headers);
        info!(subject = "orders.created", "message published");
    }

    let span = info_span!("consume");
    let _guard = span.enter();
    extract_carrier_into_span(&headers, &span);
    info!("message consumed with propagated context");

    Ok(())
}
```

## Cloud Presets

Set `CLOUD_PRESET` for quick-start wiring. Presets only prefill defaults—you can still override env vars manually.

| Preset | Default `OTLP_ENDPOINT` | Notes |
| --- | --- | --- |
| `aws` | `http://aws-otel-collector:4317` | Targets AWS Distro for OpenTelemetry collector.
| `gcp` | `http://otc-collector:4317` | Example for Google Ops Agent’s OTLP receiver.
| `azure` | `http://otel-collector-azure:4317` | Collector forwarding to Azure Monitor exporter.
| `datadog` | `http://datadog-agent:4317` | If `DD_API_KEY` present, auto-inserts `OTLP_HEADERS=DD_API_KEY=...`.
| `loki` | N/A | Keeps `json-stdout`; ship through Vector/Grafana Agent for Loki/Tempo.

`TELEMETRY_EXPORT` remains respected. If unset, presets select `otlp-grpc` (except `loki`, which leaves JSON stdout).

### Collector snippets

AWS ADOT sidecar (logs/traces):

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  awsxray:
    local_mode: true
  awscloudwatchlogs:
    log_group_name: /greentic/services
service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [awsxray]
    logs:
      receivers: [otlp]
      exporters: [awscloudwatchlogs]
```

GCP Ops Agent OTLP collector (forward to Cloud Trace / Logging):

```yaml
receivers:
  otlp:
    protocols:
      grpc:
exporters:
  googlecloud:
    project: ${PROJECT_ID}
service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [googlecloud]
    logs:
      receivers: [otlp]
      exporters: [googlecloud]
```

Azure Monitor exporter via standalone collector:

```yaml
receivers:
  otlp:
    protocols:
      grpc:
exporters:
  azuremonitor:
    instrumentation_key: ${APP_INSIGHTS_KEY}
service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [azuremonitor]
    logs:
      receivers: [otlp]
      exporters: [azuremonitor]
```

Datadog agent OTLP:

```yaml
receivers:
  otlp:
    protocols:
      grpc:
exporters:
  otlphttp:
    endpoint: https://api.datadoghq.com
    headers:
      x-api-key: ${DD_API_KEY}
service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [otlphttp]
    logs:
      receivers: [otlp]
      exporters: [otlphttp]
```

Loki + Tempo via Vector:

```yaml
sources:
  otlp_grpc:
    type: otlp
    address: 0.0.0.0:4317
sinks:
  loki:
    type: loki
    inputs: [otlp_grpc]
    endpoint: http://loki:3100
  tempo:
    type: tempo
    inputs: [otlp_grpc]
    endpoint: http://tempo:4317
```

## Metrics

- Counters, gauges, and histograms are exposed via `greentic_telemetry::metrics`.
- When `TELEMETRY_EXPORT` resolves to an OTLP exporter, measurements are forwarded over the same gRPC channel. With `json-stdout`, metrics default to no-ops so instrumentation never needs guard clauses.

```rust
let requests = greentic_telemetry::metrics::counter("service.requests");
let latency = greentic_telemetry::metrics::histogram("service.request.duration_ms");

requests.add(1.0);
latency.record(elapsed_ms);
```

Every data point automatically includes `service.name`, `service.version`, `deployment.environment`, and the active cloud context (`tenant`, `team`, `flow`, `run_id`). If a tracing span is in scope, exemplar hints (`trace_id`, `span_id`) ride along so compatible collectors can correlate metrics back to traces.

## WASM guests / host tools

The `wit/greentic-telemetry.wit` package exposes a narrow logging interface that WASM guests can rely on. With `wit-bindgen`, the guest side becomes:

```rust
// wasm_guest.rs
use greentic_telemetry::wasm_guest::{Field, Level, log, span_end, span_start};

pub fn run_tool() {
    let span = span_start("guest-tool", &[Field { key: "tenant", value: "acme" }]);
    log(Level::Info, "initialised guest tool", &[]);
    log(Level::Info, "work complete", &[]);
    span_end(span);
}
```

A native host can forward the guest calls to tracing:

```rust
use greentic_telemetry::wasm_host::{log as host_log, span_end, span_start, Field, LogLevel};

fn simulate_guest() {
    let span = span_start("guest-run", &[Field { key: "team", value: "ops" }]);
    host_log(LogLevel::Info, "guest emitted log", &[]);
    span_end(span);
}
```

See `examples/wasm_host_demo.rs` for a runnable version.

## PII Redaction

- Configure `PII_REDACTION_MODE=off|strict|allowlist` to mask sensitive values before they reach collectors.
- `strict` masks common tokens, emails, and phone numbers by default; `allowlist` keeps only the fields in `PII_ALLOWLIST_FIELDS` unchanged.
- Extend masking with `PII_MASK_REGEXES` (comma-separated regexes) to scrub custom patterns.

## OTLP demo

`cargo run --example otlp_demo` emits a span (`demo.operation`), structured logs, and metrics (`demo.request.count`, `demo.request.duration_ms`). Point `TELEMETRY_EXPORT=otlp-grpc` and `OTLP_ENDPOINT` at a collector before running.

## Troubleshooting

- **No logs**: ensure `RUST_LOG` includes `info` (or higher) and that the collector has a logs pipeline when using OTLP.
- **Metrics missing**: verify the collector has a metrics pipeline and that it isn’t filtering by resource attributes (`service.*`, `deployment.environment`).
- **Context lost**: make sure headers survive transport (case sensitivity, lower-case keys for NATS, etc.) and call `extract_carrier_into_span` _before_ entering the span that should adopt the remote context.
- **Unexpected PII**: enable `PII_REDACTION_MODE=strict` and add custom regexes for service-specific tokens.
- **Snapshot tests**: use `greentic_telemetry::dev::test_init_for_snapshot()` and `capture_logs` to gather deterministic JSON output with a fixed timestamp.
