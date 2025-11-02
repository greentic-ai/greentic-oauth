//! Telemetry initialization helpers for Greentic services.

mod context;
pub mod dev;
mod export;
mod init;
pub mod metrics;
mod presets;
mod propagation;
mod redaction;
#[cfg(feature = "wasm-guest")]
mod wasm_guest;
#[cfg(feature = "wasm-host")]
mod wasm_host;

pub use context::{CloudCtx, set_context};
pub use init::{TelemetryInit, init, shutdown};
pub use metrics::{Counter, Gauge, Histogram, counter, gauge, histogram};
pub use propagation::{Carrier, extract_carrier, extract_carrier_into_span, inject_carrier};
#[cfg(feature = "wasm-guest")]
pub use wasm_guest::{
    Field as GuestField, Level as GuestLevel, log as guest_log, span_end as guest_span_end,
    span_start as guest_span_start,
};
#[cfg(feature = "wasm-host")]
pub use wasm_host::{
    Field as HostField, LogLevel as HostLogLevel, log as host_log, span_end as host_span_end,
    span_start as host_span_start,
};

/// Commonly used tracing macros and utilities.
pub mod prelude {
    pub use tracing::{Level, debug, error, event, info, instrument, span, trace, warn};
}
