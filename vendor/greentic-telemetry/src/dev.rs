use anyhow::Result;
use once_cell::sync::{Lazy, OnceCell};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

static CAPTURE_ENABLED: AtomicBool = AtomicBool::new(false);
static CAPTURED_LOGS: Lazy<Mutex<Vec<String>>> = Lazy::new(|| Mutex::new(Vec::new()));
#[cfg(feature = "json-stdout")]
static FIXED_TIME: OnceCell<String> = OnceCell::new();
static SNAPSHOT_INIT: OnceCell<()> = OnceCell::new();

/// Initialize telemetry for deterministic snapshot testing.
///
/// - Forces `json-stdout` exporter
/// - Disables PII redaction
/// - Sets a fixed timestamp (can be overridden via `TEST_FIXED_TIME`)
pub fn test_init_for_snapshot() -> Result<()> {
    SNAPSHOT_INIT.get_or_try_init(|| {
        unsafe {
            std::env::set_var("TELEMETRY_EXPORT", "json-stdout");
            std::env::set_var("PII_REDACTION_MODE", "off");
            std::env::set_var("RUST_LOG", "info");
        }
        if std::env::var("TEST_FIXED_TIME").is_err() {
            unsafe {
                std::env::set_var("TEST_FIXED_TIME", "1700000000.000");
            }
        }

        crate::init(
            crate::TelemetryInit {
                service_name: "snapshot-test",
                service_version: "0.0.0",
                deployment_env: "test",
            },
            &["tenant", "team", "flow", "run_id"],
        )
        .map(|_| ())
    })?;

    Ok(())
}

/// Capture logs emitted inside `f` for snapshot assertions.
pub fn capture_logs<F, R>(f: F) -> Vec<String>
where
    F: FnOnce() -> R,
{
    CAPTURE_ENABLED.store(true, Ordering::SeqCst);
    {
        if let Ok(mut buffer) = CAPTURED_LOGS.lock() {
            buffer.clear();
        }
    }

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));

    CAPTURE_ENABLED.store(false, Ordering::SeqCst);
    let logs = CAPTURED_LOGS
        .lock()
        .map(|buffer| buffer.clone())
        .unwrap_or_default();

    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }

    logs
}

#[cfg(feature = "json-stdout")]
pub(crate) fn maybe_capture(bytes: &[u8]) {
    if !CAPTURE_ENABLED.load(Ordering::SeqCst) {
        return;
    }
    if let Ok(mut buffer) = CAPTURED_LOGS.lock() {
        let line = String::from_utf8_lossy(bytes).trim_end().to_string();
        buffer.push(line);
    }
}

#[cfg(feature = "json-stdout")]
pub(crate) fn fixed_timestamp() -> Option<String> {
    if let Some(value) = FIXED_TIME.get() {
        return Some(value.clone());
    }
    if let Ok(value) = std::env::var("TEST_FIXED_TIME") {
        let _ = FIXED_TIME.set(value.clone());
        return Some(value);
    }
    None
}
