#[derive(Clone, Copy, Debug)]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Clone, Debug)]
pub struct Field<'a> {
    pub key: &'a str,
    pub value: &'a str,
}

pub fn log(level: Level, message: &str, fields: &[Field<'_>]) {
    #[cfg(target_arch = "wasm32")]
    {
        host::log(level, message, fields);
        return;
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        fallback_log(level, message, fields);
    }
}

pub fn span_start(name: &str, fields: &[Field<'_>]) -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        return host::span_start(name, fields);
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        fallback_log(Level::Debug, &format!("span-start: {name}"), fields);
        0
    }
}

pub fn span_end(id: u64) {
    #[cfg(target_arch = "wasm32")]
    {
        host::span_end(id);
        return;
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = id; // silence unused warnings
    }
}

#[cfg(target_arch = "wasm32")]
mod host {
    use super::{Field, Level};

    wit_bindgen::generate!({
        path: "wit",
        world: "guest-telemetry"
    });

    pub fn log(level: Level, message: &str, fields: &[Field<'_>]) {
        use exports::greentic::telemetry::logging::{self as wit, Fields, Level as WitLevel};

        let lvl = match level {
            Level::Trace => WitLevel::Trace,
            Level::Debug => WitLevel::Debug,
            Level::Info => WitLevel::Info,
            Level::Warn => WitLevel::Warn,
            Level::Error => WitLevel::Error,
        };

        let entries = fields
            .iter()
            .map(|f| (f.key.to_string(), f.value.to_string()))
            .collect::<Vec<_>>();

        wit::log(
            lvl,
            message.to_string(),
            Fields {
                entries: entries.into(),
            },
        );
    }

    pub fn span_start(name: &str, fields: &[Field<'_>]) -> u64 {
        use exports::greentic::telemetry::logging::{self as wit, Fields};

        let entries = fields
            .iter()
            .map(|f| (f.key.to_string(), f.value.to_string()))
            .collect::<Vec<_>>();

        wit::span_start(
            name.to_string(),
            Fields {
                entries: entries.into(),
            },
        )
    }

    pub fn span_end(id: u64) {
        use exports::greentic::telemetry::logging as wit;
        wit::span_end(id);
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn fallback_log(level: Level, message: &str, fields: &[Field<'_>]) {
    let lvl = match level {
        Level::Trace => "TRACE",
        Level::Debug => "DEBUG",
        Level::Info => "INFO",
        Level::Warn => "WARN",
        Level::Error => "ERROR",
    };

    if fields.is_empty() {
        println!("[{lvl}] {message}");
    } else {
        let serialized = fields
            .iter()
            .map(|f| format!("{}={}", f.key, f.value))
            .collect::<Vec<_>>()
            .join(", ");
        println!("[{lvl}] {message} [{serialized}]");
    }
}
