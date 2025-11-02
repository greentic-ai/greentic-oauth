use once_cell::sync::{Lazy, OnceCell};
use regex::Regex;
use std::collections::HashSet;
use std::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum RedactionMode {
    #[default]
    Off,
    Strict,
    Allowlist,
}

#[derive(Clone, Debug, Default)]
pub struct Redactor {
    mode: RedactionMode,
    allowlist: Vec<String>,
    regexes: Vec<Regex>,
}

static REDACTOR: OnceCell<Redactor> = OnceCell::new();
static WARNED_PATTERNS: OnceCell<Mutex<HashSet<String>>> = OnceCell::new();

static DEFAULT_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}").unwrap(),
        Regex::new(r"(?i)bearer\s+[a-z0-9._\-]+\b").unwrap(),
        Regex::new(r"(?i)(api[-_]?key|token)\s*[:=]\s*[a-z0-9._\-]+\b").unwrap(),
        Regex::new(r"\+?\d[\d\-\s]{7,14}\d").unwrap(),
    ]
});

pub fn init_from_env() {
    let mode = std::env::var("PII_REDACTION_MODE")
        .ok()
        .map(|value| match value.to_ascii_lowercase() {
            v if matches!(v.as_str(), "off" | "none") => RedactionMode::Off,
            v if v == "strict" => RedactionMode::Strict,
            v if v == "allowlist" => RedactionMode::Allowlist,
            other => {
                tracing::warn!("unknown PII_REDACTION_MODE value: {other}, defaulting to off");
                RedactionMode::Off
            }
        })
        .unwrap_or_default();

    let allowlist = if mode == RedactionMode::Allowlist {
        std::env::var("PII_ALLOWLIST_FIELDS")
            .ok()
            .map(|value| {
                value
                    .split(',')
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let regexes = build_custom_regexes(std::env::var("PII_MASK_REGEXES").ok().as_deref());

    let _ = REDACTOR.set(Redactor {
        mode,
        allowlist,
        regexes,
    });
}

pub fn redact_field(key: &str, value: &str) -> String {
    let redactor = REDACTOR.get().cloned().unwrap_or_default();
    match redactor.mode {
        RedactionMode::Off => value.to_string(),
        RedactionMode::Strict | RedactionMode::Allowlist => {
            let is_allowed = redactor
                .allowlist
                .iter()
                .any(|item| item == &key.to_ascii_lowercase());

            if redactor.mode == RedactionMode::Allowlist && is_allowed {
                value.to_string()
            } else {
                apply_patterns(value, &redactor)
            }
        }
    }
}

fn build_custom_regexes(value: Option<&str>) -> Vec<Regex> {
    let mut list = Vec::new();

    let Some(value) = value else {
        return list;
    };

    for pattern in value.split(',') {
        let trimmed = pattern.trim();
        if trimmed.is_empty() {
            continue;
        }

        match Regex::new(trimmed) {
            Ok(regex) => list.push(regex),
            Err(err) => warn_once(trimmed.to_string(), err),
        }
    }

    list
}

fn apply_patterns(value: &str, redactor: &Redactor) -> String {
    let mut masked = value.to_string();

    if matches!(
        redactor.mode,
        RedactionMode::Strict | RedactionMode::Allowlist
    ) {
        masked = DEFAULT_PATTERNS.iter().fold(masked, |current, regex| {
            regex.replace_all(&current, "[REDACTED]").into_owned()
        });
    }

    for regex in &redactor.regexes {
        masked = regex.replace_all(&masked, "[REDACTED]").into_owned();
    }

    masked
}

fn warn_once(pattern: String, err: regex::Error) {
    let set = WARNED_PATTERNS.get_or_init(|| Mutex::new(HashSet::new()));
    if let Ok(mut guard) = set.lock() {
        if guard.insert(pattern.clone()) {
            tracing::warn!("invalid PII_MASK_REGEXES entry '{pattern}': {err}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_masks_email_phone_and_token() {
        let redactor = Redactor {
            mode: RedactionMode::Strict,
            allowlist: Vec::new(),
            regexes: Vec::new(),
        };

        let masked = apply_patterns(
            "Email alice@example.com with bearer ABC123 and call +12345678901",
            &redactor,
        );

        assert!(!masked.contains("alice@example.com"));
        assert!(!masked.contains("ABC123"));
        assert!(!masked.contains("+12345678901"));
        assert!(masked.contains("[REDACTED]"));
    }

    #[test]
    fn allowlist_keeps_fields() {
        let redactor = Redactor {
            mode: RedactionMode::Allowlist,
            allowlist: vec!["user_id".into()],
            regexes: Vec::new(),
        };

        let masked = apply_patterns("User token = secret", &redactor);
        assert!(masked.contains("[REDACTED]"));

        let field_value = redact_field("user_id", "12345");
        assert_eq!(field_value, "12345");
    }

    #[test]
    fn custom_regex_masks_access_token() {
        let redactor = Redactor {
            mode: RedactionMode::Strict,
            allowlist: Vec::new(),
            regexes: vec![Regex::new(r"(?i)secret\s*[:=]\s*[a-z0-9]+\b").unwrap()],
        };

        let masked = apply_patterns("secret=abcdef", &redactor);
        assert_eq!(masked, "[REDACTED]");
    }
}
