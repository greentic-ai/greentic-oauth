//! Shared constants used across Greentic OAuth services.

/// Canonical pattern for user subject identifiers (enforced externally).
pub const USER_SUBJECT_PATTERN: &str = r"^user:[a-z0-9][a-z0-9_-]{2,63}$";

/// Canonical pattern for service subject identifiers (enforced externally).
pub const SERVICE_SUBJECT_PATTERN: &str = r"^service:[a-z0-9][a-z0-9_-]{2,63}$";

/// Canonical pattern for team subject identifiers (enforced externally).
pub const TEAM_SUBJECT_PATTERN: &str = r"^team:[a-z0-9][a-z0-9_-]{2,63}$";
