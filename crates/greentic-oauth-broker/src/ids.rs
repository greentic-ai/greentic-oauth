use std::str::FromStr;

use greentic_types::{EnvId, GreenticError, TeamId, TenantId, UserId};

use crate::http::error::AppError;

pub fn parse_env_id(value: &str) -> Result<EnvId, AppError> {
    parse_id("environment", value)
}

pub fn parse_tenant_id(value: &str) -> Result<TenantId, AppError> {
    parse_id("tenant", value)
}

pub fn parse_team_id(value: &str) -> Result<TeamId, AppError> {
    parse_id("team", value)
}

pub fn parse_user_id(value: &str) -> Result<UserId, AppError> {
    parse_id("user", value)
}

fn parse_id<T>(label: &str, value: &str) -> Result<T, AppError>
where
    T: FromStr<Err = GreenticError>,
{
    value
        .parse::<T>()
        .map_err(|err| AppError::bad_request(format!("invalid {label} id: {err}")))
}
