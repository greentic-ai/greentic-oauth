use schemars::schema_for;
use serde_json::Value;

use crate::types::{OAuthFlowRequest, OAuthFlowResult, TokenHandleClaims, TokenSet};

/// JSON Schema for interactive OAuth flow requests.
pub fn oauth_flow_request_schema() -> Value {
    serde_json::to_value(schema_for!(OAuthFlowRequest)).expect("serialize schema")
}

/// JSON Schema for responses returned from provider authorize redirects.
pub fn oauth_flow_result_schema() -> Value {
    serde_json::to_value(schema_for!(OAuthFlowResult)).expect("serialize schema")
}

/// JSON Schema describing token exchange outputs.
pub fn token_set_schema() -> Value {
    serde_json::to_value(schema_for!(TokenSet)).expect("serialize schema")
}

/// JSON Schema for persisted token handle claims.
pub fn token_handle_claims_schema() -> Value {
    serde_json::to_value(schema_for!(TokenHandleClaims)).expect("serialize schema")
}
