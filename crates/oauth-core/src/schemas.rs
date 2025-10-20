#![cfg(feature = "schemas")]

use schemars::{schema::RootSchema, schema_for};

use crate::types::{OAuthFlowRequest, OAuthFlowResult, TokenHandleClaims, TokenSet};

/// JSON Schema for interactive OAuth flow requests.
pub fn oauth_flow_request_schema() -> RootSchema {
    schema_for!(OAuthFlowRequest)
}

/// JSON Schema for responses returned from provider authorize redirects.
pub fn oauth_flow_result_schema() -> RootSchema {
    schema_for!(OAuthFlowResult)
}

/// JSON Schema describing token exchange outputs.
pub fn token_set_schema() -> RootSchema {
    schema_for!(TokenSet)
}

/// JSON Schema for persisted token handle claims.
pub fn token_handle_claims_schema() -> RootSchema {
    schema_for!(TokenHandleClaims)
}
