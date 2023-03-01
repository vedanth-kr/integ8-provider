#![allow(improper_ctypes_definitions)]

use async_ffi::{FfiFuture, FutureExt};
use integ8_sdk::{GatewayError, Payload};
use serde_json::Value;

// Using this library allows dynamic loading of policy providers (also known as shared libraries).
// The current auth policy validates if the "x_auth_key" header matches the configured value
#[no_mangle]
pub extern "C" fn execute(
    payload: &Payload,
    policy_config: &Value,
) -> FfiFuture<Result<Payload, GatewayError>> {
    let _payload = payload.clone();
    let _policy_config = policy_config.clone();
    async move { handle(_payload, _policy_config).await }.into_ffi()
}

// 1. Extract the configured key from policy config
// 2. Extract the header value "x_auth_key"
// 3. Validate if configured value matches header value else return 401
async fn handle(payload: Payload, policy_config: Value) -> Result<Payload, GatewayError> {
    if policy_config["key"].is_null() {
        return Err(GatewayError::new(
            "Auth Key".to_string(),
            "Auth key configuration not found".to_string(),
            401,
        ));
    }

    let headers = payload.headers.as_ref().unwrap();
    let inbound = headers.inbound.as_ref().unwrap();
    let auth_key_header = inbound.get("custom_auth_key");

    if auth_key_header.is_none() {
        return Err(GatewayError::new(
            "Auth Key".to_string(),
            "Auth key not found in header".to_string(),
            401,
        ));
    }

    let auth_key = auth_key_header.unwrap();

    if auth_key != policy_config["key"].as_str().unwrap() {
        return Err(GatewayError::new(
            "Auth Key".to_string(),
            "Auth key is not valid".to_string(),
            401,
        ));
    }

    Ok(payload)
}
