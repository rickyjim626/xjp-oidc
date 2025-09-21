//! Dynamic Client Registration (DCR) implementation (server-only)

#[cfg(not(target_arch = "wasm32"))]
use crate::{
    discovery::discover,
    errors::{Error, Result},
    http::HttpClient,
    types::{ClientRegistrationResult, ClientStatus, RegisterRequest},
};

/// Register a new client if needed
///
/// This implements OAuth 2.0 Dynamic Client Registration (RFC 7591)
/// with support for the authorization server's approval workflow.
///
/// # Example
/// ```no_run
/// # #[cfg(not(target_arch = "wasm32"))]
/// # use xjp_oidc::{register_if_needed, RegisterRequest, http::ReqwestHttpClient};
/// # #[cfg(not(target_arch = "wasm32"))]
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let http = ReqwestHttpClient::default();
///
/// let result = register_if_needed(
///     "https://auth.example.com",
///     "initial_access_token",
///     RegisterRequest {
///         application_type: Some("web".into()),
///         redirect_uris: vec!["https://app.example.com/callback".into()],
///         post_logout_redirect_uris: Some(vec!["https://app.example.com".into()]),
///         grant_types: vec!["authorization_code".into()],
///         token_endpoint_auth_method: "client_secret_basic".into(),
///         scope: "openid profile email".into(),
///         contacts: Some(vec!["admin@example.com".into()]),
///         software_id: Some("my-app".into()),
///         client_name: Some("My Application".into()),
///     },
///     &http
/// ).await?;
///
/// match result.status {
///     xjp_oidc::types::ClientStatus::Active => {
///         println!("Client registered and active!");
///     }
///     xjp_oidc::types::ClientStatus::Pending => {
///         println!("Client registered but pending approval");
///     }
///     _ => {}
/// }
/// # Ok(())
/// # }
/// ```
#[cfg(not(target_arch = "wasm32"))]
pub async fn register_if_needed(
    issuer: &str,
    initial_access_token: &str,
    req: RegisterRequest,
    http: &dyn HttpClient,
) -> Result<ClientRegistrationResult> {
    // Validate parameters
    validate_register_params(&req)?;

    if issuer.is_empty() {
        return Err(Error::InvalidParam("issuer cannot be empty"));
    }
    if initial_access_token.is_empty() {
        return Err(Error::InvalidParam("initial_access_token cannot be empty"));
    }

    // Get registration endpoint from discovery
    let cache = crate::cache::NoOpCache;
    let metadata = discover(issuer, http, &cache).await?;

    let registration_endpoint = metadata
        .registration_endpoint
        .ok_or_else(|| Error::Discovery("Registration endpoint not found in metadata".into()))?;

    // Prepare request body
    let request_body = prepare_registration_request(req);

    // Make registration request
    let bearer_token = format!("Bearer {}", initial_access_token);
    let auth_header = Some(("Authorization", bearer_token.as_str()));

    let response = http
        .post_json_value(&registration_endpoint, &request_body, auth_header)
        .await
        .map_err(|e| {
        // Try to parse DCR-specific errors
        if let crate::http::HttpClientError::InvalidStatus { status: _, message } = &e {
            if let Ok(dcr_error) = serde_json::from_str::<DcrError>(&message) {
                return map_dcr_error(dcr_error);
            }
        }
        Error::Network(format!("Client registration failed: {}", e))
    })?;

    // Parse response
    parse_registration_response(response)
}

/// Validate registration parameters
#[cfg(not(target_arch = "wasm32"))]
fn validate_register_params(req: &RegisterRequest) -> Result<()> {
    if req.redirect_uris.is_empty() {
        return Err(Error::InvalidParam("redirect_uris cannot be empty"));
    }

    for uri in &req.redirect_uris {
        if uri.is_empty() {
            return Err(Error::InvalidParam("redirect_uri cannot be empty"));
        }
        // Validate URL format
        url::Url::parse(uri).map_err(|_| Error::InvalidParam("invalid redirect_uri format"))?;
    }

    if let Some(logout_uris) = &req.post_logout_redirect_uris {
        for uri in logout_uris {
            if !uri.is_empty() {
                url::Url::parse(uri)
                    .map_err(|_| Error::InvalidParam("invalid post_logout_redirect_uri format"))?;
            }
        }
    }

    if req.grant_types.is_empty() {
        return Err(Error::InvalidParam("grant_types cannot be empty"));
    }

    if req.token_endpoint_auth_method.is_empty() {
        return Err(Error::InvalidParam("token_endpoint_auth_method cannot be empty"));
    }

    Ok(())
}

/// Prepare registration request body
#[cfg(not(target_arch = "wasm32"))]
fn prepare_registration_request(req: RegisterRequest) -> serde_json::Value {
    let mut body = serde_json::json!({
        "redirect_uris": req.redirect_uris,
        "grant_types": req.grant_types,
        "token_endpoint_auth_method": req.token_endpoint_auth_method,
        "scope": req.scope,
        "response_types": ["code"], // Default to authorization code flow
    });

    let obj = body.as_object_mut().unwrap();

    if let Some(app_type) = req.application_type {
        obj.insert("application_type".to_string(), serde_json::json!(app_type));
    }

    if let Some(logout_uris) = req.post_logout_redirect_uris {
        obj.insert("post_logout_redirect_uris".to_string(), serde_json::json!(logout_uris));
    }

    if let Some(contacts) = req.contacts {
        obj.insert("contacts".to_string(), serde_json::json!(contacts));
    }

    if let Some(software_id) = req.software_id {
        obj.insert("software_id".to_string(), serde_json::json!(software_id));
    }

    if let Some(client_name) = req.client_name {
        obj.insert("client_name".to_string(), serde_json::json!(client_name));
    }

    body
}

/// Parse registration response
#[cfg(not(target_arch = "wasm32"))]
fn parse_registration_response(response: serde_json::Value) -> Result<ClientRegistrationResult> {
    // Extract required fields
    let client_id = response["client_id"]
        .as_str()
        .ok_or_else(|| Error::InvalidState("Missing client_id in response".into()))?
        .to_string();

    let client_secret = response["client_secret"].as_str().map(|s| s.to_string());

    // Determine status from response
    let status = if let Some(status_str) = response["status"].as_str() {
        match status_str {
            "active" => ClientStatus::Active,
            "pending" => ClientStatus::Pending,
            "suspended" => ClientStatus::Suspended,
            _ => ClientStatus::Pending, // Default to pending for unknown status
        }
    } else {
        // If no explicit status, assume active if client_secret is provided
        if client_secret.is_some() {
            ClientStatus::Active
        } else {
            ClientStatus::Pending
        }
    };

    let client_name = response["client_name"].as_str().unwrap_or(&client_id).to_string();

    let redirect_uris = response["redirect_uris"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
        .unwrap_or_default();

    let post_logout_redirect_uris = response["post_logout_redirect_uris"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect());

    let grant_types = response["grant_types"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
        .unwrap_or_else(|| vec!["authorization_code".to_string()]);

    let token_endpoint_auth_method = response["token_endpoint_auth_method"]
        .as_str()
        .unwrap_or("client_secret_basic")
        .to_string();

    let scope = response["scope"].as_str().unwrap_or("openid profile email").to_string();

    Ok(ClientRegistrationResult {
        client_id,
        client_secret,
        status,
        client_name,
        redirect_uris,
        post_logout_redirect_uris,
        grant_types,
        token_endpoint_auth_method,
        scope,
    })
}

/// DCR-specific error response
#[cfg(not(target_arch = "wasm32"))]
#[derive(serde::Deserialize)]
struct DcrError {
    error: String,
    error_description: Option<String>,
}

/// Map DCR errors to SDK errors
#[cfg(not(target_arch = "wasm32"))]
fn map_dcr_error(err: DcrError) -> Error {
    match err.error.as_str() {
        "invalid_client_metadata" => Error::InvalidParam("Invalid client metadata"),
        "unauthorized_client" => Error::oauth("unauthorized_client", err.error_description),
        "invalid_redirect_uri" => Error::InvalidParam("Invalid redirect URI"),
        "access_denied" => Error::oauth("access_denied", err.error_description),
        _ => Error::oauth(err.error, err.error_description),
    }
}

// WASM stub
#[cfg(target_arch = "wasm32")]
pub async fn register_if_needed(
    _issuer: &str,
    _initial_access_token: &str,
    _req: crate::types::RegisterRequest,
    _http: &dyn crate::http::HttpClient,
) -> crate::errors::Result<crate::types::ClientRegistrationResult> {
    Err(crate::errors::Error::ServerOnly)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn test_validate_register_params() {
        let valid = RegisterRequest {
            application_type: Some("web".into()),
            redirect_uris: vec!["https://app.example.com/callback".into()],
            post_logout_redirect_uris: None,
            grant_types: vec!["authorization_code".into()],
            token_endpoint_auth_method: "client_secret_basic".into(),
            scope: "openid profile".into(),
            contacts: None,
            software_id: None,
            client_name: None,
        };
        assert!(validate_register_params(&valid).is_ok());

        let invalid = RegisterRequest { redirect_uris: vec![], ..valid.clone() };
        assert!(validate_register_params(&invalid).is_err());
    }

    #[test]
    fn test_prepare_registration_request() {
        let req = RegisterRequest {
            application_type: Some("web".into()),
            redirect_uris: vec!["https://app.example.com/callback".into()],
            post_logout_redirect_uris: Some(vec!["https://app.example.com".into()]),
            grant_types: vec!["authorization_code".into()],
            token_endpoint_auth_method: "client_secret_basic".into(),
            scope: "openid profile email".into(),
            contacts: Some(vec!["admin@example.com".into()]),
            software_id: Some("my-app".into()),
            client_name: Some("My Application".into()),
        };

        let body = prepare_registration_request(req);

        assert_eq!(body["application_type"], "web");
        assert_eq!(body["redirect_uris"][0], "https://app.example.com/callback");
        assert_eq!(body["grant_types"][0], "authorization_code");
        assert_eq!(body["client_name"], "My Application");
    }
}
