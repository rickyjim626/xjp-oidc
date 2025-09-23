//! Token introspection and revocation implementation (server-only)

#[cfg(not(target_arch = "wasm32"))]
use crate::{
    discovery::discover,
    errors::{Error, Result},
    http::HttpClient,
    types::{IntrospectRequest, IntrospectResponse},
};
#[cfg(not(target_arch = "wasm32"))]
use base64::{engine::general_purpose, Engine as _};

/// Introspect a token to determine its active state and metadata
///
/// This function implements OAuth 2.0 Token Introspection (RFC 7662).
/// It is a server-only function that checks if a token is active and
/// returns metadata about the token.
///
/// # Example
/// ```no_run
/// # #[cfg(not(target_arch = "wasm32"))]
/// # use xjp_oidc::{introspect_token, IntrospectRequest, http::ReqwestHttpClient};
/// # #[cfg(not(target_arch = "wasm32"))]
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let http = ReqwestHttpClient::default();
///
/// let response = introspect_token(IntrospectRequest {
///     issuer: "https://auth.example.com".into(),
///     client_id: "my-client".into(),
///     client_secret: Some("secret".into()),
///     token: "access_token_to_check".into(),
///     token_type_hint: Some("access_token".into()),
///     token_endpoint_auth_method: None,
/// }, &http).await?;
///
/// if response.active {
///     println!("Token is active, expires at: {:?}", response.exp);
/// }
/// # Ok(())
/// # }
/// ```
#[cfg(not(target_arch = "wasm32"))]
#[tracing::instrument(
    name = "oidc_introspect_token",
    skip(req, http),
    fields(issuer = %req.issuer, client_id = %req.client_id)
)]
pub async fn introspect_token(
    req: IntrospectRequest,
    http: &dyn HttpClient,
) -> Result<IntrospectResponse> {
    tracing::info!(
        target: "xjp_oidc::introspect",
        "开始 Token Introspection"
    );

    // Validate parameters
    if req.issuer.is_empty() {
        return Err(Error::InvalidParam("issuer cannot be empty"));
    }
    if req.client_id.is_empty() {
        return Err(Error::InvalidParam("client_id cannot be empty"));
    }
    if req.token.is_empty() {
        return Err(Error::InvalidParam("token cannot be empty"));
    }

    // Get introspection endpoint from discovery
    let cache = crate::cache::NoOpCache;
    let metadata = discover(&req.issuer, http, &cache).await?;

    let introspection_endpoint = metadata
        .introspection_endpoint
        .as_ref()
        .ok_or_else(|| Error::Discovery("Introspection endpoint not found".to_string()))?;

    // Build form data
    let mut form = vec![
        ("token".to_string(), req.token.clone()),
    ];

    if let Some(hint) = &req.token_type_hint {
        form.push(("token_type_hint".to_string(), hint.clone()));
    }

    // Determine authentication method and add auth header if needed
    let auth_method = determine_auth_method(&req, &metadata)?;
    let auth_header = build_auth_header(&req, auth_method)?;

    // Handle client authentication based on method
    match auth_method {
        "client_secret_post" => {
            form.push(("client_id".to_string(), req.client_id.clone()));
            if let Some(secret) = &req.client_secret {
                form.push(("client_secret".to_string(), secret.clone()));
            }
        }
        "none" => {
            form.push(("client_id".to_string(), req.client_id.clone()));
        }
        _ => {} // client_secret_basic uses auth header
    }

    // Make the request
    let response = http
        .post_form_value(&introspection_endpoint, &form, auth_header.as_ref().map(|(k, v)| (*k, v.as_str())))
        .await
        .map_err(|e| Error::Network(format!("Introspection request failed: {}", e)))?;

    // Check for OAuth error response
    if let Some(error) = response.get("error").and_then(|v| v.as_str()) {
        let error_description = response
            .get("error_description")
            .and_then(|v| v.as_str())
            .unwrap_or("No description");

        return Err(Error::OAuth {
            error: error.to_string(),
            description: Some(error_description.to_string()),
        });
    }

    // Parse response
    let introspection_response: IntrospectResponse = serde_json::from_value(response)
        .map_err(|e| Error::Verification(format!("Failed to parse introspection response: {}", e)))?;

    tracing::info!(
        target: "xjp_oidc::introspect",
        "Token introspection 完成, active: {}",
        introspection_response.active
    );

    Ok(introspection_response)
}

/// Revoke a token (access token or refresh token)
///
/// This function implements OAuth 2.0 Token Revocation (RFC 7009).
/// It is a server-only function that revokes a token, making it invalid.
///
/// # Example
/// ```no_run
/// # #[cfg(not(target_arch = "wasm32"))]
/// # use xjp_oidc::{revoke_token, http::ReqwestHttpClient};
/// # #[cfg(not(target_arch = "wasm32"))]
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let http = ReqwestHttpClient::default();
///
/// revoke_token(
///     "https://auth.example.com",
///     "my-client",
///     Some("secret"),
///     "token_to_revoke",
///     Some("refresh_token"), // or "access_token"
///     None,
///     &http
/// ).await?;
/// # Ok(())
/// # }
/// ```
#[cfg(not(target_arch = "wasm32"))]
#[tracing::instrument(
    name = "oidc_revoke_token",
    skip(client_secret, token, http),
    fields(issuer = %issuer, client_id = %client_id)
)]
pub async fn revoke_token(
    issuer: &str,
    client_id: &str,
    client_secret: Option<&str>,
    token: &str,
    token_type_hint: Option<&str>,
    token_endpoint_auth_method: Option<&str>,
    http: &dyn HttpClient,
) -> Result<()> {
    tracing::info!(
        target: "xjp_oidc::introspect",
        "开始 Token Revocation"
    );

    // Validate parameters
    if issuer.is_empty() {
        return Err(Error::InvalidParam("issuer cannot be empty"));
    }
    if client_id.is_empty() {
        return Err(Error::InvalidParam("client_id cannot be empty"));
    }
    if token.is_empty() {
        return Err(Error::InvalidParam("token cannot be empty"));
    }

    // Get revocation endpoint from discovery
    let cache = crate::cache::NoOpCache;
    let metadata = discover(issuer, http, &cache).await?;

    let revocation_endpoint = metadata
        .revocation_endpoint
        .as_ref()
        .ok_or_else(|| Error::Discovery("Revocation endpoint not found".to_string()))?;

    // Build form data
    let mut form = vec![
        ("token".to_string(), token.to_string()),
    ];

    if let Some(hint) = token_type_hint {
        form.push(("token_type_hint".to_string(), hint.to_string()));
    }

    // Create request from parameters
    let req = IntrospectRequest {
        issuer: issuer.to_string(),
        client_id: client_id.to_string(),
        client_secret: client_secret.map(|s| s.to_string()),
        token: token.to_string(),
        token_type_hint: token_type_hint.map(|s| s.to_string()),
        token_endpoint_auth_method: token_endpoint_auth_method.map(|s| s.to_string()),
    };

    // Determine authentication method and add auth header if needed
    let auth_method = determine_auth_method(&req, &metadata)?;
    let auth_header = build_auth_header(&req, auth_method)?;

    // Handle client authentication based on method
    match auth_method {
        "client_secret_post" => {
            form.push(("client_id".to_string(), client_id.to_string()));
            if let Some(secret) = client_secret {
                form.push(("client_secret".to_string(), secret.to_string()));
            }
        }
        "none" => {
            form.push(("client_id".to_string(), client_id.to_string()));
        }
        _ => {} // client_secret_basic uses auth header
    }

    // Make the request
    let response = http
        .post_form_value(&revocation_endpoint, &form, auth_header.as_ref().map(|(k, v)| (*k, v.as_str())))
        .await
        .map_err(|e| Error::Network(format!("Revocation request failed: {}", e)))?;

    // Check for OAuth error response
    if let Some(error) = response.get("error").and_then(|v| v.as_str()) {
        let error_description = response
            .get("error_description")
            .and_then(|v| v.as_str())
            .unwrap_or("No description");

        // According to RFC 7009, some errors should not prevent revocation
        // from being considered successful (e.g., unsupported_token_type)
        if error != "unsupported_token_type" {
            return Err(Error::OAuth {
                error: error.to_string(),
                description: Some(error_description.to_string()),
            });
        }
    }

    tracing::info!(
        target: "xjp_oidc::introspect",
        "Token revocation 完成"
    );

    Ok(())
}

/// Determine the authentication method to use
#[cfg(not(target_arch = "wasm32"))]
fn determine_auth_method(
    req: &IntrospectRequest,
    metadata: &crate::types::OidcProviderMetadata,
) -> Result<&'static str> {
    // If explicitly specified, use that
    if let Some(method) = &req.token_endpoint_auth_method {
        return Ok(match method.as_str() {
            "client_secret_basic" => "client_secret_basic",
            "client_secret_post" => "client_secret_post",
            "none" => "none",
            _ => return Err(Error::InvalidParam("Unsupported auth method")),
        });
    }

    // Check if client has a secret
    let has_secret = req.client_secret.is_some();

    // Get supported methods from metadata
    let supported_methods = metadata
        .token_endpoint_auth_methods_supported
        .as_ref();

    // Determine based on client type and supported methods
    if has_secret {
        // Default to client_secret_basic if no methods specified
        if supported_methods.is_none() {
            return Ok("client_secret_basic");
        }
        
        let methods = supported_methods.unwrap();
        if methods.iter().any(|m| m == "client_secret_basic") {
            Ok("client_secret_basic")
        } else if methods.iter().any(|m| m == "client_secret_post") {
            Ok("client_secret_post")
        } else {
            Err(Error::InvalidParam("No supported auth method for confidential client"))
        }
    } else {
        // For public clients, check if 'none' is supported
        if let Some(methods) = supported_methods {
            if methods.iter().any(|m| m == "none") {
                Ok("none")
            } else {
                Err(Error::InvalidParam("No supported auth method for public client"))
            }
        } else {
            // Default to 'none' for public clients if no methods specified
            Ok("none")
        }
    }
}

/// Build authorization header for client authentication
#[cfg(not(target_arch = "wasm32"))]
fn build_auth_header(req: &IntrospectRequest, auth_method: &str) -> Result<Option<(&'static str, String)>> {
    match auth_method {
        "client_secret_basic" => {
            if let Some(secret) = &req.client_secret {
                let credentials = format!("{}:{}", req.client_id, secret);
                let encoded = general_purpose::STANDARD.encode(credentials);
                Ok(Some(("Authorization", format!("Basic {}", encoded))))
            } else {
                Err(Error::InvalidParam("client_secret required for basic auth"))
            }
        }
        _ => Ok(None),
    }
}

// WASM stub implementations
#[cfg(target_arch = "wasm32")]
use crate::{
    errors::{Error, Result},
    http::HttpClient,
    types::{IntrospectRequest, IntrospectResponse},
};

#[cfg(target_arch = "wasm32")]
pub async fn introspect_token(
    _req: IntrospectRequest,
    _http: &dyn HttpClient,
) -> Result<IntrospectResponse> {
    Err(Error::ServerOnly("Token introspection"))
}

#[cfg(target_arch = "wasm32")]
pub async fn revoke_token(
    _issuer: &str,
    _client_id: &str,
    _client_secret: Option<&str>,
    _token: &str,
    _token_type_hint: Option<&str>,
    _token_endpoint_auth_method: Option<&str>,
    _http: &dyn HttpClient,
) -> Result<()> {
    Err(Error::ServerOnly("Token revocation"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_introspect_response_parsing() {
        let json = serde_json::json!({
            "active": true,
            "scope": "openid profile email",
            "client_id": "test-client",
            "username": "test-user",
            "token_type": "Bearer",
            "exp": 1234567890,
            "iat": 1234567800,
            "sub": "user-123",
            "aud": ["https://api.example.com"],
            "iss": "https://auth.example.com"
        });

        let response: IntrospectResponse = serde_json::from_value(json).unwrap();
        assert!(response.active);
        assert_eq!(response.scope, Some("openid profile email".to_string()));
        assert_eq!(response.client_id, Some("test-client".to_string()));
        assert_eq!(response.username, Some("test-user".to_string()));
        assert_eq!(response.exp, Some(1234567890));
    }

    #[test]
    fn test_inactive_token_response() {
        let json = serde_json::json!({
            "active": false
        });

        let response: IntrospectResponse = serde_json::from_value(json).unwrap();
        assert!(!response.active);
        assert!(response.scope.is_none());
        assert!(response.client_id.is_none());
    }
}