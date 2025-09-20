//! Authorization code exchange implementation (server-only)

#[cfg(not(target_arch = "wasm32"))]
use crate::{
    discovery::discover,
    errors::{Error, Result},
    http::HttpClient,
    types::{ExchangeCode, TokenResponse},
};
#[cfg(not(target_arch = "wasm32"))]
use base64::{Engine as _, engine::general_purpose};

/// Exchange authorization code for tokens
///
/// This is a server-only function that exchanges an authorization code
/// for access token, refresh token (optional), and ID token (if openid scope).
///
/// # Example
/// ```no_run
/// # #[cfg(not(target_arch = "wasm32"))]
/// # use xjp_oidc::{exchange_code, ExchangeCode, http::ReqwestHttpClient};
/// # #[cfg(not(target_arch = "wasm32"))]
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let http = ReqwestHttpClient::default();
///
/// let tokens = exchange_code(ExchangeCode {
///     issuer: "https://auth.example.com".into(),
///     client_id: "my-client".into(),
///     code: "auth_code".into(),
///     redirect_uri: "https://app.example.com/callback".into(),
///     code_verifier: "pkce_verifier".into(),
///     client_secret: None, // For public clients
/// }, &http).await?;
/// # Ok(())
/// # }
/// ```
#[cfg(not(target_arch = "wasm32"))]
pub async fn exchange_code(
    params: ExchangeCode,
    http: &dyn HttpClient,
) -> Result<TokenResponse> {
    // Validate parameters
    validate_exchange_params(&params)?;

    // Get token endpoint from discovery
    let cache = crate::cache::NoOpCache;
    let metadata = discover(&params.issuer, http, &cache).await?;

    // Build form data
    let mut form = vec![
        ("grant_type".to_string(), "authorization_code".to_string()),
        ("code".to_string(), params.code.clone()),
        ("redirect_uri".to_string(), params.redirect_uri.clone()),
        ("code_verifier".to_string(), params.code_verifier.clone()),
    ];

    // Determine authentication method
    let auth_header = if let Some(client_secret) = &params.client_secret {
        // Use client_secret_basic by default
        let credentials = format!("{}:{}", params.client_id, client_secret);
        let encoded = general_purpose::STANDARD.encode(credentials.as_bytes());
        Some(("Authorization".to_string(), format!("Basic {}", encoded)))
    } else {
        // Public client - include client_id in form
        form.push(("client_id".to_string(), params.client_id.clone()));
        None
    };

    // Make the token request
    let response = http
        .post_form_value(&metadata.token_endpoint, &form, auth_header.as_ref().map(|(k, v)| (k.as_str(), v.as_str())))
        .await
        .map_err(|e| {
            // Try to parse OAuth error from response
            if let crate::http::HttpClientError::InvalidStatus { status: _, message } = &e {
                if let Ok(oauth_error) = serde_json::from_str::<OAuthError>(&message) {
                    return Error::oauth(oauth_error.error, oauth_error.error_description);
                }
            }
            Error::Network(format!("Token exchange failed: {}", e))
        })?;

    // Parse token response
    let tokens: TokenResponse = serde_json::from_value(response)?;

    Ok(tokens)
}

/// Validate exchange parameters
#[cfg(not(target_arch = "wasm32"))]
fn validate_exchange_params(params: &ExchangeCode) -> Result<()> {
    if params.issuer.is_empty() {
        return Err(Error::InvalidParam("issuer cannot be empty"));
    }
    if params.client_id.is_empty() {
        return Err(Error::InvalidParam("client_id cannot be empty"));
    }
    if params.code.is_empty() {
        return Err(Error::InvalidParam("code cannot be empty"));
    }
    if params.redirect_uri.is_empty() {
        return Err(Error::InvalidParam("redirect_uri cannot be empty"));
    }
    if params.code_verifier.is_empty() {
        return Err(Error::InvalidParam("code_verifier cannot be empty"));
    }
    Ok(())
}

/// OAuth error response
#[cfg(not(target_arch = "wasm32"))]
#[derive(serde::Deserialize)]
struct OAuthError {
    error: String,
    error_description: Option<String>,
}

/// Exchange code with explicit token endpoint
#[cfg(not(target_arch = "wasm32"))]
#[allow(dead_code)]
pub async fn exchange_code_with_endpoint(
    params: ExchangeCode,
    token_endpoint: &str,
    http: &dyn HttpClient,
) -> Result<TokenResponse> {
    // Validate parameters
    validate_exchange_params(&params)?;

    // Build form data
    let mut form = vec![
        ("grant_type".to_string(), "authorization_code".to_string()),
        ("code".to_string(), params.code.clone()),
        ("redirect_uri".to_string(), params.redirect_uri.clone()),
        ("code_verifier".to_string(), params.code_verifier.clone()),
    ];

    // Determine authentication method
    let auth_header = if let Some(client_secret) = &params.client_secret {
        // Check if we should use client_secret_post instead
        if should_use_client_secret_post(&params.client_id) {
            form.push(("client_id".to_string(), params.client_id.clone()));
            form.push(("client_secret".to_string(), client_secret.clone()));
            None
        } else {
            // Use client_secret_basic
            let credentials = format!("{}:{}", params.client_id, client_secret);
            let encoded = general_purpose::STANDARD.encode(credentials.as_bytes());
            Some(("Authorization".to_string(), format!("Basic {}", encoded)))
        }
    } else {
        // Public client
        form.push(("client_id".to_string(), params.client_id.clone()));
        None
    };

    // Make the token request
    let response = http
        .post_form_value(token_endpoint, &form, auth_header.as_ref().map(|(k, v)| (k.as_str(), v.as_str())))
        .await
        .map_err(|e| {
            // Try to parse OAuth error from response
            if let crate::http::HttpClientError::InvalidStatus { status: _, message } = &e {
                if let Ok(oauth_error) = serde_json::from_str::<OAuthError>(&message) {
                    return Error::oauth(oauth_error.error, oauth_error.error_description);
                }
            }
            Error::Network(format!("Token exchange failed: {}", e))
        })?;

    // Parse token response
    let tokens: TokenResponse = serde_json::from_value(response)?;

    Ok(tokens)
}

/// Determine if client should use client_secret_post
/// This is a placeholder - in real usage, this would be determined
/// from discovery metadata or client configuration
#[cfg(not(target_arch = "wasm32"))]
#[allow(dead_code)]
fn should_use_client_secret_post(_client_id: &str) -> bool {
    // Default to client_secret_basic
    false
}

// WASM stub
#[cfg(target_arch = "wasm32")]
pub async fn exchange_code(
    _params: crate::types::ExchangeCode,
    _http: &dyn crate::http::HttpClient,
) -> crate::errors::Result<crate::types::TokenResponse> {
    Err(crate::errors::Error::ServerOnly)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn test_validate_exchange_params() {
        let valid = ExchangeCode {
            issuer: "https://auth.example.com".into(),
            client_id: "test-client".into(),
            code: "auth_code".into(),
            redirect_uri: "https://app.example.com/callback".into(),
            code_verifier: "verifier".into(),
            client_secret: None,
        };
        assert!(validate_exchange_params(&valid).is_ok());

        let invalid = ExchangeCode {
            issuer: "".into(),
            ..valid.clone()
        };
        assert!(validate_exchange_params(&invalid).is_err());
    }
}