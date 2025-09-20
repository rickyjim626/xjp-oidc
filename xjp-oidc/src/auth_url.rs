//! Authorization URL building and callback parsing

use crate::{
    errors::{Error, Result},
    types::{BuildAuthUrl, CallbackParams, EndSession, OidcProviderMetadata},
};
use rand::{distributions::Alphanumeric, Rng};
use url::Url;
#[cfg(test)]
use std::collections::HashMap;

/// Build an authorization URL for the OAuth2/OIDC flow
///
/// # Example
/// ```no_run
/// use xjp_oidc::{build_auth_url, BuildAuthUrl};
///
/// let url = build_auth_url(BuildAuthUrl {
///     issuer: "https://auth.example.com".into(),
///     client_id: "my-client".into(),
///     redirect_uri: "https://app.example.com/callback".into(),
///     scope: "openid profile email".into(),
///     code_challenge: "challenge".into(),
///     ..Default::default()
/// }).unwrap();
/// ```
pub fn build_auth_url(params: BuildAuthUrl) -> Result<Url> {
    // Validate required parameters
    if params.issuer.is_empty() {
        return Err(Error::InvalidParam("issuer cannot be empty"));
    }
    if params.client_id.is_empty() {
        return Err(Error::InvalidParam("client_id cannot be empty"));
    }
    if params.redirect_uri.is_empty() {
        return Err(Error::InvalidParam("redirect_uri cannot be empty"));
    }
    if params.code_challenge.is_empty() {
        return Err(Error::InvalidParam("code_challenge cannot be empty"));
    }

    // Build authorization endpoint URL
    let auth_endpoint = if params.issuer.ends_with('/') {
        format!("{}oauth/authorize", params.issuer)
    } else {
        format!("{}/oauth/authorize", params.issuer)
    };

    let mut url = Url::parse(&auth_endpoint)?;

    // Add query parameters
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("response_type", "code");
        query.append_pair("client_id", &params.client_id);
        query.append_pair("redirect_uri", &params.redirect_uri);

        // Scope
        let scope = if params.scope.is_empty() {
            "openid profile email"
        } else {
            &params.scope
        };
        query.append_pair("scope", scope);

        // State (generate if not provided)
        let state = params.state.unwrap_or_else(generate_state);
        query.append_pair("state", &state);

        // PKCE
        query.append_pair("code_challenge", &params.code_challenge);
        query.append_pair("code_challenge_method", "S256");

        // Nonce (generate if not provided and openid scope is requested)
        if scope.contains("openid") {
            let nonce = params.nonce.unwrap_or_else(generate_nonce);
            query.append_pair("nonce", &nonce);
        }

        // Prompt (optional)
        if let Some(prompt) = &params.prompt {
            query.append_pair("prompt", prompt);
        }

        // Tenant (optional)
        if let Some(tenant) = &params.tenant {
            query.append_pair("tenant", tenant);
        }

        // Extra parameters
        if let Some(extra) = &params.extra_params {
            for (key, value) in extra {
                query.append_pair(key, value);
            }
        }
    }

    Ok(url)
}

/// Build an end session (logout) URL
///
/// # Example
/// ```no_run
/// use xjp_oidc::{build_end_session_url, EndSession};
///
/// let url = build_end_session_url(EndSession {
///     issuer: "https://auth.example.com".into(),
///     id_token_hint: "id_token_here".into(),
///     post_logout_redirect_uri: Some("https://app.example.com".into()),
///     state: None,
/// }).unwrap();
/// ```
pub fn build_end_session_url(params: EndSession) -> Result<Url> {
    // Validate required parameters
    if params.issuer.is_empty() {
        return Err(Error::InvalidParam("issuer cannot be empty"));
    }
    if params.id_token_hint.is_empty() {
        return Err(Error::InvalidParam("id_token_hint cannot be empty"));
    }

    // Build end session endpoint URL
    let end_session_endpoint = if params.issuer.ends_with('/') {
        format!("{}oidc/end_session", params.issuer)
    } else {
        format!("{}/oidc/end_session", params.issuer)
    };

    let mut url = Url::parse(&end_session_endpoint)?;

    // Add query parameters
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("id_token_hint", &params.id_token_hint);

        if let Some(redirect_uri) = &params.post_logout_redirect_uri {
            query.append_pair("post_logout_redirect_uri", redirect_uri);
        }

        if let Some(state) = &params.state {
            query.append_pair("state", state);
        }
    }

    Ok(url)
}

/// Parse callback parameters from the authorization response
///
/// # Example
/// ```
/// use xjp_oidc::parse_callback_params;
///
/// let params = parse_callback_params("https://app.example.com/callback?code=abc&state=xyz");
/// assert_eq!(params.code, Some("abc".to_string()));
/// assert_eq!(params.state, Some("xyz".to_string()));
/// ```
pub fn parse_callback_params(url: &str) -> CallbackParams {
    let mut params = CallbackParams {
        code: None,
        state: None,
        error: None,
        error_description: None,
    };

    // Parse URL and extract query parameters
    if let Ok(parsed_url) = Url::parse(url) {
        for (key, value) in parsed_url.query_pairs() {
            match key.as_ref() {
                "code" => params.code = Some(value.into_owned()),
                "state" => params.state = Some(value.into_owned()),
                "error" => params.error = Some(value.into_owned()),
                "error_description" => params.error_description = Some(value.into_owned()),
                _ => {} // Ignore other parameters
            }
        }
    } else {
        // Try to parse as relative URL (e.g., "/callback?code=...")
        // or as a query string only (e.g., "code=test&state=state123")
        let query = if let Some(query_start) = url.find('?') {
            &url[query_start + 1..]
        } else if url.contains('=') {
            // Assume it's a query string without URL prefix
            url
        } else {
            ""
        };
        
        if !query.is_empty() {
            for pair in query.split('&') {
                if let Some(eq_pos) = pair.find('=') {
                    let key = &pair[..eq_pos];
                    let value = &pair[eq_pos + 1..];
                    let decoded_value = urlencoding::decode(value).unwrap_or_else(|_| value.into());
                    
                    match key {
                        "code" => params.code = Some(decoded_value.into_owned()),
                        "state" => params.state = Some(decoded_value.into_owned()),
                        "error" => params.error = Some(decoded_value.into_owned()),
                        "error_description" => params.error_description = Some(decoded_value.into_owned()),
                        _ => {} // Ignore other parameters
                    }
                }
            }
        }
    }

    params
}

/// Build authorization URL from provider metadata
#[allow(dead_code)]
pub fn build_auth_url_with_metadata(
    metadata: &OidcProviderMetadata,
    params: BuildAuthUrl,
) -> Result<Url> {
    let mut url = Url::parse(&metadata.authorization_endpoint)?;

    // Add query parameters
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("response_type", "code");
        query.append_pair("client_id", &params.client_id);
        query.append_pair("redirect_uri", &params.redirect_uri);
        query.append_pair("scope", &params.scope);

        // State (generate if not provided)
        let state = params.state.unwrap_or_else(generate_state);
        query.append_pair("state", &state);

        // PKCE
        query.append_pair("code_challenge", &params.code_challenge);
        query.append_pair("code_challenge_method", "S256");

        // Nonce for OIDC
        if params.scope.contains("openid") {
            let nonce = params.nonce.unwrap_or_else(generate_nonce);
            query.append_pair("nonce", &nonce);
        }

        // Optional parameters
        if let Some(prompt) = &params.prompt {
            query.append_pair("prompt", prompt);
        }

        if let Some(tenant) = &params.tenant {
            query.append_pair("tenant", tenant);
        }

        // Extra parameters
        if let Some(extra) = &params.extra_params {
            for (key, value) in extra {
                query.append_pair(key, value);
            }
        }
    }

    Ok(url)
}

/// Generate a random state parameter
fn generate_state() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

/// Generate a random nonce
fn generate_nonce() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_auth_url() {
        let url = build_auth_url(BuildAuthUrl {
            issuer: "https://auth.example.com".into(),
            client_id: "test-client".into(),
            redirect_uri: "https://app.example.com/callback".into(),
            scope: "openid profile".into(),
            code_challenge: "test_challenge".into(),
            state: Some("test_state".into()),
            nonce: Some("test_nonce".into()),
            prompt: None,
            extra_params: None,
            tenant: None,
        })
        .unwrap();

        let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
        
        assert_eq!(query.get("response_type"), Some(&"code".to_string()));
        assert_eq!(query.get("client_id"), Some(&"test-client".to_string()));
        assert_eq!(query.get("redirect_uri"), Some(&"https://app.example.com/callback".to_string()));
        assert_eq!(query.get("scope"), Some(&"openid profile".to_string()));
        assert_eq!(query.get("state"), Some(&"test_state".to_string()));
        assert_eq!(query.get("nonce"), Some(&"test_nonce".to_string()));
        assert_eq!(query.get("code_challenge"), Some(&"test_challenge".to_string()));
        assert_eq!(query.get("code_challenge_method"), Some(&"S256".to_string()));
    }

    #[test]
    fn test_build_auth_url_auto_state_nonce() {
        let url = build_auth_url(BuildAuthUrl {
            issuer: "https://auth.example.com".into(),
            client_id: "test-client".into(),
            redirect_uri: "https://app.example.com/callback".into(),
            scope: "openid profile".into(),
            code_challenge: "test_challenge".into(),
            state: None,
            nonce: None,
            prompt: None,
            extra_params: None,
            tenant: None,
        })
        .unwrap();

        let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
        
        // State and nonce should be auto-generated
        assert!(query.contains_key("state"));
        assert!(query.contains_key("nonce"));
        assert_eq!(query.get("state").unwrap().len(), 32);
        assert_eq!(query.get("nonce").unwrap().len(), 32);
    }

    #[test]
    fn test_parse_callback_params() {
        let params = parse_callback_params(
            "https://app.example.com/callback?code=abc123&state=xyz456"
        );
        
        assert_eq!(params.code, Some("abc123".to_string()));
        assert_eq!(params.state, Some("xyz456".to_string()));
        assert_eq!(params.error, None);
        assert_eq!(params.error_description, None);
    }

    #[test]
    fn test_parse_callback_params_error() {
        let params = parse_callback_params(
            "https://app.example.com/callback?error=access_denied&error_description=User%20denied%20access"
        );
        
        assert_eq!(params.code, None);
        assert_eq!(params.state, None);
        assert_eq!(params.error, Some("access_denied".to_string()));
        assert_eq!(params.error_description, Some("User denied access".to_string()));
    }

    #[test]
    fn test_parse_callback_params_relative_url() {
        let params = parse_callback_params("/callback?code=test&state=test");
        
        assert_eq!(params.code, Some("test".to_string()));
        assert_eq!(params.state, Some("test".to_string()));
    }

    #[test]
    fn test_build_end_session_url() {
        let url = build_end_session_url(EndSession {
            issuer: "https://auth.example.com".into(),
            id_token_hint: "test_token".into(),
            post_logout_redirect_uri: Some("https://app.example.com".into()),
            state: Some("logout_state".into()),
        })
        .unwrap();

        let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
        
        assert_eq!(query.get("id_token_hint"), Some(&"test_token".to_string()));
        assert_eq!(query.get("post_logout_redirect_uri"), Some(&"https://app.example.com".to_string()));
        assert_eq!(query.get("state"), Some(&"logout_state".to_string()));
    }
}