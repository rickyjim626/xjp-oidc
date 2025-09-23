//! UserInfo endpoint implementation

use crate::{
    discovery::discover,
    errors::{Error, Result},
    http::HttpClient,
    types::UserInfo,
};
use serde_json::json;

/// Get user information from the UserInfo endpoint
///
/// This function retrieves user information using an access token.
/// According to OIDC spec, the UserInfo endpoint supports both GET and POST methods.
/// Due to current HttpClient trait limitations, this implementation uses POST.
///
/// # Example
/// ```no_run
/// # use xjp_oidc::{get_userinfo, http::ReqwestHttpClient};
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let http = ReqwestHttpClient::default();
///
/// let userinfo = get_userinfo(
///     "https://auth.example.com",
///     "access_token_here",
///     &http
/// ).await?;
///
/// println!("User: {} ({})", userinfo.name.unwrap_or_default(), userinfo.sub);
/// # Ok(())
/// # }
/// ```
#[tracing::instrument(
    name = "oidc_get_userinfo",
    skip(access_token, http),
    fields(issuer = %issuer)
)]
pub async fn get_userinfo(
    issuer: &str,
    access_token: &str,
    http: &dyn HttpClient,
) -> Result<UserInfo> {
    tracing::info!(
        target: "xjp_oidc::userinfo",
        "开始获取 UserInfo"
    );

    // Validate parameters
    if issuer.is_empty() {
        return Err(Error::InvalidParam("issuer cannot be empty"));
    }
    if access_token.is_empty() {
        return Err(Error::InvalidParam("access_token cannot be empty"));
    }

    // Get userinfo endpoint from discovery
    let cache = crate::cache::NoOpCache;
    let metadata = discover(issuer, http, &cache).await?;

    let userinfo_endpoint = metadata
        .userinfo_endpoint
        .ok_or_else(|| Error::Discovery("UserInfo endpoint not found".to_string()))?;

    // Make the request with Bearer token
    // Note: Due to HttpClient trait limitations, we use POST with empty body
    // instead of GET. OIDC spec allows both methods.
    let auth_header = ("Authorization", format!("Bearer {}", access_token));
    let empty_body = json!({});

    let response = http
        .post_json_value(&userinfo_endpoint, &empty_body, Some((auth_header.0, auth_header.1.as_str())))
        .await
        .map_err(|e| {
            // Handle specific error cases
            if let crate::http::HttpClientError::InvalidStatus { status, message: _ } = &e {
                match *status {
                    401 => return Error::OAuth {
                        error: "unauthorized".to_string(),
                        description: Some("Invalid or expired access token".to_string()),
                    },
                    403 => return Error::OAuth {
                        error: "forbidden".to_string(),
                        description: Some("Access token does not have required scopes".to_string()),
                    },
                    405 => {
                        // Method Not Allowed - server might only support GET
                        return Error::Network(
                            "UserInfo endpoint does not support POST method. \
                            This SDK currently requires POST support due to HttpClient trait limitations."
                                .to_string(),
                        );
                    }
                    _ => {}
                }
            }
            Error::Network(format!("UserInfo request failed: {}", e))
        })?;

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
    let userinfo: UserInfo = serde_json::from_value(response)
        .map_err(|e| Error::Verification(format!("Failed to parse UserInfo response: {}", e)))?;

    // Validate that we at least got a subject
    if userinfo.sub.is_empty() {
        return Err(Error::Verification("UserInfo response missing required 'sub' field".to_string()));
    }

    tracing::info!(
        target: "xjp_oidc::userinfo",
        "UserInfo 获取成功, sub: {}",
        userinfo.sub
    );

    Ok(userinfo)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_userinfo_parsing() {
        let json = serde_json::json!({
            "sub": "123456",
            "name": "Test User",
            "given_name": "Test",
            "family_name": "User",
            "preferred_username": "testuser",
            "email": "test@example.com",
            "email_verified": true,
            "picture": "https://example.com/photo.jpg",
            "locale": "en-US",
            "updated_at": 1234567890,
            "xjp_admin": true,
            "amr": ["pwd", "mfa"],
            "auth_time": 1234567800
        });

        let userinfo: UserInfo = serde_json::from_value(json).unwrap();
        assert_eq!(userinfo.sub, "123456");
        assert_eq!(userinfo.name, Some("Test User".to_string()));
        assert_eq!(userinfo.email, Some("test@example.com".to_string()));
        assert_eq!(userinfo.email_verified, Some(true));
        assert_eq!(userinfo.xjp_admin, Some(true));
        assert_eq!(userinfo.amr, Some(vec!["pwd".to_string(), "mfa".to_string()]));
    }

    #[test]
    fn test_minimal_userinfo() {
        let json = serde_json::json!({
            "sub": "user-123"
        });

        let userinfo: UserInfo = serde_json::from_value(json).unwrap();
        assert_eq!(userinfo.sub, "user-123");
        assert!(userinfo.name.is_none());
        assert!(userinfo.email.is_none());
    }
}