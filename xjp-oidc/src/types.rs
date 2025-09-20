//! Public types for the xjp-oidc SDK

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// OAuth2/OIDC Provider metadata from discovery endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcProviderMetadata {
    /// Issuer identifier
    pub issuer: String,
    /// Authorization endpoint URL
    pub authorization_endpoint: String,
    /// Token endpoint URL
    pub token_endpoint: String,
    /// JWKS URI for key discovery
    pub jwks_uri: String,
    /// UserInfo endpoint URL (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<String>,
    /// End session endpoint URL (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_session_endpoint: Option<String>,
    /// Registration endpoint URL (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    /// Supported response types
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_types_supported: Option<Vec<String>>,
    /// Supported grant types
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types_supported: Option<Vec<String>>,
    /// Supported scopes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    /// Supported token endpoint auth methods
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// Supported ID token signing algorithms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,
    /// PKCE code challenge methods supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<String>>,
}

/// Token response from token endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    /// Access token for API calls
    pub access_token: String,
    /// Token type (typically "Bearer")
    pub token_type: String,
    /// Token lifetime in seconds
    pub expires_in: i64,
    /// Refresh token (if offline_access scope granted)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Granted scopes space-delimited
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// ID token (if openid scope granted)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

/// Verified ID Token with parsed claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedIdToken {
    // Standard OIDC claims
    /// Issuer
    pub iss: String,
    /// Subject (user ID)
    pub sub: String,
    /// Audience
    pub aud: String,
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    /// Issued at time (Unix timestamp)
    pub iat: i64,
    /// Nonce (if provided)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Session ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    
    // Profile claims
    /// User's full name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// User's email
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// User's picture URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    
    // Custom claims
    /// Authentication methods reference (e.g., ["wechat_qr"])
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    /// Authentication time (Unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    /// Admin flag for XiaojinPro admin users
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xjp_admin: Option<bool>,
}

/// Parameters for building authorization URL
#[derive(Debug, Clone, Default)]
pub struct BuildAuthUrl {
    /// Issuer URL
    pub issuer: String,
    /// Client ID
    pub client_id: String,
    /// Redirect URI
    pub redirect_uri: String,
    /// Requested scopes (space-separated)
    pub scope: String,
    /// State parameter (will be auto-generated if not provided)
    pub state: Option<String>,
    /// Nonce for ID token (will be auto-generated if not provided)
    pub nonce: Option<String>,
    /// Prompt parameter (e.g., "login", "consent")
    pub prompt: Option<String>,
    /// PKCE code challenge
    pub code_challenge: String,
    /// Extra query parameters
    pub extra_params: Option<HashMap<String, String>>,
    /// Tenant identifier (for multi-tenant setups)
    pub tenant: Option<String>,
}

/// Parameters for exchanging authorization code
#[derive(Debug, Clone)]
pub struct ExchangeCode {
    /// Issuer URL
    pub issuer: String,
    /// Client ID
    pub client_id: String,
    /// Authorization code
    pub code: String,
    /// Redirect URI (must match the one used in authorization)
    pub redirect_uri: String,
    /// PKCE code verifier
    pub code_verifier: String,
    /// Client secret (for confidential clients)
    pub client_secret: Option<String>,
}

/// Parameters for end session (logout)
#[derive(Debug, Clone, Default)]
pub struct EndSession {
    /// Issuer URL
    pub issuer: String,
    /// ID token hint
    pub id_token_hint: String,
    /// Post-logout redirect URI
    pub post_logout_redirect_uri: Option<String>,
    /// State parameter
    pub state: Option<String>,
}

/// Callback parameters from authorization response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackParams {
    /// Authorization code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// State parameter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Error code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Error description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

/// Dynamic Client Registration request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    /// Application type (web, native)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_type: Option<String>,
    /// Redirect URIs
    pub redirect_uris: Vec<String>,
    /// Post-logout redirect URIs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_logout_redirect_uris: Option<Vec<String>>,
    /// Grant types
    pub grant_types: Vec<String>,
    /// Token endpoint auth method
    pub token_endpoint_auth_method: String,
    /// Requested scopes
    pub scope: String,
    /// Contact emails
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contacts: Option<Vec<String>>,
    /// Software ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_id: Option<String>,
    /// Client name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
}

/// Client registration result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRegistrationResult {
    /// Client ID
    pub client_id: String,
    /// Client secret (for confidential clients)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// Registration status
    pub status: ClientStatus,
    /// Client name
    pub client_name: String,
    /// Redirect URIs
    pub redirect_uris: Vec<String>,
    /// Post-logout redirect URIs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_logout_redirect_uris: Option<Vec<String>>,
    /// Grant types
    pub grant_types: Vec<String>,
    /// Token endpoint auth method
    pub token_endpoint_auth_method: String,
    /// Allowed scopes
    pub scope: String,
}

/// Client registration status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ClientStatus {
    /// Client is active and can be used
    Active,
    /// Client is pending approval
    Pending,
    /// Client is suspended
    Suspended,
}

/// Verified claims from access token (for Resource Server)
#[cfg(feature = "verifier")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedClaims {
    /// Issuer
    pub iss: String,
    /// Subject
    pub sub: String,
    /// Audience
    pub aud: String,
    /// Expiration
    pub exp: i64,
    /// Issued at
    pub iat: i64,
    /// JWT ID
    pub jti: String,
    /// Scopes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Admin flag
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xjp_admin: Option<bool>,
    /// Authentication methods
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    /// Authentication time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
}

/// Options for verifying ID tokens
#[derive(Clone)]
pub struct VerifyOptions<'a> {
    /// Expected issuer
    pub issuer: &'a str,
    /// Expected audience
    pub audience: &'a str,
    /// Expected nonce (if any)
    pub nonce: Option<&'a str>,
    /// Maximum age in seconds (for auth_time validation)
    pub max_age_sec: Option<i64>,
    /// Clock skew tolerance in seconds
    pub clock_skew_sec: Option<i64>,
    /// HTTP client for fetching JWKS
    pub http: &'a dyn crate::http::HttpClient,
    /// Cache for JWKS
    pub cache: &'a dyn crate::cache::Cache<String, crate::jwks::Jwks>,
}

impl Default for VerifyOptions<'_> {
    fn default() -> Self {
        panic!("VerifyOptions requires explicit construction with required fields")
    }
}