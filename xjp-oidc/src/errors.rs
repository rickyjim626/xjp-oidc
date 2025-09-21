//! Error types for xjp-oidc SDK

use thiserror::Error;

/// Main error type for the xjp-oidc SDK
#[derive(Error, Debug)]
pub enum Error {
    /// Network-related errors
    #[error("network error: {0}")]
    Network(String),

    /// Discovery endpoint errors
    #[error("discovery error: {0}")]
    Discovery(String),

    /// JWKS endpoint errors  
    #[error("jwks error: {0}")]
    Jwks(String),

    /// Token verification failures
    #[error("verification failed: {0}")]
    Verification(String),

    /// OAuth/OIDC protocol errors from the server
    #[error("oauth error: {error} - {description:?}")]
    OAuth {
        /// Error code as per RFC 6749
        error: String,
        /// Human-readable error description
        description: Option<String>,
    },

    /// Invalid parameter provided to a function
    #[error("invalid parameter: {0}")]
    InvalidParam(&'static str),

    /// Attempt to use server-only function in browser/WASM environment
    #[error("server-only function called in browser")]
    ServerOnly,

    /// Recent login required (step-up authentication needed)
    #[error("recent login required")]
    RequireRecentLogin,

    /// Operation timed out
    #[error("timeout")]
    Timeout,

    /// HTTP client errors
    #[error("http client error: {0}")]
    HttpClient(#[from] crate::http::HttpClientError),

    /// JSON parsing errors
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// URL parsing errors
    #[error("url parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    /// Base64 decoding errors
    #[error("base64 decode error: {0}")]
    Base64(String),

    /// JWT/JWS errors
    #[error("jwt error: {0}")]
    Jwt(String),

    /// Cache-related errors
    #[error("cache error: {0}")]
    Cache(String),

    /// Missing required configuration
    #[error("missing configuration: {0}")]
    MissingConfig(&'static str),

    /// Invalid state during operation
    #[error("invalid state: {0}")]
    InvalidState(String),
}

impl Error {
    /// Create an OAuth error from server response
    pub fn oauth(error: impl Into<String>, description: Option<String>) -> Self {
        Self::OAuth { error: error.into(), description }
    }

    /// Check if this is a specific OAuth error code
    pub fn is_oauth_error(&self, code: &str) -> bool {
        matches!(self, Self::OAuth { error, .. } if error == code)
    }

    /// Check if this error indicates that recent login is required
    pub fn requires_recent_login(&self) -> bool {
        matches!(self, Self::RequireRecentLogin)
            || self.is_oauth_error("login_required")
            || self.is_oauth_error("interaction_required")
    }

    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Network(_) | Self::Timeout | Self::Discovery(_) | Self::Jwks(_))
    }
}

/// Result type alias for operations that may fail with Error
pub type Result<T> = std::result::Result<T, Error>;
