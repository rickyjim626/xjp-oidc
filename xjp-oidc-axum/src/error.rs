//! Error types for Axum integration

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

/// Authentication/Authorization errors
#[derive(Error, Debug)]
pub enum AuthError {
    /// Missing Authorization header
    #[error("missing authorization header")]
    MissingAuthHeader,

    /// Invalid Authorization header format
    #[error("invalid authorization header format")]
    InvalidAuthFormat,

    /// Token verification failed
    #[error("token verification failed: {0}")]
    TokenVerificationFailed(#[from] xjp_oidc::Error),

    /// Insufficient permissions (403)
    #[error("insufficient permissions")]
    InsufficientPermissions,

    /// Admin access required
    #[error("admin access required")]
    AdminRequired,

    /// Recent login required (step-up auth)
    #[error("recent login required")]
    RecentLoginRequired,
}

/// Error response body
#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
    error_description: String,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_code, auth_header) = match &self {
            Self::MissingAuthHeader | Self::InvalidAuthFormat => {
                (StatusCode::UNAUTHORIZED, "invalid_request", Some("Bearer"))
            }
            Self::TokenVerificationFailed(_) => {
                (StatusCode::UNAUTHORIZED, "invalid_token", Some("Bearer"))
            }
            Self::InsufficientPermissions | Self::AdminRequired => {
                (StatusCode::FORBIDDEN, "insufficient_scope", None)
            }
            Self::RecentLoginRequired => (
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                Some(r#"Bearer error="invalid_token", error_description="Recent login required""#),
            ),
        };

        let mut response = (
            status,
            Json(ErrorResponse {
                error: error_code,
                error_description: self.to_string(),
            }),
        )
            .into_response();

        // Add WWW-Authenticate header for 401 responses
        if let Some(auth_value) = auth_header {
            response
                .headers_mut()
                .insert("WWW-Authenticate", auth_value.parse().unwrap());
        }

        response
    }
}