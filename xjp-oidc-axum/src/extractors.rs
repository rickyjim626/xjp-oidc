//! Request extractors for verified claims

use crate::error::AuthError;
use async_trait::async_trait;
use axum::{
    extract::FromRequestParts,
    http::request::Parts,
};
use std::ops::Deref;

/// Extension key for storing verified claims
#[derive(Clone)]
pub(crate) struct ClaimsExtension(pub xjp_oidc::VerifiedClaims);

/// Extractor for verified JWT claims
///
/// This extractor requires the `OidcLayer` middleware to be applied
/// to the route or router.
///
/// # Example
///
/// ```no_run
/// use axum::routing::get;
/// use xjp_oidc_axum::VerifiedClaims;
///
/// async fn handler(claims: VerifiedClaims) -> String {
///     format!("Hello, {}", claims.sub)
/// }
/// ```
#[derive(Debug, Clone)]
pub struct VerifiedClaims(pub xjp_oidc::VerifiedClaims);

impl Deref for VerifiedClaims {
    type Target = xjp_oidc::VerifiedClaims;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for VerifiedClaims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<ClaimsExtension>()
            .map(|ext| VerifiedClaims(ext.0.clone()))
            .ok_or(AuthError::MissingAuthHeader)
    }
}

/// Extractor for admin-only endpoints
///
/// This extractor requires both the `OidcLayer` middleware and
/// verifies that `xjp_admin` claim is `true`.
///
/// # Example
///
/// ```no_run
/// use axum::routing::post;
/// use xjp_oidc_axum::AdminClaims;
///
/// async fn admin_handler(admin: AdminClaims) -> &'static str {
///     "Admin action performed"
/// }
/// ```
#[derive(Debug, Clone)]
pub struct AdminClaims(pub xjp_oidc::VerifiedClaims);

impl Deref for AdminClaims {
    type Target = xjp_oidc::VerifiedClaims;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for AdminClaims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let claims = parts
            .extensions
            .get::<ClaimsExtension>()
            .map(|ext| ext.0.clone())
            .ok_or(AuthError::MissingAuthHeader)?;

        // Check xjp_admin claim
        if !claims.xjp_admin.unwrap_or(false) {
            return Err(AuthError::AdminRequired);
        }

        Ok(AdminClaims(claims))
    }
}

/// Optional extractor wrapper for verified claims
///
/// Returns `None` if no valid token is present instead of rejecting the request.
///
/// # Example
///
/// ```no_run
/// use axum::routing::get;
/// use xjp_oidc_axum::OptionalClaims;
///
/// async fn handler(claims: OptionalClaims) -> String {
///     match claims.0 {
///         Some(claims) => format!("Hello, {}", claims.sub),
///         None => "Hello, anonymous".to_string(),
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct OptionalClaims(pub Option<xjp_oidc::VerifiedClaims>);

impl Deref for OptionalClaims {
    type Target = Option<xjp_oidc::VerifiedClaims>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for OptionalClaims
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(OptionalClaims(
            parts
                .extensions
                .get::<ClaimsExtension>()
                .map(|ext| ext.0.clone())
        ))
    }
}