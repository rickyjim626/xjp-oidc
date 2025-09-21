//! Middleware layers for OIDC authentication

use crate::{error::AuthError, extractors::ClaimsExtension};
use axum::{
    extract::Request,
    http::header::AUTHORIZATION,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service};

/// OIDC authentication layer
///
/// This layer verifies Bearer tokens using the provided `JwtVerifier`
/// and injects verified claims into the request extensions.
#[derive(Clone)]
pub struct OidcLayer<C, H>
where
    C: xjp_oidc::Cache<String, xjp_oidc::Jwks> + Clone,
    H: xjp_oidc::HttpClient + Clone,
{
    verifier: Arc<xjp_oidc::JwtVerifier<C, H>>,
}

impl<C, H> OidcLayer<C, H>
where
    C: xjp_oidc::Cache<String, xjp_oidc::Jwks> + Clone,
    H: xjp_oidc::HttpClient + Clone,
{
    /// Create a new OIDC layer with the given verifier
    pub fn new(verifier: Arc<xjp_oidc::JwtVerifier<C, H>>) -> Self {
        Self { verifier }
    }
}

impl<S, C, H> Layer<S> for OidcLayer<C, H>
where
    C: xjp_oidc::Cache<String, xjp_oidc::Jwks> + Clone,
    H: xjp_oidc::HttpClient + Clone,
{
    type Service = OidcMiddleware<S, C, H>;

    fn layer(&self, inner: S) -> Self::Service {
        OidcMiddleware {
            inner,
            verifier: self.verifier.clone(),
        }
    }
}

/// OIDC middleware service
#[derive(Clone)]
pub struct OidcMiddleware<S, C, H>
where
    C: xjp_oidc::Cache<String, xjp_oidc::Jwks> + Clone,
    H: xjp_oidc::HttpClient + Clone,
{
    inner: S,
    verifier: Arc<xjp_oidc::JwtVerifier<C, H>>,
}

impl<S, C, H> Service<Request> for OidcMiddleware<S, C, H>
where
    S: Service<Request, Response = Response> + Send + 'static + Clone,
    S::Future: Send + 'static,
    C: xjp_oidc::Cache<String, xjp_oidc::Jwks> + Clone + Send + Sync + 'static,
    H: xjp_oidc::HttpClient + Clone + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        let verifier = self.verifier.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Extract authorization header
            let auth_header = req
                .headers()
                .get(AUTHORIZATION)
                .and_then(|h| h.to_str().ok());

            if let Some(bearer) = auth_header {
                // Verify the token
                match verifier.verify(bearer).await {
                    Ok(claims) => {
                        // Inject claims into request extensions
                        req.extensions_mut().insert(ClaimsExtension(claims));
                    }
                    Err(e) => {
                        // Log the error if tracing is enabled
                        #[cfg(feature = "tracing")]
                        tracing::debug!("Token verification failed: {}", e);

                        // Return unauthorized response
                        return Ok(AuthError::TokenVerificationFailed(e).into_response());
                    }
                }
            } else {
                // No authorization header - return unauthorized
                return Ok(AuthError::MissingAuthHeader.into_response());
            }

            // Call inner service
            inner.call(req).await
        })
    }
}

/// Admin guard middleware
///
/// This middleware checks for admin privileges after token verification.
/// It must be used after `OidcLayer`.
pub struct AdminGuard;

impl AdminGuard {
    /// Create a new admin guard
    pub fn new() -> Self {
        Self
    }
}

impl Default for AdminGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// Admin guard middleware function
pub async fn require_admin(req: Request, next: Next) -> Result<Response, AuthError> {
    // Check if claims exist in extensions
    let has_admin = req
        .extensions()
        .get::<ClaimsExtension>()
        .map(|ext| ext.0.xjp_admin.unwrap_or(false))
        .unwrap_or(false);

    if !has_admin {
        return Err(AuthError::AdminRequired);
    }

    Ok(next.run(req).await)
}

// Note: axum::middleware::from_fn is typically used directly in router setup
