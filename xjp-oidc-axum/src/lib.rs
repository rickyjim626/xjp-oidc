//! Axum integration for xjp-oidc
//!
//! Provides middleware and extractors for OIDC/OAuth2 authentication in Axum applications.
//!
//! # Example
//!
//! ```no_run
//! use axum::{Router, routing::get};
//! use xjp_oidc_axum::{OidcLayer, VerifiedClaims};
//! use xjp_oidc::{JwtVerifier, MokaCacheImpl, ReqwestHttpClient};
//! use std::sync::Arc;
//! use std::collections::HashMap;
//!
//! # async fn example() {
//! # let mut issuer_map = HashMap::new();
//! # issuer_map.insert("test".to_string(), "https://auth.example.com".to_string());
//! # let verifier = Arc::new(JwtVerifier::new(
//! #     issuer_map,
//! #     "test-audience".to_string(),
//! #     Arc::new(ReqwestHttpClient::default()),
//! #     Arc::new(MokaCacheImpl::new(100)),
//! # ));
//! // Setup your JWT verifier here
//!
//! let app: Router = Router::new()
//!     .route("/protected", get(handler))
//!     .layer(OidcLayer::new(verifier));
//!
//! async fn handler(claims: VerifiedClaims) -> String {
//!     format!("Hello, user {}", claims.sub)
//! }
//! # }
//! ```

#![warn(missing_docs)]

mod error;
mod extractors;
mod layer;

pub use error::AuthError;
pub use extractors::{AdminClaims, OptionalClaims, VerifiedClaims};
pub use layer::{require_admin, AdminGuard, OidcLayer};

// Re-export commonly used types from xjp-oidc
pub use xjp_oidc::{JwtVerifier, VerifiedClaims as Claims};