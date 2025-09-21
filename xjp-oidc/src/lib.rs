//! # xjp-oidc
//!
//! A comprehensive OIDC/OAuth2 SDK for Rust with support for both server and WASM environments.
//!
//! ## Features
//!
//! - Authorization Code Flow with PKCE
//! - OIDC Discovery and JWKS caching
//! - ID Token verification with standard claims validation
//! - Dynamic Client Registration (server-only)
//! - RP-Initiated Logout
//! - Resource Server JWT verification
//! - Optional Axum integration
//!
//! ## Example
//!
//! ```no_run
//! use xjp_oidc::{create_pkce, build_auth_url, BuildAuthUrl};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create PKCE challenge
//! let (verifier, challenge, method) = create_pkce()?;
//!
//! // Build authorization URL
//! let auth_url = build_auth_url(BuildAuthUrl {
//!     issuer: "https://auth.example.com".into(),
//!     client_id: "my-client".into(),
//!     redirect_uri: "https://app.example.com/callback".into(),
//!     scope: "openid profile email".into(),
//!     code_challenge: challenge,
//!     state: None,
//!     nonce: None,
//!     prompt: None,
//!     extra_params: None,
//!     tenant: None,
//! })?;
//! # Ok(())
//! # }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

pub mod errors;
pub mod types;

// Core functionality modules
mod auth_url;
pub mod cache;
mod client;
mod dcr;
mod discovery;
mod exchange;
pub mod http;
mod id_token;
mod jwks;
mod pkce;

// Conditional compilation for verifier feature
#[cfg(feature = "verifier")]
mod verify;

// Re-export main types and functions
pub use auth_url::{
    build_auth_url, build_auth_url_with_metadata, build_end_session_url, parse_callback_params,
};
pub use cache::{Cache, NoOpCache};

#[cfg(feature = "lru")]
pub use cache::LruCacheImpl;

#[cfg(all(not(target_arch = "wasm32"), feature = "moka"))]
pub use cache::MokaCacheImpl;

#[cfg(all(not(target_arch = "wasm32"), feature = "http-reqwest", feature = "moka"))]
pub use client::OidcClient;

#[cfg(not(target_arch = "wasm32"))]
pub use dcr::register_if_needed;

pub use discovery::discover;
pub use errors::Error;

#[cfg(not(target_arch = "wasm32"))]
pub use exchange::exchange_code;

pub use http::{HttpClient, HttpClientError};
pub use id_token::fetch_jwks;

#[cfg(all(not(target_arch = "wasm32"), feature = "http-reqwest"))]
pub use http::ReqwestHttpClient;

#[cfg(all(target_arch = "wasm32", feature = "http-wasm"))]
pub use http::WasmHttpClient;

pub use id_token::verify_id_token;
pub use jwks::{Jwk, Jwks};
pub use pkce::create_pkce;
pub use types::*;

#[cfg(feature = "verifier")]
pub use verify::JwtVerifier;

// Version information
/// SDK version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::{
        build_auth_url, build_end_session_url, create_pkce, discover, parse_callback_params,
        verify_id_token, BuildAuthUrl, CallbackParams, EndSession, Error, OidcProviderMetadata,
        TokenResponse, VerifiedIdToken, VerifyOptions,
    };

    #[cfg(not(target_arch = "wasm32"))]
    pub use crate::{exchange_code, register_if_needed, ExchangeCode, RegisterRequest};

    #[cfg(feature = "verifier")]
    pub use crate::{JwtVerifier, VerifiedClaims};
}
