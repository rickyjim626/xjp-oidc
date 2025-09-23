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
//! let auth_result = build_auth_url(BuildAuthUrl {
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
//!     authorization_endpoint: None,
//! })?;
//! let auth_url = auth_result.url;
//! // Save auth_result.state and auth_result.nonce for later validation
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
mod introspect;
mod jwks;
mod pkce;
mod userinfo;

// Multi-tenant support modules
pub mod tenant;
pub mod discovery_tenant;
pub mod http_tenant;

// Conditional compilation for verifier feature
#[cfg(feature = "verifier")]
mod verify;

// SSE support (server-only)
#[cfg(not(target_arch = "wasm32"))]
pub mod sse;

// Re-export main types and functions
pub use auth_url::{
    build_auth_url, build_auth_url_with_metadata, build_end_session_url,
    build_end_session_url_with_discovery, parse_callback_params,
};
pub use cache::{Cache, NoOpCache, MemoryCache};

#[cfg(feature = "lru")]
pub use cache::LruCacheImpl;

#[cfg(all(not(target_arch = "wasm32"), feature = "moka"))]
pub use cache::MokaCacheImpl;

#[cfg(all(not(target_arch = "wasm32"), feature = "http-reqwest", feature = "moka"))]
pub use client::OidcClient;

#[cfg(not(target_arch = "wasm32"))]
pub use dcr::{register_client, get_client_config};

pub use discovery::discover;
pub use errors::Error;

#[cfg(not(target_arch = "wasm32"))]
pub use exchange::{exchange_code, refresh_token};

pub use http::{HttpClient, HttpClientError};
pub use id_token::fetch_jwks;

#[cfg(all(not(target_arch = "wasm32"), feature = "http-reqwest"))]
pub use http::ReqwestHttpClient;

#[cfg(all(target_arch = "wasm32", feature = "http-wasm"))]
pub use http::WasmHttpClient;

pub use id_token::verify_id_token;
#[cfg(not(target_arch = "wasm32"))]
pub use introspect::{introspect_token, revoke_token};
pub use jwks::{Jwk, Jwks};
pub use pkce::create_pkce;
pub use types::*;
pub use userinfo::get_userinfo;

#[cfg(feature = "verifier")]
pub use verify::JwtVerifier;

// Version information
/// SDK version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::{
        build_auth_url, build_end_session_url, build_end_session_url_with_discovery,
        create_pkce, discover, parse_callback_params, verify_id_token, AuthUrlResult, BuildAuthUrl,
        CallbackParams, EndSession, Error, OidcProviderMetadata, TokenResponse,
        VerifiedIdToken, VerifyOptions,
    };

    // Multi-tenant support
    pub use crate::{
        tenant::{TenantConfig, TenantMode, TenantResolution},
        discovery_tenant::{discover_with_tenant, discover_with_tenant_simple, discover_with_tenant_resolution},
        http_tenant::{HttpClientWithAdminSupport, HttpClientAdapter},
    };
    
    #[cfg(all(not(target_arch = "wasm32"), feature = "http-reqwest"))]
    pub use crate::http_tenant::reqwest_tenant::ReqwestHttpClientWithAdminSupport;

    #[cfg(not(target_arch = "wasm32"))]
    pub use crate::{
        exchange_code, refresh_token, register_client, get_client_config,
        introspect_token, revoke_token,
        ExchangeCode, RefreshTokenRequest, RegisterRequest,
        IntrospectRequest, IntrospectResponse, ClientConfig,
    };
    
    pub use crate::{get_userinfo, UserInfo};

    #[cfg(feature = "verifier")]
    pub use crate::{JwtVerifier, VerifiedClaims};
    
    // SSE support
    #[cfg(all(not(target_arch = "wasm32"), feature = "sse"))]
    pub use crate::sse::{
        start_login_session, check_login_status, subscribe_login_events,
        LoginStatus, LoginState, LoginEvent, LoginMonitorConfig,
    };
}
