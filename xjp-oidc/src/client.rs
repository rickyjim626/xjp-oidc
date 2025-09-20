//! High-level client for convenient SDK usage

use crate::{
    cache::{Cache, MokaCacheImpl},
    errors::Result,
    http::{HttpClient, ReqwestHttpClient},
    jwks::Jwks,
    types::OidcProviderMetadata,
};
use std::sync::Arc;

/// Default OIDC client with built-in HTTP and cache implementations
/// 
/// This provides a convenient way to use the SDK without worrying about
/// the generic parameters.
#[cfg(all(not(target_arch = "wasm32"), feature = "http-reqwest", feature = "moka"))]
pub struct OidcClient {
    /// HTTP client
    pub http: Arc<ReqwestHttpClient>,
    /// Discovery metadata cache
    pub discovery_cache: Arc<MokaCacheImpl<String, OidcProviderMetadata>>,
    /// JWKS cache
    pub jwks_cache: Arc<MokaCacheImpl<String, Jwks>>,
}

#[cfg(all(not(target_arch = "wasm32"), feature = "http-reqwest", feature = "moka"))]
impl OidcClient {
    /// Create a new OIDC client with default settings
    pub fn new() -> Result<Self> {
        let http = Arc::new(ReqwestHttpClient::default());
        let discovery_cache = Arc::new(MokaCacheImpl::new(100));
        let jwks_cache = Arc::new(MokaCacheImpl::new(100));
        
        Ok(Self {
            http,
            discovery_cache,
            jwks_cache,
        })
    }
    
    /// Get a reference to the HTTP client
    pub fn http(&self) -> &dyn HttpClient {
        self.http.as_ref()
    }
    
    /// Get a reference to the discovery cache
    pub fn discovery_cache(&self) -> &dyn Cache<String, OidcProviderMetadata> {
        self.discovery_cache.as_ref()
    }
    
    /// Get a reference to the JWKS cache
    pub fn jwks_cache(&self) -> &dyn Cache<String, Jwks> {
        self.jwks_cache.as_ref()
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "http-reqwest", feature = "moka"))]
impl Default for OidcClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default OIDC client")
    }
}