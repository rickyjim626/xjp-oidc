//! OIDC Discovery implementation with multi-tenant support

use crate::{
    cache::Cache,
    errors::{Error, Result},
    tenant::TenantConfig,
    types::OidcProviderMetadata,
};
use serde_json::Value;

/// Default cache TTL for discovery metadata (10 minutes)
const DEFAULT_DISCOVERY_CACHE_TTL: u64 = 600;

/// Enhanced HTTP client trait with header support for multi-tenant
#[async_trait::async_trait]
pub trait HttpClientWithHeaders: Send + Sync {
    /// Perform a GET request with custom headers and return JSON value
    async fn get_value_with_headers(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
    ) -> Result<Value>;
}

/// Discover OIDC provider metadata with tenant support
///
/// This function extends the standard OIDC Discovery to support multi-tenant setups
/// by applying tenant configuration to the discovery request.
///
/// # Example
/// ```no_run
/// # use xjp_oidc::tenant::{TenantConfig, TenantMode};
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let tenant_config = TenantConfig::subdomain(
///     "xiaojinpro".to_string(),
///     "auth.xiaojinpro.com".to_string()
/// );
///
/// let metadata = discover_with_tenant(
///     "https://auth.xiaojinpro.com",
///     &tenant_config,
///     &http_client,
///     &cache,
/// ).await?;
/// # Ok(())
/// # }
/// ```
#[tracing::instrument(
    name = "oidc_discover_tenant",
    skip(http, cache),
    fields(
        issuer = %issuer,
        tenant = ?tenant_config.tenant,
        mode = ?tenant_config.mode
    )
)]
pub async fn discover_with_tenant(
    issuer: &str,
    tenant_config: &TenantConfig,
    http: &dyn HttpClientWithHeaders,
    cache: &dyn Cache<String, OidcProviderMetadata>,
) -> Result<OidcProviderMetadata> {
    tracing::info!(
        target: "xjp_oidc::discovery",
        "开始多租户 OIDC 发现, mode: {:?}, tenant: {:?}",
        tenant_config.mode,
        tenant_config.tenant
    );

    // Validate tenant configuration
    tenant_config.validate().map_err(|e| Error::Discovery(e))?;

    // Validate issuer URL
    if issuer.is_empty() {
        return Err(Error::InvalidParam("issuer cannot be empty"));
    }

    // Build cache key with tenant info
    let cache_key = format!(
        "discovery:{}:{}",
        issuer,
        tenant_config.tenant.as_deref().unwrap_or("default")
    );

    // Check cache first
    if let Some(cached) = cache.get(&cache_key) {
        tracing::debug!("Using cached discovery metadata");
        return Ok(cached);
    }

    // Build discovery URL
    let discovery_url = build_discovery_url(issuer)?;

    // Apply tenant configuration to URL
    let final_url = tenant_config
        .apply_to_url(&discovery_url)
        .map_err(|e| Error::Discovery(e))?;

    // Prepare headers based on tenant mode
    let mut headers = Vec::new();
    if let Some(host_header) = tenant_config.get_host_header() {
        tracing::debug!("Adding Host header: {}", host_header);
        headers.push(("Host".to_string(), host_header));
    }

    // Fetch metadata with headers
    let value = http
        .get_value_with_headers(&final_url, headers)
        .await?;

    // Check if the response is an error
    if let Some(error) = value.get("error").and_then(|v| v.as_str()) {
        let error_description = value
            .get("error_description")
            .and_then(|v| v.as_str())
            .unwrap_or("No description");

        return Err(Error::Discovery(format!(
            "Discovery failed: {} - {}",
            error, error_description
        )));
    }

    let metadata: OidcProviderMetadata = serde_json::from_value(value)
        .map_err(|e| Error::Discovery(format!("Failed to parse discovery metadata: {}", e)))?;

    // Validate metadata
    validate_metadata(&metadata, issuer)?;

    // Cache the metadata
    cache.put(cache_key, metadata.clone(), DEFAULT_DISCOVERY_CACHE_TTL);

    tracing::info!("Discovery completed successfully");
    Ok(metadata)
}

/// Build the discovery URL from issuer
fn build_discovery_url(issuer: &str) -> Result<String> {
    // Remove trailing slash if present
    let issuer = issuer.trim_end_matches('/');

    // Validate URL format
    let url = url::Url::parse(issuer)?;
    if url.scheme() != "https" && url.scheme() != "http" {
        return Err(Error::InvalidParam("issuer must use http or https scheme"));
    }

    Ok(format!("{}/.well-known/openid-configuration", issuer))
}

/// Validate discovered metadata
fn validate_metadata(metadata: &OidcProviderMetadata, expected_issuer: &str) -> Result<()> {
    // The issuer in metadata must match the requested issuer
    let normalized_expected = expected_issuer.trim_end_matches('/');
    let normalized_actual = metadata.issuer.trim_end_matches('/');

    if normalized_actual != normalized_expected {
        return Err(Error::Discovery(format!(
            "Issuer mismatch: expected '{}', got '{}'",
            normalized_expected, normalized_actual
        )));
    }

    // Ensure required endpoints are present
    if metadata.authorization_endpoint.is_empty() {
        return Err(Error::Discovery("authorization_endpoint is missing".to_string()));
    }
    if metadata.token_endpoint.is_empty() {
        return Err(Error::Discovery("token_endpoint is missing".to_string()));
    }
    if metadata.jwks_uri.is_empty() {
        return Err(Error::Discovery("jwks_uri is missing".to_string()));
    }

    Ok(())
}

/// Convenience wrapper for backward compatibility
pub async fn discover_with_tenant_simple(
    issuer: &str,
    tenant: Option<String>,
    http: &dyn HttpClientWithHeaders,
    cache: &dyn Cache<String, OidcProviderMetadata>,
) -> Result<OidcProviderMetadata> {
    let tenant_config = if let Some(tenant_id) = tenant {
        // Default to query param mode for simple tenant specification
        TenantConfig::query_param(tenant_id)
    } else {
        TenantConfig::single()
    };

    discover_with_tenant(issuer, &tenant_config, http, cache).await
}