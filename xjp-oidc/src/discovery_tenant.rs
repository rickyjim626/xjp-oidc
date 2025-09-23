//! OIDC Discovery implementation with multi-tenant support

use crate::{
    cache::Cache,
    errors::{Error, Result},
    tenant::{TenantConfig, TenantResolution},
    http_tenant::HttpClientWithAdminSupport,
    types::OidcProviderMetadata,
};

/// Default cache TTL for discovery metadata (10 minutes)
const DEFAULT_DISCOVERY_CACHE_TTL: u64 = 600;

/// Discover OIDC provider metadata with tenant support
///
/// This function extends the standard OIDC Discovery to support multi-tenant setups
/// using the new TenantResolution priority system.
///
/// # Example
/// ```no_run
/// # use xjp_oidc::tenant::{TenantResolution};
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let tenant_resolution = TenantResolution {
///     client_id_tenant: Some("xjp-web".to_string()),
///     admin_override_tenant: None,
///     default_tenant: Some("xiaojinpro".to_string()),
/// };
///
/// let metadata = discover_with_tenant_resolution(
///     "https://auth.xiaojinpro.com",
///     &tenant_resolution,
///     &http_client,
///     &cache,
/// ).await?;
/// # Ok(())
/// # }
/// ```
/// Discover OIDC provider metadata with new tenant resolution system
#[tracing::instrument(
    name = "oidc_discover_tenant_resolution",
    skip(http, cache),
    fields(
        issuer = %issuer,
        resolved_tenant = ?tenant_resolution.resolve()
    )
)]
pub async fn discover_with_tenant_resolution(
    issuer: &str,
    tenant_resolution: &TenantResolution,
    http: &dyn HttpClientWithAdminSupport,
    cache: &dyn Cache<String, OidcProviderMetadata>,
) -> Result<OidcProviderMetadata> {
    tracing::info!(
        target: "xjp_oidc::discovery",
        "开始多租户 OIDC 发现, resolved_tenant: {:?}",
        tenant_resolution.resolve()
    );

    // Validate issuer URL
    if issuer.is_empty() {
        return Err(Error::InvalidParam("issuer cannot be empty"));
    }

    // Build cache key with resolved tenant info
    let cache_key = format!(
        "discovery:{}:{}",
        issuer,
        tenant_resolution.tenant_id()
    );

    // Check cache first
    if let Some(cached) = cache.get(&cache_key) {
        tracing::debug!("Using cached discovery metadata");
        return Ok(cached);
    }

    // Build discovery URL
    let discovery_url = build_discovery_url(issuer)?;

    // Add client_id parameter if available
    let final_url = if let Some(client_id) = &tenant_resolution.client_id_tenant {
        let separator = if discovery_url.contains('?') { "&" } else { "?" };
        format!("{}{}client_id={}", discovery_url, separator, client_id)
    } else {
        discovery_url
    };

    // Fetch metadata with admin override if available
    let value = http
        .get_value_with_admin_override(&final_url, tenant_resolution.admin_override_tenant.as_deref())
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

/// Legacy function for backward compatibility with TenantConfig
#[tracing::instrument(
    name = "oidc_discover_tenant_legacy",
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
    http: &dyn HttpClientWithAdminSupport,
    cache: &dyn Cache<String, OidcProviderMetadata>,
) -> Result<OidcProviderMetadata> {
    // Convert TenantConfig to TenantResolution
    let tenant_resolution = TenantResolution {
        client_id_tenant: match tenant_config.mode {
            crate::tenant::TenantMode::ClientId => tenant_config.tenant.clone(),
            _ => None,
        },
        admin_override_tenant: None,
        default_tenant: match tenant_config.mode {
            crate::tenant::TenantMode::Single | 
            crate::tenant::TenantMode::QueryParam => tenant_config.tenant.clone(),
            _ => None,
        },
    };

    discover_with_tenant_resolution(issuer, &tenant_resolution, http, cache).await
}

/// Convenience wrapper for backward compatibility
pub async fn discover_with_tenant_simple(
    issuer: &str,
    tenant: Option<String>,
    http: &dyn HttpClientWithAdminSupport,
    cache: &dyn Cache<String, OidcProviderMetadata>,
) -> Result<OidcProviderMetadata> {
    let tenant_resolution = TenantResolution {
        client_id_tenant: None,
        admin_override_tenant: None,
        default_tenant: tenant,
    };

    discover_with_tenant_resolution(issuer, &tenant_resolution, http, cache).await
}