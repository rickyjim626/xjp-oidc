//! OIDC Discovery implementation

use crate::{
    cache::Cache,
    errors::{Error, Result},
    http::HttpClient,
    types::OidcProviderMetadata,
};

/// Default cache TTL for discovery metadata (10 minutes)
const DEFAULT_DISCOVERY_CACHE_TTL: u64 = 600;

/// Discover OIDC provider metadata from issuer URL
///
/// This implements the OIDC Discovery specification by fetching
/// metadata from the `.well-known/openid-configuration` endpoint
///
/// # Example
/// ```no_run
/// # use xjp_oidc::{discover, http::ReqwestHttpClient, cache::NoOpCache};
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let http = ReqwestHttpClient::default();
/// let cache = NoOpCache;
///
/// let metadata = discover("https://auth.example.com", &http, &cache).await?;
/// println!("Authorization endpoint: {}", metadata.authorization_endpoint);
/// # Ok(())
/// # }
/// ```
#[tracing::instrument(
    name = "oidc_discover",
    skip(http, cache),
    fields(issuer = %issuer)
)]
pub async fn discover(
    issuer: &str,
    http: &dyn HttpClient,
    cache: &dyn Cache<String, OidcProviderMetadata>,
) -> Result<OidcProviderMetadata> {
    tracing::info!(target: "xjp_oidc::discovery", "开始 OIDC 发现");

    // Validate issuer URL
    if issuer.is_empty() {
        return Err(Error::InvalidParam("issuer cannot be empty"));
    }

    // Check cache first
    let cache_key = format!("discovery:{}", issuer);
    if let Some(cached) = cache.get(&cache_key) {
        return Ok(cached);
    }

    // Build discovery URL
    let discovery_url = build_discovery_url(issuer)?;

    // Fetch metadata
    let value = http
        .get_value(&discovery_url)
        .await
        .map_err(|e| Error::Discovery(format!("Failed to fetch discovery metadata: {}", e)))?;

    let metadata: OidcProviderMetadata = serde_json::from_value(value)
        .map_err(|e| Error::Discovery(format!("Failed to parse discovery metadata: {}", e)))?;

    // Validate metadata
    validate_metadata(&metadata, issuer)?;

    // Cache the metadata
    cache.put(cache_key, metadata.clone(), DEFAULT_DISCOVERY_CACHE_TTL);

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

    // Validate required endpoints
    if metadata.authorization_endpoint.is_empty() {
        return Err(Error::Discovery("Missing authorization_endpoint".into()));
    }
    if metadata.token_endpoint.is_empty() {
        return Err(Error::Discovery("Missing token_endpoint".into()));
    }
    if metadata.jwks_uri.is_empty() {
        return Err(Error::Discovery("Missing jwks_uri".into()));
    }

    // Validate endpoint URLs
    validate_endpoint_url(&metadata.authorization_endpoint, "authorization_endpoint")?;
    validate_endpoint_url(&metadata.token_endpoint, "token_endpoint")?;
    validate_endpoint_url(&metadata.jwks_uri, "jwks_uri")?;

    if let Some(userinfo) = &metadata.userinfo_endpoint {
        validate_endpoint_url(userinfo, "userinfo_endpoint")?;
    }

    if let Some(end_session) = &metadata.end_session_endpoint {
        validate_endpoint_url(end_session, "end_session_endpoint")?;
    }

    if let Some(registration) = &metadata.registration_endpoint {
        validate_endpoint_url(registration, "registration_endpoint")?;
    }

    Ok(())
}

/// Validate an endpoint URL
fn validate_endpoint_url(url: &str, name: &str) -> Result<()> {
    url::Url::parse(url).map_err(|e| Error::Discovery(format!("Invalid {}: {}", name, e)))?;
    Ok(())
}

/// Discover with custom cache TTL
#[allow(dead_code)]
pub async fn discover_with_ttl(
    issuer: &str,
    http: &dyn HttpClient,
    cache: &dyn Cache<String, OidcProviderMetadata>,
    ttl_secs: u64,
) -> Result<OidcProviderMetadata> {
    // Check cache first
    let cache_key = format!("discovery:{}", issuer);
    if let Some(cached) = cache.get(&cache_key) {
        return Ok(cached);
    }

    // Use regular discovery
    let metadata = discover(issuer, http, cache).await?;

    // Re-cache with custom TTL
    cache.put(cache_key, metadata.clone(), ttl_secs);

    Ok(metadata)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_discovery_url() {
        assert_eq!(
            build_discovery_url("https://auth.example.com").unwrap(),
            "https://auth.example.com/.well-known/openid-configuration"
        );

        assert_eq!(
            build_discovery_url("https://auth.example.com/").unwrap(),
            "https://auth.example.com/.well-known/openid-configuration"
        );
    }

    #[test]
    fn test_validate_metadata() {
        let metadata = OidcProviderMetadata {
            issuer: "https://auth.example.com".into(),
            authorization_endpoint: "https://auth.example.com/oauth/authorize".into(),
            token_endpoint: "https://auth.example.com/oauth/token".into(),
            jwks_uri: "https://auth.example.com/oauth/jwks".into(),
            userinfo_endpoint: Some("https://auth.example.com/oauth/userinfo".into()),
            end_session_endpoint: Some("https://auth.example.com/oidc/end_session".into()),
            registration_endpoint: None,
            response_types_supported: None,
            grant_types_supported: None,
            scopes_supported: None,
            token_endpoint_auth_methods_supported: None,
            id_token_signing_alg_values_supported: None,
            code_challenge_methods_supported: None,
            subject_types_supported: vec!["public".to_string()],
            introspection_endpoint: None,
            revocation_endpoint: None,
            frontchannel_logout_supported: None,
            frontchannel_logout_session_supported: None,
            backchannel_logout_supported: None,
            backchannel_logout_session_supported: None,
            tenant_id: None,
            tenant_slug: None,
        };

        assert!(validate_metadata(&metadata, "https://auth.example.com").is_ok());
        assert!(validate_metadata(&metadata, "https://auth.example.com/").is_ok());
        assert!(validate_metadata(&metadata, "https://wrong.example.com").is_err());
    }

    #[test]
    fn test_validate_metadata_missing_fields() {
        let metadata = OidcProviderMetadata {
            issuer: "https://auth.example.com".into(),
            authorization_endpoint: "".into(),
            token_endpoint: "https://auth.example.com/oauth/token".into(),
            jwks_uri: "https://auth.example.com/oauth/jwks".into(),
            userinfo_endpoint: None,
            end_session_endpoint: None,
            registration_endpoint: None,
            response_types_supported: None,
            grant_types_supported: None,
            scopes_supported: None,
            token_endpoint_auth_methods_supported: None,
            id_token_signing_alg_values_supported: None,
            code_challenge_methods_supported: None,
            subject_types_supported: vec!["public".to_string()],
            introspection_endpoint: None,
            revocation_endpoint: None,
            frontchannel_logout_supported: None,
            frontchannel_logout_session_supported: None,
            backchannel_logout_supported: None,
            backchannel_logout_session_supported: None,
            tenant_id: None,
            tenant_slug: None,
        };

        let result = validate_metadata(&metadata, "https://auth.example.com");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("authorization_endpoint"));
    }
}
