//! Resource Server JWT verification

#[cfg(feature = "verifier")]
use crate::{
    cache::Cache,
    discovery::discover,
    errors::{Error, Result},
    http::HttpClient,
    id_token::fetch_jwks,
    jwks::Jwks,
    types::VerifiedClaims,
};

#[cfg(feature = "verifier")]
use base64::{engine::general_purpose, Engine as _};
#[cfg(feature = "verifier")]
use josekit::{
    jws::RS256,
    jwt::{self, JwtPayload},
};
#[cfg(feature = "verifier")]
use std::collections::HashMap;
#[cfg(feature = "verifier")]
use std::time::{SystemTime, UNIX_EPOCH};

/// JWT Verifier for Resource Server
#[cfg(feature = "verifier")]
pub struct JwtVerifier<C: Cache<String, Jwks>, H: HttpClient> {
    /// Map of tenant/host to issuer URL
    pub issuer_map: HashMap<String, String>,
    /// Expected audience
    pub audience: String,
    /// HTTP client
    pub http: std::sync::Arc<H>,
    /// JWKS cache
    pub cache: std::sync::Arc<C>,
    /// Clock skew tolerance in seconds
    pub clock_skew_sec: i64,
    /// Default issuer if no mapping found
    pub default_issuer: Option<String>,
}

#[cfg(feature = "verifier")]
impl<C: Cache<String, Jwks>, H: HttpClient> JwtVerifier<C, H> {
    /// Create a new JWT verifier
    pub fn new(
        issuer_map: HashMap<String, String>,
        audience: String,
        http: std::sync::Arc<H>,
        cache: std::sync::Arc<C>,
    ) -> Self {
        Self { issuer_map, audience, http, cache, clock_skew_sec: 60, default_issuer: None }
    }

    /// Create a verifier builder
    pub fn builder() -> JwtVerifierBuilder<C, H> {
        JwtVerifierBuilder::default()
    }

    /// Verify a bearer token
    pub async fn verify(&self, bearer: &str) -> Result<VerifiedClaims> {
        // Remove "Bearer " prefix if present
        let token = bearer.strip_prefix("Bearer ").unwrap_or(bearer);

        // Try to extract issuer from token payload (unverified)
        let unverified_issuer = extract_unverified_issuer(token)?;

        // Determine expected issuer
        let expected_issuer = self.resolve_issuer(&unverified_issuer)?;

        // Get JWKS for the issuer
        // Use NoOpCache for metadata discovery - JWKS are the important thing to cache
        let metadata_cache = crate::cache::NoOpCache;
        let metadata = discover(&expected_issuer, self.http.as_ref(), &metadata_cache).await?;
        let jwks = fetch_jwks(&metadata.jwks_uri, self.http.as_ref(), self.cache.as_ref()).await?;

        // Verify token - extract kid manually
        let kid = extract_kid(token)?.ok_or_else(|| Error::Jwt("Token missing kid".into()))?;

        let jwk = jwks
            .find_key(&kid)
            .ok_or_else(|| Error::Jwt(format!("Key with kid '{}' not found", kid)))?;

        let payload = verify_token_signature(token, jwk)?;

        // Extract and validate claims
        let claims = extract_and_validate_access_token_claims(
            payload,
            &expected_issuer,
            &self.audience,
            self.clock_skew_sec,
        )?;

        Ok(claims)
    }

    /// Resolve issuer from token or mapping
    fn resolve_issuer(&self, token_issuer: &str) -> Result<String> {
        // Check if token issuer is directly in our allowed list (as a value)
        if self.issuer_map.values().any(|v| v == token_issuer) {
            return Ok(token_issuer.to_string());
        }

        // Check if token issuer matches any mapped tenant/host key
        // This supports cases where the key is the issuer itself
        if self.issuer_map.contains_key(token_issuer) {
            return Ok(self.issuer_map[token_issuer].clone());
        }

        // Otherwise use default issuer if configured
        if let Some(default) = &self.default_issuer {
            return Ok(default.clone());
        }

        // If no default, reject the token
        Err(Error::Verification(format!("Issuer '{}' not in allowed list", token_issuer)))
    }

    /// Resolve issuer with tenant context
    /// This method allows multi-tenant routing by selecting issuer based on tenant identifier
    pub fn resolve_issuer_with_tenant(&self, tenant: &str) -> Result<String> {
        // Look up issuer for the given tenant
        if let Some(issuer) = self.issuer_map.get(tenant) {
            return Ok(issuer.clone());
        }

        // Fall back to default issuer if configured
        if let Some(default) = &self.default_issuer {
            return Ok(default.clone());
        }

        // No issuer found for tenant
        Err(Error::Verification(format!("No issuer configured for tenant '{}'", tenant)))
    }
}

/// JWT Verifier builder
#[cfg(feature = "verifier")]
pub struct JwtVerifierBuilder<C: Cache<String, Jwks>, H: HttpClient> {
    issuer_map: Option<HashMap<String, String>>,
    audience: Option<String>,
    http: Option<std::sync::Arc<H>>,
    cache: Option<std::sync::Arc<C>>,
    clock_skew_sec: Option<i64>,
    default_issuer: Option<String>,
}

#[cfg(feature = "verifier")]
impl<C: Cache<String, Jwks>, H: HttpClient> Default for JwtVerifierBuilder<C, H> {
    fn default() -> Self {
        Self {
            issuer_map: None,
            audience: None,
            http: None,
            cache: None,
            clock_skew_sec: None,
            default_issuer: None,
        }
    }
}

#[cfg(feature = "verifier")]
impl<C: Cache<String, Jwks>, H: HttpClient> JwtVerifierBuilder<C, H> {
    /// Set issuer mapping
    pub fn issuer_map(mut self, map: HashMap<String, String>) -> Self {
        self.issuer_map = Some(map);
        self
    }

    /// Set audience
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Set HTTP client
    pub fn http(mut self, http: std::sync::Arc<H>) -> Self {
        self.http = Some(http);
        self
    }

    /// Set cache
    pub fn cache(mut self, cache: std::sync::Arc<C>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Set clock skew tolerance
    pub fn clock_skew(mut self, seconds: i64) -> Self {
        self.clock_skew_sec = Some(seconds);
        self
    }

    /// Set default issuer
    pub fn default_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.default_issuer = Some(issuer.into());
        self
    }

    /// Build the verifier
    pub fn build(self) -> Result<JwtVerifier<C, H>> {
        Ok(JwtVerifier {
            issuer_map: self.issuer_map.unwrap_or_default(),
            audience: self.audience.ok_or(Error::MissingConfig("audience"))?,
            http: self.http.ok_or(Error::MissingConfig("http client"))?,
            cache: self.cache.ok_or(Error::MissingConfig("cache"))?,
            clock_skew_sec: self.clock_skew_sec.unwrap_or(60),
            default_issuer: self.default_issuer,
        })
    }
}

/// Extract kid from JWT header without full verification
#[cfg(feature = "verifier")]
fn extract_kid(jwt: &str) -> Result<Option<String>> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::Jwt("Invalid JWT format".into()));
    }

    let header_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| Error::Base64(format!("Failed to decode header: {}", e)))?;

    let header_value: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| Error::Jwt(format!("Failed to parse header JSON: {}", e)))?;

    Ok(header_value.get("kid").and_then(|v| v.as_str()).map(|s| s.to_string()))
}

/// Extract issuer from unverified token
#[cfg(feature = "verifier")]
fn extract_unverified_issuer(token: &str) -> Result<String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::Jwt("Invalid JWT format".into()));
    }

    let payload_json = general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| Error::Base64(e.to_string()))?;

    let payload: serde_json::Value = serde_json::from_slice(&payload_json)?;

    payload["iss"]
        .as_str()
        .ok_or_else(|| Error::Jwt("Token missing issuer".into()))
        .map(|s| s.to_string())
}

/// Verify token signature
#[cfg(feature = "verifier")]
fn verify_token_signature(token: &str, jwk: &crate::jwks::Jwk) -> Result<JwtPayload> {
    // Convert JWK to josekit format
    let key = josekit::jwk::Jwk::from_map(serde_json::to_value(jwk)?.as_object().unwrap().clone())
        .map_err(|e| Error::Jwt(format!("Invalid JWK: {}", e)))?;

    // Verify based on algorithm
    let verifier = match jwk.alg.as_str() {
        "RS256" => RS256.verifier_from_jwk(&key),
        alg => return Err(Error::Jwt(format!("Unsupported algorithm: {}", alg))),
    }
    .map_err(|e| Error::Jwt(format!("Failed to create verifier: {}", e)))?;

    let (payload, _header) = jwt::decode_with_verifier(token, &verifier)
        .map_err(|e| Error::Jwt(format!("Token verification failed: {}", e)))?;

    Ok(payload)
}

/// Extract and validate access token claims
#[cfg(feature = "verifier")]
fn extract_and_validate_access_token_claims(
    payload: JwtPayload,
    expected_issuer: &str,
    expected_audience: &str,
    clock_skew: i64,
) -> Result<VerifiedClaims> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;

    // Extract standard claims
    let iss = payload.issuer().ok_or_else(|| Error::Verification("Missing iss claim".into()))?;
    let sub = payload.subject().ok_or_else(|| Error::Verification("Missing sub claim".into()))?;
    let exp = payload
        .expires_at()
        .ok_or_else(|| Error::Verification("Missing exp claim".into()))?
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Verification("Invalid exp time".into()))?
        .as_secs() as i64;
    let iat = payload
        .issued_at()
        .ok_or_else(|| Error::Verification("Missing iat claim".into()))?
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Verification("Invalid iat time".into()))?
        .as_secs() as i64;

    // Validate issuer
    if iss != expected_issuer {
        return Err(Error::Verification(format!(
            "Invalid issuer: expected '{}', got '{}'",
            expected_issuer, iss
        )));
    }

    // Validate audience
    let aud = if let Some(audiences) = payload.audience() {
        if !audiences.iter().any(|a| *a == expected_audience) {
            return Err(Error::Verification(format!(
                "Invalid audience: expected '{}'",
                expected_audience
            )));
        }
        expected_audience.to_string()
    } else {
        return Err(Error::Verification("Missing aud claim".into()));
    };

    // Validate expiration
    if exp < now - clock_skew {
        return Err(Error::Verification("Token expired".into()));
    }

    // Validate issued at
    if iat > now + clock_skew {
        return Err(Error::Verification("Token issued in the future".into()));
    }

    // Extract custom claims
    let claims_map = payload.claims_set();

    let jti = claims_map.get("jti").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let scope = claims_map.get("scope").and_then(|v| v.as_str()).map(|s| s.to_string());

    let xjp_admin = claims_map.get("xjp_admin").and_then(|v| v.as_bool());

    let amr = claims_map.get("amr").and_then(|v| {
        v.as_array()?
            .iter()
            .map(|item| item.as_str().map(|s| s.to_string()))
            .collect::<Option<Vec<String>>>()
    });

    let auth_time = claims_map.get("auth_time").and_then(|v| v.as_i64());

    Ok(VerifiedClaims {
        iss: iss.to_string(),
        sub: sub.to_string(),
        aud: aud.to_string(),
        exp,
        iat,
        jti,
        scope,
        xjp_admin,
        amr,
        auth_time,
    })
}

#[cfg(all(test, feature = "verifier"))]
mod tests {
    use super::*;

    #[test]
    fn test_extract_unverified_issuer() {
        // This is a dummy JWT for testing - not a real token
        let token = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20ifQ.dummy";

        let issuer = extract_unverified_issuer(token).unwrap();
        assert_eq!(issuer, "https://auth.example.com");
    }
}
