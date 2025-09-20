//! ID Token verification and parsing

use crate::{
    cache::Cache,
    discovery::discover,
    errors::{Error, Result},
    http::HttpClient,
    jwks::{Jwk, Jwks},
    types::{VerifiedIdToken, VerifyOptions},
};
use josekit::{
    jws::RS256,
    jwt::{self, JwtPayload},
};
use std::time::{SystemTime, UNIX_EPOCH};
use base64::{Engine as _, engine::general_purpose};

/// Default JWKS cache TTL (10 minutes)
const DEFAULT_JWKS_CACHE_TTL: u64 = 600;

/// Verify an ID token and return verified claims
///
/// # Example
/// ```no_run
/// # use xjp_oidc::{verify_id_token, VerifyOptions, http::ReqwestHttpClient, cache::NoOpCache};
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let http = ReqwestHttpClient::default();
/// let cache = NoOpCache;
///
/// let claims = verify_id_token(
///     "eyJ...",
///     VerifyOptions {
///         issuer: "https://auth.example.com",
///         audience: "my-client",
///         nonce: Some("expected_nonce"),
///         max_age_sec: None,
///         clock_skew_sec: Some(60),
///         http: &http,
///         cache: &cache,
///     }
/// ).await?;
/// # Ok(())
/// # }
/// ```
#[tracing::instrument(
    name = "verify_id_token",
    skip(id_token, opts),
    fields(
        issuer = %opts.issuer,
        audience = %opts.audience,
        has_nonce = opts.nonce.is_some(),
    )
)]
pub async fn verify_id_token(
    id_token: &str,
    opts: VerifyOptions<'_>,
) -> Result<VerifiedIdToken> {
    tracing::debug!(target: "xjp_oidc::token", "开始验证 ID Token");
    
    // Extract kid from token header
    let kid = extract_kid(id_token)?
        .ok_or_else(|| Error::Jwt("Token missing kid".into()))?;
    
    tracing::trace!(target: "xjp_oidc::token", kid = %kid, "提取 kid 成功");

    // Discover metadata and get JWKS
    // Use NoOpCache for metadata discovery - JWKS are the important thing to cache
    let metadata_cache = crate::cache::NoOpCache;
    let metadata = discover(opts.issuer, opts.http, &metadata_cache).await?;
    let jwks = fetch_jwks(&metadata.jwks_uri, opts.http, opts.cache).await?;

    // Find the key
    let jwk = jwks
        .find_key(&kid)
        .ok_or_else(|| Error::Jwt(format!("Key with kid '{}' not found", kid)))?;

    // Verify the token
    let payload = verify_token_signature(id_token, jwk)?;

    // Extract and validate claims
    let claims = extract_and_validate_claims(payload, opts)?;

    Ok(claims)
}

/// Extract kid from JWT header without full verification
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
    
    Ok(header_value
        .get("kid")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string()))
}

/// Fetch JWKS from the endpoint
pub async fn fetch_jwks(
    jwks_uri: &str,
    http: &dyn HttpClient,
    cache: &dyn Cache<String, Jwks>,
) -> Result<Jwks> {
    // Check cache first
    let cache_key = format!("jwks:{}", jwks_uri);
    if let Some(cached) = cache.get(&cache_key) {
        return Ok(cached);
    }

    // Fetch JWKS
    let value = http
        .get_value(jwks_uri)
        .await
        .map_err(|e| Error::Jwks(format!("Failed to fetch JWKS: {}", e)))?;
        
    let jwks: Jwks = serde_json::from_value(value)
        .map_err(|e| Error::Jwks(format!("Failed to parse JWKS: {}", e)))?;

    // Cache the JWKS
    cache.put(cache_key, jwks.clone(), DEFAULT_JWKS_CACHE_TTL);

    Ok(jwks)
}

/// Verify token signature using JWK
fn verify_token_signature(token: &str, jwk: &Jwk) -> Result<JwtPayload> {
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

/// Extract and validate claims from JWT payload
fn extract_and_validate_claims(
    payload: JwtPayload,
    opts: VerifyOptions<'_>,
) -> Result<VerifiedIdToken> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let clock_skew = opts.clock_skew_sec.unwrap_or(0);

    // Extract standard claims
    let iss = payload
        .issuer()
        .ok_or_else(|| Error::Verification("Missing iss claim".into()))?;
    let sub = payload
        .subject()
        .ok_or_else(|| Error::Verification("Missing sub claim".into()))?;
    let aud = payload
        .audience()
        .and_then(|a| a.first().map(|s| s.to_string()))
        .ok_or_else(|| Error::Verification("Missing aud claim".into()))?;
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
    if iss != opts.issuer {
        return Err(Error::Verification(format!(
            "Invalid issuer: expected '{}', got '{}'",
            opts.issuer, iss
        )));
    }

    // Validate audience
    if aud != opts.audience {
        return Err(Error::Verification(format!(
            "Invalid audience: expected '{}', got '{}'",
            opts.audience, aud
        )));
    }

    // Validate expiration
    if exp < now - clock_skew {
        return Err(Error::Verification("Token expired".into()));
    }

    // Validate issued at
    if iat > now + clock_skew {
        return Err(Error::Verification("Token issued in the future".into()));
    }

    // Get custom claims from the raw payload
    let claims_map = payload.claims_set();

    // Extract optional standard claims
    let nonce = claims_map
        .get("nonce")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let sid = claims_map
        .get("sid")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Validate nonce if provided
    if let Some(expected_nonce) = opts.nonce {
        match &nonce {
            Some(actual_nonce) if actual_nonce == expected_nonce => {}
            _ => return Err(Error::Verification("Invalid nonce".into())),
        }
    }

    // Extract profile claims
    let name = claims_map
        .get("name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let email = claims_map
        .get("email")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let picture = claims_map
        .get("picture")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Extract custom claims
    let amr = claims_map
        .get("amr")
        .and_then(|v| {
            v.as_array()?.iter()
                .map(|item| item.as_str().map(|s| s.to_string()))
                .collect::<Option<Vec<String>>>()
        });
    let auth_time = claims_map
        .get("auth_time")
        .and_then(|v| v.as_i64());
    let xjp_admin = claims_map
        .get("xjp_admin")
        .and_then(|v| v.as_bool());

    // Validate auth_time if max_age is specified
    if let Some(max_age) = opts.max_age_sec {
        if let Some(auth_time) = auth_time {
            if now - auth_time > max_age + clock_skew {
                return Err(Error::RequireRecentLogin);
            }
        } else {
            return Err(Error::Verification("Missing auth_time for max_age check".into()));
        }
    }

    Ok(VerifiedIdToken {
        iss: iss.to_string(),
        sub: sub.to_string(),
        aud: aud.to_string(),
        exp,
        iat,
        nonce,
        sid,
        name,
        email,
        picture,
        amr,
        auth_time,
        xjp_admin,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_kid() {
        // This is a dummy JWT for testing - not a real token
        let token = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20ifQ.dummy";
        
        let kid = extract_kid(token).unwrap();
        assert_eq!(kid, Some("test-key".to_string()));
    }

    #[test]
    fn test_invalid_jwt_format() {
        let result = extract_kid("not.a.jwt");
        assert!(result.is_err()); // Not enough parts

        let result = extract_kid("only.two");
        assert!(result.is_err());
    }
}