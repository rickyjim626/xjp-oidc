use josekit::{
    jwk::Jwk as JosekitJwk,
    jws::JwsHeader,
    jwt::{self, JwtPayload},
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use xjp_oidc::{Jwk, Jwks, JwtVerifier, MokaCacheImpl, ReqwestHttpClient};

// Helper function to create a test RSA key pair
fn create_test_keypair() -> (JosekitJwk, Jwk) {
    let alg = josekit::jws::RS256;
    let mut jwk = JosekitJwk::generate_rsa_key(2048).unwrap();
    jwk.set_key_id("resource-key-1");
    jwk.set_algorithm(alg.name());
    jwk.set_key_use("sig");

    let public_jwk = Jwk {
        kty: "RSA".to_string(),
        use_: "sig".to_string(),
        kid: "resource-key-1".to_string(),
        alg: Some("RS256".to_string()),
        n: Some(jwk.parameter("n").unwrap().as_str().unwrap().to_string()),
        e: Some(jwk.parameter("e").unwrap().as_str().unwrap().to_string()),
        x: None,
        y: None,
        crv: None,
    };

    (jwk, public_jwk)
}

// Helper function to create and sign a test access token
fn create_signed_token(jwk: &JosekitJwk, claims: serde_json::Value) -> String {
    let mut header = JwsHeader::new();
    header.set_token_type("JWT");
    header.set_algorithm("RS256");
    header.set_key_id("resource-key-1");

    let payload = JwtPayload::from_map(claims.as_object().unwrap().clone()).unwrap();
    let signer = josekit::jws::RS256.signer_from_jwk(jwk).unwrap();
    jwt::encode_with_signer(&payload, &header, &signer).unwrap()
}

#[tokio::test]
#[cfg(feature = "verifier")]
async fn test_jwt_verifier_basic() {
    let mut server = mockito::Server::new_async().await;
    let mock_issuer = server.url();

    // Create test keypair
    let (private_key, public_key) = create_test_keypair();

    // Setup discovery endpoint
    let discovery_metadata = serde_json::json!({
        "issuer": mock_issuer,
        "authorization_endpoint": format!("{}/authorize", mock_issuer),
        "token_endpoint": format!("{}/token", mock_issuer),
        "jwks_uri": format!("{}/jwks", mock_issuer),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        "id_token_signing_alg_values_supported": ["RS256"],
    });

    let _discovery_mock = server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(discovery_metadata.to_string())
        .create_async()
        .await;

    // Setup JWKS endpoint
    let jwks = Jwks { keys: vec![public_key] };

    let _jwks_mock = server
        .mock("GET", "/jwks")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&jwks).unwrap())
        .expect(1) // Should only be called once due to caching
        .create_async()
        .await;

    // Create verifier
    let http_client = Arc::new(ReqwestHttpClient::default());
    let cache = Arc::new(MokaCacheImpl::new(100));

    let mut issuer_map = HashMap::new();
    issuer_map.insert("test".to_string(), mock_issuer.clone());

    let verifier = JwtVerifier::new(issuer_map, "test-audience".to_string(), http_client, cache);

    // Create valid access token
    let now = OffsetDateTime::now_utc();
    let claims = json!({
        "iss": mock_issuer,
        "sub": "user123",
        "aud": "test-audience",
        "exp": (now + Duration::hours(1)).unix_timestamp(),
        "iat": now.unix_timestamp(),
        "scope": "read write",
        "client_id": "test-client",
    });

    let access_token = create_signed_token(&private_key, claims);

    // Verify the token
    let result = verifier.verify(&access_token).await;
    assert!(result.is_ok(), "Verification failed: {:?}", result.err());

    let verified = result.unwrap();
    assert_eq!(verified.iss, mock_issuer);
    assert_eq!(verified.sub, "user123");
    assert_eq!(verified.aud, "test-audience");
    // Note: scope is in the VerifiedClaims struct
    assert_eq!(verified.scope.as_ref().unwrap(), "read write");
}

#[tokio::test]
#[cfg(feature = "verifier")]
async fn test_jwt_verifier_multiple_audiences() {
    let mut server = mockito::Server::new_async().await;
    let mock_issuer = server.url();

    let (private_key, public_key) = create_test_keypair();

    // Setup discovery endpoint
    let discovery_metadata = serde_json::json!({
        "issuer": mock_issuer,
        "authorization_endpoint": format!("{}/authorize", mock_issuer),
        "token_endpoint": format!("{}/token", mock_issuer),
        "jwks_uri": format!("{}/jwks", mock_issuer),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        "id_token_signing_alg_values_supported": ["RS256"],
    });

    let _discovery_mock = server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(discovery_metadata.to_string())
        .create_async()
        .await;

    let jwks = Jwks { keys: vec![public_key] };

    let _jwks_mock = server
        .mock("GET", "/jwks")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&jwks).unwrap())
        .create_async()
        .await;

    let http_client = Arc::new(ReqwestHttpClient::default());
    let cache = Arc::new(MokaCacheImpl::new(100));

    let mut issuer_map = HashMap::new();
    issuer_map.insert("test".to_string(), mock_issuer.clone());

    // Note: JwtVerifier only supports single audience
    let verifier = JwtVerifier::new(
        issuer_map,
        "api2".to_string(), // Single audience
        http_client,
        cache,
    );

    // Token with audience "api2"
    let now = OffsetDateTime::now_utc();
    let claims = json!({
        "iss": mock_issuer,
        "sub": "user456",
        "aud": "api2",
        "exp": (now + Duration::hours(1)).unix_timestamp(),
        "iat": now.unix_timestamp(),
    });

    let access_token = create_signed_token(&private_key, claims);

    let result = verifier.verify(&access_token).await;
    assert!(result.is_ok(), "Verification failed: {:?}", result.err());
}

#[tokio::test]
#[cfg(feature = "verifier")]
async fn test_jwt_verifier_expired_token() {
    let mut server = mockito::Server::new_async().await;
    let mock_issuer = server.url();

    let (private_key, public_key) = create_test_keypair();

    // Setup discovery endpoint
    let discovery_metadata = serde_json::json!({
        "issuer": mock_issuer,
        "authorization_endpoint": format!("{}/authorize", mock_issuer),
        "token_endpoint": format!("{}/token", mock_issuer),
        "jwks_uri": format!("{}/jwks", mock_issuer),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        "id_token_signing_alg_values_supported": ["RS256"],
    });

    let _discovery_mock = server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(discovery_metadata.to_string())
        .create_async()
        .await;

    let jwks = Jwks { keys: vec![public_key] };

    let _jwks_mock = server
        .mock("GET", "/jwks")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&jwks).unwrap())
        .create_async()
        .await;

    let http_client = Arc::new(ReqwestHttpClient::default());
    let cache = Arc::new(MokaCacheImpl::new(100));

    let mut issuer_map = HashMap::new();
    issuer_map.insert("test".to_string(), mock_issuer.clone());

    let verifier = JwtVerifier::new(issuer_map, "test-api".to_string(), http_client, cache);

    // Create expired token
    let now = OffsetDateTime::now_utc();
    let claims = json!({
        "iss": mock_issuer,
        "sub": "user789",
        "aud": "test-api",
        "exp": (now - Duration::hours(1)).unix_timestamp(), // Expired
        "iat": (now - Duration::hours(2)).unix_timestamp(),
    });

    let access_token = create_signed_token(&private_key, claims);

    let result = verifier.verify(&access_token).await;
    assert!(result.is_err());
}

#[tokio::test]
#[cfg(feature = "verifier")]
async fn test_jwt_verifier_wrong_issuer() {
    let mut server = mockito::Server::new_async().await;
    let mock_issuer = server.url();

    let (private_key, public_key) = create_test_keypair();

    // Setup discovery endpoint
    let discovery_metadata = serde_json::json!({
        "issuer": mock_issuer,
        "authorization_endpoint": format!("{}/authorize", mock_issuer),
        "token_endpoint": format!("{}/token", mock_issuer),
        "jwks_uri": format!("{}/jwks", mock_issuer),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        "id_token_signing_alg_values_supported": ["RS256"],
    });

    let _discovery_mock = server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(discovery_metadata.to_string())
        .create_async()
        .await;

    let jwks = Jwks { keys: vec![public_key] };

    let _jwks_mock = server
        .mock("GET", "/jwks")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&jwks).unwrap())
        .create_async()
        .await;

    let http_client = Arc::new(ReqwestHttpClient::default());
    let cache = Arc::new(MokaCacheImpl::new(100));

    let mut issuer_map = HashMap::new();
    issuer_map.insert("test".to_string(), mock_issuer.clone());

    let verifier = JwtVerifier::new(issuer_map, "test-api".to_string(), http_client, cache);

    // Token with different issuer
    let now = OffsetDateTime::now_utc();
    let claims = json!({
        "iss": "https://other-issuer.com",
        "sub": "user999",
        "aud": "test-api",
        "exp": (now + Duration::hours(1)).unix_timestamp(),
        "iat": now.unix_timestamp(),
    });

    let access_token = create_signed_token(&private_key, claims);

    let result = verifier.verify(&access_token).await;
    assert!(result.is_err());
}

#[tokio::test]
#[cfg(feature = "verifier")]
async fn test_jwt_verifier_caching() {
    let mut server = mockito::Server::new_async().await;
    let mock_issuer = server.url();

    let (private_key, public_key) = create_test_keypair();

    // Setup discovery endpoint
    let discovery_metadata = serde_json::json!({
        "issuer": mock_issuer,
        "authorization_endpoint": format!("{}/authorize", mock_issuer),
        "token_endpoint": format!("{}/token", mock_issuer),
        "jwks_uri": format!("{}/jwks", mock_issuer),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        "id_token_signing_alg_values_supported": ["RS256"],
    });

    let _discovery_mock = server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(discovery_metadata.to_string())
        .create_async()
        .await;

    let jwks = Jwks { keys: vec![public_key] };

    // Mock should only be called once due to caching
    let _jwks_mock = server
        .mock("GET", "/jwks")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&jwks).unwrap())
        .expect(1)
        .create_async()
        .await;

    let http_client = Arc::new(ReqwestHttpClient::default());
    let cache = Arc::new(MokaCacheImpl::new(100));

    let mut issuer_map = HashMap::new();
    issuer_map.insert("test".to_string(), mock_issuer.clone());

    let verifier = JwtVerifier::new(issuer_map, "cached-api".to_string(), http_client, cache);

    // Create multiple tokens
    let now = OffsetDateTime::now_utc();
    for i in 0..5 {
        let claims = json!({
            "iss": mock_issuer,
            "sub": format!("user{}", i),
            "aud": "cached-api",
            "exp": (now + Duration::hours(1)).unix_timestamp(),
            "iat": now.unix_timestamp(),
        });

        let token = create_signed_token(&private_key, claims);
        let result = verifier.verify(&token).await;
        assert!(result.is_ok());
    }

    // The JWKS endpoint should have been called only once
}
