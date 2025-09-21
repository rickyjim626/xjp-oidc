use josekit::{
    jwk::Jwk as JosekitJwk,
    jws::JwsHeader,
    jwt::{self, JwtPayload},
};
use serde_json::json;
use time::{Duration, OffsetDateTime};
use xjp_oidc::types::OidcProviderMetadata;
use xjp_oidc::{verify_id_token, Jwk, Jwks, MokaCacheImpl, NoOpCache, VerifyOptions};

// Helper function to create a test RSA key pair
fn create_test_keypair() -> (JosekitJwk, Jwk) {
    // Generate RSA key pair for testing
    let alg = josekit::jws::RS256;
    let mut jwk = JosekitJwk::generate_rsa_key(2048).unwrap();
    jwk.set_key_id("test-key-1");
    jwk.set_algorithm(alg.name());
    jwk.set_key_use("sig");

    // Convert to our Jwk type for JWKS endpoint
    let public_jwk = Jwk {
        kty: "RSA".to_string(),
        use_: "sig".to_string(),
        kid: "test-key-1".to_string(),
        alg: Some("RS256".to_string()),
        n: Some(jwk.parameter("n").unwrap().as_str().unwrap().to_string()),
        e: Some(jwk.parameter("e").unwrap().as_str().unwrap().to_string()),
        x: None,
        y: None,
        crv: None,
    };

    (jwk, public_jwk)
}

// Helper function to create and sign a test ID token
fn create_signed_id_token(jwk: &JosekitJwk, claims: serde_json::Value) -> String {
    let mut header = JwsHeader::new();
    header.set_token_type("JWT");
    header.set_algorithm("RS256");
    header.set_key_id("test-key-1");

    let payload = JwtPayload::from_map(claims.as_object().unwrap().clone()).unwrap();
    let signer = josekit::jws::RS256.signer_from_jwk(jwk).unwrap();
    let jwt = jwt::encode_with_signer(&payload, &header, &signer).unwrap();
    jwt
}

// Create HTTP client based on platform
#[cfg(all(not(target_arch = "wasm32"), feature = "http-reqwest"))]
fn create_http_client() -> xjp_oidc::ReqwestHttpClient {
    xjp_oidc::ReqwestHttpClient::default()
}

#[cfg(all(target_arch = "wasm32", feature = "http-wasm"))]
fn create_http_client() -> xjp_oidc::WasmHttpClient {
    xjp_oidc::WasmHttpClient::default()
}

#[tokio::test]
async fn test_verify_id_token_basic() {
    let mut server = mockito::Server::new_async().await;
    let issuer = server.url();

    // Create test keypair
    let (private_key, public_key) = create_test_keypair();

    // Setup JWKS endpoint
    let jwks = Jwks { keys: vec![public_key] };

    let _jwks_mock = server
        .mock("GET", "/jwks")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&jwks).unwrap())
        .create_async()
        .await;

    // Setup discovery endpoint
    let metadata = OidcProviderMetadata {
        issuer: issuer.clone(),
        authorization_endpoint: format!("{}/authorize", issuer),
        token_endpoint: format!("{}/token", issuer),
        jwks_uri: format!("{}/jwks", issuer),
        userinfo_endpoint: None,
        end_session_endpoint: None,
        registration_endpoint: None,
        response_types_supported: Some(vec!["code".to_string()]),
        grant_types_supported: Some(vec!["authorization_code".to_string()]),
        scopes_supported: Some(vec!["openid".to_string()]),
        token_endpoint_auth_methods_supported: None,
        id_token_signing_alg_values_supported: Some(vec!["RS256".to_string()]),
        code_challenge_methods_supported: Some(vec!["S256".to_string()]),
    };

    let _discovery_mock = server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&metadata).unwrap())
        .create_async()
        .await;

    // Create ID token claims
    let now = OffsetDateTime::now_utc();
    let exp = now + Duration::hours(1);
    let iat = now;
    let auth_time = now - Duration::minutes(5);

    let claims = json!({
        "iss": issuer,
        "sub": "user123",
        "aud": "test-client",
        "exp": exp.unix_timestamp(),
        "iat": iat.unix_timestamp(),
        "auth_time": auth_time.unix_timestamp(),
        "nonce": "test-nonce",
        "amr": ["pwd", "otp"],
        "xjp_admin": true,
    });

    let id_token = create_signed_id_token(&private_key, claims);

    // Verify the token
    let http_client = create_http_client();
    let jwks_cache = MokaCacheImpl::new(10);

    let opts = VerifyOptions {
        issuer: &issuer,
        audience: "test-client",
        nonce: Some("test-nonce"),
        max_age_sec: None,
        clock_skew_sec: None,
        http: &http_client,
        cache: &jwks_cache,
    };

    let result = verify_id_token(&id_token, opts).await;

    assert!(result.is_ok());

    let verified_token = result.unwrap();
    assert_eq!(verified_token.iss, issuer);
    assert_eq!(verified_token.sub, "user123");
    assert_eq!(verified_token.aud, "test-client");
    assert_eq!(verified_token.amr, Some(vec!["pwd".to_string(), "otp".to_string()]));
    assert_eq!(verified_token.xjp_admin, Some(true));
    assert!(verified_token.auth_time.is_some());
}

#[tokio::test]
async fn test_verify_id_token_invalid_signature() {
    let mut server = mockito::Server::new_async().await;
    let issuer = server.url();

    // Create two different keypairs
    let (private_key1, _) = create_test_keypair();
    let (_, public_key2) = create_test_keypair();

    // Setup JWKS endpoint with different public key
    let jwks = Jwks {
        keys: vec![public_key2], // Wrong public key
    };

    let _jwks_mock = server
        .mock("GET", "/jwks")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&jwks).unwrap())
        .create_async()
        .await;

    // Setup discovery endpoint
    let metadata = OidcProviderMetadata {
        issuer: issuer.clone(),
        authorization_endpoint: format!("{}/authorize", issuer),
        token_endpoint: format!("{}/token", issuer),
        jwks_uri: format!("{}/jwks", issuer),
        userinfo_endpoint: None,
        end_session_endpoint: None,
        registration_endpoint: None,
        response_types_supported: Some(vec!["code".to_string()]),
        grant_types_supported: Some(vec!["authorization_code".to_string()]),
        scopes_supported: Some(vec!["openid".to_string()]),
        token_endpoint_auth_methods_supported: None,
        id_token_signing_alg_values_supported: Some(vec!["RS256".to_string()]),
        code_challenge_methods_supported: Some(vec!["S256".to_string()]),
    };

    let _discovery_mock = server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&metadata).unwrap())
        .create_async()
        .await;

    // Create ID token signed with different key
    let now = OffsetDateTime::now_utc();
    let claims = json!({
        "iss": issuer,
        "sub": "user123",
        "aud": "test-client",
        "exp": (now + Duration::hours(1)).unix_timestamp(),
        "iat": now.unix_timestamp(),
    });

    let id_token = create_signed_id_token(&private_key1, claims);

    // Verify should fail due to signature mismatch
    let http_client = create_http_client();
    let jwks_cache = NoOpCache;

    let opts = VerifyOptions {
        issuer: &issuer,
        audience: "test-client",
        nonce: None,
        max_age_sec: None,
        clock_skew_sec: None,
        http: &http_client,
        cache: &jwks_cache,
    };

    let result = verify_id_token(&id_token, opts).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_verify_id_token_expired() {
    let mut server = mockito::Server::new_async().await;
    let issuer = server.url();

    let (private_key, public_key) = create_test_keypair();

    let jwks = Jwks { keys: vec![public_key] };

    let _jwks_mock = server
        .mock("GET", "/jwks")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&jwks).unwrap())
        .create_async()
        .await;

    let metadata = OidcProviderMetadata {
        issuer: issuer.clone(),
        authorization_endpoint: format!("{}/authorize", issuer),
        token_endpoint: format!("{}/token", issuer),
        jwks_uri: format!("{}/jwks", issuer),
        userinfo_endpoint: None,
        end_session_endpoint: None,
        registration_endpoint: None,
        response_types_supported: Some(vec!["code".to_string()]),
        grant_types_supported: Some(vec!["authorization_code".to_string()]),
        scopes_supported: Some(vec!["openid".to_string()]),
        token_endpoint_auth_methods_supported: None,
        id_token_signing_alg_values_supported: Some(vec!["RS256".to_string()]),
        code_challenge_methods_supported: Some(vec!["S256".to_string()]),
    };

    let _discovery_mock = server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&metadata).unwrap())
        .create_async()
        .await;

    // Create expired ID token
    let now = OffsetDateTime::now_utc();
    let claims = json!({
        "iss": issuer,
        "sub": "user123",
        "aud": "test-client",
        "exp": (now - Duration::hours(1)).unix_timestamp(), // Expired
        "iat": (now - Duration::hours(2)).unix_timestamp(),
    });

    let id_token = create_signed_id_token(&private_key, claims);

    let http_client = create_http_client();
    let jwks_cache = NoOpCache;

    let opts = VerifyOptions {
        issuer: &issuer,
        audience: "test-client",
        nonce: None,
        max_age_sec: None,
        clock_skew_sec: None,
        http: &http_client,
        cache: &jwks_cache,
    };

    let result = verify_id_token(&id_token, opts).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_verify_id_token_wrong_audience() {
    let mut server = mockito::Server::new_async().await;
    let issuer = server.url();

    let (private_key, public_key) = create_test_keypair();

    let jwks = Jwks { keys: vec![public_key] };

    let _jwks_mock = server
        .mock("GET", "/jwks")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&jwks).unwrap())
        .create_async()
        .await;

    let metadata = OidcProviderMetadata {
        issuer: issuer.clone(),
        authorization_endpoint: format!("{}/authorize", issuer),
        token_endpoint: format!("{}/token", issuer),
        jwks_uri: format!("{}/jwks", issuer),
        userinfo_endpoint: None,
        end_session_endpoint: None,
        registration_endpoint: None,
        response_types_supported: Some(vec!["code".to_string()]),
        grant_types_supported: Some(vec!["authorization_code".to_string()]),
        scopes_supported: Some(vec!["openid".to_string()]),
        token_endpoint_auth_methods_supported: None,
        id_token_signing_alg_values_supported: Some(vec!["RS256".to_string()]),
        code_challenge_methods_supported: Some(vec!["S256".to_string()]),
    };

    let _discovery_mock = server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&metadata).unwrap())
        .create_async()
        .await;

    let now = OffsetDateTime::now_utc();
    let claims = json!({
        "iss": issuer,
        "sub": "user123",
        "aud": "wrong-client", // Wrong audience
        "exp": (now + Duration::hours(1)).unix_timestamp(),
        "iat": now.unix_timestamp(),
    });

    let id_token = create_signed_id_token(&private_key, claims);

    let http_client = create_http_client();
    let jwks_cache = NoOpCache;

    let opts = VerifyOptions {
        issuer: &issuer,
        audience: "test-client", // Expected audience
        nonce: None,
        max_age_sec: None,
        clock_skew_sec: None,
        http: &http_client,
        cache: &jwks_cache,
    };

    let result = verify_id_token(&id_token, opts).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_verify_id_token_nonce_mismatch() {
    let mut server = mockito::Server::new_async().await;
    let issuer = server.url();

    let (private_key, public_key) = create_test_keypair();

    let jwks = Jwks { keys: vec![public_key] };

    let _jwks_mock = server
        .mock("GET", "/jwks")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&jwks).unwrap())
        .create_async()
        .await;

    let metadata = OidcProviderMetadata {
        issuer: issuer.clone(),
        authorization_endpoint: format!("{}/authorize", issuer),
        token_endpoint: format!("{}/token", issuer),
        jwks_uri: format!("{}/jwks", issuer),
        userinfo_endpoint: None,
        end_session_endpoint: None,
        registration_endpoint: None,
        response_types_supported: Some(vec!["code".to_string()]),
        grant_types_supported: Some(vec!["authorization_code".to_string()]),
        scopes_supported: Some(vec!["openid".to_string()]),
        token_endpoint_auth_methods_supported: None,
        id_token_signing_alg_values_supported: Some(vec!["RS256".to_string()]),
        code_challenge_methods_supported: Some(vec!["S256".to_string()]),
    };

    let _discovery_mock = server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&metadata).unwrap())
        .create_async()
        .await;

    let now = OffsetDateTime::now_utc();
    let claims = json!({
        "iss": issuer,
        "sub": "user123",
        "aud": "test-client",
        "exp": (now + Duration::hours(1)).unix_timestamp(),
        "iat": now.unix_timestamp(),
        "nonce": "wrong-nonce",
    });

    let id_token = create_signed_id_token(&private_key, claims);

    let http_client = create_http_client();
    let jwks_cache = NoOpCache;

    let opts = VerifyOptions {
        issuer: &issuer,
        audience: "test-client",
        nonce: Some("expected-nonce"), // Different nonce expected
        max_age_sec: None,
        clock_skew_sec: None,
        http: &http_client,
        cache: &jwks_cache,
    };

    let result = verify_id_token(&id_token, opts).await;

    assert!(result.is_err());
}
