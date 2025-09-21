use xjp_oidc::{fetch_jwks, Jwk, Jwks, MokaCacheImpl, NoOpCache};

fn create_test_jwks() -> Jwks {
    Jwks {
        keys: vec![
            Jwk {
                kty: "RSA".to_string(),
                use_: "sig".to_string(),
                kid: "test-key-1".to_string(),
                alg: Some("RS256".to_string()),
                n: Some("xjlCRBqkOL9XqJ_zZUXUWmr9TKsA6bmOKe8QVSG4H6tSM96WOn3sQE8RGCy7X0VVolmDpYSfnU5IM7KlJPXKjJUGKiWifUQU7QWdqhPXPq3z7oqPPtUk8hCKwqJbFgCrq3dcpTSDu38P8hcPbsCdOcxAi5CXZ2ilc0n9Na7YI_MYSHHMaVhIjgOzFCNH_pL1Eb8CQFGE79cG_rHDFBtKJIaSc7MfqBGU_uqB4BQYK3t5Y5nQh4zVkLgNoqJivr0GEXLP3Y5C2jw9PfZHZkgkc3IOjHa6hJrtn4JZYWUG4vOynk7TorEoFw6B8Zp9kEqgk8LnOzLVCB3waw6B9Q".to_string()),
                e: Some("AQAB".to_string()),
                x: None,
                y: None,
                crv: None,
            },
            Jwk {
                kty: "RSA".to_string(),
                use_: "sig".to_string(),
                kid: "test-key-2".to_string(),
                alg: Some("RS256".to_string()),
                n: Some("yGOr-H0A7KYqFcGNEXkzEM4vZkqPFJnGLPKi5TxsUZdaQr1c0BaXdGOyh0ZH_XKBqFrUTHgJ8Oh6kbqM06km74W3Jvbp-LxCC4goWaQU3eZKcX3xdiVVmj_6fHH2PjNPU-HzmS8SGCWhPvh1fN2CG9_4aVWJZxr95iGBD8Mhpwf9gQ5rZqfXdTWiAMGIxp6YP-49NiYWq8BAgl7NFT4DEqQPh_x1Kkqnt3hEF6x2qFP38eCGui6PxjWR3dVMw1dKiKpN-SdFxQ1YBmt8ProNQpXnPNGco0-Le6xA76B_Nk8X3mnUjr39x-G3LH9cdTLoDPBav-HSpCUtyBvkzw".to_string()),
                e: Some("AQAB".to_string()),
                x: None,
                y: None,
                crv: None,
            },
        ],
    }
}

#[tokio::test]
async fn test_fetch_jwks_basic() {
    let mut server = mockito::Server::new_async().await;
    let jwks_uri = format!("{}/jwks", server.url());

    let test_jwks = create_test_jwks();

    let _jwks_mock = server
        .mock("GET", "/jwks")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&test_jwks).unwrap())
        .create_async()
        .await;

    // Create HTTP client based on platform
    #[cfg(all(not(target_arch = "wasm32"), feature = "http-reqwest"))]
    let http_client = xjp_oidc::ReqwestHttpClient::default();
    #[cfg(all(target_arch = "wasm32", feature = "http-wasm"))]
    let http_client = xjp_oidc::WasmHttpClient::default();
    let cache = NoOpCache;

    let result = fetch_jwks(&jwks_uri, &http_client, &cache).await;
    assert!(result.is_ok());

    let fetched = result.unwrap();
    assert_eq!(fetched.keys.len(), 2);

    let key1 = &fetched.keys[0];
    assert_eq!(key1.kty, "RSA");
    assert_eq!(key1.kid, "test-key-1");
    assert_eq!(key1.alg, Some("RS256".to_string()));
    assert_eq!(key1.use_, "sig");

    let key2 = &fetched.keys[1];
    assert_eq!(key2.kid, "test-key-2");
}

#[tokio::test]
async fn test_fetch_jwks_with_cache() {
    let mut server = mockito::Server::new_async().await;
    let jwks_uri = format!("{}/jwks", server.url());

    let test_jwks = create_test_jwks();

    let _jwks_mock = server
        .mock("GET", "/jwks")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&test_jwks).unwrap())
        .expect(1) // Should only be called once due to caching
        .create_async()
        .await;

    // Create HTTP client based on platform
    #[cfg(all(not(target_arch = "wasm32"), feature = "http-reqwest"))]
    let http_client = xjp_oidc::ReqwestHttpClient::default();
    #[cfg(all(target_arch = "wasm32", feature = "http-wasm"))]
    let http_client = xjp_oidc::WasmHttpClient::default();
    let cache = MokaCacheImpl::new(10);

    // First fetch - should hit the server
    let result1 = fetch_jwks(&jwks_uri, &http_client, &cache).await;
    assert!(result1.is_ok());

    // Second fetch - should come from cache
    let result2 = fetch_jwks(&jwks_uri, &http_client, &cache).await;
    assert!(result2.is_ok());

    // Verify both results are the same
    let jwks1 = result1.unwrap();
    let jwks2 = result2.unwrap();
    assert_eq!(jwks1.keys.len(), jwks2.keys.len());
    assert_eq!(jwks1.keys[0].kid, jwks2.keys[0].kid);
}

#[tokio::test]
async fn test_fetch_jwks_error_cases() {
    let mut server = mockito::Server::new_async().await;
    let jwks_uri = format!("{}/jwks", server.url());
    // Create HTTP client based on platform
    #[cfg(all(not(target_arch = "wasm32"), feature = "http-reqwest"))]
    let http_client = xjp_oidc::ReqwestHttpClient::default();
    #[cfg(all(target_arch = "wasm32", feature = "http-wasm"))]
    let http_client = xjp_oidc::WasmHttpClient::default();
    let cache = NoOpCache;

    // Test 404 response
    let _not_found_mock = server.mock("GET", "/jwks").with_status(404).create_async().await;

    let result = fetch_jwks(&jwks_uri, &http_client, &cache).await;
    assert!(result.is_err());

    // Reset and test invalid JSON
    drop(_not_found_mock);
    let _invalid_json_mock = server
        .mock("GET", "/jwks")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("{invalid json}")
        .create_async()
        .await;

    let result = fetch_jwks(&jwks_uri, &http_client, &cache).await;
    assert!(result.is_err());

    // Reset and test empty keys array
    drop(_invalid_json_mock);
    let empty_jwks = Jwks { keys: vec![] };
    let _empty_mock = server
        .mock("GET", "/jwks")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&empty_jwks).unwrap())
        .create_async()
        .await;

    let result = fetch_jwks(&jwks_uri, &http_client, &cache).await;
    assert!(result.is_ok());
    let fetched = result.unwrap();
    assert_eq!(fetched.keys.len(), 0);
}

#[tokio::test]
async fn test_fetch_jwks_with_various_key_types() {
    let mut server = mockito::Server::new_async().await;
    let jwks_uri = format!("{}/jwks", server.url());

    let mixed_jwks = Jwks {
        keys: vec![
            // RSA key
            Jwk {
                kty: "RSA".to_string(),
                use_: "sig".to_string(),
                kid: "rsa-key".to_string(),
                alg: Some("RS256".to_string()),
                n: Some("test-n".to_string()),
                e: Some("AQAB".to_string()),
                x: None,
                y: None,
                crv: None,
            },
            // EC key
            Jwk {
                kty: "EC".to_string(),
                use_: "sig".to_string(),
                kid: "ec-key".to_string(),
                alg: Some("ES256".to_string()),
                n: None,
                e: None,
                x: Some("test-x".to_string()),
                y: Some("test-y".to_string()),
                crv: Some("P-256".to_string()),
            },
        ],
    };

    let _mixed_mock = server
        .mock("GET", "/jwks")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&mixed_jwks).unwrap())
        .create_async()
        .await;

    // Create HTTP client based on platform
    #[cfg(all(not(target_arch = "wasm32"), feature = "http-reqwest"))]
    let http_client = xjp_oidc::ReqwestHttpClient::default();
    #[cfg(all(target_arch = "wasm32", feature = "http-wasm"))]
    let http_client = xjp_oidc::WasmHttpClient::default();
    let cache = NoOpCache;

    let result = fetch_jwks(&jwks_uri, &http_client, &cache).await;
    assert!(result.is_ok());

    let fetched = result.unwrap();
    assert_eq!(fetched.keys.len(), 2);

    // Verify all key types are properly parsed
    assert_eq!(fetched.keys[0].kid, "rsa-key");
    assert_eq!(fetched.keys[0].kty, "RSA");
    assert!(fetched.keys[0].n.is_some());

    assert_eq!(fetched.keys[1].kid, "ec-key");
    assert_eq!(fetched.keys[1].kty, "EC");
    assert!(fetched.keys[1].x.is_some());
    assert!(fetched.keys[1].y.is_some());
    assert_eq!(fetched.keys[1].crv.as_ref().unwrap(), "P-256");
}
