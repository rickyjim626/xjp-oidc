use xjp_oidc::types::OidcProviderMetadata;
use xjp_oidc::{discover, NoOpCache};

#[tokio::test]
async fn test_discover_metadata() {
    let mut server = mockito::Server::new_async().await;
    let mock_issuer = server.url();

    let metadata = OidcProviderMetadata {
        issuer: mock_issuer.clone(),
        authorization_endpoint: format!("{}/authorize", mock_issuer),
        token_endpoint: format!("{}/token", mock_issuer),
        jwks_uri: format!("{}/jwks", mock_issuer),
        userinfo_endpoint: Some(format!("{}/userinfo", mock_issuer)),
        end_session_endpoint: Some(format!("{}/logout", mock_issuer)),
        registration_endpoint: Some(format!("{}/register", mock_issuer)),
        response_types_supported: Some(vec!["code".to_string(), "token".to_string()]),
        grant_types_supported: Some(vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ]),
        scopes_supported: Some(vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ]),
        token_endpoint_auth_methods_supported: Some(vec![
            "client_secret_basic".to_string(),
            "client_secret_post".to_string(),
        ]),
        id_token_signing_alg_values_supported: Some(vec!["RS256".to_string(), "ES256".to_string()]),
        code_challenge_methods_supported: Some(vec!["S256".to_string(), "plain".to_string()]),
    };

    let _discovery_mock = server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&metadata).unwrap())
        .create_async()
        .await;

    // Create HTTP client based on platform
    #[cfg(all(not(target_arch = "wasm32"), feature = "http-reqwest"))]
    let http_client = xjp_oidc::ReqwestHttpClient::default();
    #[cfg(all(target_arch = "wasm32", feature = "http-wasm"))]
    let http_client = xjp_oidc::WasmHttpClient::default();
    let cache = NoOpCache;

    let result = discover(&mock_issuer, &http_client, &cache).await;
    assert!(result.is_ok());

    let discovered = result.unwrap();
    assert_eq!(discovered.issuer, mock_issuer);
    assert_eq!(discovered.authorization_endpoint, format!("{}/authorize", mock_issuer));
    assert_eq!(discovered.token_endpoint, format!("{}/token", mock_issuer));
    assert_eq!(discovered.jwks_uri, format!("{}/jwks", mock_issuer));
    assert_eq!(discovered.userinfo_endpoint, Some(format!("{}/userinfo", mock_issuer)));
    assert_eq!(discovered.end_session_endpoint, Some(format!("{}/logout", mock_issuer)));
    assert_eq!(discovered.registration_endpoint, Some(format!("{}/register", mock_issuer)));

    assert!(discovered.response_types_supported.as_ref().unwrap().contains(&"code".to_string()));
    assert!(discovered
        .grant_types_supported
        .as_ref()
        .unwrap()
        .contains(&"authorization_code".to_string()));
    assert!(discovered.scopes_supported.as_ref().unwrap().contains(&"openid".to_string()));
    assert!(discovered
        .id_token_signing_alg_values_supported
        .as_ref()
        .unwrap()
        .contains(&"RS256".to_string()));
    assert!(discovered
        .code_challenge_methods_supported
        .as_ref()
        .unwrap()
        .contains(&"S256".to_string()));
}

#[tokio::test]
async fn test_discover_with_trailing_slash() {
    let mut server = mockito::Server::new_async().await;
    let mock_issuer = format!("{}/", server.url());
    let mock_issuer_clean = server.url();

    let metadata = OidcProviderMetadata {
        issuer: mock_issuer_clean.clone(),
        authorization_endpoint: format!("{}/authorize", mock_issuer_clean),
        token_endpoint: format!("{}/token", mock_issuer_clean),
        jwks_uri: format!("{}/jwks", mock_issuer_clean),
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

    // Create HTTP client based on platform
    #[cfg(all(not(target_arch = "wasm32"), feature = "http-reqwest"))]
    let http_client = xjp_oidc::ReqwestHttpClient::default();
    #[cfg(all(target_arch = "wasm32", feature = "http-wasm"))]
    let http_client = xjp_oidc::WasmHttpClient::default();
    let cache = NoOpCache;

    // Should handle trailing slash properly
    let result = discover(&mock_issuer, &http_client, &cache).await;
    assert!(result.is_ok());

    let discovered = result.unwrap();
    assert_eq!(discovered.issuer, mock_issuer_clean);
}

#[tokio::test]
async fn test_discover_error_cases() {
    let mut server = mockito::Server::new_async().await;
    let mock_issuer = server.url();
    // Create HTTP client based on platform
    #[cfg(all(not(target_arch = "wasm32"), feature = "http-reqwest"))]
    let http_client = xjp_oidc::ReqwestHttpClient::default();
    #[cfg(all(target_arch = "wasm32", feature = "http-wasm"))]
    let http_client = xjp_oidc::WasmHttpClient::default();
    let cache = NoOpCache;

    // Test 404 response
    let _not_found_mock = server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(404)
        .create_async()
        .await;

    let result = discover(&mock_issuer, &http_client, &cache).await;
    assert!(result.is_err());

    // Reset and test invalid JSON
    drop(_not_found_mock);
    let _invalid_json_mock = server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("{invalid json}")
        .create_async()
        .await;

    let result = discover(&mock_issuer, &http_client, &cache).await;
    assert!(result.is_err());

    // Reset and test missing required fields
    drop(_invalid_json_mock);
    let incomplete_metadata = serde_json::json!({
        "issuer": mock_issuer,
        // Missing required fields
    });

    let _incomplete_mock = server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(incomplete_metadata.to_string())
        .create_async()
        .await;

    let result = discover(&mock_issuer, &http_client, &cache).await;
    assert!(result.is_err());
}
