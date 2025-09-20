use xjp_oidc::exchange_code;
use xjp_oidc::types::{ExchangeCode, TokenResponse, OidcProviderMetadata};

#[tokio::test]
#[cfg(not(target_arch = "wasm32"))] // exchange_code is server-only
async fn test_exchange_code_flow() {
    let mut server = mockito::Server::new_async().await;
    let mock_issuer = server.url();
    
    // Setup discovery endpoint
    let metadata = OidcProviderMetadata {
        issuer: mock_issuer.clone(),
        authorization_endpoint: format!("{}/authorize", mock_issuer),
        token_endpoint: format!("{}/token", mock_issuer),
        jwks_uri: format!("{}/jwks", mock_issuer),
        userinfo_endpoint: Some(format!("{}/userinfo", mock_issuer)),
        end_session_endpoint: None,
        registration_endpoint: None,
        response_types_supported: Some(vec!["code".to_string()]),
        grant_types_supported: Some(vec!["authorization_code".to_string()]),
        scopes_supported: Some(vec!["openid".to_string(), "profile".to_string()]),
        token_endpoint_auth_methods_supported: Some(vec!["client_secret_basic".to_string()]),
        id_token_signing_alg_values_supported: Some(vec!["RS256".to_string()]),
        code_challenge_methods_supported: Some(vec!["S256".to_string()]),
    };
    
    let _discovery_mock = server.mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&metadata).unwrap())
        .create_async()
        .await;
    
    // Mock successful token exchange
    let token_response = TokenResponse {
        access_token: "test-access-token".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token: Some("test-refresh-token".to_string()),
        id_token: Some("test.id.token".to_string()),
        scope: Some("openid profile".to_string()),
    };
    
    let _token_mock = server.mock("POST", "/token")
        .match_header("content-type", "application/x-www-form-urlencoded")
        .match_body(mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded("grant_type".into(), "authorization_code".into()),
            mockito::Matcher::UrlEncoded("code".into(), "test-code".into()),
            mockito::Matcher::UrlEncoded("redirect_uri".into(), "https://app.example.com/callback".into()),
            mockito::Matcher::UrlEncoded("code_verifier".into(), "test-verifier".into()),
            mockito::Matcher::UrlEncoded("client_id".into(), "test-client".into()),
        ]))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&token_response).unwrap())
        .create_async()
        .await;
    
    let http_client = xjp_oidc::ReqwestHttpClient::default();
    
    let params = ExchangeCode {
        issuer: mock_issuer.clone(),
        client_id: "test-client".to_string(),
        code: "test-code".to_string(),
        redirect_uri: "https://app.example.com/callback".to_string(),
        code_verifier: "test-verifier".to_string(),
        client_secret: None, // Public client
    };
    
    let result = exchange_code(params, &http_client).await;
    assert!(result.is_ok());
    
    let response = result.unwrap();
    assert_eq!(response.access_token, "test-access-token");
    assert_eq!(response.token_type, "Bearer");
    assert_eq!(response.expires_in, 3600);
    assert_eq!(response.refresh_token, Some("test-refresh-token".to_string()));
    assert_eq!(response.id_token, Some("test.id.token".to_string()));
    assert_eq!(response.scope, Some("openid profile".to_string()));
}

#[tokio::test]
#[cfg(not(target_arch = "wasm32"))]
async fn test_exchange_code_with_client_secret() {
    let mut server = mockito::Server::new_async().await;
    let mock_issuer = server.url();
    
    // Setup discovery endpoint
    let metadata = OidcProviderMetadata {
        issuer: mock_issuer.clone(),
        authorization_endpoint: format!("{}/authorize", mock_issuer),
        token_endpoint: format!("{}/token", mock_issuer),
        jwks_uri: format!("{}/jwks", mock_issuer),
        userinfo_endpoint: None,
        end_session_endpoint: None,
        registration_endpoint: None,
        response_types_supported: Some(vec!["code".to_string()]),
        grant_types_supported: Some(vec!["authorization_code".to_string()]),
        scopes_supported: Some(vec!["openid".to_string()]),
        token_endpoint_auth_methods_supported: Some(vec!["client_secret_basic".to_string()]),
        id_token_signing_alg_values_supported: Some(vec!["RS256".to_string()]),
        code_challenge_methods_supported: Some(vec!["S256".to_string()]),
    };
    
    let _discovery_mock = server.mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&metadata).unwrap())
        .create_async()
        .await;
    
    // Mock token exchange with client secret
    let token_response = TokenResponse {
        access_token: "confidential-access-token".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token: Some("confidential-refresh-token".to_string()),
        id_token: Some("confidential.id.token".to_string()),
        scope: Some("openid".to_string()),
    };
    
    let _token_mock = server.mock("POST", "/token")
        .match_header("content-type", "application/x-www-form-urlencoded")
        .match_header("authorization", mockito::Matcher::Regex(r"^Basic .+$".to_string()))
        .match_body(mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded("grant_type".into(), "authorization_code".into()),
            mockito::Matcher::UrlEncoded("code".into(), "auth-code-123".into()),
            mockito::Matcher::UrlEncoded("redirect_uri".into(), "https://app.example.com/callback".into()),
            mockito::Matcher::UrlEncoded("code_verifier".into(), "verifier123".into()),
            // Note: client_id and client_secret are sent via Basic auth header, not in form
        ]))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&token_response).unwrap())
        .create_async()
        .await;
    
    let http_client = xjp_oidc::ReqwestHttpClient::default();
    
    let params = ExchangeCode {
        issuer: mock_issuer.clone(),
        client_id: "confidential-client".to_string(),
        code: "auth-code-123".to_string(),
        redirect_uri: "https://app.example.com/callback".to_string(),
        code_verifier: "verifier123".to_string(),
        client_secret: Some("super-secret".to_string()),
    };
    
    let result = exchange_code(params, &http_client).await;
    assert!(result.is_ok(), "Exchange code failed: {:?}", result.unwrap_err());
    
    let response = result.unwrap();
    assert_eq!(response.access_token, "confidential-access-token");
}

#[tokio::test]
#[cfg(not(target_arch = "wasm32"))]
async fn test_exchange_code_error_handling() {
    let mut server = mockito::Server::new_async().await;
    let mock_issuer = server.url();
    
    // Setup discovery endpoint
    let metadata = OidcProviderMetadata {
        issuer: mock_issuer.clone(),
        authorization_endpoint: format!("{}/authorize", mock_issuer),
        token_endpoint: format!("{}/token", mock_issuer),
        jwks_uri: format!("{}/jwks", mock_issuer),
        userinfo_endpoint: None,
        end_session_endpoint: None,
        registration_endpoint: None,
        response_types_supported: Some(vec!["code".to_string()]),
        grant_types_supported: Some(vec!["authorization_code".to_string()]),
        scopes_supported: Some(vec!["openid".to_string()]),
        token_endpoint_auth_methods_supported: Some(vec!["client_secret_basic".to_string()]),
        id_token_signing_alg_values_supported: Some(vec!["RS256".to_string()]),
        code_challenge_methods_supported: Some(vec!["S256".to_string()]),
    };
    
    let _discovery_mock = server.mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&metadata).unwrap())
        .create_async()
        .await;
    
    // Mock error response
    let error_response = serde_json::json!({
        "error": "invalid_grant",
        "error_description": "Authorization code is invalid or expired"
    });
    
    let _token_mock = server.mock("POST", "/token")
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body(error_response.to_string())
        .create_async()
        .await;
    
    let http_client = xjp_oidc::ReqwestHttpClient::default();
    
    let params = ExchangeCode {
        issuer: mock_issuer.clone(),
        client_id: "test-client".to_string(),
        code: "expired-code".to_string(),
        redirect_uri: "https://app.example.com/callback".to_string(),
        code_verifier: "test-verifier".to_string(),
        client_secret: None,
    };
    
    let result = exchange_code(params, &http_client).await;
    assert!(result.is_err());
    
    let error_message = result.unwrap_err().to_string();
    assert!(error_message.contains("invalid_grant") || error_message.contains("400"));
}