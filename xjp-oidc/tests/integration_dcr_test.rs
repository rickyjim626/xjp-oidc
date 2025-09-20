use xjp_oidc::register_if_needed;
use xjp_oidc::types::{RegisterRequest, OidcProviderMetadata};

#[tokio::test]
#[cfg(not(target_arch = "wasm32"))] // DCR is server-only
async fn test_register_new_client() {
    let mut server = mockito::Server::new_async().await;
    let mock_issuer = server.url();
    
    // Setup discovery endpoint with registration endpoint
    let metadata = OidcProviderMetadata {
        issuer: mock_issuer.clone(),
        authorization_endpoint: format!("{}/authorize", mock_issuer),
        token_endpoint: format!("{}/token", mock_issuer),
        jwks_uri: format!("{}/jwks", mock_issuer),
        userinfo_endpoint: None,
        end_session_endpoint: None,
        registration_endpoint: Some(format!("{}/register", mock_issuer)),
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
    
    // Mock successful registration
    let client_response = serde_json::json!({
        "client_id": "new-client-12345",
        "client_secret": "generated-secret-xyz",
        "client_id_issued_at": 1234567890,
        "client_secret_expires_at": 0,
        "redirect_uris": ["https://app.example.com/callback"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "client_name": "Test Application",
        "token_endpoint_auth_method": "client_secret_basic",
        "application_type": "web",
        "status": "active"
    });
    
    let _register_mock = server.mock("POST", "/register")
        .match_header("authorization", "Bearer test-token")
        .match_header("content-type", "application/json")
        .match_body(mockito::Matcher::Json(serde_json::json!({
            "redirect_uris": ["https://app.example.com/callback"],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "client_secret_basic",
            "scope": "openid profile",
            "response_types": ["code"],
            "application_type": "web",
            "client_name": "Test Application"
        })))
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(client_response.to_string())
        .create_async()
        .await;
    
    let http_client = xjp_oidc::ReqwestHttpClient::default();
    
    let req = RegisterRequest {
        application_type: Some("web".to_string()),
        redirect_uris: vec!["https://app.example.com/callback".to_string()],
        post_logout_redirect_uris: None,
        grant_types: vec!["authorization_code".to_string()],
        token_endpoint_auth_method: "client_secret_basic".to_string(),
        scope: "openid profile".to_string(),
        client_name: Some("Test Application".to_string()),
        contacts: None,
        software_id: None,
    };
    
    let result = register_if_needed(&mock_issuer, "test-token", req, &http_client).await;
    assert!(result.is_ok(), "Failed to register: {:?}", result.err());
    
    let registration = result.unwrap();
    assert_eq!(registration.client_id, "new-client-12345");
    assert_eq!(registration.client_secret, Some("generated-secret-xyz".to_string()));
    assert_eq!(registration.client_name, "Test Application");
}

#[tokio::test] 
#[cfg(not(target_arch = "wasm32"))]
async fn test_register_no_endpoint() {
    let mut server = mockito::Server::new_async().await;
    let mock_issuer = server.url();
    
    // Setup discovery endpoint WITHOUT registration endpoint
    let metadata = OidcProviderMetadata {
        issuer: mock_issuer.clone(),
        authorization_endpoint: format!("{}/authorize", mock_issuer),
        token_endpoint: format!("{}/token", mock_issuer),
        jwks_uri: format!("{}/jwks", mock_issuer),
        userinfo_endpoint: None,
        end_session_endpoint: None,
        registration_endpoint: None, // No registration endpoint
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
    
    let http_client = xjp_oidc::ReqwestHttpClient::default();
    
    let req = RegisterRequest {
        application_type: None,
        redirect_uris: vec!["https://app.example.com/callback".to_string()],
        post_logout_redirect_uris: None,
        grant_types: vec!["authorization_code".to_string()],
        token_endpoint_auth_method: "client_secret_basic".to_string(),
        scope: "openid".to_string(),
        client_name: Some("Test Application".to_string()),
        contacts: None,
        software_id: None,
    };
    
    let result = register_if_needed(&mock_issuer, "test-token", req, &http_client).await;
    assert!(result.is_err());
    
    let error = result.unwrap_err();
    let error_msg = error.to_string();
    println!("Registration error: {}", error_msg);
    assert!(error_msg.contains("registration") || 
            error_msg.contains("not supported") || 
            error_msg.contains("Registration"));
}

#[tokio::test]
#[cfg(not(target_arch = "wasm32"))]
async fn test_register_with_contacts() {
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
        registration_endpoint: Some(format!("{}/register", mock_issuer)),
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
    
    // Mock registration with contacts
    let client_response = serde_json::json!({
        "client_id": "client-with-contacts",
        "client_secret": "secret123",
        "client_id_issued_at": 1234567890,
        "client_secret_expires_at": 0,
        "redirect_uris": ["https://app.example.com/callback"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "client_name": "App with Contacts",
        "contacts": ["admin@example.com", "support@example.com"],
        "status": "active"
    });
    
    let _register_mock = server.mock("POST", "/register")
        .match_header("authorization", "Bearer test-token")
        .match_header("content-type", "application/json")
        .match_body(mockito::Matcher::Json(serde_json::json!({
            "redirect_uris": ["https://app.example.com/callback"],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "client_secret_basic",
            "scope": "openid",
            "response_types": ["code"],
            "client_name": "App with Contacts",
            "contacts": ["admin@example.com", "support@example.com"]
        })))
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(client_response.to_string())
        .create_async()
        .await;
    
    let http_client = xjp_oidc::ReqwestHttpClient::default();
    
    let req = RegisterRequest {
        application_type: None,
        redirect_uris: vec!["https://app.example.com/callback".to_string()],
        post_logout_redirect_uris: None,
        grant_types: vec!["authorization_code".to_string()],
        token_endpoint_auth_method: "client_secret_basic".to_string(),
        scope: "openid".to_string(),
        client_name: Some("App with Contacts".to_string()),
        contacts: Some(vec!["admin@example.com".to_string(), "support@example.com".to_string()]),
        software_id: None,
    };
    
    let result = register_if_needed(&mock_issuer, "test-token", req, &http_client).await;
    assert!(result.is_ok(), "Failed to register: {:?}", result.err());
    
    let registration = result.unwrap();
    assert_eq!(registration.client_id, "client-with-contacts");
}

#[tokio::test]
#[cfg(not(target_arch = "wasm32"))]
async fn test_register_error_handling() {
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
        registration_endpoint: Some(format!("{}/register", mock_issuer)),
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
        "error": "invalid_request",
        "error_description": "Invalid redirect URI"
    });
    
    let _register_mock = server.mock("POST", "/register")
        .match_header("authorization", "Bearer test-token")
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body(error_response.to_string())
        .create_async()
        .await;
    
    let http_client = xjp_oidc::ReqwestHttpClient::default();
    
    let req = RegisterRequest {
        application_type: None,
        redirect_uris: vec!["invalid://redirect".to_string()],
        post_logout_redirect_uris: None,
        grant_types: vec!["authorization_code".to_string()],
        token_endpoint_auth_method: "client_secret_basic".to_string(),
        scope: "openid".to_string(),
        client_name: Some("Bad App".to_string()),
        contacts: None,
        software_id: None,
    };
    
    let result = register_if_needed(&mock_issuer, "test-token", req, &http_client).await;
    assert!(result.is_err());
    
    let error = result.unwrap_err();
    assert!(error.to_string().contains("invalid_request") || error.to_string().contains("400"));
}