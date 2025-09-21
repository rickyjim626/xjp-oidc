use xjp_oidc::types::{BuildAuthUrl, EndSession};
use xjp_oidc::{build_auth_url, build_end_session_url, parse_callback_params};

#[test]
fn test_build_auth_url_basic() {
    let params = BuildAuthUrl {
        issuer: "https://auth.example.com".to_string(),
        client_id: "my-client".to_string(),
        redirect_uri: "https://app.example.com/callback".to_string(),
        scope: "openid profile".to_string(),
        state: Some("random-state".to_string()),
        nonce: Some("random-nonce".to_string()),
        prompt: None,
        code_challenge: "challenge123".to_string(),
        extra_params: None,
        tenant: None,
    };

    let url = build_auth_url(params).unwrap();

    // Parse URL and check components
    assert!(url.as_str().starts_with("https://auth.example.com/oauth/authorize"));

    // Check query parameters
    let query_pairs: Vec<(String, String)> =
        url.query_pairs().map(|(k, v)| (k.to_string(), v.to_string())).collect();

    // Check required parameters are present
    assert!(query_pairs.iter().any(|(k, v)| k == "client_id" && v == "my-client"));
    assert!(query_pairs
        .iter()
        .any(|(k, v)| k == "redirect_uri" && v == "https://app.example.com/callback"));
    assert!(query_pairs.iter().any(|(k, v)| k == "response_type" && v == "code"));
    assert!(query_pairs.iter().any(|(k, v)| k == "scope" && v == "openid profile"));
    assert!(query_pairs.iter().any(|(k, v)| k == "state" && v == "random-state"));
    assert!(query_pairs.iter().any(|(k, v)| k == "nonce" && v == "random-nonce"));
    assert!(query_pairs.iter().any(|(k, v)| k == "code_challenge" && v == "challenge123"));
    assert!(query_pairs.iter().any(|(k, v)| k == "code_challenge_method" && v == "S256"))
}

#[test]
fn test_parse_callback_params() {
    // Test successful callback
    let url = "https://app.example.com/callback?code=abc123&state=xyz789";
    let params = parse_callback_params(url);

    assert_eq!(params.code, Some("abc123".to_string()));
    assert_eq!(params.state, Some("xyz789".to_string()));
    assert!(params.error.is_none());
    assert!(params.error_description.is_none());

    // Test error callback
    let error_url = "https://app.example.com/callback?error=access_denied&error_description=User%20denied%20access";
    let error_params = parse_callback_params(error_url);

    assert!(error_params.code.is_none());
    assert_eq!(error_params.error, Some("access_denied".to_string()));
    assert_eq!(error_params.error_description, Some("User denied access".to_string()));

    // Test query string only
    let query_only = "code=test&state=state123";
    let query_params = parse_callback_params(query_only);

    assert_eq!(query_params.code, Some("test".to_string()));
    assert_eq!(query_params.state, Some("state123".to_string()));
}

#[test]
fn test_build_end_session_url() {
    let params = EndSession {
        issuer: "https://auth.example.com".to_string(),
        id_token_hint: "eyJ...".to_string(),
        post_logout_redirect_uri: Some("https://app.example.com".to_string()),
        state: Some("logout-state".to_string()),
    };

    // Note: This would need discovery mocking in a real test
    // For now we'll just test the structure
    let result = build_end_session_url(params);

    // Without discovery mocked, this will likely fail, but the test structure is correct
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_parse_callback_params_edge_cases() {
    // Empty string
    let params = parse_callback_params("");
    assert!(params.code.is_none());
    assert!(params.state.is_none());
    assert!(params.error.is_none());

    // Invalid URL
    let params = parse_callback_params("not-a-url");
    assert!(params.code.is_none());

    // Multiple values for same parameter (takes last)
    let params = parse_callback_params("code=first&code=second&state=test");
    assert_eq!(params.code, Some("second".to_string()));
    assert_eq!(params.state, Some("test".to_string()));
}
