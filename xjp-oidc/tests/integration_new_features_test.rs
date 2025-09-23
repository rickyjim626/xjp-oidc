//! Integration tests for new SDK features

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use xjp_oidc::{
        http::ReqwestHttpClient,
        introspect_token, revoke_token, refresh_token, get_userinfo, get_client_config,
        IntrospectRequest, IntrospectResponse, RefreshTokenRequest, UserInfo, ClientConfig,
        tenant::TenantConfig,
        OidcProviderMetadata,
    };
    
    const TEST_ISSUER: &str = "https://auth.xiaojinpro.com";
    
    #[test]
    fn test_new_metadata_fields() {
        // Test that new fields in OidcProviderMetadata compile
        let metadata = OidcProviderMetadata {
            issuer: TEST_ISSUER.to_string(),
            authorization_endpoint: format!("{}/oauth2/authorize", TEST_ISSUER),
            token_endpoint: format!("{}/oauth2/token", TEST_ISSUER),
            jwks_uri: format!("{}/.well-known/jwks.json", TEST_ISSUER),
            userinfo_endpoint: Some(format!("{}/oidc/userinfo", TEST_ISSUER)),
            end_session_endpoint: Some(format!("{}/oidc/end_session", TEST_ISSUER)),
            registration_endpoint: Some(format!("{}/connect/register", TEST_ISSUER)),
            // New fields
            introspection_endpoint: Some(format!("{}/oauth2/introspect", TEST_ISSUER)),
            revocation_endpoint: Some(format!("{}/oauth2/revoke", TEST_ISSUER)),
            frontchannel_logout_supported: Some(true),
            frontchannel_logout_session_supported: Some(true),
            backchannel_logout_supported: Some(false),
            backchannel_logout_session_supported: Some(false),
            // Other fields
            response_types_supported: Some(vec!["code".to_string()]),
            grant_types_supported: Some(vec!["authorization_code".to_string(), "refresh_token".to_string()]),
            scopes_supported: Some(vec!["openid".to_string(), "profile".to_string(), "email".to_string()]),
            token_endpoint_auth_methods_supported: Some(vec!["client_secret_basic".to_string(), "client_secret_post".to_string()]),
            id_token_signing_alg_values_supported: Some(vec!["RS256".to_string()]),
            code_challenge_methods_supported: Some(vec!["S256".to_string()]),
            tenant_id: None,
            tenant_slug: None,
        };
        
        assert_eq!(metadata.introspection_endpoint, Some(format!("{}/oauth2/introspect", TEST_ISSUER)));
        assert_eq!(metadata.revocation_endpoint, Some(format!("{}/oauth2/revoke", TEST_ISSUER)));
        assert_eq!(metadata.frontchannel_logout_supported, Some(true));
    }
    
    #[test]
    fn test_introspect_request_creation() {
        let req = IntrospectRequest {
            issuer: TEST_ISSUER.to_string(),
            client_id: "test-client".to_string(),
            client_secret: Some("secret".to_string()),
            token: "test-token".to_string(),
            token_type_hint: Some("access_token".to_string()),
            token_endpoint_auth_method: Some("client_secret_basic".to_string()),
        };
        
        assert_eq!(req.issuer, TEST_ISSUER);
        assert_eq!(req.token_type_hint, Some("access_token".to_string()));
    }
    
    #[test]
    fn test_introspect_response_parsing() {
        let json = serde_json::json!({
            "active": true,
            "scope": "openid profile email",
            "client_id": "test-client",
            "username": "user@example.com",
            "token_type": "Bearer",
            "exp": 1234567890,
            "iat": 1234567800,
            "sub": "user123",
            "iss": TEST_ISSUER
        });
        
        let response: IntrospectResponse = serde_json::from_value(json).unwrap();
        assert_eq!(response.active, true);
        assert_eq!(response.scope, Some("openid profile email".to_string()));
        assert_eq!(response.client_id, Some("test-client".to_string()));
    }
    
    #[test]
    fn test_refresh_token_request_creation() {
        let req = RefreshTokenRequest {
            issuer: TEST_ISSUER.to_string(),
            client_id: "test-client".to_string(),
            client_secret: Some("secret".to_string()),
            refresh_token: "refresh-token-here".to_string(),
            scope: Some("openid profile".to_string()),
            token_endpoint_auth_method: None,
        };
        
        assert_eq!(req.refresh_token, "refresh-token-here");
        assert_eq!(req.scope, Some("openid profile".to_string()));
    }
    
    #[test]
    fn test_userinfo_response_parsing() {
        let json = serde_json::json!({
            "sub": "user123",
            "name": "Test User",
            "email": "test@example.com",
            "email_verified": true,
            "picture": "https://example.com/picture.jpg",
            // Custom claims
            "xjp_admin": true,
            "amr": ["wechat_qr"],
            "auth_time": 1234567890
        });
        
        let userinfo: UserInfo = serde_json::from_value(json).unwrap();
        assert_eq!(userinfo.sub, "user123");
        assert_eq!(userinfo.name, Some("Test User".to_string()));
        assert_eq!(userinfo.xjp_admin, Some(true));
        assert_eq!(userinfo.amr, Some(vec!["wechat_qr".to_string()]));
    }
    
    #[test]
    fn test_client_config_parsing() {
        let json = serde_json::json!({
            "client_id": "test-client",
            "client_secret": "secret",
            "client_name": "Test Application",
            "redirect_uris": ["https://app.example.com/callback"],
            "post_logout_redirect_uris": ["https://app.example.com"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_basic",
            "scope": "openid profile email",
            "client_secret_expires_at": 1234567890
        });
        
        let config: ClientConfig = serde_json::from_value(json).unwrap();
        assert_eq!(config.client_id, "test-client");
        assert_eq!(config.client_name, "Test Application");
        assert_eq!(config.grant_types.len(), 2);
        assert_eq!(config.client_secret_expires_at, Some(1234567890));
    }
    
    #[test]
    fn test_tenant_client_id_mode() {
        use xjp_oidc::tenant::TenantConfig;
        
        let config = TenantConfig::client_id("xjp-web".to_string());
        assert!(config.validate().is_ok());
        
        let url = "https://auth.xiaojinpro.com/.well-known/openid-configuration";
        let result = config.apply_to_url(url).unwrap();
        assert_eq!(result, "https://auth.xiaojinpro.com/.well-known/openid-configuration?client_id=xjp-web");
    }

    #[tokio::test]
    async fn test_function_signatures_compile() {
        // This test just verifies that the function signatures compile correctly
        // It doesn't actually call them since we don't have a real server
        
        // Just verify the types exist and can be used
        let _http = ReqwestHttpClient::default();
        
        // The function signatures should compile without errors
        let _: fn(IntrospectRequest, &dyn xjp_oidc::http::HttpClient) -> _ = introspect_token;
        let _: fn(&str, &str, Option<&str>, &str, Option<&str>, Option<&str>, &dyn xjp_oidc::http::HttpClient) -> _ = revoke_token;
        let _: fn(RefreshTokenRequest, &dyn xjp_oidc::http::HttpClient) -> _ = refresh_token;
        let _: fn(&str, &str, &dyn xjp_oidc::http::HttpClient) -> _ = get_userinfo;
        let _: fn(&str, &str, &str, &dyn xjp_oidc::http::HttpClient) -> _ = get_client_config;
    }
}