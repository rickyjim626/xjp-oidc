//! Integration tests for introspection and userinfo features

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use xjp_oidc::{
        introspect_token, revoke_token, get_userinfo,
        IntrospectRequest, UserInfo,
        http::ReqwestHttpClient,
    };

    #[test]
    fn test_introspect_request_creation() {
        let req = IntrospectRequest {
            issuer: "https://auth.example.com".to_string(),
            client_id: "test-client".to_string(),
            client_secret: Some("secret".to_string()),
            token: "test-token".to_string(),
            token_type_hint: Some("access_token".to_string()),
            token_endpoint_auth_method: Some("client_secret_basic".to_string()),
        };

        assert_eq!(req.issuer, "https://auth.example.com");
        assert_eq!(req.client_id, "test-client");
        assert_eq!(req.client_secret, Some("secret".to_string()));
        assert_eq!(req.token, "test-token");
        assert_eq!(req.token_type_hint, Some("access_token".to_string()));
    }

    #[test]
    fn test_userinfo_deserialization() {
        let json = serde_json::json!({
            "sub": "user-123",
            "name": "Test User",
            "email": "test@example.com",
            "email_verified": true,
            "xjp_admin": true
        });

        let userinfo: UserInfo = serde_json::from_value(json).unwrap();
        assert_eq!(userinfo.sub, "user-123");
        assert_eq!(userinfo.name, Some("Test User".to_string()));
        assert_eq!(userinfo.email, Some("test@example.com".to_string()));
        assert_eq!(userinfo.email_verified, Some(true));
        assert_eq!(userinfo.xjp_admin, Some(true));
    }

    #[tokio::test]
    async fn test_function_signatures() {
        // 这个测试只是验证函数签名是否正确编译
        // 实际的网络调用会失败，但我们只关心编译
        
        let http = ReqwestHttpClient::default();
        
        // 测试 introspect_token 函数签名
        let introspect_req = IntrospectRequest {
            issuer: "https://auth.example.com".to_string(),
            client_id: "test".to_string(),
            client_secret: None,
            token: "token".to_string(),
            token_type_hint: None,
            token_endpoint_auth_method: None,
        };
        
        let _ = introspect_token(introspect_req, &http).await;
        
        // 测试 revoke_token 函数签名
        let _ = revoke_token(
            "https://auth.example.com",
            "test-client",
            Some("secret"),
            "token",
            Some("refresh_token"),
            None,
            &http
        ).await;
        
        // 测试 get_userinfo 函数签名
        let _ = get_userinfo(
            "https://auth.example.com",
            "access_token",
            &http
        ).await;
    }
}