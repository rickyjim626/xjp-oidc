use xjp_oidc::{Cache, NoOpCache, MokaCacheImpl};

#[test]
fn test_noop_cache() {
    use xjp_oidc::Cache as CacheTrait;
    let cache = NoOpCache;
    
    // Put should be a no-op
    <NoOpCache as CacheTrait<String, String>>::put(&cache, "key1".to_string(), "value1".to_string(), 60);
    
    // Get should always return None
    let result = <NoOpCache as CacheTrait<String, String>>::get(&cache, &"key1".to_string());
    assert!(result.is_none());
    
    // Remove should always return None
    let removed = <NoOpCache as CacheTrait<String, String>>::remove(&cache, &"key1".to_string());
    assert!(removed.is_none());
    
    // Clear should be a no-op
    <NoOpCache as CacheTrait<String, String>>::clear(&cache);
}

#[cfg(feature = "moka")]
#[tokio::test]
async fn test_moka_cache_basic() {
    let cache = MokaCacheImpl::new(100);
    
    // Test put and get
    cache.put("key1".to_string(), "value1".to_string(), 60);
    assert_eq!(cache.get(&"key1".to_string()), Some("value1".to_string()));
    
    // Test overwrite
    cache.put("key1".to_string(), "value2".to_string(), 60);
    assert_eq!(cache.get(&"key1".to_string()), Some("value2".to_string()));
    
    // Test remove
    let removed = cache.remove(&"key1".to_string());
    assert_eq!(removed, Some("value2".to_string()));
    assert!(cache.get(&"key1".to_string()).is_none());
    
    // Test multiple entries
    cache.put("a".to_string(), "1".to_string(), 60);
    cache.put("b".to_string(), "2".to_string(), 60);
    cache.put("c".to_string(), "3".to_string(), 60);
    
    assert_eq!(cache.get(&"a".to_string()), Some("1".to_string()));
    assert_eq!(cache.get(&"b".to_string()), Some("2".to_string()));
    assert_eq!(cache.get(&"c".to_string()), Some("3".to_string()));
    
    // Test clear
    cache.clear();
    assert!(cache.get(&"a".to_string()).is_none());
    assert!(cache.get(&"b".to_string()).is_none());
    assert!(cache.get(&"c".to_string()).is_none());
}

#[cfg(feature = "moka")]
#[tokio::test]
async fn test_moka_cache_with_complex_types() {
    use xjp_oidc::types::OidcProviderMetadata;
    
    let cache = MokaCacheImpl::new(10);
    
    let metadata = OidcProviderMetadata {
        issuer: "https://auth.example.com".to_string(),
        authorization_endpoint: "https://auth.example.com/authorize".to_string(),
        token_endpoint: "https://auth.example.com/token".to_string(),
        jwks_uri: "https://auth.example.com/jwks".to_string(),
        userinfo_endpoint: Some("https://auth.example.com/userinfo".to_string()),
        end_session_endpoint: None,
        registration_endpoint: None,
        response_types_supported: Some(vec!["code".to_string()]),
        grant_types_supported: Some(vec!["authorization_code".to_string()]),
        scopes_supported: Some(vec!["openid".to_string(), "profile".to_string()]),
        token_endpoint_auth_methods_supported: None,
        id_token_signing_alg_values_supported: Some(vec!["RS256".to_string()]),
        code_challenge_methods_supported: Some(vec!["S256".to_string()]),
    };
    
    cache.put("metadata:issuer1".to_string(), metadata.clone(), 300);
    
    let retrieved = cache.get(&"metadata:issuer1".to_string());
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.issuer, metadata.issuer);
    assert_eq!(retrieved.jwks_uri, metadata.jwks_uri);
}