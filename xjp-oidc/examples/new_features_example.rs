//! Example demonstrating the new SDK features

#[cfg(not(target_arch = "wasm32"))]
use xjp_oidc::{
    // Core imports
    http::ReqwestHttpClient,
    
    // New OAuth2 functions
    introspect_token, revoke_token, refresh_token, get_userinfo,
    IntrospectRequest, RefreshTokenRequest,
    
    // DCR functions
    register_client, get_client_config,
    RegisterRequest,
    
    // Multi-tenant support
    tenant::{TenantConfig, TenantMode},
};

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let http = ReqwestHttpClient::default();
    let issuer = "https://auth.xiaojinpro.com";
    
    println!("=== xjp-oidc New Features Example ===\n");
    
    // Example 1: Token Introspection
    println!("1. Token Introspection");
    let introspect_req = IntrospectRequest {
        issuer: issuer.to_string(),
        client_id: "xjp-web".to_string(),
        client_secret: Some("secret".to_string()),
        token: "some-access-token".to_string(),
        token_type_hint: Some("access_token".to_string()),
        token_endpoint_auth_method: None,
    };
    println!("   Would introspect token at: {}/oauth2/introspect", issuer);
    
    // Example 2: Token Revocation
    println!("\n2. Token Revocation");
    println!("   Would revoke token at: {}/oauth2/revoke", issuer);
    
    // Example 3: Refresh Token
    println!("\n3. Refresh Token");
    let refresh_req = RefreshTokenRequest {
        issuer: issuer.to_string(),
        client_id: "xjp-web".to_string(),
        client_secret: Some("secret".to_string()),
        refresh_token: "some-refresh-token".to_string(),
        scope: Some("openid profile email".to_string()),
        token_endpoint_auth_method: None,
    };
    println!("   Would refresh token at: {}/oauth2/token", issuer);
    
    // Example 4: UserInfo
    println!("\n4. UserInfo Endpoint");
    println!("   Would get user info at: {}/oidc/userinfo", issuer);
    println!("   Note: Currently uses POST due to HttpClient limitation");
    
    // Example 5: DCR Get Client Config
    println!("\n5. DCR Get Client Configuration");
    println!("   Would get client config at: {}/connect/register/{{client_id}}", issuer);
    
    // Example 6: Multi-tenant ClientId Mode
    println!("\n6. Multi-tenant ClientId Mode");
    let tenant_config = TenantConfig::client_id("xjp-web".to_string());
    let discovery_url = format!("{}/.well-known/openid-configuration", issuer);
    let tenant_url = tenant_config.apply_to_url(&discovery_url)?;
    println!("   Original URL: {}", discovery_url);
    println!("   Tenant URL:   {}", tenant_url);
    
    println!("\nNote: This example only demonstrates the API usage.");
    println!("In a real application, you would actually call these functions with a running auth server.");
    
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn main() {
    println!("This example is only available on non-WASM platforms.");
}