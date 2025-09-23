//! Example of using multi-tenant OIDC discovery

use xjp_oidc::{
    cache::MemoryCache,
    discovery_tenant::{discover_with_tenant, discover_with_tenant_resolution},
    http_tenant::reqwest_tenant::ReqwestHttpClientWithAdminSupport,
    tenant::{TenantConfig, TenantResolution},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .with_thread_ids(false)
        .init();

    println!("=== 多租户 OIDC Discovery 测试 ===\n");

    // Create HTTP client with admin support
    let http_client = ReqwestHttpClientWithAdminSupport::new()?;
    let cache = MemoryCache::new();

    // Test environment
    let issuer = "https://auth.xiaojinpro.com";

    println!("测试环境: {}\n", issuer);

    // Test 1: Single tenant mode (will fail with current backend)
    println!("1. 测试单租户模式（预期失败）...");
    let single_config = TenantConfig::single();
    match discover_with_tenant(issuer, &single_config, &http_client, &cache).await {
        Ok(metadata) => {
            println!("✅ 成功！");
            println!("   Issuer: {}", metadata.issuer);
            println!("   Authorization: {}", metadata.authorization_endpoint);
        }
        Err(e) => {
            println!("❌ 失败（预期）: {}", e);
        }
    }
    println!();

    // Test 2: Query parameter mode
    println!("2. 测试查询参数模式...");
    let query_config = TenantConfig::query_param("xiaojinpro".to_string());
    match discover_with_tenant(issuer, &query_config, &http_client, &cache).await {
        Ok(metadata) => {
            println!("✅ 成功！");
            println!("   Issuer: {}", metadata.issuer);
            println!("   Authorization: {}", metadata.authorization_endpoint);
            println!("   Token: {}", metadata.token_endpoint);
            println!("   JWKS: {}", metadata.jwks_uri);
            if let Some(tenant_id) = metadata.tenant_id {
                println!("   Tenant ID: {}", tenant_id);
            }
            if let Some(tenant_slug) = &metadata.tenant_slug {
                println!("   Tenant Slug: {}", tenant_slug);
            }
        }
        Err(e) => {
            println!("❌ 失败: {}", e);
        }
    }
    println!();

    // Test 3: ClientId mode (Recommended)
    println!("3. 测试ClientId模式 (推荐)...");
    let client_id_config = TenantConfig::client_id("xjp-web".to_string());
    match discover_with_tenant(issuer, &client_id_config, &http_client, &cache).await {
        Ok(metadata) => {
            println!("✅ 成功！");
            println!("   Issuer: {}", metadata.issuer);
            println!("   Authorization: {}", metadata.authorization_endpoint);
            println!("   Token: {}", metadata.token_endpoint);
            println!("   JWKS: {}", metadata.jwks_uri);
            if let Some(tenant_id) = metadata.tenant_id {
                println!("   Tenant ID: {}", tenant_id);
            }
            if let Some(tenant_slug) = &metadata.tenant_slug {
                println!("   Tenant Slug: {}", tenant_slug);
            }
        }
        Err(e) => {
            println!("❌ 失败: {}", e);
        }
    }
    println!();

    // Test 4: Test with new TenantResolution priority system
    println!("4. 测试新的TenantResolution优先级系统...");
    let prod_issuer = "https://auth.xiaojinpro.com";
    let tenant_resolution = TenantResolution {
        client_id_tenant: Some("xjp-web".to_string()),
        admin_override_tenant: None,
        default_tenant: Some("xiaojinpro".to_string()),
    };
    match discover_with_tenant_resolution(prod_issuer, &tenant_resolution, &http_client, &cache).await {
        Ok(metadata) => {
            println!("✅ 成功！");
            println!("   完整配置:");
            println!("   - Issuer: {}", metadata.issuer);
            println!("   - Auth Endpoint: {}", metadata.authorization_endpoint);
            println!("   - Token Endpoint: {}", metadata.token_endpoint);
            if let Some(userinfo) = &metadata.userinfo_endpoint {
                println!("   - UserInfo Endpoint: {}", userinfo);
            }
            println!("   - JWKS URI: {}", metadata.jwks_uri);
            println!("   - Supported Scopes: {:?}", metadata.scopes_supported);
            println!("   - Response Types: {:?}", metadata.response_types_supported);
            println!("   - Grant Types: {:?}", metadata.grant_types_supported);
        }
        Err(e) => {
            println!("❌ 失败: {}", e);
        }
    }

    println!("\n=== 测试完成 ===");

    Ok(())
}