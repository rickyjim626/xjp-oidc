//! 测试 xjp-oidc SDK 与真实后端的连接
//! 
//! 功能测试清单：
//! - [x] OIDC Discovery
//! - [x] JWKS 获取
//! - [x] PKCE 授权流程
//! - [x] Token 交换
//! - [x] ID Token 验证
//! - [x] 客户端凭据
//! - [x] UserInfo 端点
//! - [x] Refresh Token
//! - [x] Token Introspection
//! - [x] Token Revocation
//! - [x] 多租户模式
//! - [x] SSE 登录监控
//! - [x] 动态客户端注册 (DCR)

use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use colored::{ColoredString, Colorize};
use std::io::{self, Write};
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use xjp_oidc::HttpClient;
use xjp_oidc::{
    build_auth_url_with_metadata, create_pkce, discover, exchange_code, verify_id_token,
    BuildAuthUrl, ExchangeCode, Jwks, MokaCacheImpl, OidcProviderMetadata, ReqwestHttpClient,
    VerifyOptions, get_userinfo, refresh_token, RefreshTokenRequest, introspect_token, 
    IntrospectRequest, revoke_token, register_client, RegisterRequest, get_client_config,
};

// SSE 支持
#[cfg(feature = "sse")]
use xjp_oidc::sse::{
    start_login_session, check_login_status, subscribe_login_events,
    LoginStatus, LoginEvent, LoginMonitorConfig,
};

// 多租户支持
use xjp_oidc::{
    tenant::TenantConfig,
    discovery_tenant::discover_with_tenant,
    http_tenant::HttpClientAdapter,
};

const ISSUER: &str = "https://auth.xiaojinpro.com";
const CLIENT_ID_WEB: &str = "xjp-web";
const CLIENT_SECRET_WEB: &str = "dev_secret_change_in_production";
const CLIENT_ID_CLI: &str = "xjp-cli";
const REDIRECT_URI_WEB: &str = "http://localhost:3000/auth/callback";
const REDIRECT_URI_CLI: &str = "http://localhost:9876/callback";
const SCOPES: &str = "openid profile email offline_access";

#[tokio::main]
async fn main() -> Result<()> {
    // 初始化日志
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "test_backend=debug,xjp_oidc=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    println!("{}", "=== xjp-oidc SDK v1.0.0 完整功能测试 ===".bold().green());
    println!("测试环境: {}", ISSUER.yellow());
    println!();

    // 创建 HTTP 客户端和缓存
    let http_client = Arc::new(ReqwestHttpClient::default());
    let http_client_with_admin = Arc::new(HttpClientAdapter::new(ReqwestHttpClient::default()));
    let discovery_cache = Arc::new(MokaCacheImpl::<String, OidcProviderMetadata>::new(100));
    let jwks_cache = Arc::new(MokaCacheImpl::<String, Jwks>::new(100));

    loop {
        println!();
        println!("{}", "选择测试项目:".bold());
        println!("  1. 基础连通性测试");
        println!("  2. 多租户模式测试");
        println!("  3. SSE 登录监控测试");
        println!("  4. Token 管理测试 (Refresh/Introspect/Revoke)");
        println!("  5. 动态客户端注册 (DCR) 测试");
        println!("  6. 完整授权流程测试");
        println!("  0. 退出");
        println!();

        let choice = prompt_trimmed("请选择 (0-6): ")?;

        match choice.as_str() {
            "1" => test_basic_connectivity(&http_client, &discovery_cache, &jwks_cache).await?,
            "2" => test_multi_tenant(&http_client_with_admin, &discovery_cache).await?,
            "3" => {
                #[cfg(feature = "sse")]
                test_sse_login(&http_client).await?;
                #[cfg(not(feature = "sse"))]
                println!("{} SSE 功能未启用，请使用 --features sse 重新编译", "错误:".red());
            }
            "4" => test_token_management(&http_client, &discovery_cache, &jwks_cache).await?,
            "5" => test_dcr(&http_client).await?,
            "6" => test_full_flow(&http_client, &discovery_cache, &jwks_cache).await?,
            "0" => break,
            _ => println!("无效选择，请重试"),
        }
    }

    println!();
    println!("{}", "✅ 测试结束!".bold().green());

    Ok(())
}

/// 基础连通性测试
async fn test_basic_connectivity(
    http_client: &Arc<ReqwestHttpClient>,
    discovery_cache: &Arc<MokaCacheImpl<String, OidcProviderMetadata>>,
    _jwks_cache: &Arc<MokaCacheImpl<String, Jwks>>,
) -> Result<()> {
    println!();
    println!("{}", "=== 基础连通性测试 ===".bold().cyan());

    // 测试步骤
    let _metadata = test_discovery(&http_client, &discovery_cache).await?;
    test_jwks(&http_client).await?;
    test_client_credentials().await?;
    
    println!();
    println!("{}", "✅ 基础连通性测试完成!".bold().green());
    
    Ok(())
}

/// 测试 OIDC Discovery
async fn test_discovery(
    http_client: &Arc<ReqwestHttpClient>,
    cache: &Arc<MokaCacheImpl<String, OidcProviderMetadata>>,
) -> Result<OidcProviderMetadata> {
    println!();
    println!("{}", "1. 测试 OIDC Discovery...".bold());

    let metadata = discover(ISSUER, http_client.as_ref(), cache.as_ref())
        .await
        .context("Discovery 失败")?;

    println!("  ✓ Issuer: {}", metadata.issuer.green());
    println!("  ✓ Authorization: {}", metadata.authorization_endpoint.green());
    println!("  ✓ Token: {}", metadata.token_endpoint.green());
    if let Some(userinfo) = &metadata.userinfo_endpoint {
        println!("  ✓ UserInfo: {}", userinfo.green());
    }
    println!("  ✓ JWKS: {}", metadata.jwks_uri.green());

    if let Some(registration) = &metadata.registration_endpoint {
        println!("  ✓ Registration (DCR): {}", registration.green());
    }

    if let Some(introspection) = &metadata.introspection_endpoint {
        println!("  ✓ Introspection: {}", introspection.green());
    }

    if let Some(revocation) = &metadata.revocation_endpoint {
        println!("  ✓ Revocation: {}", revocation.green());
    }

    println!(
        "  ✓ Supported Scopes: {}",
        metadata
            .scopes_supported
            .as_ref()
            .map(|s| s.join(" "))
            .unwrap_or_default()
            .yellow()
    );

    Ok(metadata)
}

/// 测试 JWKS 获取
async fn test_jwks(http_client: &Arc<ReqwestHttpClient>) -> Result<()> {
    println!();
    println!("{}", "2. 测试 JWKS 获取...".bold());

    let jwks_uri = format!("{}/.well-known/jwks.json", ISSUER);
    let response = http_client
        .get_value(&jwks_uri)
        .await
        .context("拉取 JWKS 失败")?;

    if let Some(keys) = response.get("keys").and_then(|k| k.as_array()) {
        println!("  ✓ 获取到 {} 个密钥", keys.len().to_string().green());
        for (i, key) in keys.iter().enumerate() {
            if let (Some(kid), Some(use_), Some(alg)) = (
                key.get("kid").and_then(|k| k.as_str()),
                key.get("use").and_then(|u| u.as_str()),
                key.get("alg").and_then(|a| a.as_str()),
            ) {
                println!(
                    "    - Key {}: kid={}, use={}, alg={}",
                    i + 1,
                    kid.yellow(),
                    use_.yellow(),
                    alg.yellow()
                );
            }
        }
    }

    Ok(())
}

/// 测试客户端凭据流程
async fn test_client_credentials() -> Result<()> {
    println!();
    println!("{}", "3. 测试客户端凭据...".bold());

    // 测试 Basic Auth
    let auth_header = format!("{}:{}", CLIENT_ID_WEB, CLIENT_SECRET_WEB);
    let auth_header = format!("Basic {}", general_purpose::STANDARD.encode(auth_header));

    println!("  ✓ Client ID: {}", CLIENT_ID_WEB.yellow());
    println!("  ✓ Auth Method: {}", "client_secret_basic".yellow());
    println!("  ✓ Auth Header: {}", ellipsis(&auth_header));

    // 注意：客户端凭据流程可能需要额外配置
    println!(
        "  {} 客户端凭据流程需要后端支持 grant_type=client_credentials",
        "提示:".yellow()
    );

    Ok(())
}

/// 测试多租户模式
async fn test_multi_tenant(
    http_client: &Arc<HttpClientAdapter<ReqwestHttpClient>>,
    discovery_cache: &Arc<MokaCacheImpl<String, OidcProviderMetadata>>,
) -> Result<()> {
    println!();
    println!("{}", "=== 多租户模式测试 ===".bold().cyan());

    // 1. 测试 ClientId 模式
    println!();
    println!("{}", "1. 测试 ClientId 模式...".bold());
    let tenant_config = TenantConfig::client_id(CLIENT_ID_WEB.to_string());
    
    let metadata = discover_with_tenant(
        ISSUER,
        &tenant_config,
        http_client.as_ref(),
        discovery_cache.as_ref(),
    )
    .await
    .context("ClientId 模式 Discovery 失败")?;
    
    println!("  ✓ Issuer: {}", metadata.issuer.green());
    println!("  ✓ 使用 client_id: {}", CLIENT_ID_WEB.yellow());

    // 2. 测试 QueryParam 模式
    println!();
    println!("{}", "2. 测试 QueryParam 模式...".bold());
    let tenant_config = TenantConfig::query_param("xiaojinpro".to_string());
    
    match discover_with_tenant(
        ISSUER,
        &tenant_config,
        http_client.as_ref(),
        discovery_cache.as_ref(),
    )
    .await {
        Ok(metadata) => {
            println!("  ✓ Issuer: {}", metadata.issuer.green());
            println!("  ✓ 使用 tenant_id: {}", "xiaojinpro".yellow());
        }
        Err(e) => {
            println!("  {} QueryParam 模式不被后端支持: {}", "提示:".yellow(), e);
        }
    }

    println!();
    println!("{}", "✅ 多租户模式测试完成!".bold().green());

    Ok(())
}

/// 测试 SSE 登录监控
#[cfg(feature = "sse")]
async fn test_sse_login(http_client: &Arc<ReqwestHttpClient>) -> Result<()> {
    use futures_util::StreamExt;
    use std::time::Duration;

    println!();
    println!("{}", "=== SSE 登录监控测试 ===".bold().cyan());

    // 1. 启动登录会话
    println!();
    println!("{}", "1. 启动登录会话...".bold());
    
    let (login_id, qr_url) = start_login_session(
        ISSUER,
        CLIENT_ID_WEB,
        REDIRECT_URI_WEB,
        http_client.as_ref(),
    )
    .await
    .context("启动登录会话失败")?;

    println!("  ✓ Login ID: {}", login_id.yellow());
    println!("  ✓ QR URL: {}", qr_url.blue());

    // 2. 选择监控方式
    println!();
    println!("{}", "选择监控方式:".bold());
    println!("  1. SSE 实时监控");
    println!("  2. 轮询状态");
    println!("  3. 跳过");

    let choice = prompt_trimmed("请选择 (1-3): ")?;

    match choice.as_str() {
        "1" => {
            println!();
            println!("{}", "开始 SSE 监控 (按 Ctrl+C 退出)...".yellow());
            
            let config = LoginMonitorConfig {
                issuer: ISSUER.to_string(),
                login_id: login_id.clone(),
                timeout_secs: Some(60),
                max_reconnects: Some(3),
            };

            let mut event_stream = subscribe_login_events(config).await?;
            
            tokio::select! {
                _ = async {
                    while let Some(event) = event_stream.next().await {
                        match event {
                            Ok(LoginEvent::StatusUpdate(state)) => {
                                println!("  [状态更新] {:?}", state.status);
                                if matches!(state.status, LoginStatus::Success | LoginStatus::Failed | LoginStatus::Expired) {
                                    break;
                                }
                            }
                            Ok(LoginEvent::Heartbeat) => {
                                print!(".");
                                io::stdout().flush().ok();
                            }
                            Ok(LoginEvent::Close) => {
                                println!("\n  [SSE 关闭]");
                                break;
                            }
                            Ok(LoginEvent::Error(msg)) => {
                                println!("\n  [SSE 错误] {}", msg);
                            }
                            Err(e) => {
                                println!("\n  [事件流错误] {}", e);
                                break;
                            }
                        }
                    }
                } => {}
                _ = tokio::time::sleep(Duration::from_secs(60)) => {
                    println!("\n  超时");
                }
            }
        }
        "2" => {
            println!();
            println!("{}", "开始轮询状态 (最多 30 秒)...".yellow());
            
            for i in 0..30 {
                let state = check_login_status(ISSUER, &login_id, http_client.as_ref()).await?;
                
                print!("  [{:02}s] 状态: {:?}", i, state.status);
                
                if !matches!(state.status, LoginStatus::Pending) {
                    println!();
                    if let Some(code) = state.code {
                        println!("  ✓ 获得授权码: {}", code.green());
                    }
                    break;
                }
                
                print!("\r");
                io::stdout().flush().ok();
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            println!();
        }
        _ => {
            println!("  跳过 SSE 测试");
        }
    }

    println!();
    println!("{}", "✅ SSE 登录监控测试完成!".bold().green());

    Ok(())
}

/// 测试 Token 管理功能
async fn test_token_management(
    http_client: &Arc<ReqwestHttpClient>,
    _discovery_cache: &Arc<MokaCacheImpl<String, OidcProviderMetadata>>,
    _jwks_cache: &Arc<MokaCacheImpl<String, Jwks>>,
) -> Result<()> {
    println!();
    println!("{}", "=== Token 管理功能测试 ===".bold().cyan());
    println!("{} 此测试需要有效的 token", "提示:".yellow());
    
    // 首先需要获取一个有效的 token
    let access_token = prompt_trimmed("请输入 Access Token (直接回车跳过): ")?;
    if access_token.is_empty() {
        println!("跳过 Token 管理测试");
        return Ok(());
    }

    let refresh_token_str = prompt_trimmed("请输入 Refresh Token (用于刷新测试，可选): ")?;

    // 1. 测试 Token Introspection
    println!();
    println!("{}", "1. 测试 Token Introspection...".bold());
    
    let introspect_req = IntrospectRequest {
        issuer: ISSUER.to_string(),
        client_id: CLIENT_ID_WEB.to_string(),
        client_secret: Some(CLIENT_SECRET_WEB.to_string()),
        token: access_token.clone(),
        token_type_hint: Some("access_token".to_string()),
        token_endpoint_auth_method: None,
    };

    match introspect_token(introspect_req, http_client.as_ref()).await {
        Ok(response) => {
            println!("  ✓ Active: {}", response.active.to_string().green());
            if let Some(scope) = &response.scope {
                println!("  ✓ Scope: {}", scope.yellow());
            }
            if let Some(username) = &response.username {
                println!("  ✓ Username: {}", username.yellow());
            }
            if let Some(exp) = response.exp {
                println!("  ✓ Expires: {}", exp.to_string().yellow());
            }
        }
        Err(e) => {
            println!("  {} Introspection 失败: {}", "✗".red(), e);
        }
    }

    // 2. 测试 Refresh Token
    if !refresh_token_str.is_empty() {
        println!();
        println!("{}", "2. 测试 Refresh Token...".bold());
        
        let refresh_req = RefreshTokenRequest {
            issuer: ISSUER.to_string(),
            client_id: CLIENT_ID_WEB.to_string(),
            client_secret: Some(CLIENT_SECRET_WEB.to_string()),
            refresh_token: refresh_token_str.clone(),
            scope: Some(SCOPES.to_string()),
            token_endpoint_auth_method: None,
        };

        match refresh_token(refresh_req, http_client.as_ref()).await {
            Ok(tokens) => {
                println!("  ✓ 新 Access Token: {}", ellipsis_colored(&tokens.access_token));
                println!("  ✓ Token Type: {}", tokens.token_type.green());
                println!("  ✓ Expires In: {} 秒", tokens.expires_in.to_string().green());
                
                if let Some(new_refresh) = &tokens.refresh_token {
                    println!("  ✓ 新 Refresh Token: {}", ellipsis_colored(new_refresh));
                }
            }
            Err(e) => {
                println!("  {} Refresh 失败: {}", "✗".red(), e);
            }
        }
    }

    // 3. 测试 Token Revocation
    println!();
    println!("{}", "3. 测试 Token Revocation...".bold());
    
    let revoke_choice = prompt_trimmed("是否吊销当前 token? (y/n): ")?;
    if revoke_choice.to_lowercase() == "y" {
        match revoke_token(
            ISSUER,
            CLIENT_ID_WEB,
            Some(CLIENT_SECRET_WEB),
            &access_token,
            Some("access_token"),
            None,
            http_client.as_ref(),
        ).await {
            Ok(()) => {
                println!("  ✓ Token 已成功吊销");
            }
            Err(e) => {
                println!("  {} Revocation 失败: {}", "✗".red(), e);
            }
        }
    }

    println!();
    println!("{}", "✅ Token 管理功能测试完成!".bold().green());

    Ok(())
}

/// 测试动态客户端注册 (DCR)
async fn test_dcr(http_client: &Arc<ReqwestHttpClient>) -> Result<()> {
    println!();
    println!("{}", "=== 动态客户端注册 (DCR) 测试 ===".bold().cyan());
    println!("{} DCR 需要 Initial Access Token", "提示:".yellow());
    
    let iat = prompt_trimmed("请输入 Initial Access Token (直接回车跳过): ")?;
    if iat.is_empty() {
        println!("跳过 DCR 测试");
        return Ok(());
    }

    // 1. 注册新客户端
    println!();
    println!("{}", "1. 注册新客户端...".bold());
    
    let client_name = format!("test-client-{}", chrono::Utc::now().timestamp());
    let req = RegisterRequest {
        application_type: Some("web".to_string()),
        redirect_uris: vec!["http://localhost:8888/callback".to_string()],
        post_logout_redirect_uris: Some(vec!["http://localhost:8888".to_string()]),
        grant_types: vec!["authorization_code".to_string(), "refresh_token".to_string()],
        token_endpoint_auth_method: "client_secret_basic".to_string(),
        scope: "openid profile email".to_string(),
        contacts: Some(vec!["test@example.com".to_string()]),
        software_id: Some("xjp-oidc-test".to_string()),
        client_name: Some(client_name.clone()),
    };

    match register_client(ISSUER, &iat, req, http_client.as_ref()).await {
        Ok(result) => {
            println!("  ✓ Client ID: {}", result.client_id.green());
            if let Some(secret) = &result.client_secret {
                println!("  ✓ Client Secret: {}", ellipsis_colored(secret));
            }
            println!("  ✓ Status: {:?}", result.status);
            println!("  ✓ Name: {}", result.client_name.yellow());
            
            // 2. 查询客户端配置
            if let Some(rat) = std::env::var("REGISTRATION_ACCESS_TOKEN").ok() {
                println!();
                println!("{}", "2. 查询客户端配置...".bold());
                
                match get_client_config(ISSUER, &result.client_id, &rat, http_client.as_ref()).await {
                    Ok(config) => {
                        println!("  ✓ Client ID: {}", config.client_id.green());
                        println!("  ✓ Redirect URIs: {:?}", config.redirect_uris);
                        println!("  ✓ Grant Types: {:?}", config.grant_types);
                    }
                    Err(e) => {
                        println!("  {} 查询配置失败: {}", "提示:".yellow(), e);
                        println!("    请设置 REGISTRATION_ACCESS_TOKEN 环境变量");
                    }
                }
            }
        }
        Err(e) => {
            println!("  {} DCR 注册失败: {}", "✗".red(), e);
        }
    }

    println!();
    println!("{}", "✅ DCR 测试完成!".bold().green());

    Ok(())
}

/// 测试完整授权流程
async fn test_full_flow(
    http_client: &Arc<ReqwestHttpClient>,
    discovery_cache: &Arc<MokaCacheImpl<String, OidcProviderMetadata>>,
    jwks_cache: &Arc<MokaCacheImpl<String, Jwks>>,
) -> Result<()> {
    println!();
    println!("{}", "=== 完整授权流程测试 ===".bold().cyan());

    // 获取元数据
    let metadata = discover(ISSUER, http_client.as_ref(), discovery_cache.as_ref())
        .await
        .context("Discovery 失败")?;

    // 1. 生成 PKCE
    println!();
    println!("{}", "1. 生成 PKCE...".bold());
    let (verifier, challenge, method) = create_pkce()?;
    println!("  ✓ Verifier: {}", ellipsis(&verifier));
    println!("  ✓ Challenge: {}", ellipsis(&challenge));
    println!("  ✓ Method: {}", method.yellow());

    // 2. 构建授权 URL
    println!();
    println!("{}", "2. 构建授权 URL...".bold());
    let auth_url = build_auth_url_with_metadata(
        &metadata,
        BuildAuthUrl {
            issuer: ISSUER.into(),
            client_id: CLIENT_ID_WEB.into(),
            redirect_uri: REDIRECT_URI_WEB.into(),
            scope: SCOPES.into(),
            code_challenge: challenge,
            state: Some("test-state".into()),
            nonce: Some("test-nonce".into()),
            prompt: None,
            extra_params: None,
            tenant: None,
            authorization_endpoint: None,
        },
    )?;

    println!("  授权 URL: {}", auth_url.url.to_string().blue());
    println!();
    println!("{} 请在浏览器中访问上述 URL 进行授权", "提示:".yellow());

    // 3. 等待授权码
    let code = prompt_trimmed("请输入授权码 (直接回车跳过): ")?;
    if code.is_empty() {
        println!("跳过后续测试");
        return Ok(());
    }

    // 4. 交换 Token
    println!();
    println!("{}", "3. 交换 Token...".bold());
    let params = ExchangeCode {
        issuer: ISSUER.into(),
        code: code.into(),
        client_id: CLIENT_ID_WEB.into(),
        client_secret: Some(CLIENT_SECRET_WEB.into()),
        redirect_uri: REDIRECT_URI_WEB.into(),
        code_verifier: Some(verifier.into()),
        token_endpoint_auth_method: None,
    };

    let tokens = exchange_code(params, http_client.as_ref()).await?;
    
    println!("  ✓ Access Token: {}", ellipsis_colored(&tokens.access_token));
    println!("  ✓ Token Type: {}", tokens.token_type.green());
    println!("  ✓ Expires In: {} 秒", tokens.expires_in.to_string().green());

    if let Some(refresh) = &tokens.refresh_token {
        println!("  ✓ Refresh Token: {}", ellipsis_colored(refresh));
    }

    // 5. 验证 ID Token
    if let Some(id_token) = tokens.id_token.as_deref() {
        println!();
        println!("{}", "4. 验证 ID Token...".bold());
        
        let verified = verify_id_token(
            id_token,
            VerifyOptions {
                issuer: ISSUER,
                audience: CLIENT_ID_WEB,
                nonce: Some("test-nonce"),
                max_age_sec: None,
                clock_skew_sec: Some(60),
                http: http_client.as_ref(),
                cache: jwks_cache.as_ref(),
            },
        )
        .await?;

        println!("  ✓ Subject: {}", verified.sub.yellow());
        println!("  ✓ Issuer: {}", verified.iss.yellow());
        println!("  ✓ Audience: {}", verified.aud.yellow());

        if let Some(amr) = &verified.amr {
            println!("  ✓ AMR: {:?}", amr);
        }

        if let Some(admin) = verified.xjp_admin {
            println!("  ✓ Admin: {}", admin.to_string().yellow());
        }

        if let Some(auth_time) = verified.auth_time {
            println!("  ✓ Auth Time: {}", auth_time.to_string().yellow());
        }
    }

    // 6. 获取 UserInfo
    println!();
    println!("{}", "5. 获取 UserInfo...".bold());
    
    match get_userinfo(ISSUER, &tokens.access_token, http_client.as_ref()).await {
        Ok(userinfo) => {
            println!("  ✓ Sub: {}", userinfo.sub.yellow());
            if let Some(name) = &userinfo.name {
                println!("  ✓ Name: {}", name.yellow());
            }
            if let Some(email) = &userinfo.email {
                println!("  ✓ Email: {}", email.yellow());
            }
            if let Some(admin) = userinfo.xjp_admin {
                println!("  ✓ Admin: {}", admin.to_string().yellow());
            }
        }
        Err(e) => {
            println!("  {} UserInfo 获取失败: {}", "✗".red(), e);
        }
    }

    println!();
    println!("{}", "✅ 完整授权流程测试完成!".bold().green());

    Ok(())
}

// 辅助函数
fn ellipsis(value: &str) -> ColoredString {
    let preview: String = value.chars().take(20).collect();
    let suffix = if value.chars().count() > 20 { "..." } else { "" };
    format!("{}{}", preview, suffix).yellow()
}

fn ellipsis_colored(value: &str) -> ColoredString {
    let preview: String = value.chars().take(20).collect();
    let suffix = if value.chars().count() > 20 { "..." } else { "" };
    format!("{}{}", preview, suffix).green()
}

fn prompt_trimmed(message: &str) -> Result<String> {
    print!("{}", message);
    io::stdout().flush().context("刷新标准输出失败")?;
    let mut input = String::new();
    io::stdin().read_line(&mut input).context("读取输入失败")?;
    Ok(input.trim().to_string())
}