//! 测试 xjp-oidc SDK 与真实后端的连接

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
    VerifyOptions,
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

    println!("{}", "=== xjp-oidc 后端连接测试 ===".bold().green());
    println!("测试环境: {}", ISSUER.yellow());
    println!();

    // 创建 HTTP 客户端和缓存
    let http_client = Arc::new(ReqwestHttpClient::default());
    let discovery_cache = Arc::new(MokaCacheImpl::<String, OidcProviderMetadata>::new(100));
    let jwks_cache = Arc::new(MokaCacheImpl::<String, Jwks>::new(100));

    // 测试步骤
    let metadata = test_discovery(&http_client, &discovery_cache).await?;
    test_jwks(&http_client).await?;
    let (verifier, auth_url_web, auth_url_cli) = test_pkce_flow(&metadata).await?;
    test_client_credentials().await?;
    test_userinfo().await?;

    println!();
    println!("{} 授权 URL 已准备好:", "提示".yellow());
    println!("  - Web 客户端: {}", auth_url_web.blue());
    println!("  - CLI 客户端: {}", auth_url_cli.blue());
    println!("请在浏览器中打开其一并完成认证。认证完成后，将重定向到回调地址并携带授权码 (code)。");
    println!(
        "当前会话的 PKCE verifier 已自动保存，如需手动保存可复制: {}",
        verifier.yellow()
    );

    let code_input = prompt_trimmed("\n请输入授权码 (直接回车跳过 Token 交换): ")?;
    if code_input.is_empty() {
        println!("未输入授权码，跳过 Token 交换测试。");
    } else {
        let client_choice = prompt_trimmed("使用的客户端 (web/cli，默认 web): ")?;
        let client_choice = client_choice.to_lowercase();
        let (client_id, client_secret, redirect_uri) = match client_choice.as_str() {
            "cli" => (CLIENT_ID_CLI, None, REDIRECT_URI_CLI),
            _ => (CLIENT_ID_WEB, Some(CLIENT_SECRET_WEB), REDIRECT_URI_WEB),
        };

        test_token_exchange(
            &code_input,
            &verifier,
            client_id,
            client_secret,
            redirect_uri,
            &http_client,
            &jwks_cache,
        )
        .await?;
    }

    println!();
    println!("{}", "✅ 基础连通性测试完成!".bold().green());

    Ok(())
}

/// 测试 OIDC Discovery
async fn test_discovery(
    http_client: &Arc<ReqwestHttpClient>,
    cache: &Arc<MokaCacheImpl<String, OidcProviderMetadata>>,
) -> Result<OidcProviderMetadata> {
    println!("{}", "1. 测试 OIDC Discovery...".bold());

    let metadata = discover(ISSUER, http_client.as_ref(), cache.as_ref())
        .await
        .context("Discovery 失败")?;

    println!("  ✓ Issuer: {}", metadata.issuer.green());
    println!(
        "  ✓ Authorization: {}",
        metadata.authorization_endpoint.green()
    );
    println!("  ✓ Token: {}", metadata.token_endpoint.green());
    if let Some(userinfo) = &metadata.userinfo_endpoint {
        println!("  ✓ UserInfo: {}", userinfo.green());
    } else {
        println!("  - UserInfo 端点未在 discovery 中返回");
    }
    println!("  ✓ JWKS: {}", metadata.jwks_uri.green());

    if let Some(registration) = &metadata.registration_endpoint {
        println!("  ✓ Registration (DCR): {}", registration.green());
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

/// 测试 PKCE 流程
async fn test_pkce_flow(metadata: &OidcProviderMetadata) -> Result<(String, String, String)> {
    println!();
    println!("{}", "3. 测试 PKCE 授权流程...".bold());

    // 1. 生成 PKCE
    let (verifier, challenge, method) = create_pkce()?;
    println!("  ✓ PKCE Verifier: {}", ellipsis(&verifier));
    println!("  ✓ PKCE Challenge: {}", ellipsis(&challenge));
    println!("  ✓ PKCE Method: {}", method.yellow());

    // 2. 构建授权 URL (Web Client)
    let auth_url_web = build_auth_url_with_metadata(
        metadata,
        BuildAuthUrl {
            issuer: ISSUER.into(),
            client_id: CLIENT_ID_WEB.into(),
            redirect_uri: REDIRECT_URI_WEB.into(),
            scope: SCOPES.into(),
            code_challenge: challenge.clone(),
            state: Some("test-state-web".into()),
            nonce: Some("test-nonce-web".into()),
            prompt: None,
            extra_params: None,
            tenant: None,
            authorization_endpoint: None,
        },
    )?;

    println!();
    println!("  {} Confidential Client (xjp-web):", "Web".bold());
    println!("  授权 URL: {}", auth_url_web.url.to_string().blue());

    // 3. 构建授权 URL (CLI Client)
    let auth_url_cli = build_auth_url_with_metadata(
        metadata,
        BuildAuthUrl {
            issuer: ISSUER.into(),
            client_id: CLIENT_ID_CLI.into(),
            redirect_uri: REDIRECT_URI_CLI.into(),
            scope: SCOPES.into(),
            code_challenge: challenge,
            state: Some("test-state-cli".into()),
            nonce: Some("test-nonce-cli".into()),
            prompt: None,
            extra_params: None,
            tenant: None,
            authorization_endpoint: None,
        },
    )?;

    println!();
    println!("  {} Public Client (xjp-cli):", "CLI".bold());
    println!("  授权 URL: {}", auth_url_cli.url.to_string().blue());

    println!();
    println!(
        "  {} 请访问上述 URL 进行授权，然后使用返回的 code 继续测试",
        "提示:".yellow()
    );

    Ok((verifier, auth_url_web.url.to_string(), auth_url_cli.url.to_string()))
}

/// 测试客户端凭据流程
async fn test_client_credentials() -> Result<()> {
    println!();
    println!("{}", "4. 测试客户端凭据...".bold());

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

/// 测试 UserInfo 端点
async fn test_userinfo() -> Result<()> {
    println!();
    println!("{}", "5. 测试 UserInfo 端点...".bold());

    println!(
        "  {} 需要有效的 access_token 才能测试 UserInfo",
        "提示:".yellow()
    );
    println!("  预期的自定义声明:");
    println!("    - amr: 认证方法 (如 [\"wechat_qr\"])");
    println!("    - xjp_admin: 管理员标志 (布尔值)");
    println!("    - auth_time: 认证时间 (UNIX 时间戳)");

    Ok(())
}

/// 辅助函数：测试 token 交换（需要真实的授权码）
async fn test_token_exchange(
    code: &str,
    verifier: &str,
    client_id: &str,
    client_secret: Option<&str>,
    redirect_uri: &str,
    http_client: &Arc<ReqwestHttpClient>,
    jwks_cache: &Arc<MokaCacheImpl<String, Jwks>>,
) -> Result<()> {
    println!();
    println!("{}", "测试 Token 交换...".bold());

    let params = ExchangeCode {
        issuer: ISSUER.into(),
        code: code.into(),
        client_id: client_id.into(),
        client_secret: client_secret.map(Into::into),
        redirect_uri: redirect_uri.into(),
        code_verifier: Some(verifier.into()),
        token_endpoint_auth_method: None,
    };

    match exchange_code(params, http_client.as_ref()).await {
        Ok(tokens) => {
            println!(
                "  ✓ Access Token: {}",
                ellipsis_colored(&tokens.access_token)
            );
            println!("  ✓ Token Type: {}", tokens.token_type.green());
            println!(
                "  ✓ Expires In: {} 秒",
                tokens.expires_in.to_string().green()
            );

            if let Some(refresh) = &tokens.refresh_token {
                println!("  ✓ Refresh Token: {}", ellipsis_colored(refresh));
            }

            if let Some(id_token) = tokens.id_token.as_deref() {
                println!("  ✓ ID Token: {}", ellipsis_colored(id_token));

                let verified = verify_id_token(
                    id_token,
                    VerifyOptions {
                        issuer: ISSUER,
                        audience: client_id,
                        nonce: Some("test-nonce"),
                        max_age_sec: None,
                        clock_skew_sec: Some(60),
                        http: http_client.as_ref(),
                        cache: jwks_cache.as_ref(),
                    },
                )
                .await?;

                println!();
                println!("  {} ID Token 验证成功!", "✓".green());
                println!("    - Subject: {}", verified.sub.yellow());
                println!("    - Issuer: {}", verified.iss.yellow());
                println!("    - Audience: {}", verified.aud.yellow());

                if let Some(amr) = &verified.amr {
                    println!("    - AMR: {:?}", amr);
                }

                if let Some(admin) = verified.xjp_admin {
                    println!("    - Admin: {}", admin.to_string().yellow());
                }

                if let Some(auth_time) = verified.auth_time {
                    println!("    - Auth Time: {}", auth_time.to_string().yellow());
                }
            } else {
                println!("  {} 返回的 token 中缺少 ID Token", "✗".red());
            }
        }
        Err(e) => {
            println!("  {} Token 交换失败: {}", "✗".red(), e);
        }
    }

    Ok(())
}

fn ellipsis(value: &str) -> ColoredString {
    let preview: String = value.chars().take(20).collect();
    let suffix = if value.chars().count() > 20 {
        "..."
    } else {
        ""
    };
    format!("{}{}", preview, suffix).yellow()
}

fn ellipsis_colored(value: &str) -> ColoredString {
    let preview: String = value.chars().take(20).collect();
    let suffix = if value.chars().count() > 20 {
        "..."
    } else {
        ""
    };
    format!("{}{}", preview, suffix).green()
}

fn prompt_trimmed(message: &str) -> Result<String> {
    print!("{}", message);
    io::stdout().flush().context("刷新标准输出失败")?;
    let mut input = String::new();
    io::stdin().read_line(&mut input).context("读取输入失败")?;
    Ok(input.trim().to_string())
}
