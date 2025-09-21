//! Tracing 和日志示例
//!
//! 展示如何配置和使用 xjp-oidc 的日志功能

use std::{collections::HashMap, sync::Arc};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use xjp_oidc::{
    build_auth_url, discover, verify_id_token, BuildAuthUrl, JwtVerifier, MokaCacheImpl,
    NoOpCache, ReqwestHttpClient, VerifyOptions,
};

/// 初始化基础日志
fn init_basic_logging() {
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,xjp_oidc=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}

/// 初始化 JSON 格式日志
fn init_json_logging() {
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,xjp_oidc=debug".into()),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_current_span(true)
                .with_span_list(true),
        )
        .init();
}

/// 初始化带文件输出的日志
fn init_file_logging() -> Result<(), Box<dyn std::error::Error>> {
    use tracing_subscriber::fmt::writer::MakeWriterExt;

    let file_appender = tracing_appender::rolling::daily("logs", "xjp-oidc.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stdout.and(non_blocking))
                .pretty(),
        )
        .init();

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 选择一种日志初始化方式
    init_basic_logging();
    // init_json_logging();
    // init_file_logging()?;

    tracing::info!("开始 xjp-oidc 日志示例");

    // 创建 HTTP 客户端和缓存
    let http_client = Arc::new(ReqwestHttpClient::default());
    let cache = Arc::new(MokaCacheImpl::new(100));

    // 示例 1: 构建授权 URL（会记录日志）
    tracing::info!("示例 1: 构建授权 URL");
    let auth_url = build_auth_url(BuildAuthUrl {
        issuer: "https://auth.example.com".into(),
        client_id: "test-client".into(),
        redirect_uri: "https://app.example.com/callback".into(),
        scope: "openid profile email".into(),
        code_challenge: "test-challenge".into(),
        authorization_endpoint: Some("https://auth.example.com/oauth/authorize".into()),
        ..Default::default()
    })?;
    tracing::debug!("生成的授权 URL: {}", auth_url);

    // 示例 2: OIDC 发现（会记录详细日志）
    tracing::info!("示例 2: OIDC 发现");
    match discover(
        "https://accounts.google.com",
        http_client.as_ref(),
        cache.as_ref(),
    )
    .await
    {
        Ok(metadata) => {
            tracing::info!(
                authorization_endpoint = %metadata.authorization_endpoint,
                token_endpoint = %metadata.token_endpoint,
                "发现成功"
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "发现失败");
        }
    }

    // 示例 3: JWT 验证器（展示多发行者配置）
    tracing::info!("示例 3: 配置 JWT 验证器");
    let mut issuers = HashMap::new();
    issuers.insert(
        "google".to_string(),
        "https://accounts.google.com".to_string(),
    );
    issuers.insert(
        "auth0".to_string(),
        "https://example.auth0.com".to_string(),
    );

    let verifier = Arc::new(JwtVerifier::new(
        issuers.clone(),
        "my-audience".to_string(),
        http_client.clone(),
        cache.clone(),
    ));

    tracing::info!(
        issuer_count = issuers.len(),
        audience = "my-audience",
        "JWT 验证器配置完成"
    );

    // 示例 4: 使用 span 追踪复杂操作
    complex_operation().await;

    // 示例 5: 结构化错误日志
    simulate_error_scenarios();

    // 示例 6: 性能追踪
    performance_tracking_example().await;

    tracing::info!("日志示例完成");
    Ok(())
}

#[tracing::instrument(name = "复杂操作")]
async fn complex_operation() {
    tracing::info!("开始复杂操作");

    // 子 span
    let _span = tracing::info_span!("子操作", operation_id = 123).entered();
    tracing::debug!("执行子操作");
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    tracing::debug!("子操作完成");
    drop(_span);

    tracing::info!("复杂操作完成");
}

fn simulate_error_scenarios() {
    use xjp_oidc::Error;

    // 不同类型的错误日志
    let errors = vec![
        Error::InvalidParam("缺少必需参数"),
        Error::Network("连接超时".into()),
        Error::Jwt("签名验证失败".into()),
    ];

    for (i, error) in errors.iter().enumerate() {
        tracing::error!(
            error = %error,
            error_type = ?error,
            scenario = i + 1,
            "模拟错误场景"
        );
    }
}

async fn performance_tracking_example() {
    let urls = vec![
        "https://httpbin.org/delay/1",
        "https://httpbin.org/delay/2",
        "https://httpbin.org/status/200",
    ];

    for url in urls {
        let start = std::time::Instant::now();

        // 模拟 HTTP 请求
        match reqwest::get(url).await {
            Ok(response) => {
                let duration = start.elapsed();
                tracing::info!(
                    target: "performance",
                    url = %url,
                    duration_ms = duration.as_millis() as u64,
                    status = response.status().as_u16(),
                    "请求完成"
                );
            }
            Err(e) => {
                tracing::error!(
                    target: "performance",
                    url = %url,
                    error = %e,
                    "请求失败"
                );
            }
        }
    }
}

// 自定义日志过滤示例
#[allow(dead_code)]
fn custom_filter_example() {
    use tracing_subscriber::filter::{FilterFn, LevelFilter};

    let filter = FilterFn::new(|metadata| {
        // 仅记录特定目标的日志
        metadata.target().starts_with("xjp_oidc")
            || metadata.target() == "performance"
            || metadata.level() <= &tracing::Level::WARN
    });

    tracing_subscriber::registry()
        .with(filter)
        .with(LevelFilter::TRACE)
        .with(tracing_subscriber::fmt::layer())
        .init();
}