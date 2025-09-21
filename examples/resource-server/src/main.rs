//! 资源服务器示例 - 展示如何使用 JWT 验证保护 API
//!
//! 这个示例展示了：
//! 1. 配置 JWT 验证器
//! 2. 使用 OidcLayer 中间件保护路由
//! 3. 提取和使用验证后的声明
//! 4. 基于管理员权限的访问控制

use axum::{middleware, routing::get, Json, Router};
use serde::Serialize;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use xjp_oidc::{JwtVerifier, NoOpCache, ReqwestHttpClient};
use xjp_oidc_axum::{require_admin, AdminClaims, OidcLayer, OptionalClaims, VerifiedClaims};

#[derive(Clone)]
struct AppState {
    #[allow(dead_code)]
    verifier: Arc<JwtVerifier<NoOpCache, ReqwestHttpClient>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 初始化日志
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "resource_server=debug,xjp_oidc=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // 配置 issuer 映射
    let mut issuer_map = HashMap::new();
    issuer_map.insert(
        "xiaojin".to_string(),
        "https://auth.xiaojinpro.com".to_string(),
    );
    issuer_map.insert(
        "google".to_string(),
        "https://accounts.google.com".to_string(),
    );

    // 创建 JWT 验证器
    let verifier = Arc::new(JwtVerifier::new(
        issuer_map,
        "resource-server-api".to_string(), // audience
        Arc::new(ReqwestHttpClient::default()),
        Arc::new(NoOpCache),
    ));

    let state = AppState {
        verifier: verifier.clone(),
    };

    // 构建应用
    let app = Router::new()
        // 公开路由
        .route("/", get(root))
        .route("/health", get(health_check))
        // 需要认证的路由（添加 JWT 验证中间件）
        .nest(
            "/api",
            Router::new()
                .route("/profile", get(get_profile))
                .route("/protected", get(protected_resource))
                .layer(OidcLayer::new(verifier.clone())),
        )
        // 需要管理员权限的路由
        .nest(
            "/api/admin",
            Router::new()
                .route("/users", get(list_users))
                .route("/settings", get(admin_settings))
                .layer(middleware::from_fn(require_admin))
                .layer(OidcLayer::new(verifier.clone())),
        )
        // 可选认证路由
        .route("/api/public", get(public_with_optional_auth))
        .with_state(state)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(
                    CorsLayer::new()
                        .allow_origin(Any)
                        .allow_methods(Any)
                        .allow_headers(Any),
                ),
        );

    let addr = SocketAddr::from(([0, 0, 0, 0], 8081));
    tracing::info!("资源服务器启动在 {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

// 根路由
async fn root() -> &'static str {
    "资源服务器示例 - 访问 /api/* 路由需要有效的 JWT"
}

// 健康检查
async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "resource-server"
    }))
}

// 获取用户资料（需要认证）
#[derive(Serialize)]
struct UserProfile {
    sub: String,
    email: Option<String>,
    scopes: Vec<String>,
    is_admin: bool,
    auth_methods: Vec<String>,
}

async fn get_profile(claims: VerifiedClaims) -> Json<UserProfile> {
    Json(UserProfile {
        sub: claims.sub.clone(),
        email: claims.sub.clone().into(), // 示例：假设 sub 是 email
        scopes: claims
            .scope
            .as_ref()
            .map(|s| s.split_whitespace().map(String::from).collect())
            .unwrap_or_default(),
        is_admin: claims.xjp_admin.unwrap_or(false),
        auth_methods: claims.amr.clone().unwrap_or_default(),
    })
}

// 受保护的资源（需要认证）
#[derive(Serialize)]
struct ProtectedData {
    message: String,
    user_id: String,
    timestamp: i64,
}

async fn protected_resource(claims: VerifiedClaims) -> Json<ProtectedData> {
    Json(ProtectedData {
        message: format!("你好 {}, 这是受保护的数据", claims.sub),
        user_id: claims.sub.clone(),
        timestamp: chrono::Utc::now().timestamp(),
    })
}

// 列出所有用户（需要管理员权限）
#[derive(Serialize)]
struct User {
    id: String,
    email: String,
    name: String,
    role: String,
}

async fn list_users(_admin: AdminClaims) -> Json<Vec<User>> {
    // 示例数据
    let users = vec![
        User {
            id: "1".to_string(),
            email: "admin@example.com".to_string(),
            name: "管理员".to_string(),
            role: "admin".to_string(),
        },
        User {
            id: "2".to_string(),
            email: "user@example.com".to_string(),
            name: "普通用户".to_string(),
            role: "user".to_string(),
        },
    ];

    Json(users)
}

// 管理员设置（需要管理员权限）
#[derive(Serialize)]
struct AdminSettings {
    feature_flags: HashMap<String, bool>,
    rate_limits: HashMap<String, i32>,
}

async fn admin_settings(_admin: AdminClaims) -> Json<AdminSettings> {
    let mut feature_flags = HashMap::new();
    feature_flags.insert("new_dashboard".to_string(), true);
    feature_flags.insert("beta_features".to_string(), false);

    let mut rate_limits = HashMap::new();
    rate_limits.insert("api_requests_per_hour".to_string(), 1000);
    rate_limits.insert("uploads_per_day".to_string(), 100);

    Json(AdminSettings {
        feature_flags,
        rate_limits,
    })
}

// 公开 API，支持可选认证
#[derive(Serialize)]
struct PublicResponse {
    message: String,
    authenticated: bool,
    user_id: Option<String>,
}

async fn public_with_optional_auth(claims: OptionalClaims) -> Json<PublicResponse> {
    match claims.0 {
        Some(verified_claims) => Json(PublicResponse {
            message: format!("欢迎 {}", verified_claims.sub),
            authenticated: true,
            user_id: Some(verified_claims.sub),
        }),
        None => Json(PublicResponse {
            message: "欢迎，匿名用户".to_string(),
            authenticated: false,
            user_id: None,
        }),
    }
}

// 添加 chrono 依赖用于时间戳
use chrono;
