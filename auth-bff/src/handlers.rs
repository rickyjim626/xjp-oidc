use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_sessions::Session;

use xjp_oidc::{
    build_auth_url, build_end_session_url_with_discovery, create_pkce, discover, exchange_code,
    parse_callback_params,
    types::{BuildAuthUrl, EndSession, ExchangeCode, VerifyOptions},
    verify_id_token,
};

use crate::{
    config::Config,
    error::{AppError, Result},
    session::{
        clear_auth_state, clear_session, get_auth_state, get_tokens, get_user, store_auth_state,
        store_user, SessionTokens, SessionUser,
    },
};

// 健康检查
pub async fn health_check() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "service": "auth-bff",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

// 获取登录 URL
#[derive(Serialize)]
pub struct LoginUrlResponse {
    pub auth_url: String,
}

pub async fn get_login_url(
    State(config): State<Config>,
    session: Session,
) -> Result<Json<LoginUrlResponse>> {
    // 发现端点
    let discovery = discover(
        &config.oidc_issuer,
        config.http_client.as_ref(),
        config.discovery_cache.as_ref(),
    )
    .await?;

    // 创建 PKCE
    let (verifier, challenge, _) = create_pkce()?;

    // 保存状态到会话
    let (state, nonce) = store_auth_state(&session, verifier).await?;

    // 构建授权 URL，使用发现的授权端点
    let auth_url = build_auth_url(BuildAuthUrl {
        issuer: config.oidc_issuer.clone(),
        client_id: config.client_id.clone(),
        redirect_uri: config.redirect_uri.clone(),
        scope: config.scopes.clone(),
        state: Some(state),
        nonce: Some(nonce),
        code_challenge: challenge,
        authorization_endpoint: Some(discovery.authorization_endpoint.clone()),
        ..Default::default()
    })?;

    Ok(Json(LoginUrlResponse {
        auth_url: auth_url.url.to_string(),
    }))
}

// 处理回调
#[derive(Deserialize)]
pub struct CallbackRequest {
    pub callback_params: String,
}

#[derive(Serialize)]
pub struct CallbackResponse {
    pub success: bool,
    pub redirect_url: String,
}

pub async fn handle_callback(
    State(config): State<Config>,
    session: Session,
    Json(req): Json<CallbackRequest>,
) -> Result<Json<CallbackResponse>> {
    // 解析回调参数
    let params = parse_callback_params(&req.callback_params);

    // 获取会话中的状态
    let (stored_state, nonce, pkce_verifier) = get_auth_state(&session).await?;

    // 验证 state
    if params.state.as_ref() != Some(&stored_state) {
        return Err(AppError::BadRequest("Invalid state parameter".to_string()));
    }

    // 清理临时状态
    clear_auth_state(&session).await?;

    // 检查错误
    if let Some(error) = &params.error {
        return Err(AppError::BadRequest(format!(
            "OAuth error: {} - {}",
            error,
            params
                .error_description
                .as_deref()
                .unwrap_or("No description")
        )));
    }

    let code = params
        .code
        .ok_or_else(|| AppError::BadRequest("Missing authorization code".to_string()))?;

    // 发现端点
    let _discovery = discover(
        &config.oidc_issuer,
        config.http_client.as_ref(),
        config.discovery_cache.as_ref(),
    )
    .await?;

    // 交换代码
    let token_params = ExchangeCode {
        issuer: config.oidc_issuer.clone(),
        client_id: config.client_id.clone(),
        client_secret: config.client_secret.clone(),
        redirect_uri: config.redirect_uri.clone(),
        code,
        code_verifier: Some(pkce_verifier),
        token_endpoint_auth_method: None,
    };

    let tokens = exchange_code(token_params, config.http_client.as_ref()).await?;

    // 验证 ID Token
    let id_token = tokens
        .id_token
        .as_ref()
        .ok_or_else(|| AppError::BadRequest("Missing ID token".to_string()))?;

    let verify_options = VerifyOptions {
        issuer: &config.oidc_issuer,
        audience: &config.client_id,
        nonce: Some(&nonce),
        max_age_sec: None,
        clock_skew_sec: None,
        http: config.http_client.as_ref(),
        cache: config.jwks_cache.as_ref(),
    };

    let verified = verify_id_token(id_token, verify_options).await?;

    // 创建用户会话
    let user = SessionUser {
        sub: verified.sub.clone(),
        email: verified.email.clone(),
        name: verified.name.clone(),
        picture: verified.picture.clone(),
        is_admin: verified.xjp_admin.unwrap_or(false),
        auth_time: verified.auth_time,
        auth_methods: verified.amr.clone().unwrap_or_default(),
    };

    let session_tokens = SessionTokens {
        id_token: id_token.clone(),
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_at: Some(
            (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + tokens.expires_in as u64) as i64,
        ),
    };

    store_user(&session, user, session_tokens).await?;

    Ok(Json(CallbackResponse {
        success: true,
        redirect_url: config.frontend_url.clone(),
    }))
}

// 获取当前用户
#[derive(Serialize)]
pub struct UserResponse {
    pub sub: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub is_admin: bool,
    pub auth_methods: Vec<String>,
}

pub async fn get_current_user(session: Session) -> Result<Json<UserResponse>> {
    let user = get_user(&session).await?;

    Ok(Json(UserResponse {
        sub: user.sub,
        email: user.email,
        name: user.name,
        picture: user.picture,
        is_admin: user.is_admin,
        auth_methods: user.auth_methods,
    }))
}

// 登出
pub async fn logout(session: Session) -> Result<StatusCode> {
    clear_session(&session).await?;
    Ok(StatusCode::OK)
}

// 获取登出 URL
#[derive(Serialize)]
pub struct LogoutUrlResponse {
    pub logout_url: Option<String>,
}

pub async fn get_logout_url(
    State(config): State<Config>,
    session: Session,
) -> Result<Json<LogoutUrlResponse>> {
    // 尝试获取 ID Token
    let logout_url = match get_tokens(&session).await {
        Ok(tokens) => {
            // 发现端点
            let discovery = discover(
                &config.oidc_issuer,
                config.http_client.as_ref(),
                config.discovery_cache.as_ref(),
            )
            .await?;

            // 使用 build_end_session_url_with_discovery 来正确使用发现的端点
            if discovery.end_session_endpoint.is_some() {
                build_end_session_url_with_discovery(
                    EndSession {
                        issuer: config.oidc_issuer.clone(),
                        id_token_hint: tokens.id_token,
                        post_logout_redirect_uri: Some(config.post_logout_redirect_uri.clone()),
                        state: Some(uuid::Uuid::new_v4().to_string()),
                        end_session_endpoint: None, // Will be filled from discovery
                    },
                    &discovery,
                )
                .ok()
                .map(|url| url.to_string())
            } else {
                None
            }
        }
        Err(_) => None,
    };

    Ok(Json(LogoutUrlResponse { logout_url }))
}
