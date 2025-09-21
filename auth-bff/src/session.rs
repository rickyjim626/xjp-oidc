use serde::{Deserialize, Serialize};
use tower_sessions::Session;
use uuid::Uuid;

use crate::error::{AppError, Result};

const SESSION_KEY_TOKENS: &str = "oidc_tokens";
const SESSION_KEY_PKCE: &str = "pkce_verifier";
const SESSION_KEY_NONCE: &str = "nonce";
const SESSION_KEY_STATE: &str = "state";
const SESSION_KEY_USER: &str = "user";
const SESSION_KEY_LOGOUT_STATE: &str = "logout_state";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTokens {
    pub id_token: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionUser {
    pub sub: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub is_admin: bool,
    pub auth_time: Option<i64>,
    pub auth_methods: Vec<String>,
}

pub async fn store_auth_state(session: &Session, pkce_verifier: String) -> Result<(String, String)> {
    let state = Uuid::new_v4().to_string();
    let nonce = Uuid::new_v4().to_string();

    session
        .insert(SESSION_KEY_STATE, &state)
        .await
        .map_err(|e| AppError::Session(format!("Failed to store state: {}", e)))?;
    session
        .insert(SESSION_KEY_NONCE, &nonce)
        .await
        .map_err(|e| AppError::Session(format!("Failed to store nonce: {}", e)))?;
    session
        .insert(SESSION_KEY_PKCE, pkce_verifier)
        .await
        .map_err(|e| AppError::Session(format!("Failed to store PKCE verifier: {}", e)))?;

    Ok((state, nonce))
}

pub async fn get_auth_state(session: &Session) -> Result<(String, String, String)> {
    let state = session
        .get::<String>(SESSION_KEY_STATE)
        .await
        .map_err(|e| AppError::Session(format!("Failed to get state: {}", e)))?
        .ok_or_else(|| AppError::BadRequest("Missing state in session".to_string()))?;
    let nonce = session
        .get::<String>(SESSION_KEY_NONCE)
        .await
        .map_err(|e| AppError::Session(format!("Failed to get nonce: {}", e)))?
        .ok_or_else(|| AppError::BadRequest("Missing nonce in session".to_string()))?;
    let pkce_verifier = session
        .get::<String>(SESSION_KEY_PKCE)
        .await
        .map_err(|e| AppError::Session(format!("Failed to get PKCE: {}", e)))?
        .ok_or_else(|| AppError::BadRequest("Missing PKCE verifier in session".to_string()))?;

    Ok((state, nonce, pkce_verifier))
}

pub async fn clear_auth_state(session: &Session) -> Result<()> {
    session
        .remove::<String>(SESSION_KEY_STATE)
        .await
        .map_err(|e| AppError::Session(format!("Failed to remove state: {}", e)))?;
    session
        .remove::<String>(SESSION_KEY_NONCE)
        .await
        .map_err(|e| AppError::Session(format!("Failed to remove nonce: {}", e)))?;
    session
        .remove::<String>(SESSION_KEY_PKCE)
        .await
        .map_err(|e| AppError::Session(format!("Failed to remove PKCE: {}", e)))?;
    Ok(())
}

pub async fn store_user(session: &Session, user: SessionUser, tokens: SessionTokens) -> Result<()> {
    session
        .insert(SESSION_KEY_USER, &user)
        .await
        .map_err(|e| AppError::Session(format!("Failed to store user: {}", e)))?;
    session
        .insert(SESSION_KEY_TOKENS, &tokens)
        .await
        .map_err(|e| AppError::Session(format!("Failed to store tokens: {}", e)))?;

    Ok(())
}

pub async fn get_user(session: &Session) -> Result<SessionUser> {
    session
        .get::<SessionUser>(SESSION_KEY_USER)
        .await
        .map_err(|e| AppError::Session(format!("Failed to get user: {}", e)))?
        .ok_or(AppError::Unauthorized)
}

pub async fn get_tokens(session: &Session) -> Result<SessionTokens> {
    session
        .get::<SessionTokens>(SESSION_KEY_TOKENS)
        .await
        .map_err(|e| AppError::Session(format!("Failed to get tokens: {}", e)))?
        .ok_or(AppError::Unauthorized)
}

pub async fn clear_session(session: &Session) -> Result<()> {
    session
        .flush()
        .await
        .map_err(|e| AppError::Session(format!("Failed to clear session: {}", e)))?;
    Ok(())
}

pub async fn store_logout_state(session: &Session, state: String) -> Result<()> {
    session
        .insert(SESSION_KEY_LOGOUT_STATE, state)
        .await
        .map_err(|e| AppError::Session(format!("Failed to store logout state: {}", e)))?;
    Ok(())
}

pub async fn get_and_clear_logout_state(session: &Session) -> Result<String> {
    let state = session
        .get::<String>(SESSION_KEY_LOGOUT_STATE)
        .await
        .map_err(|e| AppError::Session(format!("Failed to get logout state: {}", e)))?;

    if let Some(state) = state {
        session
            .remove::<String>(SESSION_KEY_LOGOUT_STATE)
            .await
            .map_err(|e| AppError::Session(format!("Failed to remove logout state: {}", e)))?;
        Ok(state)
    } else {
        Err(AppError::BadRequest("Missing logout state in session".to_string()))
    }
}
