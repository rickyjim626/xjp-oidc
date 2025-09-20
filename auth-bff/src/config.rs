use std::sync::Arc;
use xjp_oidc::{ReqwestHttpClient, NoOpCache};

#[derive(Clone)]
pub struct Config {
    // OIDC Configuration
    pub oidc_issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    pub scopes: String,
    
    // Session
    #[allow(dead_code)]
    pub session_secret: String,
    
    // Frontend URLs
    pub frontend_url: String,
    pub post_logout_redirect_uri: String,
    
    // HTTP Client and Cache
    pub http_client: Arc<ReqwestHttpClient>,
    pub jwks_cache: Arc<NoOpCache>,
    pub discovery_cache: Arc<NoOpCache>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        dotenvy::dotenv().ok();
        
        Ok(Self {
            oidc_issuer: std::env::var("OIDC_ISSUER")
                .expect("OIDC_ISSUER must be set"),
            client_id: std::env::var("CLIENT_ID")
                .expect("CLIENT_ID must be set"),
            client_secret: std::env::var("CLIENT_SECRET").ok(),
            redirect_uri: std::env::var("REDIRECT_URI")
                .unwrap_or_else(|_| "http://localhost:8080/api/auth/callback".into()),
            scopes: std::env::var("SCOPES")
                .unwrap_or_else(|_| "openid profile email".into()),
            session_secret: std::env::var("SESSION_SECRET")
                .unwrap_or_else(|_| "please-change-this-secret-key-in-production".into()),
            frontend_url: std::env::var("FRONTEND_URL")
                .unwrap_or_else(|_| "http://localhost:3000".into()),
            post_logout_redirect_uri: std::env::var("POST_LOGOUT_REDIRECT_URI")
                .unwrap_or_else(|_| "http://localhost:3000/logged-out".into()),
            http_client: Arc::new(ReqwestHttpClient::default()),
            jwks_cache: Arc::new(NoOpCache),
            discovery_cache: Arc::new(NoOpCache),
        })
    }
}