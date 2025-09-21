mod config;
mod error;
mod handlers;
mod session;

use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tower_sessions::{MemoryStore, SessionManagerLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "auth_bff=debug,tower_http=debug,axum=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::from_env()?;
    tracing::info!("Starting Auth BFF with issuer: {}", config.oidc_issuer);

    // Create session store
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store).with_secure(false); // 开发环境设为 false，生产环境应设为 true

    // Build application
    let app = Router::new()
        // Auth endpoints
        .route("/api/auth/login-url", get(handlers::get_login_url))
        .route("/api/auth/callback", post(handlers::handle_callback))
        .route("/api/auth/user", get(handlers::get_current_user))
        .route("/api/auth/logout", post(handlers::logout))
        .route("/api/auth/logout-url", get(handlers::get_logout_url))
        .route("/api/auth/logout-callback", get(handlers::post_logout_callback))
        // Health check
        .route("/health", get(handlers::health_check))
        // Add state
        .with_state(config)
        // Add middleware
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(
                    CorsLayer::new()
                        .allow_origin(Any)
                        .allow_methods(Any)
                        .allow_headers(Any)
                        .allow_credentials(true),
                )
                .layer(session_layer),
        );

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("Auth BFF listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
