use axum::{
    extract::State,
    http::StatusCode,
    middleware,
    response::Json,
    routing::get,
    Router,
};
use serde_json::json;
use std::{net::SocketAddr, sync::Arc};
use xjp_oidc::{JwtVerifier, MokaCacheImpl, ReqwestHttpClient};
use xjp_oidc_axum::{require_admin, AdminClaims, OptionalClaims, OidcLayer, VerifiedClaims};

#[derive(Clone)]
struct AppState {
    // In real applications, you'd configure the verifier with your issuer
    dummy: String,
}

#[tokio::main]
async fn main() {
    // Load environment variables
    dotenvy::dotenv().ok();
    
    let issuer = std::env::var("ISSUER").expect("ISSUER env var required");
    let audience = std::env::var("AUDIENCE").expect("AUDIENCE env var required");
    
    // Create JWT verifier
    let http = Arc::new(ReqwestHttpClient::default());
    let cache = Arc::new(MokaCacheImpl::new(1024));
    
    // Create issuer map for multi-tenant support
    let mut issuer_map = std::collections::HashMap::new();
    issuer_map.insert("default".to_string(), issuer.clone());
    
    let verifier = Arc::new(
        JwtVerifier::builder()
            .issuer_map(issuer_map)
            .default_issuer(issuer)
            .audience(audience)
            .http(http)
            .cache(cache)
            .clock_skew(120)
            .build()
            .expect("Failed to build JWT verifier"),
    );
    
    // Create OIDC layer
    let oidc_layer = OidcLayer::new(verifier);
    
    let state = AppState {
        dummy: "Resource Server".to_string(),
    };
    
    // Build routes
    let public_routes = Router::new()
        .route("/", get(home))
        .route("/health", get(health));
    
    let protected_routes = Router::new()
        .route("/api/profile", get(get_profile))
        .route("/api/data", get(get_data))
        .layer(oidc_layer.clone()); // Apply OIDC verification to all routes
    
    let admin_routes = Router::new()
        .route("/api/admin/users", get(list_users))
        .route("/api/admin/settings", get(admin_settings))
        .layer(middleware::from_fn(require_admin)) // Add admin guard
        .layer(oidc_layer); // Apply OIDC verification first
    
    let optional_auth_routes = Router::new()
        .route("/api/optional", get(optional_endpoint));
    
    // Combine all routes
    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .merge(admin_routes)
        .merge(optional_auth_routes)
        .with_state(state);
    
    let addr: SocketAddr = "0.0.0.0:3001".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    
    println!("Resource Server listening on http://{}", addr);
    println!("\nEndpoints:");
    println!("  Public:");
    println!("    GET /              - Home page");
    println!("    GET /health        - Health check");
    println!("  Protected (requires valid JWT):");
    println!("    GET /api/profile   - User profile");
    println!("    GET /api/data      - Protected data");
    println!("  Admin only (requires xjp_admin=true):");
    println!("    GET /api/admin/users    - List users");
    println!("    GET /api/admin/settings - Admin settings");
    println!("  Optional auth:");
    println!("    GET /api/optional  - Works with or without auth");
    println!("\nTest with: curl -H 'Authorization: Bearer YOUR_JWT' http://localhost:3001/api/profile");
    
    axum::serve(listener, app).await.unwrap();
}

async fn home() -> &'static str {
    "XJP-OIDC Resource Server Example\n\nThis server demonstrates JWT verification with the xjp-oidc-axum middleware."
}

async fn health() -> StatusCode {
    StatusCode::OK
}

// Protected endpoints - require valid JWT
async fn get_profile(claims: VerifiedClaims, State(state): State<AppState>) -> Json<serde_json::Value> {
    println!("Profile accessed by: {}", claims.sub);
    Json(json!({
        "server": state.dummy,
        "user": {
            "subject": claims.sub,
            "issuer": claims.iss,
            "audience": claims.aud,
            "scopes": claims.scope,
            "is_admin": claims.xjp_admin.unwrap_or(false),
            "auth_methods": claims.amr,
            "auth_time": claims.auth_time
        }
    }))
}

async fn get_data(claims: VerifiedClaims) -> Json<serde_json::Value> {
    println!("Data accessed by: {}", claims.sub);
    Json(json!({
        "data": "This is protected data",
        "accessed_by": claims.sub,
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

// Admin endpoints - require xjp_admin=true
async fn list_users(admin: AdminClaims) -> Json<serde_json::Value> {
    println!("Admin endpoint accessed by: {}", admin.sub);
    Json(json!({
        "users": [
            {"id": "u1", "name": "User One"},
            {"id": "u2", "name": "User Two"}
        ],
        "admin": admin.sub
    }))
}

async fn admin_settings(admin: AdminClaims) -> Json<serde_json::Value> {
    println!("Admin settings accessed by: {}", admin.sub);
    Json(json!({
        "settings": {
            "feature_flags": {
                "new_ui": true,
                "beta_features": false
            },
            "limits": {
                "max_users": 1000,
                "max_storage_gb": 100
            }
        },
        "managed_by": admin.sub
    }))
}

// Optional auth endpoint
async fn optional_endpoint(claims: OptionalClaims) -> Json<serde_json::Value> {
    match claims.0 {
        Some(verified_claims) => {
            println!("Optional endpoint accessed by authenticated user: {}", verified_claims.sub);
            Json(json!({
                "message": format!("Hello, {}!", verified_claims.sub),
                "authenticated": true
            }))
        }
        None => {
            println!("Optional endpoint accessed anonymously");
            Json(json!({
                "message": "Hello, anonymous user!",
                "authenticated": false
            }))
        }
    }
}