use axum::{
    extract::{Query, State},
    response::Redirect,
    routing::get,
    Router,
};
use serde::Deserialize;
use std::{net::SocketAddr, sync::Arc};
use xjp_oidc::{
    build_auth_url, build_end_session_url, create_pkce, exchange_code, parse_callback_params,
    types::{BuildAuthUrl, EndSession, ExchangeCode, VerifyOptions},
    verify_id_token, MokaCacheImpl, ReqwestHttpClient,
};

#[derive(Clone)]
struct Config {
    issuer: String,
    client_id: String,
    redirect_uri: String,
    post_logout_redirect_uri: String,
}

#[derive(Clone)]
struct AppState {
    http: Arc<ReqwestHttpClient>,
    cache: Arc<MokaCacheImpl<String, xjp_oidc::Jwks>>,
    cfg: Arc<Config>,
}

#[tokio::main]
async fn main() {
    // Load environment variables
    dotenvy::dotenv().ok();

    let cfg = Arc::new(Config {
        issuer: std::env::var("ISSUER").expect("ISSUER env var required"),
        client_id: std::env::var("CLIENT_ID").expect("CLIENT_ID env var required"),
        redirect_uri: std::env::var("REDIRECT_URI").expect("REDIRECT_URI env var required"),
        post_logout_redirect_uri: std::env::var("POST_LOGOUT_REDIRECT_URI")
            .expect("POST_LOGOUT_REDIRECT_URI env var required"),
    });

    let state = AppState {
        http: Arc::new(ReqwestHttpClient::default()),
        cache: Arc::new(MokaCacheImpl::new(1024)),
        cfg,
    };

    let app = Router::new()
        .route("/", get(home))
        .route("/login", get(login))
        .route("/callback", get(callback))
        .route("/me", get(me))
        .route("/logout", get(logout))
        .with_state(state);

    let addr: SocketAddr = "0.0.0.0:3000".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!("Example BFF server listening on http://{}", addr);
    println!("Visit http://localhost:3000 to start");

    axum::serve(listener, app).await.unwrap();
}

async fn home() -> &'static str {
    "Welcome to xjp-oidc BFF example!\n\nVisit /login to start the OAuth flow."
}

async fn login(State(st): State<AppState>) -> Redirect {
    // Generate PKCE challenge
    let (verifier, challenge, _method) = create_pkce().expect("Failed to create PKCE");

    // In production: Save verifier to server-side session
    // For demo simplicity, we're using a temporary file (NOT FOR PRODUCTION!)
    std::fs::write("/tmp/pkce_verifier", &verifier).ok();

    // Build authorization URL
    let auth_url = build_auth_url(BuildAuthUrl {
        issuer: st.cfg.issuer.clone(),
        client_id: st.cfg.client_id.clone(),
        redirect_uri: st.cfg.redirect_uri.clone(),
        scope: "openid profile email xjp.admin".into(),
        state: Some("demo_state_12345".into()), // In production: generate random state
        nonce: Some("demo_nonce_67890".into()), // In production: generate random nonce
        prompt: None,
        code_challenge: challenge,
        extra_params: None,
        tenant: None,
    })
    .expect("Failed to build auth URL");

    // Also save state and nonce for verification (demo only)
    std::fs::write("/tmp/oauth_state", "demo_state_12345").ok();
    std::fs::write("/tmp/oauth_nonce", "demo_nonce_67890").ok();

    println!("Redirecting to: {}", auth_url);
    Redirect::to(auth_url.as_str())
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

async fn callback(State(st): State<AppState>, Query(query): Query<CallbackQuery>) -> String {
    // Parse callback parameters
    // Create a simple query string from the callback parameters
    let mut query_parts = vec![];
    if let Some(code) = &query.code {
        query_parts.push(format!("code={}", code));
    }
    if let Some(state) = &query.state {
        query_parts.push(format!("state={}", state));
    }
    if let Some(error) = &query.error {
        query_parts.push(format!("error={}", error));
    }
    if let Some(desc) = &query.error_description {
        query_parts.push(format!("error_description={}", desc));
    }
    let query_string = query_parts.join("&");

    let params = parse_callback_params(&query_string);

    // Check for OAuth errors
    if let Some(error) = params.error {
        return format!(
            "OAuth error: {} - {}",
            error,
            params.error_description.unwrap_or_default()
        );
    }

    // Verify state (demo only - in production use secure session)
    let expected_state = std::fs::read_to_string("/tmp/oauth_state")
        .ok()
        .unwrap_or_default();
    if params.state.as_deref() != Some(expected_state.trim()) {
        return "Invalid state parameter".to_string();
    }

    let code = params.code.expect("Authorization code missing");

    // Retrieve PKCE verifier (demo only - in production use secure session)
    let verifier = std::fs::read_to_string("/tmp/pkce_verifier")
        .expect("PKCE verifier not found")
        .trim()
        .to_string();

    // Exchange authorization code for tokens
    let tokens = match exchange_code(
        ExchangeCode {
            issuer: st.cfg.issuer.clone(),
            client_id: st.cfg.client_id.clone(),
            code,
            redirect_uri: st.cfg.redirect_uri.clone(),
            code_verifier: verifier,
            client_secret: None, // Public client
        },
        st.http.as_ref(),
    )
    .await
    {
        Ok(tokens) => tokens,
        Err(e) => return format!("Token exchange failed: {}", e),
    };

    // Verify ID token
    let id_token = tokens.id_token.as_ref().expect("ID token missing");

    // Retrieve expected nonce (demo only)
    let expected_nonce = std::fs::read_to_string("/tmp/oauth_nonce")
        .ok()
        .map(|n| n.trim().to_string());

    let claims = match verify_id_token(
        id_token,
        VerifyOptions {
            issuer: &st.cfg.issuer,
            audience: &st.cfg.client_id,
            nonce: expected_nonce.as_deref(),
            max_age_sec: None,
            clock_skew_sec: Some(120),
            http: st.http.as_ref(),
            cache: st.cache.as_ref(),
        },
    )
    .await
    {
        Ok(claims) => claims,
        Err(e) => return format!("ID token verification failed: {}", e),
    };

    // Save tokens and claims (demo only - in production use secure session)
    std::fs::write("/tmp/access_token", &tokens.access_token).ok();
    std::fs::write("/tmp/id_token", id_token).ok();

    // Display user info
    format!(
        "Login successful!\n\n\
        Subject: {}\n\
        Name: {}\n\
        Email: {}\n\
        Admin: {:?}\n\
        Auth Methods (amr): {:?}\n\
        Auth Time: {:?}\n\n\
        Access Token (first 20 chars): {}...\n\n\
        Visit /me to see the current user or /logout to end the session.",
        claims.sub,
        claims.name.as_deref().unwrap_or("(not provided)"),
        claims.email.as_deref().unwrap_or("(not provided)"),
        claims.xjp_admin,
        claims.amr,
        claims.auth_time,
        &tokens.access_token[..20.min(tokens.access_token.len())]
    )
}

async fn me() -> String {
    // In production: retrieve user info from secure session
    // For demo: check if we have tokens
    if std::fs::read_to_string("/tmp/access_token").is_ok() {
        "You are logged in!\n\nThis endpoint would normally return user info from the session."
            .to_string()
    } else {
        "Not logged in. Visit /login to start.".to_string()
    }
}

async fn logout(State(st): State<AppState>) -> Redirect {
    // Get ID token hint if available
    let id_token_hint = std::fs::read_to_string("/tmp/id_token")
        .unwrap_or_default()
        .trim()
        .to_string();

    // Clear session (demo only)
    std::fs::remove_file("/tmp/access_token").ok();
    std::fs::remove_file("/tmp/id_token").ok();
    std::fs::remove_file("/tmp/pkce_verifier").ok();
    std::fs::remove_file("/tmp/oauth_state").ok();
    std::fs::remove_file("/tmp/oauth_nonce").ok();

    // Build logout URL
    let logout_url = build_end_session_url(EndSession {
        issuer: st.cfg.issuer.clone(),
        id_token_hint,
        post_logout_redirect_uri: Some(st.cfg.post_logout_redirect_uri.clone()),
        state: None,
    })
    .unwrap_or_else(|_| url::Url::parse(&st.cfg.post_logout_redirect_uri).unwrap());

    Redirect::to(logout_url.as_str())
}
