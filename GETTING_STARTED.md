# Getting Started with xjp-oidc

Welcome to xjp-oidc! This guide will help you get started with integrating OpenID Connect (OIDC) and OAuth2 authentication into your Rust application.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Platform Support](#platform-support)
- [Common Use Cases](#common-use-cases)
- [Examples](#examples)
- [Next Steps](#next-steps)

## Installation

Add xjp-oidc to your `Cargo.toml`:

```toml
[dependencies]
xjp-oidc = "1.0"

# For Axum integration (optional)
xjp-oidc-axum = "1.0"
```

### Feature Flags

```toml
# Default features (server with reqwest)
xjp-oidc = "1.0"

# For WASM/browser support
xjp-oidc = { version = "1.0", default-features = false, features = ["http-wasm", "browser-min"] }

# Minimal server (no caching)
xjp-oidc = { version = "1.0", default-features = false, features = ["http-reqwest"] }

# With specific cache implementation
xjp-oidc = { version = "1.0", features = ["moka"] }  # or "lru"
```

## Quick Start

### 1. Basic Authorization Code Flow

```rust
use xjp_oidc::{create_pkce, build_auth_url, parse_callback_params, exchange_code, verify_id_token};
use xjp_oidc::types::{BuildAuthUrl, ExchangeCode, VerifyOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Create PKCE challenge
    let (verifier, challenge, _) = create_pkce()?;
    
    // Step 2: Build authorization URL
    let auth_url = build_auth_url(BuildAuthUrl {
        issuer: "https://auth.example.com".into(),
        client_id: "your-client-id".into(),
        redirect_uri: "https://app.example.com/callback".into(),
        scope: "openid profile email".into(),
        code_challenge: challenge,
        state: Some("random-state".into()),
        nonce: Some("random-nonce".into()),
        ..Default::default()
    })?;
    
    println!("Visit this URL to authenticate: {}", auth_url);
    
    // Step 3: After user authentication, parse callback
    let callback_url = "https://app.example.com/callback?code=abc123&state=random-state";
    let params = parse_callback_params(callback_url);
    
    if let Some(code) = params.code {
        // Step 4: Exchange code for tokens
        let http_client = xjp_oidc::ReqwestHttpClient::default();
        
        let tokens = exchange_code(ExchangeCode {
            issuer: "https://auth.example.com".into(),
            client_id: "your-client-id".into(),
            code,
            redirect_uri: "https://app.example.com/callback".into(),
            code_verifier: verifier,
            client_secret: None, // For public clients
        }, &http_client).await?;
        
        // Step 5: Verify ID token
        if let Some(id_token) = tokens.id_token {
            let cache = xjp_oidc::MokaCacheImpl::new(100);
            
            let verified = verify_id_token(
                &id_token,
                VerifyOptions {
                    issuer: "https://auth.example.com",
                    audience: "your-client-id",
                    nonce: Some("random-nonce"),
                    max_age_sec: None,
                    clock_skew_sec: Some(60),
                    http: &http_client,
                    cache: &cache,
                }
            ).await?;
            
            println!("Authenticated user: {}", verified.sub);
            println!("Email: {:?}", verified.email);
        }
    }
    
    Ok(())
}
```

## Platform Support

### Server (Native) Platform

Full feature set including:
- Authorization code flow with PKCE
- Client credentials flow
- Dynamic Client Registration (DCR)
- Token exchange
- Full caching support (Moka/LRU)

### WASM/Browser Platform

Browser-compatible features:
- Authorization code flow with PKCE  
- ID token verification
- OIDC Discovery
- Minimal bundle size with `browser-min` feature

## Common Use Cases

### 1. Backend for Frontend (BFF) Pattern

```rust
use axum::{Router, response::Redirect};
use xjp_oidc::{create_pkce, build_auth_url};
use xjp_oidc::types::BuildAuthUrl;

async fn login() -> Result<Redirect, String> {
    let (verifier, challenge, _) = create_pkce()
        .map_err(|e| e.to_string())?;
    
    // Store verifier in session
    // session.insert("pkce_verifier", verifier);
    
    let auth_url = build_auth_url(BuildAuthUrl {
        issuer: "https://auth.example.com".into(),
        client_id: "your-client-id".into(),
        redirect_uri: "https://app.example.com/callback".into(),
        scope: "openid profile email".into(),
        code_challenge: challenge,
        ..Default::default()
    }).map_err(|e| e.to_string())?;
    
    Ok(Redirect::temporary(auth_url.as_str()))
}
```

### 2. Resource Server (API Protection)

```rust
use xjp_oidc::{JwtVerifier, MokaCacheImpl, ReqwestHttpClient};
use std::collections::HashMap;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let mut issuer_map = HashMap::new();
    issuer_map.insert(
        "auth.example.com".to_string(),
        "https://auth.example.com/jwks".to_string()
    );
    
    let verifier = JwtVerifier::new(
        issuer_map,
        "api-audience".to_string(),
        Arc::new(ReqwestHttpClient::default()),
        Arc::new(MokaCacheImpl::new(100)),
    );
    
    // In your API handler
    match verifier.verify("Bearer eyJ...").await {
        Ok(claims) => {
            println!("Valid token for user: {}", claims.sub);
        }
        Err(e) => {
            println!("Invalid token: {}", e);
        }
    }
}
```

### 3. Dynamic Client Registration

```rust
use xjp_oidc::{register_if_needed, ReqwestHttpClient};
use xjp_oidc::types::RegisterRequest;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let http_client = ReqwestHttpClient::default();
    
    let registration = register_if_needed(
        "https://auth.example.com",
        "initial-access-token",
        RegisterRequest {
            application_type: Some("web".into()),
            redirect_uris: vec!["https://app.example.com/callback".into()],
            grant_types: vec!["authorization_code".into()],
            token_endpoint_auth_method: "client_secret_basic".into(),
            scope: "openid profile email".into(),
            client_name: Some("My App".into()),
            ..Default::default()
        },
        &http_client
    ).await?;
    
    println!("Client ID: {}", registration.client_id);
    println!("Client Secret: {:?}", registration.client_secret);
    
    Ok(())
}
```

## Examples

The repository includes complete examples:

- **axum-bff**: Full BFF implementation with session management
- **axum-guard**: Resource server with JWT verification  
- **cli-discover**: CLI tool for OIDC discovery and debugging

To run an example:

```bash
cargo run --example axum-bff
```

## Next Steps

- Read the [API Documentation](API.md) for detailed reference
- Check [SECURITY.md](SECURITY.md) for security best practices
- See [DCR.md](DCR.md) for Dynamic Client Registration details
- Consult [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common issues

## Getting Help

- GitHub Issues: [https://github.com/xiaojinpro/xjp-oidc/issues](https://github.com/xiaojinpro/xjp-oidc/issues)
- API Documentation: Run `cargo doc --open`

## License

This project is licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.