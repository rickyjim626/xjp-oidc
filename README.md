# xjp-oidc

A comprehensive OIDC/OAuth2 SDK for Rust with support for both server and WASM environments.

[![Crates.io](https://img.shields.io/crates/v/xjp-oidc.svg)](https://crates.io/crates/xjp-oidc)
[![Documentation](https://docs.rs/xjp-oidc/badge.svg)](https://docs.rs/xjp-oidc)
[![CI](https://github.com/xiaojinpro/xjp-oidc/workflows/CI/badge.svg)](https://github.com/xiaojinpro/xjp-oidc/actions)
[![License: MIT OR Apache-2.0](https://img.shields.io/crates/l/xjp-oidc.svg)](LICENSE-MIT)

## Features

- 🔐 **Authorization Code Flow with PKCE**: Full support for the most secure OAuth2 flow
- 🌐 **OIDC Discovery**: Automatic endpoint discovery with caching
- 🔑 **JWKS Caching**: Efficient key rotation handling
- ✅ **ID Token Verification**: Comprehensive claim validation including `amr`, `xjp_admin`, and `auth_time`
- 📝 **Dynamic Client Registration** (DCR): Server-side client registration support
- 🚪 **RP-Initiated Logout**: Clean session termination
- 🛡️ **Resource Server Verification**: JWT access token validation for APIs
- 🔌 **Axum Integration**: Optional middleware and extractors for Axum web framework
- 🌍 **Multi-Platform**: Works on both server (native) and browser (WASM)

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
xjp-oidc = "1.0"

# For Axum integration
xjp-oidc-axum = "1.0"
```

### Server-side Usage

```rust
use xjp_oidc::prelude::*;

// Create PKCE challenge
let (verifier, challenge, _) = create_pkce()?;

// Build authorization URL
let auth_url = build_auth_url(BuildAuthUrl {
    issuer: "https://auth.example.com".into(),
    client_id: "my-client".into(),
    redirect_uri: "https://app.example.com/callback".into(),
    scope: "openid profile email".into(),
    code_challenge: challenge,
    ..Default::default()
})?;

// After user authorization, exchange code for tokens
let tokens = exchange_code(ExchangeCode {
    issuer: "https://auth.example.com".into(),
    client_id: "my-client".into(),
    code: "auth_code_from_callback".into(),
    redirect_uri: "https://app.example.com/callback".into(),
    code_verifier: verifier,
    client_secret: None,
}, &http_client).await?;

// Verify ID token
let claims = verify_id_token(&tokens.id_token, VerifyOptions {
    issuer: "https://auth.example.com",
    audience: "my-client",
    http: &http_client,
    cache: &cache,
    ..Default::default()
}).await?;
```

### Browser (WASM) Usage

For browser environments, only URL building and callback parsing are available:

```rust
// Build authorization URL
let auth_url = build_auth_url(...)?;

// Parse callback
let params = parse_callback_params(&window.location.href)?;
```

## Axum Integration

```rust
use xjp_oidc_axum::{OidcLayer, AdminGuard};

let verifier = JwtVerifier::new(...);

let app = Router::new()
    .route("/api/data", get(handler))
    .layer(OidcLayer::new(verifier))
    .route("/admin", post(admin_handler))
    .route_layer(AdminGuard::new());
```

## MSRV

The Minimum Supported Rust Version is 1.75.0.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.