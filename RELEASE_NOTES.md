# xjp-oidc v1.0.0-rc.1 Release Notes

## 🎉 First Release Candidate

We are excited to announce the first release candidate of xjp-oidc, a comprehensive OIDC/OAuth2 SDK for Rust with support for both server and WASM environments.

## 📦 Installation

```toml
[dependencies]
xjp-oidc = "1.0.0-rc.1"

# For Axum integration
xjp-oidc-axum = "1.0.0-rc.1"
```

## ✨ Features

### Core Functionality
- 🔐 **Authorization Code Flow with PKCE** - Secure authentication for public and confidential clients
- 🌐 **OIDC Discovery** - Automatic endpoint discovery with caching
- 🔑 **JWKS Caching** - Efficient key rotation handling
- ✅ **ID Token Verification** - Comprehensive validation including custom claims (amr, xjp_admin, auth_time)
- 📝 **Dynamic Client Registration** - Server-side client registration (RFC 7591)
- 🚪 **RP-Initiated Logout** - Proper session termination
- 🛡️ **Resource Server Verification** - JWT access token validation for APIs

### Platform Support
- 🖥️ **Server/Native** - Full feature set with async runtime
- 🌐 **WASM/Browser** - Browser-compatible subset for SPAs
- 🎯 **Cross-Platform** - Single codebase for all platforms

### Integration
- 🔌 **Axum Middleware** - Ready-to-use authentication layer
- 📤 **Extractors** - Type-safe claim extraction
- 🛡️ **Guards** - Route protection based on claims

## 📖 Documentation

- [Getting Started Guide](https://github.com/xiaojinpro/xjp-oidc/blob/v1.0.0-rc.1/GETTING_STARTED.md)
- [API Reference](https://docs.rs/xjp-oidc/1.0.0-rc.1)
- [Security Best Practices](https://github.com/xiaojinpro/xjp-oidc/blob/v1.0.0-rc.1/SECURITY.md)
- [DCR Guide](https://github.com/xiaojinpro/xjp-oidc/blob/v1.0.0-rc.1/DCR.md)
- [Troubleshooting](https://github.com/xiaojinpro/xjp-oidc/blob/v1.0.0-rc.1/TROUBLESHOOTING.md)

## 🚀 Quick Start

```rust
use xjp_oidc::{create_pkce, build_auth_url, exchange_code, verify_id_token};
use xjp_oidc::types::{BuildAuthUrl, ExchangeCode, VerifyOptions};

// 1. Create PKCE challenge
let (verifier, challenge, _) = create_pkce()?;

// 2. Build authorization URL
let auth_url = build_auth_url(BuildAuthUrl {
    issuer: "https://auth.example.com".into(),
    client_id: "your-client-id".into(),
    redirect_uri: "https://app.example.com/callback".into(),
    scope: "openid profile email".into(),
    code_challenge: challenge,
    ..Default::default()
})?;

// 3. Exchange code for tokens (after callback)
let tokens = exchange_code(params, &http_client).await?;

// 4. Verify ID token
let verified = verify_id_token(&tokens.id_token, options).await?;
```

## 📝 Examples

The repository includes three comprehensive examples:

- **axum-bff** - Backend for Frontend implementation with session management
- **axum-guard** - Resource server with JWT verification
- **cli-discover** - CLI tool for OIDC discovery and debugging

## 🔧 Minimum Supported Rust Version

MSRV: 1.82

## 🤝 Contributing

This is a release candidate. We welcome feedback and bug reports!

- Report issues: https://github.com/xiaojinpro/xjp-oidc/issues
- Security issues: See [SECURITY.md](SECURITY.md)

## 📄 License

Licensed under either of:
- Apache License, Version 2.0
- MIT license

at your option.