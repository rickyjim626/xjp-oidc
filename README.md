# xjp-oidc - OpenID Connect SDK for Rust

[![Crates.io](https://img.shields.io/crates/v/xjp-oidc)](https://crates.io/crates/xjp-oidc)
[![Documentation](https://docs.rs/xjp-oidc/badge.svg)](https://docs.rs/xjp-oidc)
[![License](https://img.shields.io/crates/l/xjp-oidc)](LICENSE)
[![CI](https://github.com/xiaojinpro/xjp-oidc/actions/workflows/ci.yml/badge.svg)](https://github.com/xiaojinpro/xjp-oidc/actions)

A comprehensive OpenID Connect (OIDC) and OAuth 2.0 SDK for Rust, supporting both server-side and WebAssembly environments.

[中文文档](README_ZH.md) | English

## Features

- 🔐 **Complete OAuth2/OIDC Implementation**
  - Authorization Code Flow with PKCE
  - OIDC Discovery
  - JWKS Caching
  - ID Token Verification
  - Custom Claims Support

- 🌍 **Multi-Platform Support**
  - Native Rust (Linux, macOS, Windows)
  - WebAssembly (Browser)
  - Conditional Compilation

- 🚀 **Production Ready**
  - Enterprise Features (DCR, RP-Initiated Logout)
  - JWT Access Token Verification
  - Multi-Issuer Support
  - Comprehensive Error Handling

- 🔧 **Framework Integration**
  - Axum Middleware and Extractors
  - Tower Service Compatible
  - Type-Safe Claim Extraction

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
xjp-oidc = "1.0.0-rc.1"

# For Axum integration
xjp-oidc-axum = "1.0.0-rc.1"
```

Basic usage:

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

// 3. After callback, exchange code for tokens
let tokens = exchange_code(params, &http_client).await?;

// 4. Verify ID token
let verified = verify_id_token(&tokens.id_token, options).await?;
```

## Examples

The repository includes several comprehensive examples:

### Auth BFF Service
A production-ready authentication backend service:

```bash
cd auth-bff
cargo run
```

### Resource Server
JWT-protected API example:

```bash
cd examples/resource-server
cargo run
```

### DCR Tool
Dynamic Client Registration CLI:

```bash
cd examples/dcr-registration
cargo run -- register
```

## Documentation

- [Getting Started Guide](GETTING_STARTED.md) - Quick introduction and setup
- [API Reference](https://docs.rs/xjp-oidc) - Complete API documentation
- [Security Best Practices](SECURITY.md) - Security guidelines
- [Troubleshooting](TROUBLESHOOTING.md) - Common issues and solutions

## Platform Support

| Platform | Features | Status |
|----------|----------|---------|
| Linux x86_64 | Full | ✅ Supported |
| macOS (Intel/ARM) | Full | ✅ Supported |
| Windows | Full | ✅ Supported |
| WebAssembly | Core | ✅ Supported |

## Security

Security is our top priority. Please see [SECURITY.md](SECURITY.md) for:

- Vulnerability reporting process
- Security best practices
- Update policy

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for:

- Code of conduct
- Development setup
- Submission guidelines

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Project Structure

```
xjp-oidc/
├── xjp-oidc/           # Core SDK
├── xjp-oidc-axum/      # Axum integration
├── auth-bff/           # Auth BFF service example
├── examples/
│   ├── resource-server/  # Resource server example
│   └── dcr-registration/ # DCR CLI tool
└── docs/               # Documentation
```

## Minimum Supported Rust Version

MSRV: 1.82

## Support

- GitHub Issues: [Report bugs](https://github.com/xiaojinpro/xjp-oidc/issues)
- Discussions: [Ask questions](https://github.com/xiaojinpro/xjp-oidc/discussions)
- Security: security@xiaojinpro.com

---

Built with ❤️ by the XiaojinPro team