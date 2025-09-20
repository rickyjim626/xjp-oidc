# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0-rc.1] - 2025-01-20

### Added
- Initial release of xjp-oidc
- Authorization Code Flow with PKCE support
- OIDC Discovery with caching
- JWKS endpoint support with automatic key rotation
- ID Token verification with custom claims (amr, xjp_admin, auth_time)
- Dynamic Client Registration (DCR) for server environments
- RP-Initiated Logout support
- Resource Server JWT verification
- Multi-tenant issuer mapping
- Axum integration with middleware and extractors
- Cross-platform support (native and WASM)
- Comprehensive examples (axum-bff, axum-guard, cli-discover)
- Full documentation suite

### Security
- PKCE required for all public clients
- State parameter validation
- Nonce support for replay protection
- Secure defaults throughout

[unreleased]: https://github.com/xiaojinpro/xjp-oidc/compare/v1.0.0-rc.1...HEAD
[1.0.0-rc.1]: https://github.com/xiaojinpro/xjp-oidc/releases/tag/v1.0.0-rc.1