# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2025-01-23

### Added
- Server-Sent Events (SSE) support for real-time login status monitoring
  - `start_login_session` function to create login sessions
  - `subscribe_login_events` for SSE event streaming
  - `check_login_status` for polling-based status checking
  - Login status tracking (Pending, Scanned, Authorized, Success, Failed, Expired)
  - Automatic reconnection and heartbeat support
  - Example code demonstrating SSE usage
- New `sse` feature flag for enabling SSE functionality
- Complete implementation of all features mentioned in the integration documentation

### Fixed
- Multi-tenant ClientId mode now properly appends client_id to discovery URL

### Dependencies
- Added `eventsource-client` v0.12 for SSE support
- Added `futures-util` v0.3 for stream processing
- Added `tokio-stream` v0.1 for timeout handling

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

[unreleased]: https://github.com/xiaojinpro/xjp-oidc/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/xiaojinpro/xjp-oidc/compare/v1.0.0-rc.1...v1.0.0
[1.0.0-rc.1]: https://github.com/xiaojinpro/xjp-oidc/releases/tag/v1.0.0-rc.1