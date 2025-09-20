# Security Best Practices for xjp-oidc

This document outlines security best practices and considerations when using xjp-oidc for OpenID Connect and OAuth2 authentication.

## Table of Contents

- [PKCE (Proof Key for Code Exchange)](#pkce-proof-key-for-code-exchange)
- [State Parameter and CSRF Protection](#state-parameter-and-csrf-protection)
- [Nonce Validation](#nonce-validation)
- [Token Storage](#token-storage)
- [HTTPS Requirements](#https-requirements)
- [Client Credentials](#client-credentials)
- [Token Validation](#token-validation)
- [Session Management](#session-management)
- [CORS and Origin Validation](#cors-and-origin-validation)
- [Vulnerability Disclosure](#vulnerability-disclosure)

## PKCE (Proof Key for Code Exchange)

**Always use PKCE for public clients** (SPAs, mobile apps, CLI tools):

```rust
// Generate PKCE challenge
let (verifier, challenge, method) = create_pkce()?;

// Store verifier securely (e.g., in session)
session.insert("pkce_verifier", verifier);

// Include challenge in authorization URL
let auth_url = build_auth_url(BuildAuthUrl {
    // ...
    code_challenge: challenge,
    // ...
})?;
```

PKCE protects against:
- Authorization code interception attacks
- Code injection attacks
- Compromised redirect URIs

## State Parameter and CSRF Protection

**Always use the state parameter** to prevent CSRF attacks:

```rust
use uuid::Uuid;

// Generate random state
let state = Uuid::new_v4().to_string();

// Store in session before redirect
session.insert("oauth_state", state.clone());

// Include in authorization URL
let auth_url = build_auth_url(BuildAuthUrl {
    // ...
    state: Some(state),
    // ...
})?;

// Validate on callback
let params = parse_callback_params(callback_url);
let session_state = session.get("oauth_state");

if params.state != session_state {
    return Err("CSRF attack detected");
}
```

## Nonce Validation

**Use nonce for ID token validation** to prevent replay attacks:

```rust
// Generate nonce
let nonce = Uuid::new_v4().to_string();
session.insert("oauth_nonce", nonce.clone());

// Include in authorization request
let auth_url = build_auth_url(BuildAuthUrl {
    // ...
    nonce: Some(nonce),
    // ...
})?;

// Validate in ID token
let verified = verify_id_token(
    &id_token,
    VerifyOptions {
        // ...
        nonce: Some(&session_nonce),
        // ...
    }
).await?;
```

## Token Storage

### Server-Side Applications

**Store tokens in secure server-side sessions**:

```rust
// Use encrypted session storage
session.insert("access_token", tokens.access_token);
session.insert("id_token", tokens.id_token);
session.insert("refresh_token", tokens.refresh_token);
```

**Never**:
- Log tokens
- Store tokens in URLs
- Include tokens in error messages
- Store tokens in local storage (for server apps)

### Browser Applications

For SPAs using the BFF pattern:
- Keep tokens on the server only
- Use secure, httpOnly, sameSite cookies for session
- Never expose tokens to JavaScript

## HTTPS Requirements

**Always use HTTPS in production**:

```rust
// Enforce HTTPS redirect URIs
let redirect_uri = "https://app.example.com/callback";

// Validate issuer uses HTTPS
if !issuer.starts_with("https://") {
    return Err("Issuer must use HTTPS");
}
```

## Client Credentials

### Public Clients

```rust
// No client secret for public clients
let params = ExchangeCode {
    // ...
    client_secret: None, // MUST be None for public clients
};
```

### Confidential Clients

```rust
// Store client secret securely
let client_secret = env::var("CLIENT_SECRET")?;

// Use environment variables or secure key management
let params = ExchangeCode {
    // ...
    client_secret: Some(client_secret),
};
```

**Never**:
- Hard-code client secrets
- Commit secrets to version control
- Log client secrets
- Expose secrets in error messages

## Token Validation

### ID Token Validation

Always validate ID tokens:

```rust
let verified = verify_id_token(
    &id_token,
    VerifyOptions {
        issuer: &expected_issuer,
        audience: &client_id,
        nonce: Some(&expected_nonce),
        max_age_sec: Some(300), // 5 minutes
        clock_skew_sec: Some(60), // 1 minute tolerance
        http: &http_client,
        cache: &jwks_cache,
    }
).await?;
```

Validation includes:
- Signature verification
- Issuer validation
- Audience validation
- Expiration checks
- Nonce validation (if provided)
- Max age validation (if provided)

### Access Token Validation (Resource Servers)

```rust
let verifier = JwtVerifier::builder()
    .issuer_map(allowed_issuers)
    .audience("api-audience")
    .clock_skew(60)
    .build()?;

// Validate bearer token
match verifier.verify(&bearer_token).await {
    Ok(claims) => {
        // Check additional claims
        if claims.scope.contains("required-scope") {
            // Authorized
        }
    }
    Err(_) => {
        // Unauthorized
    }
}
```

## Session Management

### Secure Session Configuration

```rust
use axum_sessions::{SessionLayer, SameSite};

let session_layer = SessionLayer::new(session_store, secret)
    .with_secure(true) // HTTPS only
    .with_same_site(SameSite::Lax) // CSRF protection
    .with_http_only(true); // No JS access
```

### Logout

Implement proper logout:

```rust
// Clear local session
session.clear();

// Redirect to OIDC end session endpoint
let logout_url = build_end_session_url(EndSession {
    issuer: issuer.clone(),
    id_token_hint: id_token,
    post_logout_redirect_uri: Some("https://app.example.com/logged-out"),
    state: Some(generate_state()),
})?;
```

## CORS and Origin Validation

For APIs accepting tokens:

```rust
use tower_http::cors::{CorsLayer, AllowOrigin};

let cors = CorsLayer::new()
    .allow_origin(AllowOrigin::predicate(|origin: &HeaderValue, _| {
        // Validate against allowed origins
        allowed_origins.contains(origin.to_str().unwrap_or(""))
    }))
    .allow_credentials(true);
```

## Security Headers

Implement security headers:

```rust
use tower_http::set_header::SetResponseHeaderLayer;
use http::header;

app.layer(SetResponseHeaderLayer::if_not_present(
    header::X_CONTENT_TYPE_OPTIONS,
    HeaderValue::from_static("nosniff"),
))
.layer(SetResponseHeaderLayer::if_not_present(
    header::X_FRAME_OPTIONS,
    HeaderValue::from_static("DENY"),
))
.layer(SetResponseHeaderLayer::if_not_present(
    header::REFERRER_POLICY,
    HeaderValue::from_static("strict-origin-when-cross-origin"),
));
```

## Rate Limiting

Implement rate limiting for authentication endpoints:

```rust
use tower::ServiceBuilder;
use tower_governor::{GovernorLayer, GovernorConfig};

let governor_conf = Box::new(
    GovernorConfig::default()
        .per_second(10) // 10 requests per second
        .burst_size(20)
);

let rate_limit = ServiceBuilder::new()
    .layer(GovernorLayer { config: governor_conf });
```

## Audit Logging

Log security-relevant events:

```rust
#[tracing::instrument(skip(tokens))]
async fn handle_callback(
    params: CallbackParams,
    tokens: TokenResponse,
) {
    tracing::info!(
        user_id = %verified.sub,
        auth_time = %verified.auth_time.unwrap_or(0),
        amr = ?verified.amr,
        "User authenticated successfully"
    );
}
```

**Never log**:
- Tokens (access, refresh, ID)
- Client secrets
- PKCE verifiers
- Full authorization codes

## Input Validation

Validate all inputs:

```rust
// Validate redirect URI format
fn validate_redirect_uri(uri: &str) -> Result<()> {
    let parsed = Url::parse(uri)?;
    
    // No fragments allowed
    if parsed.fragment().is_some() {
        return Err("Redirect URI cannot contain fragments");
    }
    
    // Must be HTTPS in production
    if !cfg!(debug_assertions) && parsed.scheme() != "https" {
        return Err("Redirect URI must use HTTPS");
    }
    
    Ok(())
}
```

## Vulnerability Disclosure

If you discover a security vulnerability in xjp-oidc:

1. **Do not** open a public issue
2. Email security@example.com with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will:
- Acknowledge receipt within 48 hours
- Provide a fix timeline within 7 days
- Credit researchers in security advisories (unless anonymity requested)

## Additional Resources

- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [OpenID Connect Security Considerations](https://openid.net/specs/openid-connect-core-1_0.html#Security)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

## Checklist

Before deploying to production:

- [ ] HTTPS enabled for all endpoints
- [ ] PKCE implemented for public clients
- [ ] State parameter validation enabled
- [ ] Nonce validation for ID tokens
- [ ] Secure session configuration
- [ ] Token storage follows best practices
- [ ] Client secrets stored securely
- [ ] Rate limiting implemented
- [ ] Security headers configured
- [ ] Audit logging enabled
- [ ] Input validation on all endpoints
- [ ] Error messages don't leak sensitive data
- [ ] Dependencies up to date
- [ ] Security scanning in CI/CD pipeline