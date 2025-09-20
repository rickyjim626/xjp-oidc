# Troubleshooting Guide for xjp-oidc

This guide helps you diagnose and resolve common issues when using xjp-oidc.

## Table of Contents

- [Common Errors](#common-errors)
- [Platform-Specific Issues](#platform-specific-issues)
- [Provider-Specific Issues](#provider-specific-issues)
- [Debug Techniques](#debug-techniques)
- [Performance Issues](#performance-issues)
- [Security Issues](#security-issues)
- [Getting Help](#getting-help)

## Common Errors

### "Network error: Failed to fetch"

**Symptoms:**
- HTTP requests fail immediately
- No response from provider

**Possible Causes:**
1. Network connectivity issues
2. CORS issues (browser environments)
3. SSL/TLS certificate problems
4. Firewall blocking requests

**Solutions:**

```rust
// 1. Check network connectivity
let http_client = ReqwestHttpClient::default();
match http_client.get_value("https://example.com/.well-known/openid-configuration").await {
    Ok(_) => println!("Network OK"),
    Err(e) => println!("Network error: {}", e),
}

// 2. For CORS issues in browser, ensure provider allows your origin
// Provider must include appropriate CORS headers

// 3. For SSL issues in development
#[cfg(debug_assertions)]
let http_client = ReqwestHttpClient::builder()
    .danger_accept_invalid_certs(true) // NEVER use in production
    .build()?;

// 4. Use proxy if needed
let http_client = ReqwestHttpClient::builder()
    .proxy("http://proxy.company.com:8080")
    .build()?;
```

### "JWT verification failed: Invalid signature"

**Symptoms:**
- ID token verification fails
- Access token verification fails
- "Invalid signature" error

**Possible Causes:**
1. Wrong JWKS endpoint
2. Cached JWKS is stale
3. Token tampered or corrupted
4. Wrong issuer configuration

**Solutions:**

```rust
// 1. Clear JWKS cache to force refresh
cache.clear();

// 2. Verify issuer configuration
let metadata = discover(&issuer, &http_client, &cache).await?;
println!("JWKS URI: {}", metadata.jwks_uri);

// 3. Manually verify JWKS is accessible
let jwks_response = http_client.get_value(&metadata.jwks_uri).await?;
println!("JWKS: {}", jwks_response);

// 4. Check token hasn't been modified
// Decode without verification to inspect claims
let parts: Vec<&str> = token.split('.').collect();
if parts.len() == 3 {
    let payload = base64_decode_url_safe(parts[1])?;
    let claims: serde_json::Value = serde_json::from_slice(&payload)?;
    println!("Token claims: {}", claims);
}
```

### "Invalid audience"

**Symptoms:**
- Token verification succeeds but audience check fails
- "Invalid audience: expected 'X', got 'Y'"

**Possible Causes:**
1. Wrong client ID configured
2. Token issued for different application
3. Provider configuration mismatch

**Solutions:**

```rust
// 1. Verify expected audience
println!("Expected audience: {}", client_id);

// 2. Check token's actual audience
// The error message should show actual vs expected

// 3. For resource servers, ensure correct audience
let verifier = JwtVerifier::builder()
    .audience("api-audience") // Must match token's aud claim
    .build()?;

// 4. Some providers use arrays for audience
// xjp-oidc handles this automatically, but verify token format
```

### "Token expired"

**Symptoms:**
- Token verification fails with expiration error
- Previously working tokens stop working

**Possible Causes:**
1. Token actually expired
2. Clock skew between systems
3. Incorrect timezone handling

**Solutions:**

```rust
// 1. Check token expiration
let verified = verify_id_token(
    &id_token,
    VerifyOptions {
        // ...
        clock_skew_sec: Some(300), // Allow 5 minutes clock skew
        // ...
    }
).await?;

// 2. Implement token refresh
async fn ensure_valid_token(session: &Session) -> Result<String> {
    let access_token = session.get("access_token")?;
    let expires_at = session.get("expires_at")?;
    
    if expires_at <= current_time() + 60 { // Refresh 1 minute before expiry
        let new_tokens = refresh_token(&refresh_token).await?;
        session.set("access_token", new_tokens.access_token);
        session.set("expires_at", current_time() + new_tokens.expires_in);
        return Ok(new_tokens.access_token);
    }
    
    Ok(access_token)
}
```

### "PKCE validation failed"

**Symptoms:**
- Token exchange fails
- "invalid_grant" error with PKCE-related message

**Possible Causes:**
1. Mismatch between verifier and challenge
2. Verifier not stored correctly
3. Challenge method not supported

**Solutions:**

```rust
// 1. Ensure PKCE values are stored correctly
let (verifier, challenge, method) = create_pkce()?;
session.insert("pkce_verifier", verifier.clone()); // Store before redirect

// 2. Verify challenge method is supported
let metadata = discover(&issuer, &http_client, &cache).await?;
if let Some(methods) = &metadata.code_challenge_methods_supported {
    assert!(methods.contains(&"S256".to_string()));
}

// 3. Debug PKCE values
println!("Verifier: {}", verifier);
println!("Challenge: {}", challenge);
println!("Method: {}", method); // Should be "S256"

// 4. Ensure verifier is retrieved correctly
let stored_verifier = session.get("pkce_verifier")
    .ok_or("PKCE verifier not found in session")?;
```

## Platform-Specific Issues

### WASM/Browser Issues

#### "Cannot use blocking operations"

**Error:** `RuntimeError: unreachable`

**Solution:**
```rust
// Use browser-compatible features only
#[cfg(target_arch = "wasm32")]
use xjp_oidc::WasmHttpClient;

#[cfg(not(target_arch = "wasm32"))]
use xjp_oidc::ReqwestHttpClient;

// Use appropriate cache
#[cfg(target_arch = "wasm32")]
let cache = xjp_oidc::NoOpCache; // Or implement browser storage cache

#[cfg(not(target_arch = "wasm32"))]
let cache = xjp_oidc::MokaCacheImpl::new(100);
```

#### "Failed to fetch" in browser

**Cause:** CORS not configured on provider

**Solution:**
- Ensure OIDC provider allows your origin
- Use BFF pattern to avoid CORS
- Configure provider to add CORS headers

### Server/Native Issues

#### "There is no reactor running"

**Error:** Tokio runtime not found

**Solution:**
```rust
// Ensure you have a runtime
#[tokio::main]
async fn main() {
    // Your code here
}

// Or create runtime explicitly
let runtime = tokio::runtime::Runtime::new()?;
runtime.block_on(async {
    // Your async code
});
```

#### Certificate errors

**Error:** "certificate verify failed"

**Solution:**
```rust
// For development only
#[cfg(debug_assertions)]
let http_client = ReqwestHttpClient::builder()
    .danger_accept_invalid_certs(true)
    .build()?;

// For production, add CA certificates
let http_client = ReqwestHttpClient::builder()
    .add_root_certificate(cert)
    .build()?;
```

## Provider-Specific Issues

### Keycloak

#### "Invalid redirect_uri"

Keycloak requires exact redirect URI matching:

```rust
// Ensure redirect_uri matches exactly
let redirect_uri = "https://app.example.com/callback"; // No trailing slash
```

#### Missing claims

Enable mappers in Keycloak client configuration for custom claims.

### Auth0

#### Custom claims not appearing

Auth0 requires namespaced custom claims:

```json
{
  "https://example.com/xjp_admin": true,
  "https://example.com/amr": ["pwd", "mfa"]
}
```

#### Rate limiting

Auth0 has strict rate limits:

```rust
// Implement exponential backoff
use backoff::{ExponentialBackoff, backoff::Error};

async fn with_retry<F, Fut, T>(f: F) -> Result<T>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut backoff = ExponentialBackoff::default();
    loop {
        match f().await {
            Ok(result) => return Ok(result),
            Err(e) if e.to_string().contains("429") => {
                if let Some(duration) = backoff.next() {
                    tokio::time::sleep(duration).await;
                } else {
                    return Err(e);
                }
            }
            Err(e) => return Err(e),
        }
    }
}
```

### Okta

#### "invalid_client" errors

Okta requires specific client authentication methods:

```rust
// For public clients
ExchangeCode {
    // ...
    client_secret: None,
}

// For confidential clients with client_secret_post
let form_params = vec![
    ("client_id", client_id),
    ("client_secret", client_secret),
    // ... other params
];
```

## Debug Techniques

### Enable Logging

```rust
use tracing_subscriber;

// Enable debug logging
tracing_subscriber::fmt()
    .with_max_level(tracing::Level::DEBUG)
    .with_env_filter("xjp_oidc=debug")
    .init();
```

### Capture HTTP Traffic

```rust
// Log all HTTP requests/responses
let http_client = ReqwestHttpClient::builder()
    .connection_verbose(true)
    .build()?;
```

### Manual Token Inspection

```rust
// Decode token without verification
fn inspect_token(token: &str) -> Result<()> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid token format");
    }
    
    // Decode header
    let header = base64_decode_url_safe(parts[0])?;
    let header_json: serde_json::Value = serde_json::from_slice(&header)?;
    println!("Header: {}", serde_json::to_string_pretty(&header_json)?);
    
    // Decode payload
    let payload = base64_decode_url_safe(parts[1])?;
    let payload_json: serde_json::Value = serde_json::from_slice(&payload)?;
    println!("Payload: {}", serde_json::to_string_pretty(&payload_json)?);
    
    Ok(())
}
```

### Discovery Endpoint Testing

```rust
use xjp_oidc::cli_discover;

// Use the CLI tool
// cargo run --example cli-discover -- https://auth.example.com

// Or programmatically
async fn test_discovery(issuer: &str) -> Result<()> {
    let http_client = ReqwestHttpClient::default();
    let cache = NoOpCache;
    
    match discover(issuer, &http_client, &cache).await {
        Ok(metadata) => {
            println!("Discovery successful!");
            println!("Auth endpoint: {}", metadata.authorization_endpoint);
            println!("Token endpoint: {}", metadata.token_endpoint);
            println!("JWKS URI: {}", metadata.jwks_uri);
        }
        Err(e) => {
            println!("Discovery failed: {}", e);
            // Try manual URL
            let well_known = format!("{}/.well-known/openid-configuration", issuer);
            println!("Try accessing: {}", well_known);
        }
    }
    Ok(())
}
```

## Performance Issues

### Slow Token Verification

**Cause:** JWKS fetched on every verification

**Solution:**
```rust
// Use proper caching
let cache = MokaCacheImpl::new(100); // Cache up to 100 JWKS
let cache_arc = Arc::new(cache);

// Reuse cache across requests
let verifier = JwtVerifier::new(
    issuer_map,
    audience,
    http_arc,
    cache_arc.clone(), // Share cache
);
```

### High Memory Usage

**Cause:** Large cache or memory leaks

**Solution:**
```rust
// Limit cache size
let cache = MokaCacheImpl::builder()
    .max_capacity(50) // Limit entries
    .time_to_live(Duration::from_secs(3600)) // TTL
    .build();

// Use LRU for constrained memory
let cache = LruCacheImpl::new(10); // Only 10 entries
```

## Security Issues

### Token Leakage in Logs

**Never log tokens:**

```rust
// Bad
println!("Token: {}", access_token);

// Good
println!("Token length: {}", access_token.len());
println!("Token prefix: {}...", &access_token[..10]);
```

### Insecure Token Storage

**Use secure session storage:**

```rust
// Configure secure sessions
let session_layer = SessionLayer::new(store, secret)
    .with_secure(true)
    .with_http_only(true)
    .with_same_site(SameSite::Lax);
```

## Getting Help

### Before Asking for Help

1. **Check error messages carefully** - They often contain the solution
2. **Enable debug logging** - See what's actually happening
3. **Test with CLI tool** - Isolate the issue
4. **Check provider documentation** - Provider-specific requirements
5. **Search existing issues** - Someone may have had the same problem

### Information to Provide

When reporting issues, include:

```markdown
**Environment:**
- xjp-oidc version: 1.0.0
- Rust version: 1.75.0
- Platform: Linux/macOS/Windows/WASM
- Provider: Keycloak/Auth0/Okta/Other

**Configuration:**
```rust
// Your configuration (redact secrets)
```

**Error:**
```
// Full error message and stack trace
```

**Steps to Reproduce:**
1. ...
2. ...

**Expected behavior:**
What should happen

**Actual behavior:**
What actually happens
```

### Community Resources

- GitHub Issues: [https://github.com/xiaojinpro/xjp-oidc/issues](https://github.com/xiaojinpro/xjp-oidc/issues)
- Discord/Slack: [Community Chat]
- Stack Overflow: Tag with `xjp-oidc`

### Commercial Support

For commercial support, contact: support@example.com

## Quick Reference

### Error Mapping

| Error | Common Cause | Quick Fix |
|-------|--------------|-----------|
| `Network error` | Connectivity/CORS | Check network, use BFF |
| `Invalid signature` | Wrong JWKS | Clear cache, verify issuer |
| `Invalid audience` | Wrong client_id | Check aud claim |
| `Token expired` | Time issue | Add clock skew |
| `Invalid grant` | PKCE mismatch | Check verifier storage |
| `Discovery failed` | Wrong issuer URL | Verify well-known endpoint |
| `CORS error` | Browser security | Use BFF pattern |
| `No reactor` | No async runtime | Add tokio::main |

### Health Check Endpoint

Implement a health check for your OIDC integration:

```rust
async fn oidc_health_check() -> Result<HealthStatus> {
    let mut status = HealthStatus::default();
    
    // Check discovery
    match discover(&issuer, &http_client, &cache).await {
        Ok(_) => status.discovery = true,
        Err(e) => status.errors.push(format!("Discovery: {}", e)),
    }
    
    // Check JWKS
    match fetch_jwks(&jwks_uri, &http_client, &cache).await {
        Ok(_) => status.jwks = true,
        Err(e) => status.errors.push(format!("JWKS: {}", e)),
    }
    
    Ok(status)
}
```