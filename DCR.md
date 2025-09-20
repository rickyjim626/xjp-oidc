# Dynamic Client Registration (DCR) Guide

This guide covers Dynamic Client Registration (DCR) functionality in xjp-oidc, which allows applications to register OAuth2/OIDC clients programmatically.

## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Basic Usage](#basic-usage)
- [Registration Parameters](#registration-parameters)
- [Initial Access Tokens](#initial-access-tokens)
- [Client Management](#client-management)
- [Security Considerations](#security-considerations)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)

## Overview

Dynamic Client Registration (DCR) is defined in [RFC 7591](https://tools.ietf.org/html/rfc7591) and allows OAuth2 clients to register themselves with authorization servers at runtime, rather than through manual configuration.

### When to Use DCR

DCR is useful for:
- Multi-tenant SaaS applications
- Developer portals with self-service client registration
- Automated deployment pipelines
- Testing and development environments

### When NOT to Use DCR

DCR is not appropriate for:
- Public/browser-based applications (security risk)
- Applications with static deployment configurations
- Environments where client registration requires manual approval

## Requirements

1. **Server-side only**: DCR is only available in server environments (not WASM/browser)
2. **Initial access token**: Most providers require an initial access token
3. **Provider support**: The OIDC provider must support DCR

Check provider support:

```rust
use xjp_oidc::{discover, ReqwestHttpClient, NoOpCache};

let http_client = ReqwestHttpClient::default();
let cache = NoOpCache;

let metadata = discover(issuer, &http_client, &cache).await?;

if let Some(registration_endpoint) = metadata.registration_endpoint {
    println!("DCR supported at: {}", registration_endpoint);
} else {
    println!("DCR not supported by this provider");
}
```

## Basic Usage

### Register a New Client

```rust
use xjp_oidc::{register_if_needed, ReqwestHttpClient};
use xjp_oidc::types::RegisterRequest;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let http_client = ReqwestHttpClient::default();
    
    let registration_request = RegisterRequest {
        application_type: Some("web".to_string()),
        redirect_uris: vec![
            "https://app.example.com/callback".to_string(),
            "https://app.example.com/silent-callback".to_string(),
        ],
        post_logout_redirect_uris: Some(vec![
            "https://app.example.com/logged-out".to_string(),
        ]),
        grant_types: vec!["authorization_code".to_string()],
        token_endpoint_auth_method: "client_secret_basic".to_string(),
        scope: "openid profile email".to_string(),
        client_name: Some("My Application".to_string()),
        contacts: Some(vec!["admin@example.com".to_string()]),
        software_id: Some("my-app-v1".to_string()),
    };
    
    let result = register_if_needed(
        "https://auth.example.com",
        "initial-access-token-from-provider",
        registration_request,
        &http_client
    ).await?;
    
    println!("Client ID: {}", result.client_id);
    println!("Client Secret: {:?}", result.client_secret);
    
    // Store these securely!
    store_client_credentials(&result);
    
    Ok(())
}
```

## Registration Parameters

### RegisterRequest Fields

| Field | Type | Description | Required |
|-------|------|-------------|----------|
| `application_type` | `Option<String>` | "web" or "native" | No |
| `redirect_uris` | `Vec<String>` | Allowed redirect URIs | Yes |
| `post_logout_redirect_uris` | `Option<Vec<String>>` | Allowed logout redirect URIs | No |
| `grant_types` | `Vec<String>` | OAuth2 grant types | Yes |
| `token_endpoint_auth_method` | `String` | Client authentication method | Yes |
| `scope` | `String` | Requested scopes | Yes |
| `client_name` | `Option<String>` | Human-readable name | No |
| `contacts` | `Option<Vec<String>>` | Contact emails | No |
| `software_id` | `Option<String>` | Software identifier | No |

### Common Configurations

#### Web Application (Confidential Client)

```rust
RegisterRequest {
    application_type: Some("web".to_string()),
    redirect_uris: vec!["https://app.example.com/callback".to_string()],
    grant_types: vec!["authorization_code".to_string(), "refresh_token".to_string()],
    token_endpoint_auth_method: "client_secret_basic".to_string(),
    scope: "openid profile email".to_string(),
    client_name: Some("My Web App".to_string()),
    ..Default::default()
}
```

#### Native Application (Public Client)

```rust
RegisterRequest {
    application_type: Some("native".to_string()),
    redirect_uris: vec![
        "com.example.app://callback".to_string(),
        "http://localhost:8080/callback".to_string(), // For development
    ],
    grant_types: vec!["authorization_code".to_string()],
    token_endpoint_auth_method: "none".to_string(), // Public client
    scope: "openid profile".to_string(),
    client_name: Some("My Mobile App".to_string()),
    ..Default::default()
}
```

#### Service-to-Service (Client Credentials)

```rust
RegisterRequest {
    application_type: Some("service".to_string()),
    redirect_uris: vec![], // Not needed for client credentials
    grant_types: vec!["client_credentials".to_string()],
    token_endpoint_auth_method: "client_secret_post".to_string(),
    scope: "api:read api:write".to_string(),
    client_name: Some("Backend Service".to_string()),
    ..Default::default()
}
```

## Initial Access Tokens

Most providers require an initial access token for DCR. How to obtain one varies by provider:

### Provider-Specific Examples

#### Keycloak

```bash
# Get initial access token from Keycloak admin
curl -X POST https://keycloak.example.com/auth/admin/realms/myrealm/clients-initial-access \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"count": 1, "expiration": 3600}'
```

#### Auth0

```bash
# Use Management API to create DCR token
curl -X POST https://your-domain.auth0.com/api/v2/client-grants \
  -H "Authorization: Bearer $MGMT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "dcr-client",
    "audience": "https://your-domain.auth0.com/api/v2/",
    "scope": ["create:client"]
  }'
```

### Storing Initial Access Tokens

```rust
use std::env;

// Development: Environment variable
let initial_token = env::var("DCR_INITIAL_TOKEN")?;

// Production: Use secure key management
let initial_token = key_vault.get_secret("dcr-initial-token").await?;
```

## Client Management

### Storing Client Credentials

After successful registration, store credentials securely:

```rust
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct StoredClient {
    client_id: String,
    client_secret: Option<String>,
    client_id_issued_at: i64,
    registration_access_token: Option<String>,
    registration_client_uri: Option<String>,
}

async fn store_client_credentials(result: &ClientRegistrationResult) -> Result<()> {
    let stored = StoredClient {
        client_id: result.client_id.clone(),
        client_secret: result.client_secret.clone(),
        client_id_issued_at: result.client_id_issued_at,
        registration_access_token: result.registration_access_token.clone(),
        registration_client_uri: result.registration_client_uri.clone(),
    };
    
    // Encrypt before storing
    let encrypted = encrypt(&serde_json::to_vec(&stored)?)?;
    
    // Store in database
    db.execute(
        "INSERT INTO oauth_clients (app_id, credentials) VALUES (?, ?)",
        &[&app_id, &encrypted]
    ).await?;
    
    Ok(())
}
```

### Updating Client Configuration

If the provider returns a `registration_access_token` and `registration_client_uri`, you can update the client:

```rust
// Read current configuration
let response = http_client.get_value(
    &registration_client_uri,
    Some(("Authorization", &format!("Bearer {}", registration_access_token)))
).await?;

// Update configuration
let updated = serde_json::json!({
    "redirect_uris": [
        "https://app.example.com/callback",
        "https://app.example.com/new-callback"  // Add new URI
    ],
    // ... other fields
});

let result = http_client.put_json_value(
    &registration_client_uri,
    &updated,
    Some(("Authorization", &format!("Bearer {}", registration_access_token)))
).await?;
```

## Security Considerations

### 1. Never Use DCR in Public Clients

```rust
#[cfg(target_arch = "wasm32")]
compile_error!("DCR cannot be used in browser/WASM environments");
```

### 2. Protect Initial Access Tokens

- Rotate tokens regularly
- Use short expiration times
- Monitor usage
- Implement rate limiting

### 3. Validate Registration Responses

```rust
fn validate_registration_response(response: &ClientRegistrationResult) -> Result<()> {
    // Ensure client_id is present and valid
    if response.client_id.is_empty() {
        return Err("Invalid client_id");
    }
    
    // For confidential clients, ensure secret is provided
    if response.token_endpoint_auth_method != "none" 
        && response.client_secret.is_none() {
        return Err("Missing client_secret for confidential client");
    }
    
    // Validate expiration if provided
    if let Some(expires_at) = response.client_secret_expires_at {
        if expires_at > 0 && expires_at < current_timestamp() {
            return Err("Client secret already expired");
        }
    }
    
    Ok(())
}
```

### 4. Secure Storage

```rust
// Use environment-specific encryption
let key = match env::var("ENVIRONMENT") {
    Ok(env) if env == "production" => kms.get_encryption_key().await?,
    _ => derive_key_from_passphrase(&env::var("DEV_PASSPHRASE")?),
};

let encrypted_credentials = encrypt_with_aes_gcm(&credentials, &key)?;
```

## Examples

### Multi-Tenant Registration

```rust
async fn register_tenant_client(
    tenant_id: &str,
    tenant_domain: &str,
) -> Result<ClientRegistrationResult> {
    let request = RegisterRequest {
        application_type: Some("web".to_string()),
        redirect_uris: vec![
            format!("https://{}.example.com/callback", tenant_domain),
            format!("https://{}.example.com/silent-renew", tenant_domain),
        ],
        post_logout_redirect_uris: Some(vec![
            format!("https://{}.example.com/", tenant_domain),
        ]),
        grant_types: vec!["authorization_code".to_string()],
        token_endpoint_auth_method: "client_secret_basic".to_string(),
        scope: "openid profile email tenant:read".to_string(),
        client_name: Some(format!("{} Portal", tenant_id)),
        software_id: Some(format!("tenant-portal-{}", tenant_id)),
        ..Default::default()
    };
    
    let result = register_if_needed(
        &issuer,
        &get_initial_token().await?,
        request,
        &http_client
    ).await?;
    
    // Store with tenant association
    store_tenant_client(tenant_id, &result).await?;
    
    Ok(result)
}
```

### Conditional Registration

```rust
async fn get_or_create_client(app_id: &str) -> Result<OAuthClient> {
    // Check if client already exists
    if let Some(existing) = load_client_from_db(app_id).await? {
        return Ok(existing);
    }
    
    // Register new client
    let request = build_registration_request(app_id);
    
    let result = register_if_needed(
        &issuer,
        &get_initial_token().await?,
        request,
        &http_client
    ).await?;
    
    // Store and return
    let client = OAuthClient::from(result);
    save_client_to_db(app_id, &client).await?;
    
    Ok(client)
}
```

## Troubleshooting

### Common Errors

#### "Registration endpoint not found"

The provider doesn't support DCR or hasn't enabled it:

```rust
// Check discovery document
let metadata = discover(&issuer, &http_client, &cache).await?;
match metadata.registration_endpoint {
    Some(endpoint) => println!("DCR endpoint: {}", endpoint),
    None => println!("DCR not supported"),
}
```

#### "Invalid initial access token"

- Token might be expired
- Token might be for wrong realm/tenant
- Token might lack required permissions

#### "Invalid redirect_uri"

- Ensure URIs match provider requirements
- Check for HTTPS requirement
- Verify URI format (no fragments, proper encoding)

### Debug Logging

Enable debug logging to see DCR requests/responses:

```rust
use tracing_subscriber;

tracing_subscriber::fmt()
    .with_max_level(tracing::Level::DEBUG)
    .init();

// DCR requests will be logged
```

### Provider-Specific Quirks

#### Keycloak
- Requires `application_type` field
- Supports `default_acr_values` in request
- Returns `registration_access_token` for updates

#### Auth0
- Requires specific grant types format
- Custom claims via `app_metadata`
- Limited update capabilities

#### Okta
- Requires `response_types` in addition to `grant_types`
- Supports `logo_uri` and `policy_uri`
- Enforces strict redirect URI validation

## Best Practices

1. **Cache Registration Results**: Don't re-register on every startup
2. **Handle Expiration**: Some providers expire client credentials
3. **Monitor Usage**: Track registration failures and patterns
4. **Implement Retry Logic**: Handle transient failures gracefully
5. **Audit Registration**: Log all registration attempts for security
6. **Validate Provider**: Ensure you're registering with the correct issuer
7. **Use Descriptive Names**: Help administrators identify your clients

## References

- [RFC 7591 - OAuth 2.0 Dynamic Client Registration Protocol](https://tools.ietf.org/html/rfc7591)
- [OpenID Connect Dynamic Client Registration](https://openid.net/specs/openid-connect-registration-1_0.html)
- [RFC 7592 - OAuth 2.0 Dynamic Client Registration Management Protocol](https://tools.ietf.org/html/rfc7592)