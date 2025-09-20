# xjp-oidc API Reference

## Core Functions

### PKCE (Proof Key for Code Exchange)

```rust
pub fn create_pkce() -> Result<(String, String, String)>
```

Creates a PKCE verifier and challenge for the authorization code flow.

**Returns:**
- `verifier`: The code verifier (43-128 characters)
- `challenge`: The code challenge (base64url-encoded SHA256 hash)
- `method`: Always "S256"

**Example:**
```rust
let (verifier, challenge, method) = create_pkce()?;
assert_eq!(method, "S256");
```

### Authorization URLs

```rust
pub fn build_auth_url(params: BuildAuthUrl) -> Result<Url>
```

Builds an authorization URL for the OAuth2/OIDC flow.

**Parameters:**
- `issuer`: The OIDC issuer URL
- `client_id`: Your application's client ID
- `redirect_uri`: Where to redirect after authentication
- `scope`: Space-separated scopes (e.g., "openid profile email")
- `code_challenge`: PKCE code challenge
- `state`: Optional state parameter for CSRF protection
- `nonce`: Optional nonce for ID token validation
- `prompt`: Optional prompt parameter (e.g., "login", "consent")
- `extra_params`: Additional query parameters
- `tenant`: Optional tenant identifier

**Example:**
```rust
let url = build_auth_url(BuildAuthUrl {
    issuer: "https://auth.example.com".into(),
    client_id: "my-app".into(),
    redirect_uri: "https://app.example.com/callback".into(),
    scope: "openid profile".into(),
    code_challenge: challenge,
    ..Default::default()
})?;
```

```rust
pub fn parse_callback_params(url: &str) -> CallbackParams
```

Parses OAuth2/OIDC callback parameters from a URL.

**Returns:**
```rust
pub struct CallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}
```

### Discovery

```rust
pub async fn discover(
    issuer: &str,
    http: &dyn HttpClient,
    cache: &dyn Cache<String, OidcProviderMetadata>
) -> Result<OidcProviderMetadata>
```

Discovers OIDC provider metadata from the issuer's well-known endpoint.

**Parameters:**
- `issuer`: The issuer URL
- `http`: HTTP client implementation
- `cache`: Cache for storing metadata

**Returns:** Provider metadata including endpoints, supported features, etc.

### Token Exchange

```rust
pub async fn exchange_code(
    params: ExchangeCode,
    http: &dyn HttpClient
) -> Result<TokenResponse>
```

Exchanges an authorization code for tokens (server-only).

**Parameters:**
```rust
pub struct ExchangeCode {
    pub issuer: String,
    pub client_id: String,
    pub code: String,
    pub redirect_uri: String,
    pub code_verifier: String,
    pub client_secret: Option<String>,
}
```

**Returns:**
```rust
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub id_token: Option<String>,
}
```

### ID Token Verification

```rust
pub async fn verify_id_token(
    id_token: &str,
    opts: VerifyOptions<'_>
) -> Result<VerifiedIdToken>
```

Verifies and parses an ID token.

**Parameters:**
```rust
pub struct VerifyOptions<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub nonce: Option<&'a str>,
    pub max_age_sec: Option<i64>,
    pub clock_skew_sec: Option<i64>,
    pub http: &'a dyn HttpClient,
    pub cache: &'a dyn Cache<String, Jwks>,
}
```

**Returns:** Verified token claims including standard OIDC claims and custom claims (amr, xjp_admin, auth_time).

### Dynamic Client Registration

```rust
pub async fn register_if_needed(
    issuer: &str,
    initial_access_token: &str,
    req: RegisterRequest,
    http: &dyn HttpClient
) -> Result<ClientRegistrationResult>
```

Registers a new OAuth2/OIDC client (server-only).

**Parameters:**
```rust
pub struct RegisterRequest {
    pub application_type: Option<String>,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Option<Vec<String>>,
    pub grant_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub scope: String,
    pub client_name: Option<String>,
    pub contacts: Option<Vec<String>>,
    pub software_id: Option<String>,
}
```

### Logout

```rust
pub fn build_end_session_url(params: EndSession) -> Result<Url>
```

Builds an end session (logout) URL.

**Parameters:**
```rust
pub struct EndSession {
    pub issuer: String,
    pub id_token_hint: String,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
}
```

## Types

### OidcProviderMetadata

Complete OIDC provider metadata from discovery:

```rust
pub struct OidcProviderMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub userinfo_endpoint: Option<String>,
    pub end_session_endpoint: Option<String>,
    pub registration_endpoint: Option<String>,
    pub response_types_supported: Option<Vec<String>>,
    pub grant_types_supported: Option<Vec<String>>,
    pub scopes_supported: Option<Vec<String>>,
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,
    pub code_challenge_methods_supported: Option<Vec<String>>,
}
```

### VerifiedIdToken

Verified ID token claims:

```rust
pub struct VerifiedIdToken {
    // Standard claims
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub nonce: Option<String>,
    pub sid: Option<String>,
    
    // Profile claims  
    pub name: Option<String>,
    pub email: Option<String>,
    pub picture: Option<String>,
    
    // Custom claims
    pub amr: Option<Vec<String>>,      // Authentication methods
    pub auth_time: Option<i64>,         // Authentication timestamp
    pub xjp_admin: Option<bool>,        // Admin flag
}
```

## Cache Trait

```rust
pub trait Cache<K, V>: Send + Sync {
    fn get(&self, key: &K) -> Option<V>;
    fn put(&self, key: K, value: V, ttl_secs: u64);
    fn remove(&self, key: &K) -> Option<V>;
    fn clear(&self);
}
```

Built-in implementations:
- `NoOpCache`: No caching (always returns None)
- `MokaCacheImpl`: High-performance async cache (recommended)
- `LruCacheImpl`: Simple LRU cache

## HTTP Client Trait

```rust
#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn get_value(&self, url: &str) -> Result<Value, HttpClientError>;
    async fn post_form_value(
        &self,
        url: &str,
        form: &[(String, String)],
        auth_header: Option<(&str, &str)>
    ) -> Result<Value, HttpClientError>;
    async fn post_json_value(
        &self,
        url: &str,
        body: &Value,
        auth_header: Option<(&str, &str)>
    ) -> Result<Value, HttpClientError>;
}
```

Built-in implementations:
- `ReqwestHttpClient`: For server/native platforms
- `WasmHttpClient`: For browser/WASM platforms

## Resource Server Verification

```rust
pub struct JwtVerifier<C, H> {
    // ...
}

impl<C: Cache<String, Jwks>, H: HttpClient> JwtVerifier<C, H> {
    pub fn new(
        issuer_map: HashMap<String, String>,
        audience: String,
        http: Arc<H>,
        cache: Arc<C>
    ) -> Self;
    
    pub async fn verify(&self, bearer: &str) -> Result<VerifiedClaims>;
}
```

## Error Types

```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("network error: {0}")]
    Network(String),
    
    #[error("discovery error: {0}")]
    Discovery(String),
    
    #[error("JWT error: {0}")]
    Jwt(String),
    
    #[error("invalid parameter: {0}")]
    InvalidParam(&'static str),
    
    // ... more variants
}
```

## Feature Flags

- `default`: Includes `http-reqwest`, `tls-rustls`, `tracing`, `moka`, `lru`, `verifier`
- `http-reqwest`: Reqwest HTTP client for native platforms
- `http-wasm`: Gloo-net HTTP client for WASM
- `moka`: Moka cache implementation
- `lru`: LRU cache implementation  
- `verifier`: Resource server JWT verification
- `browser-min`: Minimal browser support
- `tracing`: Tracing/logging support