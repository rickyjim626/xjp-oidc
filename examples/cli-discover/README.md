# CLI Discover Example

A command-line tool for OIDC discovery, JWKS inspection, and ID token verification.

## Features

- **discover**: Fetch and display OpenID Configuration
- **jwks**: Fetch and display JSON Web Key Set
- **verify-id**: Verify an ID token and display claims (including custom XJP claims)

## Usage

### Build the CLI tool
```bash
cargo build --release --example cli-discover
```

### Discover OpenID Configuration
```bash
# Pretty format (default)
cargo run --example cli-discover -- discover --issuer https://auth.example.com

# JSON format
cargo run --example cli-discover -- discover --issuer https://auth.example.com --format json
```

### Fetch JWKS
```bash
# Display JWKS information
cargo run --example cli-discover -- jwks --issuer https://auth.example.com

# JSON format
cargo run --example cli-discover -- jwks --issuer https://auth.example.com --format json
```

### Verify ID Token
```bash
# Basic verification
cargo run --example cli-discover -- verify-id \
  --issuer https://auth.example.com \
  --audience my-client-id \
  --token "eyJhbGciOiJ..."

# With nonce verification
cargo run --example cli-discover -- verify-id \
  --issuer https://auth.example.com \
  --audience my-client-id \
  --token "eyJhbGciOiJ..." \
  --nonce "expected-nonce-value"

# JSON output
cargo run --example cli-discover -- verify-id \
  --issuer https://auth.example.com \
  --audience my-client-id \
  --token "eyJhbGciOiJ..." \
  --format json
```

## Example Output

### Discovery
```
OpenID Configuration for https://auth.example.com
==================================================
Authorization endpoint: https://auth.example.com/oauth/authorize
Token endpoint:         https://auth.example.com/oauth/token
JWKS URI:              https://auth.example.com/oauth/jwks
UserInfo endpoint:      https://auth.example.com/oauth/userinfo
End session endpoint:   https://auth.example.com/oidc/logout

Supported features:
  Response types: code, code id_token
  Grant types: authorization_code, refresh_token
  Scopes: openid, profile, email, xjp.admin
  PKCE methods: S256
```

### Token Verification
```
ID Token verified successfully!
==================================================
Subject (sub):     user123
Issuer (iss):      https://auth.example.com
Audience (aud):    my-client-id
Issued at (iat):   1704067200
Expires at (exp):  1704070800

Profile claims:
  Name:  John Doe
  Email: john@example.com

Custom XJP claims:
  Admin (xjp_admin): Some(true)
  Auth methods (amr): Some(["wechat_qr", "mfa"])
  Auth time: Some(1704067100)
```

## Use Cases

1. **Debugging**: Quickly inspect OIDC provider configuration
2. **Testing**: Verify tokens during development
3. **Operations**: Check JWKS rotation and key information
4. **Integration**: Validate custom claims in tokens