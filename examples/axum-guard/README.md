# Axum Guard Example

This example demonstrates a Resource Server implementation using xjp-oidc-axum middleware for JWT verification.

## Features

- JWT Bearer token verification using `OidcLayer`
- Protected endpoints requiring valid tokens
- Admin-only endpoints using `require_admin` middleware
- Optional authentication endpoints
- Automatic JWKS fetching and caching
- Custom claims extraction (xjp_admin, amr, auth_time)

## Setup

1. Copy `.env.example` to `.env` and configure:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` with your OIDC configuration:
   - `ISSUER`: Your OIDC provider's issuer URL
   - `AUDIENCE`: Expected audience for tokens (your API identifier)

3. Run the example:
   ```bash
   cargo run --example axum-guard
   ```

4. The server will start on http://localhost:3001

## Testing

### Public Endpoints (no auth required)
```bash
curl http://localhost:3001/
curl http://localhost:3001/health
```

### Protected Endpoints (valid JWT required)
```bash
# Get a valid JWT token from your OIDC provider first
export TOKEN="your-jwt-token-here"

curl -H "Authorization: Bearer $TOKEN" http://localhost:3001/api/profile
curl -H "Authorization: Bearer $TOKEN" http://localhost:3001/api/data
```

### Admin Endpoints (requires xjp_admin=true in token)
```bash
# Requires a token with xjp_admin claim set to true
curl -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:3001/api/admin/users
curl -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:3001/api/admin/settings
```

### Optional Auth Endpoint
```bash
# Works without auth
curl http://localhost:3001/api/optional

# Or with auth for personalized response
curl -H "Authorization: Bearer $TOKEN" http://localhost:3001/api/optional
```

## Expected Responses

- **No token**: 401 Unauthorized (for protected endpoints)
- **Invalid token**: 401 Unauthorized with error details
- **Valid token but not admin**: 403 Forbidden (for admin endpoints)
- **Valid admin token**: 200 OK with data

## Security Notes

- The middleware automatically validates:
  - Token signature using JWKS from issuer
  - Token expiration (exp claim)
  - Token audience (aud claim)
  - Token issuer (iss claim)
- JWKS are cached to reduce latency
- Clock skew tolerance is set to 120 seconds
- Admin endpoints require both valid token AND xjp_admin=true claim