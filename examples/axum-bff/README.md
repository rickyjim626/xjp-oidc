# Axum BFF Example

This example demonstrates a minimal Backend-for-Frontend (BFF) implementation using xjp-oidc with Axum.

## Features

- OAuth2/OIDC Authorization Code Flow with PKCE
- Login, callback, user info, and logout endpoints
- ID token verification with custom claims (xjp_admin, amr, auth_time)

## Setup

1. Copy `.env.example` to `.env` and configure your OIDC provider:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` with your provider details:
   - `ISSUER`: Your OIDC provider's issuer URL
   - `CLIENT_ID`: Your registered client ID
   - `REDIRECT_URI`: Must match the redirect URI registered with your provider
   - `POST_LOGOUT_REDIRECT_URI`: Where to redirect after logout

3. Run the example:
   ```bash
   cargo run --example axum-bff
   ```

4. Open http://localhost:3000 in your browser

## Endpoints

- `/` - Home page
- `/login` - Initiates OAuth2 flow
- `/callback` - Handles OAuth2 callback
- `/me` - Shows login status
- `/logout` - Ends session and redirects to OIDC provider logout

## Security Notes

⚠️ **This example uses temporary files for demo purposes only!**

In production, you should:
- Use secure server-side sessions (e.g., Redis, encrypted cookies)
- Generate cryptographically random state and nonce values
- Store PKCE verifier securely between login and callback
- Use HTTPS for all endpoints
- Set appropriate CORS and security headers