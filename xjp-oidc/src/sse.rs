//! Server-Sent Events (SSE) support for login flows
//!
//! This module provides support for real-time login status updates via SSE,
//! commonly used for QR code login flows where the status needs to be
//! monitored in real-time.

#[cfg(not(target_arch = "wasm32"))]
use crate::{
    errors::{Error, Result},
    http::HttpClient,
};

#[cfg(not(target_arch = "wasm32"))]
use serde::{Deserialize, Serialize};

/// Login status enum matching the backend implementation
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum LoginStatus {
    /// Waiting for user action (e.g., QR code scan)
    Pending,
    /// User has scanned but not yet authorized
    Scanned,
    /// User has authorized the login
    Authorized,
    /// Login completed successfully
    Success,
    /// Login failed
    Failed,
    /// Login session expired
    Expired,
}

/// Login state information
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginState {
    /// Current status of the login session
    pub status: LoginStatus,
    /// OAuth authorization code (present when status is Success)
    pub code: Option<String>,
    /// Error message (present when status is Failed)
    pub error: Option<String>,
    /// Creation timestamp (Unix timestamp)
    pub created_at: i64,
}

/// SSE event types
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone)]
pub enum LoginEvent {
    /// Status update event
    StatusUpdate(LoginState),
    /// Heartbeat event (no data)
    Heartbeat,
    /// Stream closed event
    Close,
    /// Error event
    Error(String),
}

/// Start a login session and get a login ID for monitoring
///
/// This creates a new login session on the server and returns a login ID
/// that can be used to monitor the login status via SSE.
///
/// # Example
/// ```no_run
/// # #[cfg(not(target_arch = "wasm32"))]
/// # use xjp_oidc::{sse::start_login_session, http::ReqwestHttpClient};
/// # #[cfg(not(target_arch = "wasm32"))]
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let http = ReqwestHttpClient::default();
///
/// let (login_id, qr_url) = start_login_session(
///     "https://auth.example.com",
///     "my-client-id",
///     "https://app.example.com/callback",
///     &http
/// ).await?;
///
/// println!("Login ID: {}", login_id);
/// println!("QR Code URL: {}", qr_url);
/// # Ok(())
/// # }
/// ```
#[cfg(not(target_arch = "wasm32"))]
pub async fn start_login_session(
    issuer: &str,
    client_id: &str,
    redirect_uri: &str,
    http: &dyn HttpClient,
) -> Result<(String, String)> {
    // Validate parameters
    if issuer.is_empty() {
        return Err(Error::InvalidParam("issuer cannot be empty"));
    }
    if client_id.is_empty() {
        return Err(Error::InvalidParam("client_id cannot be empty"));
    }
    if redirect_uri.is_empty() {
        return Err(Error::InvalidParam("redirect_uri cannot be empty"));
    }

    // Build the login session endpoint URL
    let session_endpoint = format!("{}/auth/start-login-session", issuer.trim_end_matches('/'));

    // Prepare request body
    let body = serde_json::json!({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
    });

    // Make the request
    let response = http
        .post_json_value(&session_endpoint, &body, None)
        .await
        .map_err(|e| Error::Network(format!("Failed to start login session: {}", e)))?;

    // Extract login_id and qr_url from response
    let login_id = response["login_id"]
        .as_str()
        .ok_or_else(|| Error::InvalidState("Missing login_id in response".to_string()))?
        .to_string();

    let qr_url = response["qr_url"]
        .as_str()
        .ok_or_else(|| Error::InvalidState("Missing qr_url in response".to_string()))?
        .to_string();

    Ok((login_id, qr_url))
}

/// Configuration for SSE login monitoring
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone)]
pub struct LoginMonitorConfig {
    /// The issuer URL
    pub issuer: String,
    /// The login ID to monitor
    pub login_id: String,
    /// Optional timeout in seconds (default: 300)
    pub timeout_secs: Option<u64>,
    /// Optional reconnect attempts (default: 3)
    pub max_reconnects: Option<u32>,
}

/// Subscribe to login status updates via SSE
///
/// This function returns a stream of login events that can be consumed
/// to track the login progress in real-time.
///
/// # Example
/// ```no_run
/// # #[cfg(not(target_arch = "wasm32"))]
/// # use xjp_oidc::sse::{subscribe_login_events, LoginMonitorConfig, LoginEvent, LoginStatus};
/// # #[cfg(not(target_arch = "wasm32"))]
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use futures_util::StreamExt;
///
/// let config = LoginMonitorConfig {
///     issuer: "https://auth.example.com".to_string(),
///     login_id: "login-123".to_string(),
///     timeout_secs: Some(300),
///     max_reconnects: Some(3),
/// };
///
/// let mut event_stream = subscribe_login_events(config).await?;
///
/// while let Some(event) = event_stream.next().await {
///     match event {
///         Ok(LoginEvent::StatusUpdate(state)) => {
///             println!("Status: {:?}", state.status);
///             if state.status == LoginStatus::Success {
///                 println!("Login successful! Code: {:?}", state.code);
///                 break;
///             }
///         }
///         Ok(LoginEvent::Heartbeat) => {
///             println!("Heartbeat received");
///         }
///         Ok(LoginEvent::Close) => {
///             println!("Stream closed");
///             break;
///         }
///         Err(e) => {
///             eprintln!("Error: {}", e);
///             break;
///         }
///     }
/// }
/// # Ok(())
/// # }
/// ```
#[cfg(all(not(target_arch = "wasm32"), feature = "sse"))]
pub async fn subscribe_login_events(
    config: LoginMonitorConfig,
) -> Result<impl futures_util::Stream<Item = Result<LoginEvent>>> {
    use eventsource_client::{Client, ClientBuilder, ReconnectOptions, SSE};
    use futures_util::StreamExt;

    // Build SSE endpoint URL
    let sse_url = format!(
        "{}/auth/login-stream?login_id={}",
        config.issuer.trim_end_matches('/'),
        urlencoding::encode(&config.login_id)
    );

    // Create reconnect options with available methods
    let reconnect = ReconnectOptions::reconnect(true)
        .retry_initial(false)
        .delay(std::time::Duration::from_secs(1))
        .delay_max(std::time::Duration::from_secs(5))
        .build();

    // Create SSE client
    let client = ClientBuilder::for_url(&sse_url)
        .map_err(|e| Error::Network(format!("Failed to create SSE client: {}", e)))?
        .reconnect(reconnect)
        .build();

    // Convert the event stream to our LoginEvent type
    let event_stream = client.stream().map(|result| {
        match result {
            Ok(SSE::Event(e)) => {
                match e.event_type.as_str() {
                    "pending" | "scanned" | "authorized" | "success" | "failed" | "expired" => {
                        // Parse login state from event data
                        match serde_json::from_str::<LoginState>(&e.data) {
                            Ok(state) => Ok(LoginEvent::StatusUpdate(state)),
                            Err(e) => Err(Error::Verification(format!("Failed to parse login state: {}", e))),
                        }
                    }
                    "close" => Ok(LoginEvent::Close),
                    "heartbeat" | "" => Ok(LoginEvent::Heartbeat),
                    _ => Ok(LoginEvent::Heartbeat), // Treat unknown events as heartbeat
                }
            }
            Ok(SSE::Comment(_)) => Ok(LoginEvent::Heartbeat),
            Err(e) => Err(Error::Network(format!("SSE error: {}", e))),
        }
    });

    // Apply timeout if specified
    if let Some(timeout_secs) = config.timeout_secs {
        let timeout_stream = tokio_stream::StreamExt::timeout(
            event_stream,
            std::time::Duration::from_secs(timeout_secs),
        )
        .map(move |result| {
            result
                .map_err(|_| Error::Network("SSE stream timeout".to_string()))
                .and_then(|inner| inner)
        });

        Ok(Box::pin(timeout_stream) as std::pin::Pin<Box<dyn futures_util::Stream<Item = Result<LoginEvent>> + Send>>)
    } else {
        Ok(Box::pin(event_stream) as std::pin::Pin<Box<dyn futures_util::Stream<Item = Result<LoginEvent>> + Send>>)
    }
}

/// Check login status once (non-streaming)
///
/// This is useful for polling the login status without using SSE,
/// or as a fallback when SSE is not available.
///
/// # Example
/// ```no_run
/// # #[cfg(not(target_arch = "wasm32"))]
/// # use xjp_oidc::{sse::check_login_status, http::ReqwestHttpClient};
/// # #[cfg(not(target_arch = "wasm32"))]
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let http = ReqwestHttpClient::default();
///
/// let state = check_login_status(
///     "https://auth.example.com",
///     "login-123",
///     &http
/// ).await?;
///
/// println!("Current status: {:?}", state.status);
/// # Ok(())
/// # }
/// ```
#[cfg(not(target_arch = "wasm32"))]
pub async fn check_login_status(
    issuer: &str,
    login_id: &str,
    http: &dyn HttpClient,
) -> Result<LoginState> {
    // Validate parameters
    if issuer.is_empty() {
        return Err(Error::InvalidParam("issuer cannot be empty"));
    }
    if login_id.is_empty() {
        return Err(Error::InvalidParam("login_id cannot be empty"));
    }

    // Build status check endpoint URL
    let status_endpoint = format!(
        "{}/auth/login-status/{}",
        issuer.trim_end_matches('/'),
        urlencoding::encode(login_id)
    );

    // Make the request
    let response = http
        .get_value(&status_endpoint)
        .await
        .map_err(|e| Error::Network(format!("Failed to check login status: {}", e)))?;

    // Parse response
    let state: LoginState = serde_json::from_value(response)
        .map_err(|e| Error::Verification(format!("Failed to parse login state: {}", e)))?;

    Ok(state)
}

// WASM stub implementations
#[cfg(target_arch = "wasm32")]
use crate::errors::{Error, Result};

#[cfg(target_arch = "wasm32")]
pub async fn start_login_session(
    _issuer: &str,
    _client_id: &str,
    _redirect_uri: &str,
    _http: &dyn crate::http::HttpClient,
) -> Result<(String, String)> {
    Err(Error::ServerOnly("SSE login sessions"))
}

#[cfg(target_arch = "wasm32")]
pub async fn check_login_status(
    _issuer: &str,
    _login_id: &str,
    _http: &dyn crate::http::HttpClient,
) -> Result<()> {
    Err(Error::ServerOnly("SSE login status"))
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[test]
    fn test_login_state_parsing() {
        let json = serde_json::json!({
            "status": "SUCCESS",
            "code": "auth_code_123",
            "error": null,
            "created_at": 1234567890
        });

        let state: LoginState = serde_json::from_value(json).unwrap();
        assert_eq!(state.status, LoginStatus::Success);
        assert_eq!(state.code, Some("auth_code_123".to_string()));
        assert!(state.error.is_none());
        assert_eq!(state.created_at, 1234567890);
    }

    #[test]
    fn test_login_status_serialization() {
        let status = LoginStatus::Pending;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, r#""PENDING""#);

        let status = LoginStatus::Success;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, r#""SUCCESS""#);
    }
}