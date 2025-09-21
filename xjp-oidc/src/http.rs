//! HTTP client abstraction for both server and WASM environments

use async_trait::async_trait;
use thiserror::Error;

/// HTTP client errors
#[derive(Error, Debug)]
pub enum HttpClientError {
    /// Network request failed
    #[error("request failed: {0}")]
    RequestFailed(String),
    /// Response parsing failed
    #[error("response parse error: {0}")]
    ParseError(String),
    /// Invalid response status
    #[error("invalid status: {status} - {message}")]
    InvalidStatus {
        /// HTTP status code
        status: u16,
        /// Error message from response
        message: String,
    },
    /// Timeout occurred
    #[error("request timeout")]
    Timeout,
    /// Not supported in current environment
    #[error("operation not supported: {0}")]
    NotSupported(String),
}

/// HTTP client trait for abstraction over different implementations
///
/// This trait uses serde_json::Value to maintain object safety
#[async_trait]
pub trait HttpClient: Send + Sync {
    /// Perform a GET request and return JSON value
    async fn get_value(&self, url: &str) -> Result<serde_json::Value, HttpClientError>;

    /// Perform a POST request with form data and return JSON value
    async fn post_form_value(
        &self,
        url: &str,
        form: &[(String, String)],
        auth_header: Option<(&str, &str)>,
    ) -> Result<serde_json::Value, HttpClientError>;

    /// Perform a POST request with JSON body and return JSON value
    async fn post_json_value(
        &self,
        url: &str,
        body: &serde_json::Value,
        auth_header: Option<(&str, &str)>,
    ) -> Result<serde_json::Value, HttpClientError>;
}

// Server-side implementation using reqwest
#[cfg(all(not(target_arch = "wasm32"), feature = "http-reqwest"))]
pub use reqwest_impl::ReqwestHttpClient;

#[cfg(all(not(target_arch = "wasm32"), feature = "http-reqwest"))]
mod reqwest_impl {
    use super::*;
    use reqwest::Client;
    use std::time::Duration;

    /// Reqwest-based HTTP client for server environments
    #[derive(Clone)]
    pub struct ReqwestHttpClient {
        client: Client,
    }

    impl ReqwestHttpClient {
        /// Create a new HTTP client with default settings
        pub fn new() -> Result<Self, HttpClientError> {
            let client = Client::builder()
                .timeout(Duration::from_secs(30))
                .use_rustls_tls()
                .build()
                .map_err(|e| HttpClientError::RequestFailed(e.to_string()))?;

            Ok(Self { client })
        }

        /// Create a new HTTP client with custom timeout
        pub fn with_timeout(timeout_secs: u64) -> Result<Self, HttpClientError> {
            let client = Client::builder()
                .timeout(Duration::from_secs(timeout_secs))
                .use_rustls_tls()
                .build()
                .map_err(|e| HttpClientError::RequestFailed(e.to_string()))?;

            Ok(Self { client })
        }
    }

    impl Default for ReqwestHttpClient {
        fn default() -> Self {
            Self::new().expect("Failed to create default HTTP client")
        }
    }

    #[async_trait]
    impl HttpClient for ReqwestHttpClient {
        async fn get_value(&self, url: &str) -> Result<serde_json::Value, HttpClientError> {
            let start = std::time::Instant::now();
            let response = self.client.get(url).send().await.map_err(|e| {
                tracing::error!(
                    target: "xjp_oidc::http",
                    url = %url,
                    error = %e,
                    "HTTP GET 请求失败"
                );
                if e.is_timeout() {
                    HttpClientError::Timeout
                } else {
                    HttpClientError::RequestFailed(e.to_string())
                }
            })?;

            let status = response.status();
            let duration = start.elapsed();

            tracing::info!(
                target: "xjp_oidc::http",
                url = %url,
                method = "GET",
                duration_ms = duration.as_millis() as u64,
                status = status.as_u16(),
                "HTTP 请求完成"
            );
            if !status.is_success() {
                let message =
                    response.text().await.unwrap_or_else(|_| "No error message".to_string());
                return Err(HttpClientError::InvalidStatus { status: status.as_u16(), message });
            }

            response
                .json::<serde_json::Value>()
                .await
                .map_err(|e| HttpClientError::ParseError(e.to_string()))
        }

        async fn post_form_value(
            &self,
            url: &str,
            form: &[(String, String)],
            auth_header: Option<(&str, &str)>,
        ) -> Result<serde_json::Value, HttpClientError> {
            let mut request = self.client.post(url).form(form);

            if let Some((name, value)) = auth_header {
                request = request.header(name, value);
            }

            let response = request.send().await.map_err(|e| {
                if e.is_timeout() {
                    HttpClientError::Timeout
                } else {
                    HttpClientError::RequestFailed(e.to_string())
                }
            })?;

            let status = response.status();
            if !status.is_success() {
                let message =
                    response.text().await.unwrap_or_else(|_| "No error message".to_string());
                return Err(HttpClientError::InvalidStatus { status: status.as_u16(), message });
            }

            response
                .json::<serde_json::Value>()
                .await
                .map_err(|e| HttpClientError::ParseError(e.to_string()))
        }

        async fn post_json_value(
            &self,
            url: &str,
            body: &serde_json::Value,
            auth_header: Option<(&str, &str)>,
        ) -> Result<serde_json::Value, HttpClientError> {
            let mut request = self.client.post(url).json(body);

            if let Some((name, value)) = auth_header {
                request = request.header(name, value);
            }

            let response = request.send().await.map_err(|e| {
                if e.is_timeout() {
                    HttpClientError::Timeout
                } else {
                    HttpClientError::RequestFailed(e.to_string())
                }
            })?;

            let status = response.status();
            if !status.is_success() {
                let message =
                    response.text().await.unwrap_or_else(|_| "No error message".to_string());
                return Err(HttpClientError::InvalidStatus { status: status.as_u16(), message });
            }

            response
                .json::<serde_json::Value>()
                .await
                .map_err(|e| HttpClientError::ParseError(e.to_string()))
        }
    }
}

// WASM implementation using gloo-net
#[cfg(all(target_arch = "wasm32", feature = "http-wasm"))]
pub use wasm_impl::WasmHttpClient;

#[cfg(all(target_arch = "wasm32", feature = "http-wasm"))]
mod wasm_impl {
    use super::*;
    use gloo_net::http::{Request, Response};

    /// WASM-based HTTP client for browser environments
    pub struct WasmHttpClient;

    impl WasmHttpClient {
        /// Create a new WASM HTTP client
        pub fn new() -> Self {
            Self
        }
    }

    impl Default for WasmHttpClient {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait(?Send)]
    impl HttpClient for WasmHttpClient {
        async fn get_value(&self, url: &str) -> Result<serde_json::Value, HttpClientError> {
            let response = Request::get(url)
                .send()
                .await
                .map_err(|e| HttpClientError::RequestFailed(e.to_string()))?;

            if !response.ok() {
                return Err(HttpClientError::InvalidStatus {
                    status: response.status(),
                    message: response
                        .text()
                        .await
                        .unwrap_or_else(|_| "No error message".to_string()),
                });
            }

            response
                .json::<serde_json::Value>()
                .await
                .map_err(|e| HttpClientError::ParseError(e.to_string()))
        }

        async fn post_form_value(
            &self,
            _url: &str,
            _form: &[(String, String)],
            _auth_header: Option<(&str, &str)>,
        ) -> Result<serde_json::Value, HttpClientError> {
            Err(HttpClientError::NotSupported("POST form not supported in WASM".to_string()))
        }

        async fn post_json_value(
            &self,
            _url: &str,
            _body: &serde_json::Value,
            _auth_header: Option<(&str, &str)>,
        ) -> Result<serde_json::Value, HttpClientError> {
            Err(HttpClientError::NotSupported("POST JSON not supported in WASM".to_string()))
        }
    }
}
