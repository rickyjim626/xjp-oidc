//! HTTP client extension for multi-tenant support

use crate::{
    discovery_tenant::HttpClientWithHeaders,
    errors::Result,
    http::{HttpClient, HttpClientError},
};
use async_trait::async_trait;
use serde_json::Value;

/// Adapter to add header support to existing HttpClient implementations
pub struct HttpClientAdapter<T: HttpClient> {
    inner: T,
}

impl<T: HttpClient> HttpClientAdapter<T> {
    /// Create a new adapter wrapping an existing HTTP client
    pub fn new(client: T) -> Self {
        Self { inner: client }
    }
}

#[async_trait]
impl<T: HttpClient> HttpClientWithHeaders for HttpClientAdapter<T> {
    async fn get_value_with_headers(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
    ) -> Result<Value> {
        // For now, we'll use the standard get_value since headers need to be implemented
        // in the underlying client. This is a temporary solution.
        if !headers.is_empty() {
            tracing::warn!(
                "Headers requested but not supported by underlying client: {:?}",
                headers
            );
        }
        self.inner
            .get_value(url)
            .await
            .map_err(|e| crate::errors::Error::Network(e.to_string()))
    }
}

// Enhanced Reqwest implementation with header support
#[cfg(all(not(target_arch = "wasm32"), feature = "http-reqwest"))]
pub mod reqwest_tenant {
    use super::*;
    use reqwest::{Client, header::{HeaderMap, HeaderName, HeaderValue}};
    use std::time::Duration;

    /// Enhanced Reqwest HTTP client with multi-tenant support
    #[derive(Clone)]
    pub struct ReqwestHttpClientWithHeaders {
        client: Client,
    }

    impl ReqwestHttpClientWithHeaders {
        /// Create a new HTTP client with default settings
        pub fn new() -> Result<Self> {
            let client = Client::builder()
                .timeout(Duration::from_secs(30))
                .use_rustls_tls()
                .build()
                .map_err(|e| crate::errors::Error::Network(e.to_string()))?;

            Ok(Self { client })
        }

        /// Create a new HTTP client with custom timeout
        pub fn with_timeout(timeout_secs: u64) -> Result<Self> {
            let client = Client::builder()
                .timeout(Duration::from_secs(timeout_secs))
                .use_rustls_tls()
                .build()
                .map_err(|e| crate::errors::Error::Network(e.to_string()))?;

            Ok(Self { client })
        }
    }

    impl Default for ReqwestHttpClientWithHeaders {
        fn default() -> Self {
            Self::new().expect("Failed to create default HTTP client")
        }
    }

    #[async_trait]
    impl HttpClientWithHeaders for ReqwestHttpClientWithHeaders {
        async fn get_value_with_headers(
            &self,
            url: &str,
            headers: Vec<(String, String)>,
        ) -> Result<Value> {
            let mut request = self.client.get(url);

            // Add custom headers
            let header_count = headers.len();
            if !headers.is_empty() {
                let mut header_map = HeaderMap::new();
                for (key, value) in headers {
                    let header_name = HeaderName::from_bytes(key.as_bytes())
                        .map_err(|e| crate::errors::Error::Network(format!("Invalid header name: {}", e)))?;
                    let header_value = HeaderValue::from_str(&value)
                        .map_err(|e| crate::errors::Error::Network(format!("Invalid header value: {}", e)))?;
                    header_map.insert(header_name, header_value);
                }
                request = request.headers(header_map);
            }

            tracing::info!(
                target: "xjp_oidc::http",
                "HTTP 请求: {} (headers: {})",
                url,
                header_count
            );

            let response = request
                .send()
                .await
                .map_err(|e| crate::errors::Error::Network(format!("Request failed: {}", e)))?;

            let status = response.status();
            let duration = std::time::Instant::now();

            if !status.is_success() {
                let error_body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Failed to read error response".to_string());

                tracing::error!(
                    target: "xjp_oidc::http",
                    "HTTP 请求失败 url={} status={} error={}",
                    url,
                    status,
                    error_body
                );

                return Err(crate::errors::Error::Network(format!(
                    "HTTP {} - {}",
                    status, error_body
                )));
            }

            let value = response
                .json::<Value>()
                .await
                .map_err(|e| crate::errors::Error::Network(format!("Failed to parse JSON: {}", e)))?;

            tracing::info!(
                target: "xjp_oidc::http",
                "HTTP 请求完成 url={} method=\"GET\" duration_ms={} status={}",
                url,
                duration.elapsed().as_millis(),
                status.as_u16()
            );

            Ok(value)
        }
    }

    // Also implement the standard HttpClient trait
    #[async_trait]
    impl HttpClient for ReqwestHttpClientWithHeaders {
        async fn get_value(&self, url: &str) -> std::result::Result<Value, HttpClientError> {
            let response = self
                .client
                .get(url)
                .send()
                .await
                .map_err(|e| HttpClientError::RequestFailed(e.to_string()))?;

            let status = response.status();
            if !status.is_success() {
                let error_body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Failed to read error response".to_string());

                return Err(HttpClientError::InvalidStatus {
                    status: status.as_u16(),
                    message: error_body,
                });
            }

            response
                .json::<Value>()
                .await
                .map_err(|e| HttpClientError::ParseError(e.to_string()))
        }

        async fn post_form_value(
            &self,
            url: &str,
            form: &[(String, String)],
            auth_header: Option<(&str, &str)>,
        ) -> std::result::Result<Value, HttpClientError> {
            let mut request = self.client.post(url).form(form);

            if let Some((key, value)) = auth_header {
                let header_value = HeaderValue::from_str(value)
                    .map_err(|e| HttpClientError::RequestFailed(format!("Invalid header value: {}", e)))?;
                let header_name = HeaderName::from_bytes(key.as_bytes())
                    .map_err(|e| HttpClientError::RequestFailed(format!("Invalid header name: {}", e)))?;
                request = request.header(header_name, header_value);
            }

            let response = request
                .send()
                .await
                .map_err(|e| HttpClientError::RequestFailed(e.to_string()))?;

            let status = response.status();
            if !status.is_success() {
                let error_body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Failed to read error response".to_string());

                return Err(HttpClientError::InvalidStatus {
                    status: status.as_u16(),
                    message: error_body,
                });
            }

            response
                .json::<Value>()
                .await
                .map_err(|e| HttpClientError::ParseError(e.to_string()))
        }

        async fn post_json_value(
            &self,
            url: &str,
            body: &Value,
            auth_header: Option<(&str, &str)>,
        ) -> std::result::Result<Value, HttpClientError> {
            let mut request = self.client.post(url).json(body);

            if let Some((key, value)) = auth_header {
                let header_value = HeaderValue::from_str(value)
                    .map_err(|e| HttpClientError::RequestFailed(format!("Invalid header value: {}", e)))?;
                let header_name = HeaderName::from_bytes(key.as_bytes())
                    .map_err(|e| HttpClientError::RequestFailed(format!("Invalid header name: {}", e)))?;
                request = request.header(header_name, header_value);
            }

            let response = request
                .send()
                .await
                .map_err(|e| HttpClientError::RequestFailed(e.to_string()))?;

            let status = response.status();
            if !status.is_success() {
                let error_body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Failed to read error response".to_string());

                return Err(HttpClientError::InvalidStatus {
                    status: status.as_u16(),
                    message: error_body,
                });
            }

            response
                .json::<Value>()
                .await
                .map_err(|e| HttpClientError::ParseError(e.to_string()))
        }
    }
}