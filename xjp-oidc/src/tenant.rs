//! Multi-tenant support for OIDC SDK

use serde::{Deserialize, Serialize};
use std::fmt;

/// Tenant resolution strategy
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TenantMode {
    /// Single tenant mode - no tenant resolution needed
    Single,
    /// Use subdomain for tenant resolution (e.g., tenant.auth.example.com)
    Subdomain,
    /// Use query parameter for tenant resolution (e.g., ?tenant_id=tenant)
    QueryParam,
    /// Use client_id association for tenant resolution
    ClientId,
}

impl Default for TenantMode {
    fn default() -> Self {
        TenantMode::Single
    }
}

/// Tenant configuration for multi-tenant setups
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TenantConfig {
    /// Tenant mode - how to resolve tenant
    pub mode: TenantMode,
    /// Tenant identifier (slug or id)
    pub tenant: Option<String>,
    /// Base domain for subdomain mode (e.g., "auth.example.com")
    pub base_domain: Option<String>,
}

impl TenantConfig {
    /// Create a new single tenant configuration
    pub fn single() -> Self {
        Self {
            mode: TenantMode::Single,
            tenant: None,
            base_domain: None,
        }
    }

    /// Create a new subdomain-based tenant configuration
    pub fn subdomain(tenant: String, base_domain: String) -> Self {
        Self {
            mode: TenantMode::Subdomain,
            tenant: Some(tenant),
            base_domain: Some(base_domain),
        }
    }

    /// Create a new query parameter-based tenant configuration
    pub fn query_param(tenant: String) -> Self {
        Self {
            mode: TenantMode::QueryParam,
            tenant: Some(tenant),
            base_domain: None,
        }
    }

    /// Create a new client_id-based tenant configuration
    pub fn client_id() -> Self {
        Self {
            mode: TenantMode::ClientId,
            tenant: None,
            base_domain: None,
        }
    }

    /// Apply tenant configuration to a URL
    pub fn apply_to_url(&self, url: &str) -> Result<String, String> {
        match &self.mode {
            TenantMode::Single => Ok(url.to_string()),
            TenantMode::QueryParam => {
                if let Some(tenant) = &self.tenant {
                    let separator = if url.contains('?') { "&" } else { "?" };
                    Ok(format!("{}{}tenant_id={}", url, separator, tenant))
                } else {
                    Err("Tenant identifier required for query param mode".to_string())
                }
            }
            TenantMode::Subdomain | TenantMode::ClientId => {
                // For subdomain and client_id modes, URL modification is handled via headers
                Ok(url.to_string())
            }
        }
    }

    /// Get the Host header for subdomain mode
    pub fn get_host_header(&self) -> Option<String> {
        match &self.mode {
            TenantMode::Subdomain => {
                if let (Some(tenant), Some(base_domain)) = (&self.tenant, &self.base_domain) {
                    Some(format!("{}.{}", tenant, base_domain))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Check if tenant configuration is valid
    pub fn validate(&self) -> Result<(), String> {
        match &self.mode {
            TenantMode::Single => Ok(()),
            TenantMode::Subdomain => {
                if self.tenant.is_none() || self.base_domain.is_none() {
                    Err("Subdomain mode requires both tenant and base_domain".to_string())
                } else {
                    Ok(())
                }
            }
            TenantMode::QueryParam => {
                if self.tenant.is_none() {
                    Err("Query param mode requires tenant".to_string())
                } else {
                    Ok(())
                }
            }
            TenantMode::ClientId => Ok(()),
        }
    }
}

impl fmt::Display for TenantConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.mode {
            TenantMode::Single => write!(f, "Single tenant"),
            TenantMode::Subdomain => {
                if let (Some(tenant), Some(domain)) = (&self.tenant, &self.base_domain) {
                    write!(f, "Subdomain: {}.{}", tenant, domain)
                } else {
                    write!(f, "Subdomain (unconfigured)")
                }
            }
            TenantMode::QueryParam => {
                if let Some(tenant) = &self.tenant {
                    write!(f, "Query param: tenant_id={}", tenant)
                } else {
                    write!(f, "Query param (unconfigured)")
                }
            }
            TenantMode::ClientId => write!(f, "Client ID based"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_tenant() {
        let config = TenantConfig::single();
        assert_eq!(config.mode, TenantMode::Single);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_subdomain_tenant() {
        let config = TenantConfig::subdomain("xiaojinpro".to_string(), "auth.xiaojinpro.com".to_string());
        assert_eq!(config.mode, TenantMode::Subdomain);
        assert!(config.validate().is_ok());
        assert_eq!(config.get_host_header(), Some("xiaojinpro.auth.xiaojinpro.com".to_string()));
    }

    #[test]
    fn test_query_param_tenant() {
        let config = TenantConfig::query_param("xiaojinpro".to_string());
        assert_eq!(config.mode, TenantMode::QueryParam);
        assert!(config.validate().is_ok());

        let url = "https://auth.xiaojinpro.com/test";
        let result = config.apply_to_url(url).unwrap();
        assert_eq!(result, "https://auth.xiaojinpro.com/test?tenant_id=xiaojinpro");

        let url_with_params = "https://auth.xiaojinpro.com/test?foo=bar";
        let result = config.apply_to_url(url_with_params).unwrap();
        assert_eq!(result, "https://auth.xiaojinpro.com/test?foo=bar&tenant_id=xiaojinpro");
    }
}