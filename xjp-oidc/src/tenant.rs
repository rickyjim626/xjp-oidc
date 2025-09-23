//! Multi-tenant support for OIDC SDK

use serde::{Deserialize, Serialize};
use std::fmt;

/// Tenant resolution strategy
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TenantMode {
    /// Single tenant mode - no tenant resolution needed
    Single,
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
}

/// Tenant resolution with priority support
#[derive(Debug, Clone, Default)]
pub struct TenantResolution {
    /// Tenant resolved from client_id
    pub client_id_tenant: Option<String>,
    /// Admin override header value
    pub admin_override_tenant: Option<String>,
    /// Default tenant fallback
    pub default_tenant: Option<String>,
}

impl TenantResolution {
    /// Resolve tenant based on priority: client_id -> admin_override -> default
    pub fn resolve(&self) -> Option<String> {
        self.client_id_tenant
            .as_ref()
            .or(self.admin_override_tenant.as_ref())
            .or(self.default_tenant.as_ref())
            .cloned()
    }
    
    /// Get the effective tenant ID as string
    pub fn tenant_id(&self) -> String {
        self.resolve().unwrap_or_else(|| "default".to_string())
    }
}

impl TenantConfig {
    /// Create a new single tenant configuration
    pub fn single() -> Self {
        Self {
            mode: TenantMode::Single,
            tenant: None,
        }
    }


    /// Create a new query parameter-based tenant configuration
    pub fn query_param(tenant: String) -> Self {
        Self {
            mode: TenantMode::QueryParam,
            tenant: Some(tenant),
        }
    }

    /// Create a new client_id-based tenant configuration
    pub fn client_id(client_id: String) -> Self {
        Self {
            mode: TenantMode::ClientId,
            tenant: Some(client_id),
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
            TenantMode::ClientId => {
                if let Some(client_id) = &self.tenant {
                    let separator = if url.contains('?') { "&" } else { "?" };
                    Ok(format!("{}{}client_id={}", url, separator, client_id))
                } else {
                    Err("Client ID required for client_id mode".to_string())
                }
            }
        }
    }


    /// Check if tenant configuration is valid
    pub fn validate(&self) -> Result<(), String> {
        match &self.mode {
            TenantMode::Single => Ok(()),
            TenantMode::QueryParam => {
                if self.tenant.is_none() {
                    Err("Query param mode requires tenant".to_string())
                } else {
                    Ok(())
                }
            }
            TenantMode::ClientId => {
                if self.tenant.is_none() {
                    Err("Client ID mode requires client_id".to_string())
                } else {
                    Ok(())
                }
            }
        }
    }
}

impl fmt::Display for TenantConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.mode {
            TenantMode::Single => write!(f, "Single tenant"),
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

    #[test]
    fn test_client_id_tenant() {
        let config = TenantConfig::client_id("xjp-web".to_string());
        assert_eq!(config.mode, TenantMode::ClientId);
        assert!(config.validate().is_ok());

        let url = "https://auth.xiaojinpro.com/.well-known/openid-configuration";
        let result = config.apply_to_url(url).unwrap();
        assert_eq!(result, "https://auth.xiaojinpro.com/.well-known/openid-configuration?client_id=xjp-web");

        let url_with_params = "https://auth.xiaojinpro.com/.well-known/openid-configuration?foo=bar";
        let result = config.apply_to_url(url_with_params).unwrap();
        assert_eq!(result, "https://auth.xiaojinpro.com/.well-known/openid-configuration?foo=bar&client_id=xjp-web");
    }

    #[test]
    fn test_client_id_tenant_validation() {
        let mut config = TenantConfig {
            mode: TenantMode::ClientId,
            tenant: None,
        };
        
        // Should fail without client_id
        assert!(config.validate().is_err());
        
        // Should pass with client_id
        config.tenant = Some("xjp-web".to_string());
        assert!(config.validate().is_ok());
    }
    
    #[test]
    fn test_tenant_resolution_priority() {
        let resolution = TenantResolution {
            client_id_tenant: Some("client-tenant".to_string()),
            admin_override_tenant: Some("admin-tenant".to_string()),
            default_tenant: Some("default-tenant".to_string()),
        };
        
        // Should resolve to client_id first
        assert_eq!(resolution.resolve(), Some("client-tenant".to_string()));
        
        // With no client_id, should resolve to admin override
        let resolution = TenantResolution {
            client_id_tenant: None,
            admin_override_tenant: Some("admin-tenant".to_string()),
            default_tenant: Some("default-tenant".to_string()),
        };
        assert_eq!(resolution.resolve(), Some("admin-tenant".to_string()));
        
        // With no client_id or admin, should resolve to default
        let resolution = TenantResolution {
            client_id_tenant: None,
            admin_override_tenant: None,
            default_tenant: Some("default-tenant".to_string()),
        };
        assert_eq!(resolution.resolve(), Some("default-tenant".to_string()));
        
        // With nothing, should return None
        let resolution = TenantResolution::default();
        assert_eq!(resolution.resolve(), None);
        assert_eq!(resolution.tenant_id(), "default");
    }
}