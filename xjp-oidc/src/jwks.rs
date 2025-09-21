//! JSON Web Key Set (JWKS) types and utilities

use serde::{Deserialize, Serialize};

/// JSON Web Key (JWK) structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type (e.g., "RSA", "EC")
    pub kty: String,
    /// Key ID
    pub kid: String,
    /// Key use (e.g., "sig", "enc")
    #[serde(rename = "use")]
    pub use_: String,
    /// Algorithm (e.g., "RS256")
    pub alg: String,
    /// RSA modulus (for RSA keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// RSA public exponent (for RSA keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    /// X coordinate (for EC keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// Y coordinate (for EC keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    /// Curve (for EC keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
}

/// JSON Web Key Set (JWKS)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    /// Array of JSON Web Keys
    pub keys: Vec<Jwk>,
}

impl Jwks {
    /// Find a key by its ID
    pub fn find_key(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid == kid)
    }

    /// Find keys by algorithm
    pub fn find_keys_by_alg(&self, alg: &str) -> Vec<&Jwk> {
        self.keys.iter().filter(|k| k.alg == alg).collect()
    }

    /// Find keys by use
    pub fn find_keys_by_use(&self, use_: &str) -> Vec<&Jwk> {
        self.keys.iter().filter(|k| k.use_ == use_).collect()
    }
}
