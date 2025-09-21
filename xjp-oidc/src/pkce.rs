//! PKCE (Proof Key for Code Exchange) implementation

use crate::errors::Result;
use base64::{engine::general_purpose, Engine as _};
use rand::{distributions::Alphanumeric, Rng};
use sha2::{Digest, Sha256};

/// Generate a PKCE verifier/challenge pair
///
/// Returns (verifier, challenge, method) where method is always "S256"
///
/// # Example
/// ```
/// use xjp_oidc::create_pkce;
///
/// let (verifier, challenge, method) = create_pkce().unwrap();
/// assert_eq!(method, "S256");
/// assert!(verifier.len() >= 43 && verifier.len() <= 128);
/// ```
pub fn create_pkce() -> Result<(String, String, &'static str)> {
    // Generate random verifier (43-128 characters)
    let verifier = generate_verifier();

    // Create S256 challenge
    let challenge = create_s256_challenge(&verifier);

    Ok((verifier, challenge, "S256"))
}

/// Generate a cryptographically secure random verifier
fn generate_verifier() -> String {
    // RFC 7636 recommends 43-128 characters
    // We'll use 64 for a good balance
    rand::thread_rng().sample_iter(&Alphanumeric).take(64).map(char::from).collect()
}

/// Create S256 challenge from verifier
fn create_s256_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();

    // Base64url encode without padding
    general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

/// Verify a PKCE challenge
///
/// This is mainly for testing purposes as the actual verification
/// happens on the authorization server
#[cfg(test)]
fn verify_pkce_challenge(verifier: &str, challenge: &str, method: &str) -> bool {
    match method {
        "S256" => {
            let computed_challenge = create_s256_challenge(verifier);
            computed_challenge == challenge
        }
        "plain" => verifier == challenge,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_pkce() {
        let (verifier, challenge, method) = create_pkce().unwrap();

        // Check method
        assert_eq!(method, "S256");

        // Check verifier length
        assert!(verifier.len() >= 43);
        assert!(verifier.len() <= 128);

        // Check challenge format (base64url)
        assert!(challenge.chars().all(|c| { c.is_ascii_alphanumeric() || c == '-' || c == '_' }));

        // Verify the challenge
        assert!(verify_pkce_challenge(&verifier, &challenge, method));
    }

    #[test]
    fn test_pkce_uniqueness() {
        let (v1, c1, _) = create_pkce().unwrap();
        let (v2, c2, _) = create_pkce().unwrap();

        assert_ne!(v1, v2);
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_verifier_format() {
        let verifier = generate_verifier();

        // Should only contain alphanumeric characters
        assert!(verifier.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_eq!(verifier.len(), 64);
    }

    #[test]
    fn test_s256_challenge() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        let challenge = create_s256_challenge(verifier);
        assert_eq!(challenge, expected);
    }

    #[test]
    fn test_verify_pkce() {
        let verifier = "test_verifier_123";
        let challenge = create_s256_challenge(verifier);

        assert!(verify_pkce_challenge(verifier, &challenge, "S256"));
        assert!(!verify_pkce_challenge(verifier, &challenge, "plain"));
        assert!(!verify_pkce_challenge("wrong_verifier", &challenge, "S256"));
    }
}
