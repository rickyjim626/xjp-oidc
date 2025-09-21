use xjp_oidc::create_pkce;

#[test]
fn test_pkce_creation() {
    let result = create_pkce();
    assert!(result.is_ok());

    let (verifier, challenge, method) = result.unwrap();

    // Check method is always S256
    assert_eq!(method, "S256");

    // Check verifier length (RFC 7636: 43-128 characters)
    assert!(verifier.len() >= 43);
    assert!(verifier.len() <= 128);

    // Check verifier contains only unreserved characters
    assert!(verifier.chars().all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c)));

    // Check challenge is base64url encoded (no padding)
    assert!(challenge.chars().all(|c| c.is_ascii_alphanumeric() || "-_".contains(c)));
    assert!(!challenge.contains('='));
    assert!(!challenge.contains('+'));
    assert!(!challenge.contains('/'));
}

#[test]
fn test_pkce_challenge_consistency() {
    use base64::{engine::general_purpose, Engine as _};
    use sha2::{Digest, Sha256};

    let (verifier, challenge, _) = create_pkce().unwrap();

    // Manually compute the challenge
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    let expected_challenge = general_purpose::URL_SAFE_NO_PAD.encode(hash);

    assert_eq!(challenge, expected_challenge);
}

#[test]
fn test_pkce_uniqueness() {
    let results: Vec<_> = (0..100).map(|_| create_pkce().unwrap()).collect();

    // Check all verifiers are unique
    let verifiers: Vec<_> = results.iter().map(|(v, _, _)| v).collect();
    let unique_verifiers: std::collections::HashSet<_> = verifiers.iter().collect();
    assert_eq!(verifiers.len(), unique_verifiers.len());

    // Check all challenges are unique
    let challenges: Vec<_> = results.iter().map(|(_, c, _)| c).collect();
    let unique_challenges: std::collections::HashSet<_> = challenges.iter().collect();
    assert_eq!(challenges.len(), unique_challenges.len());
}
