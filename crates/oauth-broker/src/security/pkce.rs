use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::TryRngCore;
use sha2::{Digest, Sha256};

/// Combined PKCE verifier + challenge pair using the S256 method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkcePair {
    pub verifier: String,
    pub challenge: String,
}

impl PkcePair {
    /// Generate a new verifier + challenge pair using RFC 7636 S256.
    pub fn generate() -> Self {
        let mut entropy = [0u8; 32];
        let mut rng = OsRng;
        rng.try_fill_bytes(&mut entropy)
            .expect("os entropy source unavailable");
        let verifier = URL_SAFE_NO_PAD.encode(entropy);

        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let digest = hasher.finalize();
        let challenge = URL_SAFE_NO_PAD.encode(digest);

        Self {
            verifier,
            challenge,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_pair_has_no_padding() {
        let pair = PkcePair::generate();
        assert!(!pair.verifier.contains('='));
        assert!(!pair.challenge.contains('='));
        assert!(!pair.verifier.is_empty());
        assert!(!pair.challenge.is_empty());
    }

    #[test]
    fn challenge_matches_hash_of_verifier() {
        let pair = PkcePair::generate();
        let recomputed = URL_SAFE_NO_PAD.encode(Sha256::digest(pair.verifier.as_bytes()));
        assert_eq!(recomputed, pair.challenge);
    }
}
