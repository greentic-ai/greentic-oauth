use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::{Rng, distr::Alphanumeric};
use sha2::{Digest, Sha256};

/// Length of the PKCE verifier string.
const DEFAULT_VERIFIER_LEN: usize = 64;

/// Represents a generated PKCE verifier/challenge pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkcePair {
    pub verifier: String,
    pub challenge: String,
}

impl PkcePair {
    /// Generate a PKCE pair using the thread-local RNG.
    pub fn generate() -> Self {
        Self::generate_with_len(DEFAULT_VERIFIER_LEN)
    }

    /// Generate a verifier/challenge pair with a custom verifier length.
    pub fn generate_with_len(len: usize) -> Self {
        let mut rng = rand::rng();
        Self::generate_with_rng(len, &mut rng)
    }

    /// Generate a PKCE pair using the provided RNG.
    pub fn generate_with_rng<R: Rng + ?Sized>(len: usize, rng: &mut R) -> Self {
        let verifier: String = (0..len).map(|_| rng.sample(Alphanumeric) as char).collect();

        let challenge = Self::challenge_for(&verifier);
        Self {
            verifier,
            challenge,
        }
    }

    /// Compute the S256 challenge for an arbitrary verifier.
    pub fn challenge_for(verifier: &str) -> String {
        let digest = Sha256::digest(verifier.as_bytes());
        URL_SAFE_NO_PAD.encode(digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_has_valid_charset() {
        let pair = PkcePair::generate_with_len(43);
        assert!(
            pair.verifier
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~'))
        );
    }

    #[test]
    fn challenge_matches_reference() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        let challenge = PkcePair::challenge_for(verifier);
        assert_eq!(challenge, expected);
    }
}
