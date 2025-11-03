use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as EdSigner, SigningKey as Ed25519SigningKey,
};
use p256::{
    SecretKey as P256SecretKey,
    ecdsa::{
        Signature as P256Signature, SigningKey as P256SigningKey, signature::Signer as EcdsaSigner,
    },
};
use serde_json::{Map, Value, json};

use super::SecurityError;

#[derive(Clone)]
pub struct DiscoverySigner {
    kid: String,
    kind: DiscoveryKind,
    public_jwk: Value,
}

#[derive(Clone)]
enum DiscoveryKind {
    Ed25519 { signing: Ed25519SigningKey },
    Es256 { signing: P256SigningKey },
}

pub struct JwsSignature {
    pub protected: String,
    pub signature: String,
}

impl DiscoverySigner {
    pub fn from_jwk_str(jwk: &str) -> Result<Self, SecurityError> {
        let value: Value = serde_json::from_str(jwk)?;
        Self::from_jwk_value(value)
    }

    pub fn from_jwk_value(value: Value) -> Result<Self, SecurityError> {
        let obj = value.as_object().ok_or(SecurityError::InvalidKey(
            "OAUTH_DISCOVERY_JWK must be an object",
        ))?;
        let kid = obj
            .get("kid")
            .and_then(|v| v.as_str())
            .ok_or(SecurityError::InvalidKey("OAUTH_DISCOVERY_JWK missing kid"))?
            .to_string();
        let kty = obj
            .get("kty")
            .and_then(|v| v.as_str())
            .ok_or(SecurityError::InvalidKey("OAUTH_DISCOVERY_JWK missing kty"))?;

        match kty {
            "OKP" => Self::build_ed25519(obj, kid),
            "EC" => Self::build_es256(obj, kid),
            _ => Err(SecurityError::InvalidKey("unsupported discovery key type")),
        }
    }

    pub fn sign(&self, payload: &[u8]) -> Result<JwsSignature, SecurityError> {
        let header = json!({
            "alg": self.alg_name(),
            "kid": self.kid,
        });
        let protected_bytes = serde_json::to_vec(&header)?;
        let protected = URL_SAFE_NO_PAD.encode(protected_bytes);

        let signature = match &self.kind {
            DiscoveryKind::Ed25519 { signing, .. } => {
                let sig: Ed25519Signature = EdSigner::sign(signing, payload);
                URL_SAFE_NO_PAD.encode(sig.to_bytes())
            }
            DiscoveryKind::Es256 { signing } => {
                let sig: P256Signature = EcdsaSigner::sign(signing, payload);
                URL_SAFE_NO_PAD.encode(sig.to_bytes())
            }
        };

        Ok(JwsSignature {
            protected,
            signature,
        })
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn jwks_document(&self) -> Value {
        json!({ "keys": [self.public_jwk.clone()] })
    }

    fn alg_name(&self) -> &'static str {
        match self.kind {
            DiscoveryKind::Ed25519 { .. } => "EdDSA",
            DiscoveryKind::Es256 { .. } => "ES256",
        }
    }

    fn build_ed25519(obj: &Map<String, Value>, kid: String) -> Result<Self, SecurityError> {
        let crv = obj
            .get("crv")
            .and_then(|v| v.as_str())
            .ok_or(SecurityError::InvalidKey("OAUTH_DISCOVERY_JWK missing crv"))?;
        if crv != "Ed25519" {
            return Err(SecurityError::InvalidKey("unsupported OKP curve"));
        }

        let secret = obj
            .get("d")
            .and_then(|v| v.as_str())
            .ok_or(SecurityError::InvalidKey("OAUTH_DISCOVERY_JWK missing d"))?;
        let secret_bytes = URL_SAFE_NO_PAD.decode(secret.as_bytes())?;
        if secret_bytes.len() != 32 {
            return Err(SecurityError::InvalidKey(
                "Ed25519 private key must be 32 bytes",
            ));
        }
        let mut secret_array = [0u8; 32];
        secret_array.copy_from_slice(&secret_bytes);
        let signing = Ed25519SigningKey::from_bytes(&secret_array);
        let verifying = signing.verifying_key();
        let x = URL_SAFE_NO_PAD.encode(verifying.as_bytes());

        let alg = obj
            .get("alg")
            .and_then(|v| v.as_str())
            .unwrap_or("EdDSA")
            .to_string();
        let mut public = Map::new();
        public.insert("kty".into(), Value::String("OKP".into()));
        public.insert("crv".into(), Value::String("Ed25519".into()));
        public.insert("x".into(), Value::String(x));
        public.insert("kid".into(), Value::String(kid.clone()));
        public.insert("alg".into(), Value::String(alg));

        if let Some(use_field) = obj.get("use").and_then(|v| v.as_str()) {
            public.insert("use".into(), Value::String(use_field.to_string()));
        }

        Ok(Self {
            kid,
            kind: DiscoveryKind::Ed25519 { signing },
            public_jwk: Value::Object(public),
        })
    }

    fn build_es256(obj: &Map<String, Value>, kid: String) -> Result<Self, SecurityError> {
        let crv = obj
            .get("crv")
            .and_then(|v| v.as_str())
            .ok_or(SecurityError::InvalidKey("OAUTH_DISCOVERY_JWK missing crv"))?;
        if crv != "P-256" {
            return Err(SecurityError::InvalidKey("unsupported EC curve"));
        }
        let secret = obj
            .get("d")
            .and_then(|v| v.as_str())
            .ok_or(SecurityError::InvalidKey("OAUTH_DISCOVERY_JWK missing d"))?;
        let secret_bytes = URL_SAFE_NO_PAD.decode(secret.as_bytes())?;
        let secret_key = P256SecretKey::from_slice(&secret_bytes)
            .map_err(|_| SecurityError::InvalidKey("invalid P-256 private key"))?;
        let signing = P256SigningKey::from(secret_key);
        let verifying = signing.verifying_key();
        let encoded = verifying.to_encoded_point(false);
        let x = encoded
            .x()
            .ok_or(SecurityError::InvalidKey("invalid P-256 public key"))?;
        let y = encoded
            .y()
            .ok_or(SecurityError::InvalidKey("invalid P-256 public key"))?;

        let x_b64 = URL_SAFE_NO_PAD.encode(x);
        let y_b64 = URL_SAFE_NO_PAD.encode(y);

        let alg = obj
            .get("alg")
            .and_then(|v| v.as_str())
            .unwrap_or("ES256")
            .to_string();

        let mut public = Map::new();
        public.insert("kty".into(), Value::String("EC".into()));
        public.insert("crv".into(), Value::String("P-256".into()));
        public.insert("x".into(), Value::String(x_b64));
        public.insert("y".into(), Value::String(y_b64));
        public.insert("kid".into(), Value::String(kid.clone()));
        public.insert("alg".into(), Value::String(alg));

        if let Some(use_field) = obj.get("use").and_then(|v| v.as_str()) {
            public.insert("use".into(), Value::String(use_field.to_string()));
        }

        Ok(Self {
            kid,
            kind: DiscoveryKind::Es256 { signing },
            public_jwk: Value::Object(public),
        })
    }
}
