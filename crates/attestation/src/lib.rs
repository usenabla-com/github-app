use serde_json::{json, Value};
use chrono::Utc;
use sha2::{Sha256, Digest};
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::Signer;
use anyhow::Result;

pub struct AttestationGenerator;

impl AttestationGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn create_in_toto_statement(
        &self,
        file_name: &str,
        file_bytes: &[u8],
        analysis_result: &Value,
    ) -> Value {
        let mut hasher = Sha256::new();
        hasher.update(file_bytes);
        let hash = hasher.finalize();
        let encoded_hash = hex::encode(&hash);

        json!({
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{
                "name": file_name,
                "digest": {
                    "sha256": encoded_hash
                }
            }],
            "predicateType": "https://www.usenabla.com/attestation/v0.1",
            "predicate": {
                "timestamp": Utc::now().to_rfc3339(),
                "analysis": analysis_result
            }
        })
    }

    pub fn sign_attestation(
        &self,
        attestation: &Value,
        signing_key: &[u8],
    ) -> Result<Value> {
        let key_pair = self.parse_signing_key(signing_key)?;
        
        let attestation_bytes = serde_json::to_vec(attestation)?;
        let signature = key_pair.try_sign(&attestation_bytes)
            .map_err(|e| anyhow::anyhow!("Signing failed: {}", e))?;
        let signature_b64 = general_purpose::STANDARD.encode(signature.to_bytes());

        let mut signed_attestation = attestation.clone();
        let signatures = json!([{
            "keyid": "keyid123",
            "sig": signature_b64,
            "cert": "certificate_here"
        }]);

        if let Some(obj) = signed_attestation.as_object_mut() {
            obj.insert("signatures".to_string(), signatures);
        }

        Ok(signed_attestation)
    }

    fn parse_signing_key(&self, key_bytes: &[u8]) -> Result<ed25519_dalek::SigningKey> {
        let key_str = String::from_utf8_lossy(key_bytes);
        
        let pem_content = if key_str.contains("-----BEGIN PRIVATE KEY-----") {
            let lines: Vec<&str> = key_str.lines().collect();
            let mut key_content = String::new();
            let mut in_key = false;
            
            for line in lines {
                if line.contains("-----BEGIN PRIVATE KEY-----") {
                    in_key = true;
                    continue;
                }
                if line.contains("-----END PRIVATE KEY-----") {
                    break;
                }
                if in_key {
                    key_content.push_str(line);
                }
            }
            
            general_purpose::STANDARD.decode(key_content.as_bytes())?
        } else {
            general_purpose::STANDARD.decode(key_bytes)?
        };

        if pem_content.len() != 32 {
            return Err(anyhow::anyhow!("Invalid key length: expected 32 bytes, got {}", pem_content.len()));
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&pem_content);

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_array);
        Ok(signing_key)
    }
}