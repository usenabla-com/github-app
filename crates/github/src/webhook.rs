use serde_json::Value;
use sha2::{Sha256, Digest};
use hex;
use anyhow::{Result, anyhow};

pub struct WebhookValidator {
    secret: String,
}

impl WebhookValidator {
    pub fn new(secret: String) -> Self {
        Self { secret }
    }

    pub fn validate_signature(&self, payload: &[u8], signature: &str) -> Result<bool> {
        if !signature.starts_with("sha256=") {
            return Err(anyhow!("Invalid signature format"));
        }

        let expected_signature = &signature[7..];
        
        let mut hasher = Sha256::new();
        hasher.update(self.secret.as_bytes());
        hasher.update(payload);
        let hash = hasher.finalize();
        let computed_signature = hex::encode(hash);

        Ok(computed_signature == expected_signature)
    }

    pub fn parse_event(&self, payload: &[u8], event_type: &str) -> Result<Value> {
        let event: Value = serde_json::from_slice(payload)?;
        
        // Add event type for easier processing
        let mut event_with_type = event;
        if let Some(obj) = event_with_type.as_object_mut() {
            obj.insert("event_type".to_string(), Value::String(event_type.to_string()));
        }

        Ok(event_with_type)
    }

    pub fn should_process_event(&self, event: &Value) -> bool {
        let event_type = event.get("event_type").and_then(|v| v.as_str()).unwrap_or("");
        
        match event_type {
            "push" => true,
            "pull_request" => {
                let action = event.get("action").and_then(|v| v.as_str()).unwrap_or("");
                matches!(action, "opened" | "synchronize" | "reopened")
            }
            "installation" => {
                let action = event.get("action").and_then(|v| v.as_str()).unwrap_or("");
                matches!(action, "created" | "deleted")
            }
            _ => false,
        }
    }
}