use serde::{Deserialize, Serialize};
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub database_url: String,
    pub port: u16,
    pub github_webhook_secret: String,
    pub stripe_webhook_secret: String,
    pub github_app_id: String,
    pub github_private_key: String,
    pub github_api_base: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let github_private_key_env = std::env::var("GITHUB_PRIVATE_KEY_BASE64")?;
        let github_private_key = if github_private_key_env.starts_with("-----BEGIN") {
            github_private_key_env
        } else {
            String::from_utf8(base64::engine::general_purpose::STANDARD.decode(github_private_key_env)?)?
        };

        Ok(Self {
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgresql://localhost/nabla".to_string()),
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "3000".to_string())
                .parse()?,
            github_webhook_secret: std::env::var("GITHUB_WEBHOOK_SECRET")?,
            stripe_webhook_secret: std::env::var("STRIPE_WEBHOOK_SECRET")?,
            github_app_id: std::env::var("GITHUB_APP_ID")?,
            github_private_key,
            github_api_base: std::env::var("GITHUB_API_BASE")
                .unwrap_or_else(|_| "https://api.github.com".to_string()),
        })
    }
}