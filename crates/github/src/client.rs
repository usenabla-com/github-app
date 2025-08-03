use octocrab::{Octocrab, Result as OctocrabResult};
use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};
use chrono::{Utc, Duration};
use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: String,
    iat: i64,
    exp: i64,
}

pub struct GitHubClient {
    app_id: String,
    private_key: String,
    api_base: String,
}

impl GitHubClient {
    pub fn new(app_id: String, private_key: String, api_base: String) -> Self {
        Self {
            app_id,
            private_key,
            api_base,
        }
    }

    pub fn generate_jwt(&self) -> Result<String> {
        let now = Utc::now();
        let claims = Claims {
            iss: self.app_id.clone(),
            iat: now.timestamp(),
            exp: (now + Duration::minutes(10)).timestamp(),
        };

        let key = EncodingKey::from_rsa_pem(self.private_key.as_bytes())
            .map_err(|e| anyhow!("Failed to parse private key: {}", e))?;

        encode(&Header::new(Algorithm::RS256), &claims, &key)
            .map_err(|e| anyhow!("Failed to encode JWT: {}", e))
    }

    pub async fn get_installation_token(&self, installation_id: i64) -> Result<String> {
        let jwt = self.generate_jwt()?;
        
        let client = reqwest::Client::new();
        let url = format!("{}/app/installations/{}/access_tokens", self.api_base, installation_id);
        
        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", jwt))
            .header("Accept", "application/vnd.github.v3+json")
            .header("User-Agent", "nabla-github-app")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!("Failed to get installation token: {}", response.status()));
        }

        let json: serde_json::Value = response.json().await?;
        let token = json["token"].as_str()
            .ok_or_else(|| anyhow!("Token not found in response"))?;

        Ok(token.to_string())
    }

    pub async fn create_octocrab_client(&self, installation_id: i64) -> OctocrabResult<Octocrab> {
        let token = self.get_installation_token(installation_id).await
            .map_err(|e| octocrab::Error::Other(Box::new(e)))?;

        Octocrab::builder()
            .personal_token(token)
            .base_uri(&self.api_base)?
            .build()
    }

    pub async fn post_check_run(
        &self,
        installation_id: i64,
        owner: &str,
        repo: &str,
        head_sha: &str,
        status: &str,
        conclusion: Option<&str>,
        output: Option<serde_json::Value>,
    ) -> Result<()> {
        let octocrab = self.create_octocrab_client(installation_id).await?;
        
        let mut check_run = octocrab
            .checks(owner, repo)
            .create_check_run("Nabla Security Scan", head_sha)
            .status(octocrab::models::checks::CheckRunStatus::try_from(status)?);

        if let Some(conclusion) = conclusion {
            check_run = check_run.conclusion(octocrab::models::checks::CheckRunConclusion::try_from(conclusion)?);
        }

        if let Some(output) = output {
            if let (Some(title), Some(summary)) = (output.get("title").and_then(|v| v.as_str()), 
                                                   output.get("summary").and_then(|v| v.as_str())) {
                check_run = check_run.output(title, summary);
            }
        }

        check_run.send().await?;
        Ok(())
    }

    pub async fn post_pr_comment(
        &self,
        installation_id: i64,
        owner: &str,
        repo: &str,
        pr_number: u64,
        body: &str,
    ) -> Result<()> {
        let octocrab = self.create_octocrab_client(installation_id).await?;
        
        octocrab
            .issues(owner, repo)
            .create_comment(pr_number, body)
            .await?;

        Ok(())
    }
}