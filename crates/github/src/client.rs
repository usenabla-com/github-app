use octocrab::{Octocrab, Result as OctocrabResult};
use octocrab::models::checks::{CheckRunStatus, CheckRunConclusion};
use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};
use chrono::{Utc, Duration};
use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow};
use snafu::Backtrace;

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
            .map_err(|e| {
                octocrab::Error::Other {
                    source: e.into(),
                    backtrace: Backtrace::capture(),
                }
            })?;

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
        
        let mut builder = octocrab
            .checks(owner, repo)
            .create_check_run("Nabla Security Scan", head_sha);

        let status_enum = match status {
            "queued" => CheckRunStatus::Queued,
            "in_progress" => CheckRunStatus::InProgress,
            "completed" => CheckRunStatus::Completed,
            _ => return Err(anyhow!("Invalid check run status")),
        };
        builder = builder.status(status_enum);

        if let Some(conclusion_str) = conclusion {
            let conclusion_enum = match conclusion_str {
                "success" => CheckRunConclusion::Success,
                "failure" => CheckRunConclusion::Failure,
                "neutral" => CheckRunConclusion::Neutral,
                "cancelled" => CheckRunConclusion::Cancelled,
                "skipped" => CheckRunConclusion::Skipped,
                "timed_out" => CheckRunConclusion::TimedOut,
                "action_required" => CheckRunConclusion::ActionRequired,
                _ => return Err(anyhow!("Invalid check run conclusion")),
            };
            builder = builder.conclusion(conclusion_enum);
        }

        if let Some(output_val) = output {
            if let (Some(title), Some(summary)) = (output_val.get("title").and_then(|v| v.as_str()), output_val.get("summary").and_then(|v| v.as_str())) {
                builder = builder.output(title, summary);
            }
        }

        builder.send().await
            .map_err(|e| anyhow!("Failed to create check run: {}", e))?;
        
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
            .await
            .map_err(|e| anyhow!("Failed to create PR comment: {}", e))?;

        Ok(())
    }
}