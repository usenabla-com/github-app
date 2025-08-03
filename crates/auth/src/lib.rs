use nabla_core::{Customer, GitHubInstallation, DbPool};
use anyhow::{Result, anyhow};
use serde_json::Value;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub customer: Customer,
    pub installation: GitHubInstallation,
    pub features: Vec<String>,
}

pub struct AuthService {
    db: DbPool,
}

impl AuthService {
    pub fn new(db: DbPool) -> Self {
        Self { db }
    }

    pub async fn validate_installation(&self, installation_id: i64) -> Result<GitHubInstallation> {
        let row = sqlx::query!(
            r#"
            SELECT id, github_app_id, installation_id, account_login, account_type, 
                   permissions, events, created_at, suspended_at
            FROM github_installations 
            WHERE installation_id = $1 AND suspended_at IS NULL
            "#,
            installation_id
        )
        .fetch_optional(&self.db)
        .await?
        .ok_or_else(|| anyhow!("Installation not found or suspended"))?;

        let permissions: HashMap<String, String> = serde_json::from_value(row.permissions.unwrap_or_default())?;
        let events: Vec<Value> = serde_json::from_value(row.events.unwrap_or_default())?;

        Ok(GitHubInstallation {
            id: row.id,
            github_app_id: row.github_app_id,
            installation_id: row.installation_id,
            account_login: row.account_login,
            account_type: row.account_type,
            permissions,
            events,
            created_at: row.created_at,
            suspended_at: row.suspended_at,
        })
    }

    pub async fn get_customer_by_github_login(&self, github_login: &str) -> Result<Option<Customer>> {
        let row = sqlx::query!(
            r#"
            SELECT id, name, email, github_account_login, features, events, created_at, updated_at
            FROM customers 
            WHERE github_account_login = $1
            "#,
            github_login
        )
        .fetch_optional(&self.db)
        .await?;

        match row {
            Some(row) => {
                let events: Vec<Value> = serde_json::from_value(row.events.unwrap_or_default())?;
                Ok(Some(Customer {
                    id: row.id,
                    name: row.name,
                    email: row.email,
                    github_account_login: row.github_account_login,
                    features: serde_json::from_value(row.features.unwrap_or_default())?,
                    events,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                }))
            }
            None => Ok(None),
        }
    }

    pub async fn check_subscription_status(&self, customer: &Customer) -> Result<SubscriptionStatus> {
        let latest_event = customer.events
            .iter()
            .filter_map(|event| {
                if let (Some(event_type), Some(timestamp)) = (
                    event.get("type").and_then(|v| v.as_str()),
                    event.get("timestamp").and_then(|v| v.as_str())
                ) {
                    if matches!(event_type, "subscription_created" | "subscription_renewed" | "subscription_cancelled") {
                        DateTime::parse_from_rfc3339(timestamp).ok().map(|dt| (event_type, dt.with_timezone(&Utc)))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .max_by_key(|(_, timestamp)| *timestamp);

        match latest_event {
            Some(("subscription_created" | "subscription_renewed", timestamp)) => {
                let expires_at = timestamp + chrono::Duration::days(365);
                if Utc::now() < expires_at {
                    Ok(SubscriptionStatus::Active { expires_at })
                } else {
                    Ok(SubscriptionStatus::Expired)
                }
            }
            Some(("subscription_cancelled", _)) => Ok(SubscriptionStatus::Cancelled),
            None => Ok(SubscriptionStatus::None),
        }
    }

    pub async fn get_auth_context(&self, installation_id: i64) -> Result<AuthContext> {
        let installation = self.validate_installation(installation_id).await?;
        
        let customer = self.get_customer_by_github_login(&installation.account_login).await?
            .ok_or_else(|| anyhow!("Customer not found for installation"))?;

        let subscription_status = self.check_subscription_status(&customer).await?;
        let features = self.get_features_for_subscription(&subscription_status);

        Ok(AuthContext {
            customer,
            installation,
            features,
        })
    }

    pub async fn create_installation(&self, installation_id: i64, github_app_id: Uuid, account_login: &str, account_type: &str) -> Result<GitHubInstallation> {
        let id = Uuid::new_v4();
        
        sqlx::query!(
            r#"
            INSERT INTO github_installations (id, github_app_id, installation_id, account_login, account_type, permissions, events)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            id,
            github_app_id,
            installation_id,
            account_login,
            account_type,
            serde_json::json!({}),
            serde_json::json!([])
        )
        .execute(&self.db)
        .await?;

        self.validate_installation(installation_id).await
    }

    pub async fn delete_installation(&self, installation_id: i64) -> Result<()> {
        sqlx::query!(
            "UPDATE github_installations SET suspended_at = NOW() WHERE installation_id = $1",
            installation_id
        )
        .execute(&self.db)
        .await?;

        Ok(())
    }

    fn get_features_for_subscription(&self, status: &SubscriptionStatus) -> Vec<String> {
        match status {
            SubscriptionStatus::Active { .. } => vec![
                "scan".to_string(),
                "attestation".to_string(),
                "full_cve_data".to_string(),
                "unlimited_scans".to_string(),
            ],
            _ => vec![
                "scan".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone)]
pub enum SubscriptionStatus {
    None,
    Active { expires_at: DateTime<Utc> },
    Expired,
    Cancelled,
}

impl AuthContext {
    pub fn can_scan(&self) -> bool {
        self.features.contains(&"scan".to_string())
    }

    pub fn can_generate_attestations(&self) -> bool {
        self.features.contains(&"attestation".to_string())
    }

    pub fn has_full_cve_access(&self) -> bool {
        self.features.contains(&"full_cve_data".to_string())
    }

    pub fn has_unlimited_scans(&self) -> bool {
        self.features.contains(&"unlimited_scans".to_string())
    }
}