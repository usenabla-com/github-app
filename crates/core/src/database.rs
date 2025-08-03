use sqlx::{Pool, Postgres};
use anyhow::Result;
use crate::types::*;

pub type DbPool = Pool<Postgres>;

pub async fn create_tables(pool: &DbPool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS customers (
            id UUID PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            github_account_login TEXT NOT NULL,
            events JSONB DEFAULT '[]'::jsonb,
            features JSONB DEFAULT '{}'::jsonb,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS github_apps (
            id UUID PRIMARY KEY,
            app_id BIGINT NOT NULL,
            private_key TEXT NOT NULL,
            github_api_base TEXT NOT NULL,
            webhook_secret TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS github_installations (
            id UUID PRIMARY KEY,
            github_app_id UUID NOT NULL REFERENCES github_apps(id),
            installation_id BIGINT NOT NULL,
            account_login TEXT NOT NULL,
            account_type TEXT NOT NULL,
            permissions JSONB,
            events JSONB,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            suspended_at TIMESTAMP WITH TIME ZONE,
            UNIQUE(github_app_id, installation_id)
        );
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}