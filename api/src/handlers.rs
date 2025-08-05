use axum::{
    extract::{State, Request},
    http::{StatusCode, HeaderMap},
    response::Json,
};
use serde_json::{json, Value};
use nabla_github::{WebhookValidator, GitHubClient};
use nabla_core::{ScanConfiguration, SeverityLevel, BinaryFormat};
use crate::{AppState, scanner::RepoScanner};

pub async fn health() -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "service": "nabla-github-app"
    }))
}

pub async fn metrics() -> Json<Value> {
    Json(json!({
        "metrics": "placeholder"
    }))
}

pub async fn github_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
) -> Result<Json<Value>, StatusCode> {
    let signature = headers
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;

    let event_type = headers
        .get("x-github-event")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;

    let body = axum::body::to_bytes(request.into_body(), usize::MAX)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let validator = WebhookValidator::new(state.config.github_webhook_secret.clone());
    
    if !validator.validate_signature(&body, signature).map_err(|_| StatusCode::UNAUTHORIZED)? {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let event = validator.parse_event(&body, event_type).map_err(|_| StatusCode::BAD_REQUEST)?;

    if validator.should_process_event(&event) {
        tokio::spawn(async move {
            if let Err(e) = process_github_event(state, event).await {
                tracing::error!("Failed to process GitHub event: {}", e);
            }
        });
    }

    Ok(Json(json!({"status": "received"})))
}

pub async fn stripe_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
) -> Result<Json<Value>, StatusCode> {
    let signature = headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;

    let body = axum::body::to_bytes(request.into_body(), usize::MAX)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // TODO: Validate Stripe signature
    
    let event: Value = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    tokio::spawn(async move {
        if let Err(e) = process_stripe_event(state, event).await {
            tracing::error!("Failed to process Stripe event: {}", e);
        }
    });

    Ok(Json(json!({"status": "received"})))
}

async fn process_github_event(state: AppState, event: Value) -> anyhow::Result<()> {
    let event_type = event.get("event_type").and_then(|v| v.as_str()).unwrap_or("");
    
    match event_type {
        "installation" => {
            let action = event.get("action").and_then(|v| v.as_str()).unwrap_or("");
            let installation_id = event
                .get("installation")
                .and_then(|i| i.get("id"))
                .and_then(|v| v.as_i64())
                .ok_or_else(|| anyhow::anyhow!("Missing installation ID"))?;

            match action {
                "created" => {
                    let account = event
                        .get("installation")
                        .and_then(|i| i.get("account"))
                        .ok_or_else(|| anyhow::anyhow!("Missing account"))?;
                    
                    let login = account.get("login").and_then(|v| v.as_str()).unwrap_or("");
                    let account_type = account.get("type").and_then(|v| v.as_str()).unwrap_or("");

                    // TODO: Get github_app_id from database based on webhook source
                    let github_app_id = uuid::Uuid::new_v4(); // Placeholder
                    
                    state.auth_service.create_installation(
                        installation_id,
                        github_app_id,
                        login,
                        account_type,
                    ).await?;
                }
                "deleted" => {
                    state.auth_service.delete_installation(installation_id).await?;
                }
                _ => {}
            }
        }
        "push" | "pull_request" => {
            // Process push/PR events for scanning
            process_scan_event(state, event).await?;
        }
        _ => {}
    }

    Ok(())
}

async fn process_scan_event(state: AppState, event: Value) -> anyhow::Result<()> {
    let installation_id = event
        .get("installation")
        .and_then(|i| i.get("id"))
        .and_then(|v| v.as_i64())
        .ok_or_else(|| anyhow::anyhow!("Missing installation ID"))?;

    let auth_context = state.auth_service.get_auth_context(installation_id).await?;
    
    if !auth_context.can_scan() {
        tracing::warn!("Installation {} cannot scan - subscription required", installation_id);
        return Ok(());
    }

    // Create GitHub client for this installation
    let github_client = GitHubClient::new(
        state.config.github_app_id.clone(),
        state.config.github_private_key.clone(),
        state.config.github_api_base.clone(),
    );

    // Extract repository and commit info
    let repository = event.get("repository").ok_or_else(|| anyhow::anyhow!("Missing repository"))?;
    let repo_full_name = repository.get("full_name").and_then(|v| v.as_str()).unwrap_or("");
    let repo_parts: Vec<&str> = repo_full_name.split('/').collect();
    if repo_parts.len() != 2 {
        return Err(anyhow::anyhow!("Invalid repository name: {}", repo_full_name));
    }
    let (owner, repo) = (repo_parts[0], repo_parts[1]);

    // Get commit SHA
    let head_sha = if let Some(pr) = event.get("pull_request") {
        pr.get("head").and_then(|h| h.get("sha")).and_then(|v| v.as_str()).unwrap_or("")
    } else if let Some(head_commit) = event.get("head_commit") {
        head_commit.get("id").and_then(|v| v.as_str()).unwrap_or("")
    } else {
        return Err(anyhow::anyhow!("Cannot determine head commit SHA"));
    };

    // Post initial check run
    github_client.post_check_run(
        installation_id,
        owner,
        repo,
        head_sha,
        "in_progress",
        None,
        Some(serde_json::json!({
            "title": "Nabla Security Scan",
            "summary": "Firmware security scan in progress..."
        }))
    ).await?;

    // Clone and scan the repository
    let repo_url = repository.get("clone_url")
        .and_then(|v| v.as_str())
        .map(|url| format!("{}.git", url))
        .unwrap_or_else(|| {
            // Extract base domain from github_api_base config for GHES compatibility
            let base_url = state.config.github_api_base
                .replace("/api/v3", "")  // Remove API path
                .replace("api.", "");    // Handle api.github.com -> github.com
            format!("{}/{}.git", base_url, repo_full_name)
        });
    
    let scan_config = ScanConfiguration {
        severity_threshold: SeverityLevel::Medium,
        include_cve_data: auth_context.has_full_cve_access(),
        generate_attestation: auth_context.can_generate_attestations(),
        binary_formats: vec![BinaryFormat::ELF, BinaryFormat::PE, BinaryFormat::MachO, BinaryFormat::IntelHex],
        advanced_config: Some(nabla_core::AdvancedScanConfig {
            enable_static_analysis: auth_context.has_advanced_scanning(),
            enable_behavioral_analysis: auth_context.has_behavioral_analysis(),
            enable_crypto_analysis: true,
            enable_supply_chain_detection: auth_context.has_supply_chain_detection(),
            enable_exploitability_analysis: true,
            custom_yara_rules: auth_context.get_custom_rules(),
            max_analysis_depth: Some(10),
        }),
    };

    let mut repo_scanner = RepoScanner::new();
    match repo_scanner.clone_and_scan(&repo_url, head_sha, &scan_config).await {
        Ok(scan_result) => {
            let total_vulnerabilities: usize = scan_result.scan_results.iter()
                .map(|r| r.vulnerabilities.len())
                .sum();
            
            let total_checks_failed: usize = scan_result.scan_results.iter()
                .map(|r| r.checks.iter().filter(|c| matches!(c.status, nabla_core::CheckStatus::Fail)).count())
                .sum();

            let source_vulnerabilities = scan_result.source_analysis.vulnerabilities.len();

            let (conclusion, summary) = if total_vulnerabilities > 0 || total_checks_failed > 0 || source_vulnerabilities > 0 {
                ("failure", format!(
                    "Security scan found issues:\n• {} binary vulnerabilities\n• {} failed security checks\n• {} source code issues\n• {} builds completed\n• {} source files analyzed",
                    total_vulnerabilities,
                    total_checks_failed,
                    source_vulnerabilities,
                    scan_result.build_results.iter().filter(|b| b.success).count(),
                    scan_result.repository_info.source_files
                ))
            } else {
                ("success", format!(
                    "Security scan completed successfully:\n• No vulnerabilities found\n• All security checks passed\n• {} builds completed\n• {} source files analyzed",
                    scan_result.build_results.iter().filter(|b| b.success).count(),
                    scan_result.repository_info.source_files
                ))
            };

            // Post detailed results
            github_client.post_check_run(
                installation_id,
                owner,
                repo,
                head_sha,
                "completed",
                Some(conclusion),
                Some(serde_json::json!({
                    "title": "Nabla Security Scan",
                    "summary": summary,
                    "text": format!("## Repository Analysis\n- **Total files**: {}\n- **Source files**: {}\n- **Binary files**: {}\n\n## Build Results\n{}\n\n## Security Analysis\n- **Binary scans**: {}\n- **Source analysis**: {} potential issues found",
                        scan_result.repository_info.total_files,
                        scan_result.repository_info.source_files,
                        scan_result.repository_info.binary_files,
                        scan_result.build_results.iter()
                            .map(|b| format!("- {:?}: {}", b.build_system, if b.success { "✅ Success" } else { "❌ Failed" }))
                            .collect::<Vec<_>>()
                            .join("\n"),
                        scan_result.scan_results.len(),
                        source_vulnerabilities
                    )
                }))
            ).await?;

            tracing::info!("Scan completed for {}/{}: {} vulnerabilities, {} builds", 
                owner, repo, total_vulnerabilities, scan_result.build_results.len());
        }
        Err(e) => {
            tracing::error!("Scan failed for {}/{}: {}", owner, repo, e);
            
            github_client.post_check_run(
                installation_id,
                owner,
                repo,
                head_sha,
                "completed",
                Some("failure"),
                Some(serde_json::json!({
                    "title": "Nabla Security Scan",
                    "summary": format!("Scan failed: {}", e),
                    "text": "The security scan encountered an error. Please check the repository structure and try again."
                }))
            ).await?;
        }
    }
    
    Ok(())
}

async fn process_stripe_event(state: AppState, event: Value) -> anyhow::Result<()> {
    let event_type = event.get("type").and_then(|v| v.as_str()).unwrap_or("");
    
    match event_type {
        "customer.subscription.created" | "customer.subscription.updated" => {
            // TODO: Update customer subscription status
        }
        "customer.subscription.deleted" | "invoice.payment_failed" => {
            // TODO: Suspend installations for this customer
        }
        _ => {}
    }

    Ok(())
}