use nabla_core::{ScanResult, ScanConfiguration, Vulnerability, ExploitabilityAnalysis};
use anyhow::{Result, anyhow};
use std::path::Path;
use uuid::Uuid;
use chrono::Utc;
use std::time::Instant;
use tokio::fs;

// Import the functions from your nabla_cli crate
use nabla_cli::binary::analyze_binary;
use nabla_cli::binary::scanner::enterprise_scan_binary;

pub mod types;
pub use types::*;

pub struct BinaryScanner;

impl BinaryScanner {
    pub fn new() -> Self {
        Self
    }

    pub async fn scan_binary(&self, file_path: &Path, _config: &ScanConfiguration) -> Result<ScanResult> {
        let start_time = Instant::now();
        let scan_id = Uuid::new_v4();

        // 1. Read the raw binary data
        let binary_data = fs::read(file_path).await
            .map_err(|e| anyhow!("Failed to read binary file at {}: {}", file_path.display(), e))?;

        // 2. Call analyze_binary to get the detailed analysis struct
        let analysis = analyze_binary(&file_path.to_string_lossy(), &binary_data).await?;

        // 3. Call the enterprise scanner with the analysis result
        let enterprise_result = enterprise_scan_binary(&analysis);

        // 4. Build the Control Flow Graph
        let cfg_result = nabla_cli::enterprise::secure::control_flow::build_cfg(&binary_data)?;
        let control_flow_graph = serde_json::to_string_pretty(&cfg_result).ok();

        // 5. Translate the vulnerability findings
        let vulnerabilities = enterprise_result.vulnerability_findings.into_iter().map(|v| {
            Vulnerability {
                // Use the CVE ID as the primary ID if available, otherwise the title.
                id: v.cve_id.clone().unwrap_or_else(|| v.title.clone()),
                severity: nabla_core::SeverityLevel::High, // Placeholder
                title: v.title,
                description: v.description,
                cve_id: v.cve_id,
                reachability: ExploitabilityAnalysis { is_reachable: false, path: None, sink: "".to_string() },
                category: nabla_core::VulnerabilityCategory::StaticAnalysis,
            }
        }).collect();

        let scan_duration_ms = start_time.elapsed().as_millis() as u64;

        // 6. Construct the final ScanResult for this application
        Ok(ScanResult {
            scan_id,
            file_path: file_path.to_string_lossy().to_string(),
            file_hash: analysis.hash_sha256,
            vulnerabilities,
            checks: vec![],
            findings: vec![],
            control_flow_graph,
            scan_duration_ms,
            timestamp: Utc::now(),
        })
    }
}