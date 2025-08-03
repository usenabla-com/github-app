use clap::{Parser, Subcommand};
use anyhow::Result;
use std::path::PathBuf;
use tracing_subscriber;
use serde_sarif::sarif::{Sarif, Run, Tool, Driver, Result as SarifResult, Rule, Message, Level, ReportingDescriptor, Location, PhysicalLocation, ArtifactLocation};

use nabla_runner::{BuildRunner, FirmwareBuildRunner};
use nabla_scanner::BinaryScanner;
use nabla_attestation::AttestationGenerator;
use nabla_core::{ScanConfiguration, SeverityLevel, BinaryFormat};

#[derive(Parser)]
#[command(name = "nabla-action")]
#[command(about = "Nabla GitHub Action CLI for firmware security scanning")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build and scan firmware
    Scan {
        /// Path to the firmware project
        #[arg(short, long, default_value = ".")]
        path: PathBuf,
        
        /// Minimum severity level to report
        #[arg(short, long, default_value = "medium")]
        severity: String,
        
        /// Generate attestation
        #[arg(long)]
        attestation: bool,
        
        /// Output format (json, sarif)
        #[arg(short, long, default_value = "json")]
        output: String,
        
        /// Output file path
        #[arg(short, long)]
        file: Option<PathBuf>,
    },
    /// Build firmware only
    Build {
        /// Path to the firmware project
        #[arg(short, long, default_value = ".")]
        path: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { path, severity, attestation, output, file } => {
            scan_command(path, severity, attestation, output, file).await?;
        }
        Commands::Build { path } => {
            build_command(path).await?;
        }
    }

    Ok(())
}

async fn scan_command(
    path: PathBuf,
    severity: String,
    generate_attestation: bool,
    output_format: String,
    output_file: Option<PathBuf>,
) -> Result<()> {
    println!("🔍 Starting Nabla firmware scan...");

    // 1. Build firmware
    let runner = FirmwareBuildRunner::new();
    
    if let Some(build_system) = runner.detect(&path).await {
        println!("📦 Detected build system: {:?}", build_system);
        
        let build_result = runner.build(&path, build_system).await?;
        
        if !build_result.success {
            anyhow::bail!("Build failed: {}", build_result.error_output.unwrap_or_default());
        }
        
        println!("✅ Build completed successfully");
        
        if let Some(output_path) = &build_result.output_path {
            // 2. Scan built firmware
            let scanner = BinaryScanner::new();
            let config = ScanConfiguration {
                severity_threshold: parse_severity(&severity)?,
                include_cve_data: true,
                generate_attestation,
                binary_formats: vec![BinaryFormat::ELF, BinaryFormat::PE, BinaryFormat::MachO],
            };

            // Find binary files in output directory
            let binary_files = find_binary_files(&PathBuf::from(output_path)).await?;
            let mut all_scan_results = Vec::new();
            
            for binary_file in binary_files {
                println!("🔍 Scanning binary: {}", binary_file.display());
                
                let scan_result = scanner.scan_binary(&binary_file, &config).await?;
                
                println!("📊 Found {} vulnerabilities, {} security checks", 
                    scan_result.vulnerabilities.len(),
                    scan_result.checks.len()
                );

                all_scan_results.push(scan_result);

                // Generate attestation if requested
                if generate_attestation {
                    let scan_result = &all_scan_results[all_scan_results.len() - 1];
                    generate_attestation_for_scan(scan_result, &binary_file).await?;
                }
            }

            // Output results
            let output_data = match output_format.as_str() {
                "json" => serde_json::to_string_pretty(&all_scan_results)?,
                "sarif" => convert_to_sarif(&all_scan_results)?,
                _ => anyhow::bail!("Unsupported output format: {}", output_format),
            };

            if let Some(output_file) = &output_file {
                tokio::fs::write(output_file, &output_data).await?;
                println!("📄 Results written to: {}", output_file.display());
            } else {
                println!("{}", output_data);
            }
        }
    } else {
        anyhow::bail!("No supported build system detected in {}", path.display());
    }

    println!("✅ Scan completed");
    Ok(())
}

async fn build_command(path: PathBuf) -> Result<()> {
    println!("🔨 Building firmware...");
    
    let runner = FirmwareBuildRunner::new();
    
    if let Some(build_system) = runner.detect(&path).await {
        println!("📦 Detected build system: {:?}", build_system);
        
        let build_result = runner.build(&path, build_system).await?;
        
        if build_result.success {
            println!("✅ Build completed successfully");
            if let Some(output_path) = &build_result.output_path {
                println!("📂 Output: {}", output_path);
            }
        } else {
            anyhow::bail!("Build failed: {}", build_result.error_output.unwrap_or_default());
        }
    } else {
        anyhow::bail!("No supported build system detected in {}", path.display());
    }

    Ok(())
}

fn parse_severity(severity: &str) -> Result<SeverityLevel> {
    match severity.to_lowercase().as_str() {
        "low" => Ok(SeverityLevel::Low),
        "medium" => Ok(SeverityLevel::Medium),
        "high" => Ok(SeverityLevel::High),
        "critical" => Ok(SeverityLevel::Critical),
        _ => anyhow::bail!("Invalid severity level: {}", severity),
    }
}

async fn find_binary_files(dir: &PathBuf) -> Result<Vec<PathBuf>> {
    let mut binary_files = Vec::new();
    
    if dir.is_file() {
        if is_binary_file(dir) {
            binary_files.push(dir.clone());
        }
        return Ok(binary_files);
    }

    let mut entries = tokio::fs::read_dir(dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.is_file() && is_binary_file(&path) {
            binary_files.push(path);
        } else if path.is_dir() {
            let mut sub_files = find_binary_files(&path).await?;
            binary_files.append(&mut sub_files);
        }
    }

    Ok(binary_files)
}

fn is_binary_file(path: &PathBuf) -> bool {
    if let Some(extension) = path.extension().and_then(|s| s.to_str()) {
        matches!(extension, "elf" | "bin" | "hex" | "exe" | "dll" | "so" | "dylib")
    } else {
        // Check if file has no extension (common for ELF files)
        path.file_name()
            .and_then(|s| s.to_str())
            .map(|s| !s.contains('.'))
            .unwrap_or(false)
    }
}

fn convert_to_sarif(scan_results: &[nabla_core::ScanResult]) -> Result<String> {
    let mut sarif_results = Vec::new();
    let mut rules = Vec::new();

    for scan_result in scan_results {
        // Convert vulnerabilities to SARIF results
        for vuln in &scan_result.vulnerabilities {
            let rule_id = format!("nabla-{}", vuln.id);
            
            // Add rule if not already present
            if !rules.iter().any(|r: &ReportingDescriptor| r.id == rule_id) {
                rules.push(ReportingDescriptor {
                    id: rule_id.clone(),
                    name: Some(vuln.title.clone()),
                    short_description: Some(Message {
                        text: vuln.title.clone(),
                        ..Default::default()
                    }),
                    full_description: Some(Message {
                        text: vuln.description.clone(),
                        ..Default::default()
                    }),
                    ..Default::default()
                });
            }

            let level = match vuln.severity {
                SeverityLevel::Low => Level::Note,
                SeverityLevel::Medium => Level::Warning,
                SeverityLevel::High => Level::Error,
                SeverityLevel::Critical => Level::Error,
            };

            sarif_results.push(SarifResult {
                rule_id: Some(rule_id),
                level: Some(level),
                message: Message {
                    text: format!("{}: {}", vuln.title, vuln.description),
                    ..Default::default()
                },
                locations: Some(vec![Location {
                    physical_location: Some(PhysicalLocation {
                        artifact_location: Some(ArtifactLocation {
                            uri: scan_result.file_path.clone(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]),
                ..Default::default()
            });
        }

        // Convert security checks to SARIF results
        for check in &scan_result.checks {
            if matches!(check.status, nabla_core::CheckStatus::Fail) {
                let rule_id = format!("nabla-check-{}", check.check_id);
                
                if !rules.iter().any(|r: &ReportingDescriptor| r.id == rule_id) {
                    rules.push(ReportingDescriptor {
                        id: rule_id.clone(),
                        name: Some(check.name.clone()),
                        short_description: Some(Message {
                            text: check.name.clone(),
                            ..Default::default()
                        }),
                        full_description: Some(Message {
                            text: check.description.clone(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    });
                }

                let level = if let Some(severity) = &check.severity {
                    match severity {
                        SeverityLevel::Low => Level::Note,
                        SeverityLevel::Medium => Level::Warning,
                        SeverityLevel::High => Level::Error,
                        SeverityLevel::Critical => Level::Error,
                    }
                } else {
                    Level::Warning
                };

                sarif_results.push(SarifResult {
                    rule_id: Some(rule_id),
                    level: Some(level),
                    message: Message {
                        text: format!("{}: {}", check.name, check.description),
                        ..Default::default()
                    },
                    locations: Some(vec![Location {
                        physical_location: Some(PhysicalLocation {
                            artifact_location: Some(ArtifactLocation {
                                uri: scan_result.file_path.clone(),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }]),
                    ..Default::default()
                });
            }
        }
    }

    let sarif = Sarif {
        version: "2.1.0".to_string(),
        runs: vec![Run {
            tool: Tool {
                driver: Driver {
                    name: "Nabla".to_string(),
                    version: Some("0.1.0".to_string()),
                    information_uri: Some("https://www.usenabla.com".to_string()),
                    rules: Some(rules),
                    ..Default::default()
                },
                ..Default::default()
            },
            results: Some(sarif_results),
            ..Default::default()
        }],
        ..Default::default()
    };

    Ok(serde_json::to_string_pretty(&sarif)?)
}

async fn generate_attestation_for_scan(
    scan_result: &nabla_core::ScanResult,
    binary_path: &PathBuf,
) -> Result<()> {
    println!("📜 Generating attestation...");
    
    let generator = AttestationGenerator::new();
    let file_bytes = tokio::fs::read(binary_path).await?;
    let file_name = binary_path.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");
    
    let analysis_json = serde_json::to_value(scan_result)?;
    let statement = generator.create_in_toto_statement(file_name, &file_bytes, &analysis_json);
    
    println!("📄 Attestation generated: {}", serde_json::to_string_pretty(&statement)?);
    
    Ok(())
}