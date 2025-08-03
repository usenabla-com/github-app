use anyhow::{Result, anyhow};
use std::path::{Path, PathBuf};
use ignore::{WalkBuilder, DirEntry};
use globset::{Glob, GlobSetBuilder};
use tree_sitter::{Parser, Language, Node};
use git2::Repository;
use tempfile::TempDir;
use serde_json::Value;

use nabla_runner::{BuildRunner, FirmwareBuildRunner};
use nabla_scanner::BinaryScanner;
use nabla_core::{ScanConfiguration, ScanResult, SeverityLevel, BinaryFormat, BuildResult};

extern "C" {
    fn tree_sitter_c() -> Language;
    fn tree_sitter_rust() -> Language;
}

pub struct RepoScanner {
    temp_dir: Option<TempDir>,
    ignore_patterns: Vec<String>,
}

impl RepoScanner {
    pub fn new() -> Self {
        Self {
            temp_dir: None,
            ignore_patterns: vec![
                "*.git".to_string(),
                "node_modules".to_string(),
                "target".to_string(),
                "build".to_string(),
                ".pio".to_string(),
                "*.tmp".to_string(),
                "*.log".to_string(),
            ],
        }
    }

    pub async fn clone_and_scan(&mut self, repo_url: &str, commit_sha: &str, config: &ScanConfiguration) -> Result<RepoScanResult> {
        // Clone repository
        let repo_path = self.clone_repository(repo_url, commit_sha).await?;
        
        // Scan the repository
        self.scan_repository(&repo_path, config).await
    }

    async fn clone_repository(&mut self, repo_url: &str, commit_sha: &str) -> Result<PathBuf> {
        let temp_dir = TempDir::new()?;
        let repo_path = temp_dir.path().to_path_buf();
        
        tracing::info!("Cloning repository {} to {:?}", repo_url, repo_path);
        
        // Clone repository
        let repo = Repository::clone(repo_url, &repo_path)?;
        
        // Checkout specific commit
        let commit = repo.find_commit(git2::Oid::from_str(commit_sha)?)?;
        repo.checkout_tree(commit.tree()?.as_object(), None)?;
        repo.set_head_detached(commit.id())?;
        
        self.temp_dir = Some(temp_dir);
        Ok(repo_path)
    }

    async fn scan_repository(&self, repo_path: &Path, config: &ScanConfiguration) -> Result<RepoScanResult> {
        let mut result = RepoScanResult {
            build_results: Vec::new(),
            scan_results: Vec::new(),
            source_analysis: SourceAnalysis::default(),
            repository_info: self.analyze_repository_structure(repo_path)?,
        };

        // 1. Analyze source code structure
        result.source_analysis = self.analyze_source_code(repo_path)?;

        // 2. Detect and run builds
        result.build_results = self.detect_and_build(repo_path).await?;

        // 3. Scan any built binaries
        for build_result in &result.build_results {
            if build_result.success {
                if let Some(output_path) = &build_result.output_path {
                    let binary_files = self.find_binary_files(&PathBuf::from(output_path))?;
                    for binary_file in binary_files {
                        let scanner = BinaryScanner::new();
                        match scanner.scan_binary(&binary_file, config).await {
                            Ok(scan_result) => result.scan_results.push(scan_result),
                            Err(e) => tracing::warn!("Failed to scan binary {}: {}", binary_file.display(), e),
                        }
                    }
                }
            }
        }

        // 4. Scan any pre-existing binaries in the repo
        let repo_binaries = self.find_binary_files(repo_path)?;
        for binary_file in repo_binaries {
            let scanner = BinaryScanner::new();
            match scanner.scan_binary(&binary_file, config).await {
                Ok(scan_result) => result.scan_results.push(scan_result),
                Err(e) => tracing::warn!("Failed to scan existing binary {}: {}", binary_file.display(), e),
            }
        }

        Ok(result)
    }

    fn analyze_repository_structure(&self, repo_path: &Path) -> Result<RepositoryInfo> {
        let mut info = RepositoryInfo::default();
        
        let walker = WalkBuilder::new(repo_path)
            .hidden(false)
            .git_ignore(true)
            .build();

        for entry in walker {
            let entry = entry?;
            if entry.file_type().map_or(false, |ft| ft.is_file()) {
                if let Some(extension) = entry.path().extension().and_then(|s| s.to_str()) {
                    *info.file_types.entry(extension.to_string()).or_insert(0) += 1;
                }
                info.total_files += 1;

                // Categorize files
                match extension {
                    Some("c") | Some("h") | Some("cpp") | Some("hpp") | Some("cc") => info.source_files += 1,
                    Some("rs") => info.source_files += 1,
                    Some("py") => info.source_files += 1,
                    Some("js") | Some("ts") => info.source_files += 1,
                    Some("elf") | Some("bin") | Some("hex") | Some("exe") => info.binary_files += 1,
                    _ => {}
                }
            }
        }

        Ok(info)
    }

    fn analyze_source_code(&self, repo_path: &Path) -> Result<SourceAnalysis> {
        let mut analysis = SourceAnalysis::default();
        
        // Build glob patterns for source files
        let mut glob_builder = GlobSetBuilder::new();
        glob_builder.add(Glob::new("**/*.c")?);
        glob_builder.add(Glob::new("**/*.h")?);
        glob_builder.add(Glob::new("**/*.cpp")?);
        glob_builder.add(Glob::new("**/*.hpp")?);
        glob_builder.add(Glob::new("**/*.rs")?);
        let glob_set = glob_builder.build()?;

        let walker = WalkBuilder::new(repo_path)
            .hidden(false)
            .git_ignore(true)
            .build();

        for entry in walker {
            let entry = entry?;
            if entry.file_type().map_or(false, |ft| ft.is_file()) {
                let path = entry.path();
                
                if glob_set.is_match(path) {
                    if let Ok(content) = std::fs::read_to_string(path) {
                        analysis.total_lines += content.lines().count();
                        
                        // Analyze with tree-sitter if it's C/C++ or Rust
                        if let Some(extension) = path.extension().and_then(|s| s.to_str()) {
                            match extension {
                                "c" | "h" | "cpp" | "hpp" => {
                                    if let Ok(c_analysis) = self.analyze_c_code(&content) {
                                        analysis.functions.extend(c_analysis.functions);
                                        analysis.vulnerabilities.extend(c_analysis.vulnerabilities);
                                    }
                                }
                                "rs" => {
                                    if let Ok(rust_analysis) = self.analyze_rust_code(&content) {
                                        analysis.functions.extend(rust_analysis.functions);
                                        analysis.vulnerabilities.extend(rust_analysis.vulnerabilities);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        Ok(analysis)
    }

    fn analyze_c_code(&self, source: &str) -> Result<CodeAnalysis> {
        let mut parser = Parser::new();
        let language = unsafe { tree_sitter_c() };
        parser.set_language(language)?;

        let tree = parser.parse(source, None).ok_or_else(|| anyhow!("Failed to parse C code"))?;
        let root_node = tree.root_node();

        let mut analysis = CodeAnalysis::default();
        self.walk_tree_for_analysis(&root_node, source, &mut analysis);

        Ok(analysis)
    }

    fn analyze_rust_code(&self, source: &str) -> Result<CodeAnalysis> {
        let mut parser = Parser::new();
        let language = unsafe { tree_sitter_rust() };
        parser.set_language(language)?;

        let tree = parser.parse(source, None).ok_or_else(|| anyhow!("Failed to parse Rust code"))?;
        let root_node = tree.root_node();

        let mut analysis = CodeAnalysis::default();
        self.walk_tree_for_analysis(&root_node, source, &mut analysis);

        Ok(analysis)
    }

    fn walk_tree_for_analysis(&self, node: &Node, source: &str, analysis: &mut CodeAnalysis) {
        let node_type = node.kind();
        
        match node_type {
            "function_definition" | "function_item" => {
                if let Ok(function_text) = node.utf8_text(source.as_bytes()) {
                    if let Some(name) = self.extract_function_name(node, source) {
                        analysis.functions.push(FunctionInfo {
                            name: name.to_string(),
                            line_start: node.start_position().row + 1,
                            line_end: node.end_position().row + 1,
                            is_unsafe: function_text.contains("unsafe"),
                        });

                        // Check for potentially dangerous functions
                        if self.is_dangerous_function(&name) {
                            analysis.vulnerabilities.push(PotentialVulnerability {
                                severity: "medium".to_string(),
                                description: format!("Use of potentially dangerous function: {}", name),
                                line: node.start_position().row + 1,
                                function: Some(name.to_string()),
                            });
                        }
                    }
                }
            }
            "call_expression" => {
                if let Some(function_name) = self.extract_call_name(node, source) {
                    if self.is_dangerous_function(&function_name) {
                        analysis.vulnerabilities.push(PotentialVulnerability {
                            severity: "high".to_string(),
                            description: format!("Call to dangerous function: {}", function_name),
                            line: node.start_position().row + 1,
                            function: None,
                        });
                    }
                }
            }
            _ => {}
        }

        // Recursively analyze child nodes
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.walk_tree_for_analysis(&child, source, analysis);
            }
        }
    }

    fn extract_function_name(&self, node: &Node, source: &str) -> Option<&str> {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "identifier" {
                    return child.utf8_text(source.as_bytes()).ok();
                }
            }
        }
        None
    }

    fn extract_call_name(&self, node: &Node, source: &str) -> Option<String> {
        if let Some(function_node) = node.child_by_field_name("function") {
            if let Ok(name) = function_node.utf8_text(source.as_bytes()) {
                return Some(name.to_string());
            }
        }
        None
    }

    fn is_dangerous_function(&self, name: &str) -> bool {
        matches!(name, 
            "strcpy" | "strcat" | "sprintf" | "gets" | "scanf" | 
            "memcpy" | "memmove" | "memset" | "free" | "malloc" |
            "system" | "exec" | "eval"
        )
    }

    async fn detect_and_build(&self, repo_path: &Path) -> Result<Vec<BuildResult>> {
        let runner = FirmwareBuildRunner::new();
        let mut build_results = Vec::new();

        // Check for multiple build systems in subdirectories
        let walker = WalkBuilder::new(repo_path)
            .max_depth(Some(3))
            .hidden(false)
            .git_ignore(true)
            .build();

        let mut checked_dirs = std::collections::HashSet::new();

        for entry in walker {
            let entry = entry?;
            if entry.file_type().map_or(false, |ft| ft.is_dir()) {
                let dir_path = entry.path();
                
                if checked_dirs.contains(dir_path) {
                    continue;
                }
                checked_dirs.insert(dir_path.to_path_buf());

                if let Some(build_system) = runner.detect(dir_path).await {
                    tracing::info!("Found build system {:?} in {:?}", build_system, dir_path);
                    
                    match runner.build(dir_path, build_system.clone()).await {
                        Ok(result) => {
                            tracing::info!("Build result for {:?}: success={}", dir_path, result.success);
                            build_results.push(result);
                        }
                        Err(e) => {
                            tracing::warn!("Build failed for {:?}: {}", dir_path, e);
                            build_results.push(BuildResult {
                                success: false,
                                output_path: None,
                                target_format: None,
                                error_output: Some(e.to_string()),
                                build_system,
                                duration_ms: 0,
                            });
                        }
                    }
                }
            }
        }

        Ok(build_results)
    }

    fn find_binary_files(&self, dir: &Path) -> Result<Vec<PathBuf>> {
        let mut binary_files = Vec::new();
        
        let walker = WalkBuilder::new(dir)
            .hidden(false)
            .git_ignore(true)
            .build();

        for entry in walker {
            let entry = entry?;
            if entry.file_type().map_or(false, |ft| ft.is_file()) {
                let path = entry.path();
                if self.is_binary_file(path) {
                    binary_files.push(path.to_path_buf());
                }
            }
        }

        Ok(binary_files)
    }

    fn is_binary_file(&self, path: &Path) -> bool {
        if let Some(extension) = path.extension().and_then(|s| s.to_str()) {
            matches!(extension, "elf" | "bin" | "hex" | "exe" | "dll" | "so" | "dylib")
        } else {
            // Check if file has no extension and might be an ELF binary
            if let Ok(content) = std::fs::read(path) {
                content.starts_with(&[0x7f, b'E', b'L', b'F']) // ELF magic number
            } else {
                false
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RepoScanResult {
    pub build_results: Vec<BuildResult>,
    pub scan_results: Vec<ScanResult>,
    pub source_analysis: SourceAnalysis,
    pub repository_info: RepositoryInfo,
}

#[derive(Debug, Clone, Default)]
pub struct RepositoryInfo {
    pub total_files: usize,
    pub source_files: usize,
    pub binary_files: usize,
    pub file_types: std::collections::HashMap<String, usize>,
}

#[derive(Debug, Clone, Default)]
pub struct SourceAnalysis {
    pub total_lines: usize,
    pub functions: Vec<FunctionInfo>,
    pub vulnerabilities: Vec<PotentialVulnerability>,
}

#[derive(Debug, Clone, Default)]
pub struct CodeAnalysis {
    pub functions: Vec<FunctionInfo>,
    pub vulnerabilities: Vec<PotentialVulnerability>,
}

#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub line_start: usize,
    pub line_end: usize,
    pub is_unsafe: bool,
}

#[derive(Debug, Clone)]
pub struct PotentialVulnerability {
    pub severity: String,
    pub description: String,
    pub line: usize,
    pub function: Option<String>,
}