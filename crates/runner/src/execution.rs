use nabla_core::{BuildResult, BuildSystem};
use anyhow::{Result, anyhow};
use std::path::Path;
use std::process::Stdio;
use tokio::process::Command;
use std::time::Instant;

pub async fn execute_build(path: &Path, system: BuildSystem) -> Result<BuildResult> {
    let start_time = Instant::now();
    
    let result = match system {
        BuildSystem::Cargo => build_cargo(path).await,
        BuildSystem::Makefile => build_makefile(path).await,
        BuildSystem::CMake => build_cmake(path).await,
        BuildSystem::PlatformIO => build_platformio(path).await,
        BuildSystem::ZephyrWest => build_zephyr(path).await,
        BuildSystem::STM32CubeIDE => build_stm32(path).await,
        BuildSystem::SCons => build_scons(path).await,
    };

    let duration_ms = start_time.elapsed().as_millis() as u64;

    match result {
        Ok((output_path, target_format)) => Ok(BuildResult {
            success: true,
            output_path: Some(output_path),
            target_format: Some(target_format),
            error_output: None,
            build_system: system,
            duration_ms,
        }),
        Err(error) => Ok(BuildResult {
            success: false,
            output_path: None,
            target_format: None,
            error_output: Some(error.to_string()),
            build_system: system,
            duration_ms,
        }),
    }
}

async fn build_cargo(path: &Path) -> Result<(String, String)> {
    let output = Command::new("cargo")
        .arg("build")
        .arg("--release")
        .current_dir(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    if !output.status.success() {
        return Err(anyhow!("Cargo build failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    let target_dir = path.join("target/release");
    Ok((target_dir.to_string_lossy().to_string(), "elf".to_string()))
}

async fn build_makefile(path: &Path) -> Result<(String, String)> {
    let output = Command::new("make")
        .current_dir(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    if !output.status.success() {
        return Err(anyhow!("Make build failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    Ok((path.to_string_lossy().to_string(), "bin".to_string()))
}

async fn build_cmake(path: &Path) -> Result<(String, String)> {
    let build_dir = path.join("build");
    tokio::fs::create_dir_all(&build_dir).await?;

    let configure = Command::new("cmake")
        .arg("..")
        .current_dir(&build_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    if !configure.status.success() {
        return Err(anyhow!("CMake configure failed: {}", String::from_utf8_lossy(&configure.stderr)));
    }

    let build = Command::new("cmake")
        .arg("--build")
        .arg(".")
        .current_dir(&build_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    if !build.status.success() {
        return Err(anyhow!("CMake build failed: {}", String::from_utf8_lossy(&build.stderr)));
    }

    Ok((build_dir.to_string_lossy().to_string(), "elf".to_string()))
}

async fn build_platformio(path: &Path) -> Result<(String, String)> {
    let output = Command::new("pio")
        .arg("run")
        .current_dir(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    if !output.status.success() {
        return Err(anyhow!("PlatformIO build failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    let build_dir = path.join(".pio/build");
    Ok((build_dir.to_string_lossy().to_string(), "hex".to_string()))
}

async fn build_zephyr(path: &Path) -> Result<(String, String)> {
    let output = Command::new("west")
        .arg("build")
        .current_dir(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    if !output.status.success() {
        return Err(anyhow!("Zephyr build failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    let build_dir = path.join("build/zephyr");
    Ok((build_dir.to_string_lossy().to_string(), "elf".to_string()))
}

async fn build_stm32(path: &Path) -> Result<(String, String)> {
    return Err(anyhow!("STM32CubeIDE build not implemented - requires IDE integration"));
}

async fn build_scons(path: &Path) -> Result<(String, String)> {
    let output = Command::new("scons")
        .current_dir(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    if !output.status.success() {
        return Err(anyhow!("SCons build failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    Ok((path.to_string_lossy().to_string(), "bin".to_string()))
}