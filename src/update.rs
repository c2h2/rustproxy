//! Self-update from GitHub releases (`c2h2/rustproxy`).
//!
//! `rustproxy --update` always re-downloads the latest release asset for this
//! platform and replaces the running binary in place (same behavior as
//! `scripts/install.sh`, but targeted at `std::env::current_exe()`).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// GitHub repository used for release downloads.
pub const REPO: &str = "c2h2/rustproxy";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveKind {
    TarGz,
    Zip,
}

/// Map OS/arch names (as from `std::env::consts` or uname-style) to the
/// release asset name used by CI / install.sh.
pub fn asset_for(os: &str, arch: &str) -> Result<(&'static str, ArchiveKind), String> {
    let os = os.to_ascii_lowercase();
    let arch = arch.to_ascii_lowercase();
    // Normalize common aliases.
    let arch = match arch.as_str() {
        "x86_64" | "amd64" => "x86_64",
        "aarch64" | "arm64" => "aarch64",
        other => other,
    };
    let os = match os.as_str() {
        "darwin" | "macos" => "macos",
        "linux" => "linux",
        other => other,
    };

    match (os, arch) {
        ("linux", "x86_64") => Ok(("rustproxy-linux-amd64.tar.gz", ArchiveKind::TarGz)),
        ("linux", "aarch64") => Ok(("rustproxy-linux-arm64-musl.tar.gz", ArchiveKind::TarGz)),
        ("macos", "aarch64") => Ok(("rustproxy-macos-arm64.zip", ArchiveKind::Zip)),
        _ => Err(format!(
            "unsupported platform {}/{} (need linux-amd64, linux-arm64, or macos-arm64)",
            os, arch
        )),
    }
}

fn this_platform_asset() -> Result<(&'static str, ArchiveKind), String> {
    asset_for(env::consts::OS, env::consts::ARCH)
}

/// Latest release download URL for this platform (always "latest", never pinned).
pub fn latest_download_url(asset: &str) -> String {
    format!(
        "https://github.com/{}/releases/latest/download/{}",
        REPO, asset
    )
}

/// Best-effort tag of the latest GitHub release (e.g. `v1.11`). Empty on failure.
pub fn fetch_latest_tag() -> Option<String> {
    let api = format!("https://api.github.com/repos/{}/releases/latest", REPO);
    let body = http_get_string(&api).ok()?;
    // Tiny JSON scrape: `"tag_name": "v1.11"`
    let key = "\"tag_name\"";
    let idx = body.find(key)?;
    let rest = &body[idx + key.len()..];
    let start = rest.find('"')? + 1;
    let rest = &rest[start..];
    let end = rest.find('"')?;
    let tag = rest[..end].trim();
    if tag.is_empty() {
        None
    } else {
        Some(tag.to_string())
    }
}

fn http_get_to_file(url: &str, dest: &Path) -> Result<(), String> {
    if let Ok(curl) = which("curl") {
        let status = Command::new(curl)
            .args([
                "-fL",
                "--progress-bar",
                "-A",
                "rustproxy-update",
                "-o",
            ])
            .arg(dest)
            .arg(url)
            .status()
            .map_err(|e| format!("failed to run curl: {}", e))?;
        if status.success() {
            return Ok(());
        }
        return Err(format!("curl failed downloading {} (status {})", url, status));
    }
    if let Ok(wget) = which("wget") {
        let status = Command::new(wget)
            .args(["-q", "--show-progress", "-O"])
            .arg(dest)
            .arg(url)
            .status()
            .map_err(|e| format!("failed to run wget: {}", e))?;
        if status.success() {
            return Ok(());
        }
        return Err(format!("wget failed downloading {} (status {})", url, status));
    }
    Err("need curl or wget to download updates".into())
}

fn http_get_string(url: &str) -> Result<String, String> {
    if let Ok(curl) = which("curl") {
        let out = Command::new(curl)
            .args(["-fsSL", "-A", "rustproxy-update", url])
            .output()
            .map_err(|e| format!("curl: {}", e))?;
        if !out.status.success() {
            return Err(format!("curl HTTP failed for {}", url));
        }
        return String::from_utf8(out.stdout).map_err(|e| e.to_string());
    }
    if let Ok(wget) = which("wget") {
        let out = Command::new(wget)
            .args(["-qO-", url])
            .output()
            .map_err(|e| format!("wget: {}", e))?;
        if !out.status.success() {
            return Err(format!("wget HTTP failed for {}", url));
        }
        return String::from_utf8(out.stdout).map_err(|e| e.to_string());
    }
    Err("need curl or wget".into())
}

fn which(bin: &str) -> Result<PathBuf, ()> {
    if let Ok(p) = env::var("PATH") {
        for dir in env::split_paths(&p) {
            let candidate = dir.join(bin);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(())
}

fn extract_binary(archive: &Path, kind: ArchiveKind, out_dir: &Path) -> Result<PathBuf, String> {
    match kind {
        ArchiveKind::TarGz => {
            let status = Command::new("tar")
                .args(["-xzf"])
                .arg(archive)
                .arg("-C")
                .arg(out_dir)
                .status()
                .map_err(|e| format!("failed to run tar: {}", e))?;
            if !status.success() {
                return Err(format!("tar extract failed: {}", status));
            }
        }
        ArchiveKind::Zip => {
            if which("unzip").is_err() {
                return Err("unzip required to extract macOS release archive".into());
            }
            let status = Command::new("unzip")
                .args(["-qo"])
                .arg(archive)
                .arg("-d")
                .arg(out_dir)
                .status()
                .map_err(|e| format!("failed to run unzip: {}", e))?;
            if !status.success() {
                return Err(format!("unzip extract failed: {}", status));
            }
        }
    }

    let candidate = out_dir.join("rustproxy");
    if candidate.is_file() {
        return Ok(candidate);
    }
    // Some archives may nest; search one level.
    if let Ok(entries) = fs::read_dir(out_dir) {
        for ent in entries.flatten() {
            let p = ent.path();
            if p.is_file() && p.file_name().and_then(|n| n.to_str()) == Some("rustproxy") {
                return Ok(p);
            }
            if p.is_dir() {
                let nested = p.join("rustproxy");
                if nested.is_file() {
                    return Ok(nested);
                }
            }
        }
    }
    Err("archive did not contain a rustproxy binary".into())
}

fn replace_exe(new_bin: &Path, target: &Path) -> Result<(), String> {
    let parent = target
        .parent()
        .ok_or_else(|| format!("cannot determine parent of {}", target.display()))?;
    // Write temp sibling so rename stays on the same filesystem.
    let tmp = parent.join(format!(
        ".rustproxy.update.{}.tmp",
        std::process::id()
    ));
    if tmp.exists() {
        let _ = fs::remove_file(&tmp);
    }
    fs::copy(new_bin, &tmp).map_err(|e| {
        format!(
            "failed to stage update next to {} (permission?): {}",
            target.display(),
            e
        )
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod failed: {}", e))?;
    }

    // Rename over the live binary. On Unix the running process keeps the old
    // inode; the path now points at the new file for subsequent launches.
    fs::rename(&tmp, target).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!(
            "failed to replace {} (try installing to a writable path): {}",
            target.display(),
            e
        )
    })?;
    Ok(())
}

/// Always re-download the latest GitHub release and replace the current binary.
pub fn run_update() -> Result<(), String> {
    let current = env::current_exe().map_err(|e| format!("current_exe: {}", e))?;
    // Resolve symlinks so we replace the real file (e.g. /usr/local/bin/rustproxy).
    let current = fs::canonicalize(&current).unwrap_or(current);

    let (asset, kind) = this_platform_asset()?;
    let url = latest_download_url(asset);
    let remote_tag = fetch_latest_tag();
    let local = env!("CARGO_PKG_VERSION");

    println!("rustproxy: self-update from https://github.com/{}", REPO);
    println!("  local version : {}", local);
    if let Some(ref tag) = remote_tag {
        println!("  remote latest : {}", tag);
    } else {
        println!("  remote latest : (unknown — will download /latest anyway)");
    }
    println!("  binary        : {}", current.display());
    println!("  asset         : {}", asset);
    println!("  url           : {}", url);
    println!("  mode          : always re-download (no skip)");

    let tmp_dir = env::temp_dir().join(format!("rustproxy-update-{}", std::process::id()));
    if tmp_dir.exists() {
        let _ = fs::remove_dir_all(&tmp_dir);
    }
    fs::create_dir_all(&tmp_dir).map_err(|e| format!("tmpdir: {}", e))?;

    let archive_path = tmp_dir.join(asset);
    println!("rustproxy: downloading…");
    let dl = http_get_to_file(&url, &archive_path);
    if let Err(e) = dl {
        let _ = fs::remove_dir_all(&tmp_dir);
        return Err(e);
    }

    println!("rustproxy: extracting…");
    let extracted = match extract_binary(&archive_path, kind, &tmp_dir) {
        Ok(p) => p,
        Err(e) => {
            let _ = fs::remove_dir_all(&tmp_dir);
            return Err(e);
        }
    };

    println!("rustproxy: installing → {}", current.display());
    let result = replace_exe(&extracted, &current);
    let _ = fs::remove_dir_all(&tmp_dir);
    result?;

    println!(
        "rustproxy: updated successfully{}",
        remote_tag
            .as_ref()
            .map(|t| format!(" (latest release {})", t))
            .unwrap_or_default()
    );
    println!(
        "rustproxy: run `{} --version` to confirm the new build",
        current.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_for_linux_amd64() {
        let (a, k) = asset_for("linux", "x86_64").unwrap();
        assert_eq!(a, "rustproxy-linux-amd64.tar.gz");
        assert_eq!(k, ArchiveKind::TarGz);
        let (a, _) = asset_for("Linux", "amd64").unwrap();
        assert_eq!(a, "rustproxy-linux-amd64.tar.gz");
    }

    #[test]
    fn asset_for_linux_arm64_prefers_musl() {
        // install.sh uses musl for portable ARM64 — match that.
        let (a, k) = asset_for("linux", "aarch64").unwrap();
        assert_eq!(a, "rustproxy-linux-arm64-musl.tar.gz");
        assert_eq!(k, ArchiveKind::TarGz);
        let (a, _) = asset_for("linux", "arm64").unwrap();
        assert_eq!(a, "rustproxy-linux-arm64-musl.tar.gz");
    }

    #[test]
    fn asset_for_macos_arm64() {
        let (a, k) = asset_for("macos", "aarch64").unwrap();
        assert_eq!(a, "rustproxy-macos-arm64.zip");
        assert_eq!(k, ArchiveKind::Zip);
        let (a, _) = asset_for("darwin", "arm64").unwrap();
        assert_eq!(a, "rustproxy-macos-arm64.zip");
    }

    #[test]
    fn asset_for_unsupported() {
        assert!(asset_for("windows", "x86_64").is_err());
        assert!(asset_for("linux", "riscv64").is_err());
    }

    #[test]
    fn latest_download_url_points_at_github_latest() {
        let u = latest_download_url("rustproxy-macos-arm64.zip");
        assert_eq!(
            u,
            "https://github.com/c2h2/rustproxy/releases/latest/download/rustproxy-macos-arm64.zip"
        );
        assert!(u.contains(REPO));
    }

    #[test]
    fn this_platform_asset_is_supported_on_ci_hosts() {
        // On the developer's machine / CI matrix hosts this must succeed.
        let r = this_platform_asset();
        assert!(
            r.is_ok(),
            "current platform must be a published release target: {:?}",
            r
        );
    }
}
