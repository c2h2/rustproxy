use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn main() {
    // Human-readable git version, e.g. "v1.9" on a tagged build or
    // "v1.8-3-gabc1234[-dirty]" between tags. Empty when git is unavailable
    // (falls back to CARGO_PKG_VERSION at the call site).
    let describe = git(&["describe", "--tags", "--always", "--dirty"]).unwrap_or_default();

    // Build date (best-effort; empty if `date` is unavailable).
    let date = Command::new("date")
        .args(["+%Y-%m-%d"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    // Legacy combined version kept for compatibility.
    let commit_count = git(&["rev-list", "--count", "HEAD"]).unwrap_or_else(|| "0".to_string());
    println!("cargo:rustc-env=RUSTPROXY_VERSION={}_r{}", date, commit_count);

    println!("cargo:rustc-env=RUSTPROXY_GIT={}", describe);
    println!("cargo:rustc-env=RUSTPROXY_BUILD_DATE={}", date);

    // Rerun when git state changes
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");
}
