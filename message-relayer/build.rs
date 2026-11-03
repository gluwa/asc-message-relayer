//! Embeds the git commit the binary was built from as `RELAYER_GIT_COMMIT`, so outbound requests
//! (see `proofgen::user_agent`) can identify the exact build.
//!
//! Resolution order:
//!   1. the `GIT_COMMIT` environment variable — what the Docker build passes in, because
//!      `.dockerignore` excludes `.git/` and `git rev-parse` cannot work inside the image build;
//!   2. `git rev-parse --short=12 HEAD` in a checkout;
//!   3. `unknown` (a source tarball, or a build without git on the PATH).
//!
//! The build never fails over this: a missing commit degrades the User-Agent, not the relayer.

use std::path::Path;
use std::process::Command;

/// Short enough to read in a log line, long enough to be unambiguous for this repo.
const SHORT_LEN: usize = 12;

fn main() {
    println!("cargo:rerun-if-env-changed=GIT_COMMIT");
    // Re-run when HEAD moves so a local `cargo build` after a commit picks up the new hash. The
    // path is only registered when it exists: a missing `rerun-if-changed` path re-runs the
    // script on every build.
    for head in ["../.git/HEAD", "../.git/refs/heads"] {
        if Path::new(head).exists() {
            println!("cargo:rerun-if-changed={head}");
        }
    }

    let commit = commit_from_env()
        .or_else(commit_from_git)
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=RELAYER_GIT_COMMIT={commit}");
}

fn commit_from_env() -> Option<String> {
    let raw = std::env::var("GIT_COMMIT").ok()?;
    let raw = raw.trim();
    if raw.is_empty() || !raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(raw.chars().take(SHORT_LEN).collect())
}

fn commit_from_git() -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", &format!("--short={SHORT_LEN}"), "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let sha = String::from_utf8(out.stdout).ok()?;
    let sha = sha.trim();
    (!sha.is_empty()).then(|| sha.to_string())
}
