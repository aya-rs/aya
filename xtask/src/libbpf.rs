/// Functionality for ensuring that the submodule is properly set up.
use std::{path::PathBuf, process::Command};

use anyhow::Context;

/// Ensures that the submodule is initialized and returns the path to the submodule.
pub(crate) fn ensure_initialized() -> Result<PathBuf, anyhow::Error> {
    // It's okay to hard-code this path because the submodule is checked in.
    let libbpf_dir = PathBuf::from("libbpf");
    // Exec `git submodule update --init` to ensure that the submodule is initialized.
    let status = Command::new("git")
        .args(["submodule", "update", "--init", "--"])
        .arg(&libbpf_dir)
        .status()
        .context("failed to initialized submodules")?;
    if status.success() {
        Ok(libbpf_dir)
    } else {
        Err(anyhow::anyhow!(
            "failed to initialize submodules: {status:?}"
        ))
    }
}
