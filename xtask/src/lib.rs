#![expect(unused_crate_dependencies, reason = "used in bin")]

use std::{ffi::OsString, path::Path, process::Command};

use anyhow::{Context as _, Result, bail};

pub const AYA_BUILD_INTEGRATION_BPF: &str = "AYA_BUILD_INTEGRATION_BPF";
pub const LIBBPF_DIR: &str = "xtask/libbpf";

pub fn exec(cmd: &mut Command) -> Result<()> {
    let status = cmd
        .status()
        .with_context(|| format!("failed to run {cmd:?}"))?;
    if status.code() != Some(0) {
        bail!("{cmd:?} failed: {status:?}")
    }
    Ok(())
}

/// Returns a [`Command`] that Installs the libbpf headers files from the `source_dir` to the
/// `headers_dir`.
pub fn install_libbpf_headers_cmd(
    source_dir: impl AsRef<Path>,
    headers_dir: impl AsRef<Path>,
) -> Command {
    let mut includedir = OsString::new();
    includedir.push("INCLUDEDIR=");
    includedir.push(headers_dir.as_ref().as_os_str());

    let mut cmd = Command::new("make");
    cmd.arg("-C")
        .arg(source_dir.as_ref().join("src"))
        .arg(includedir)
        .arg("install_headers");
    cmd
}
