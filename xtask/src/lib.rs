use anyhow::{bail, Context as _, Result};
use std::process::Command;

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
