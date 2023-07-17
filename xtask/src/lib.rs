use anyhow::{anyhow, Context as _, Result};
use std::process::Command;

pub fn exec(cmd: &mut Command) -> Result<()> {
    let status = cmd
        .status()
        .with_context(|| format!("failed to run {cmd:?}"))?;
    match status.code() {
        Some(code) => match code {
            0 => Ok(()),
            code => Err(anyhow!("{cmd:?} exited with code {code}")),
        },
        None => Err(anyhow!("{cmd:?} terminated by signal")),
    }
}

pub const LIBBPF_DIR: &str = "xtask/libbpf";
