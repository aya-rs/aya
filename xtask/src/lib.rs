use anyhow::{anyhow, Context as _, Result};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use which::which;

pub const LIBBPF_DIR: &str = "xtask/libbpf";

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

// Create a symlink in the out directory to work around the fact that cargo ignores anything
// in `$CARGO_HOME`, which is also where `cargo install` likes to place binaries. Cargo will
// stat through the symlink and discover that the binary has changed.
//
// This was introduced in https://github.com/rust-lang/cargo/commit/99f841c.
//
// TODO(https://github.com/rust-lang/cargo/pull/12369): Remove this when the fix is available.
pub fn create_symlink_to_binary(out_dir: &Path, binary_name: &str) -> Result<PathBuf> {
    let binary = which(binary_name).unwrap();
    let symlink = out_dir.join(binary_name);
    match fs::remove_file(&symlink) {
        Ok(()) => {}
        Err(err) => {
            if err.kind() != std::io::ErrorKind::NotFound {
                return Err(err).context(format!("failed to remove symlink {}", symlink.display()));
            }
        }
    }
    std::os::unix::fs::symlink(binary, &symlink)
        .with_context(|| format!("failed to create symlink {}", symlink.display()))?;
    Ok(symlink)
}
