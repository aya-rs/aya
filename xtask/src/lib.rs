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

/// Returns a [`Command`]` that Installs the libbpf headers files from the `source_dir` to the
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

#[derive(Debug)]
pub struct Errors<E>(Vec<E>);

impl<E> Errors<E> {
    pub fn new(errors: Vec<E>) -> Self {
        Self(errors)
    }
}

impl<E> std::fmt::Display for Errors<E>
where
    E: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(errors) = self;
        for (i, error) in errors.iter().enumerate() {
            if i != 0 {
                writeln!(f)?;
            }
            write!(f, "{error:?}")?;
        }
        Ok(())
    }
}

impl<E> std::error::Error for Errors<E> where E: std::fmt::Debug {}
