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
            write!(f, "{:?}", error)?;
        }
        Ok(())
    }
}

impl<E> std::error::Error for Errors<E> where E: std::fmt::Debug {}
