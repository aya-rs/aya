use std::{cell::OnceCell, process::Command};

use anyhow::{bail, Context as _, Result};

pub fn workspace_root() -> &'static str {
    static mut WORKSPACE_ROOT: OnceCell<String> = OnceCell::new();
    unsafe { &mut WORKSPACE_ROOT }.get_or_init(|| {
        let cmd = cargo_metadata::MetadataCommand::new();
        cmd.exec().unwrap().workspace_root.to_string()
    })
}

pub fn exec(cmd: &mut Command) -> Result<()> {
    let status = cmd
        .status()
        .with_context(|| format!("failed to run {cmd:?}"))?;
    match status.code() {
        Some(code) => match code {
            0 => Ok(()),
            code => bail!("{cmd:?} exited with code {code}"),
        },
        None => bail!("{cmd:?} terminated by signal"),
    }
}
