use anyhow::{bail, Context as _, Result};
use clap::Parser;
use std::process::Command;

use crate::build_ebpf;

#[derive(Parser)]
pub struct Options {
    /// Target triple for which the code is compiled
    #[clap(long)]
    pub musl_target: Option<String>,

    #[clap(flatten)]
    pub ebpf_options: build_ebpf::BuildEbpfOptions,
}

pub fn build_test(opts: Options) -> Result<()> {
    let Options {
        musl_target,
        ebpf_options,
    } = opts;

    build_ebpf::build_ebpf(ebpf_options)?;

    let mut cmd = Command::new("cargo");
    cmd.args(["build", "-p", "integration-test"]);

    if let Some(target) = musl_target {
        cmd.args(["--target", &target]);
    }
    let status = cmd
        .status()
        .with_context(|| format!("Failed to run {cmd:?}"))?;
    match status.code() {
        Some(code) => match code {
            0 => Ok(()),
            code => bail!("{cmd:?} exited with code {code}"),
        },
        None => bail!("{cmd:?} terminated by signal"),
    }
}
