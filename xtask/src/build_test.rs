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

pub fn build_test(opts: Options) -> anyhow::Result<()> {
    build_ebpf::build_ebpf(opts.ebpf_options)?;

    let mut args = ["build", "-p", "integration-test", "--verbose"]
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    if let Some(target) = opts.musl_target {
        args.push(format!("--target={target}"));
    }
    let status = Command::new("cargo")
        .args(&args)
        .status()
        .expect("failed to build bpf program");
    assert!(status.success());
    Ok(())
}
