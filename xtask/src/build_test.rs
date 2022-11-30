use clap::Parser;
use std::process::Command;

use crate::build_ebpf;

#[derive(Parser)]
pub struct Options {
    /// Whether to compile for the musl libc target
    #[clap(short, long)]
    pub musl: bool,

    #[clap(flatten)]
    pub ebpf_options: build_ebpf::BuildEbpfOptions,
}

pub fn build_test(opts: Options) -> anyhow::Result<()> {
    build_ebpf::build_ebpf(opts.ebpf_options)?;

    let mut args = vec!["build", "-p", "integration-test", "--verbose"];
    if opts.musl {
        args.push("--target=x86_64-unknown-linux-musl");
    }
    let status = Command::new("cargo")
        .args(&args)
        .status()
        .expect("failed to build bpf program");
    assert!(status.success());
    Ok(())
}
