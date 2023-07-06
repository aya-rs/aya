use std::{os::unix::process::CommandExt, path::PathBuf, process::Command};

use anyhow::Context as _;
use clap::Parser;

use crate::build_ebpf::{build_ebpf, Architecture, BuildEbpfOptions};

#[derive(Debug, Parser)]
pub struct Options {
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub bpf_target: Architecture,
    /// Build and run the release target
    #[clap(long)]
    pub release: bool,
    /// The command used to wrap your application
    #[clap(short, long, default_value = "sudo -E")]
    pub runner: String,
    /// libbpf directory
    #[clap(long, action)]
    pub libbpf_dir: PathBuf,
    /// Arguments to pass to your application
    #[clap(name = "args", last = true)]
    pub run_args: Vec<String>,
}

/// Configures building the integration test binary.
pub struct BuildOptions {
    pub release: bool,
}

/// Build the project. Returns the path to the binary that was built.
pub fn build(opts: BuildOptions) -> Result<std::path::PathBuf, anyhow::Error> {
    let BuildOptions { release } = opts;
    let mut args = vec!["build"];
    if opts.release {
        args.push("--release")
    }
    args.push("-p");
    args.push("integration-test");
    let status = Command::new("cargo")
        .args(&args)
        .status()
        .expect("failed to build userspace");
    assert!(status.success());
    let profile = if release { "release" } else { "debug" };
    let bin_path = format!("target/{profile}/integration-test");
    Ok(PathBuf::from(bin_path))
}

/// Build and run the project
pub fn run(opts: Options) -> Result<(), anyhow::Error> {
    let Options {
        bpf_target,
        release,
        runner,
        libbpf_dir,
        run_args,
    } = opts;
    // build our ebpf program followed by our application
    build_ebpf(BuildEbpfOptions {
        target: bpf_target,
        libbpf_dir,
    })
    .context("Error while building eBPF program")?;
    let bin_path =
        build(BuildOptions { release }).context("Error while building userspace application")?;

    // arguments to pass to the application
    let mut run_args: Vec<_> = run_args.iter().map(String::as_str).collect();

    // configure args
    let mut args: Vec<_> = runner.trim().split_terminator(' ').collect();
    args.push(bin_path.to_str().expect("Invalid binary path"));
    args.append(&mut run_args);

    // spawn the command
    let err = Command::new(args.first().expect("No first argument"))
        .args(args.iter().skip(1))
        .exec();

    // we shouldn't get here unless the command failed to spawn
    Err(anyhow::Error::from(err).context(format!("Failed to run `{}`", args.join(" "))))
}
