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

    /// The target triple to build for.
    pub target: Option<String>,
}

/// Build the project. Returns the path to the binary that was built.
pub fn build(opts: BuildOptions) -> Result<String, anyhow::Error> {
    let mut args = vec!["build"];
    if opts.release {
        args.push("--release")
    }
    args.push("-p");
    args.push("integration-test");
    let target_path = if let Some(target) = &opts.target {
        args.push("--target");
        args.push(target);
        format!("{target}/")
    } else {
        String::new()
    };
    let status = Command::new("cargo")
        .args(&args)
        .status()
        .expect("failed to build userspace");
    assert!(status.success());
    let profile = if opts.release { "release" } else { "debug" };
    Ok(format!("target/{target_path}{profile}/integration-test"))
}

/// Build and run the project
pub fn run(opts: Options) -> Result<(), anyhow::Error> {
    let Options {
        runner,
        run_args,
        bpf_target,
        libbpf_dir,
        release,
    } = opts;

    // build our ebpf program followed by our application
    build_ebpf(BuildEbpfOptions {
        target: bpf_target,
        libbpf_dir,
    })
    .context("Error while building eBPF program")?;

    let bin_path = build(BuildOptions {
        release,
        target: None,
    })
    .context("Error while building userspace application")?;

    // arguments to pass to the application
    let mut run_args: Vec<_> = run_args.iter().map(String::as_str).collect();

    // configure args
    let mut args: Vec<_> = runner.trim().split_terminator(' ').collect();
    args.push(&bin_path);
    args.append(&mut run_args);

    // spawn the command
    let err = Command::new(args.first().expect("No first argument"))
        .args(args.iter().skip(1))
        .exec();

    // we shouldn't get here unless the command failed to spawn
    Err(anyhow::Error::from(err).context(format!("Failed to run `{}`", args.join(" "))))
}
