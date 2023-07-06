use std::{os::unix::process::CommandExt, path::PathBuf, process::Command};

use anyhow::Context as _;
use clap::Parser;

use crate::build_ebpf::{build_ebpf, Architecture};

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
    pub libbpf_dir: String,
    /// Arguments to pass to your application
    #[clap(name = "args", last = true)]
    pub run_args: Vec<String>,
}

impl Options {
    fn build_options(&self) -> BuildOptions {
        let Self { release, .. } = self;
        BuildOptions {
            release: *release,
            target: None,
        }
    }

    fn build_ebpf_options(&self) -> crate::build_ebpf::BuildEbpfOptions {
        let Self {
            bpf_target,
            libbpf_dir,
            ..
        } = self;
        crate::build_ebpf::BuildEbpfOptions {
            target: *bpf_target,
            libbpf_dir: PathBuf::from(libbpf_dir),
        }
    }
}

/// Configures building the integration test binary.
pub struct BuildOptions {
    pub release: bool,
    pub target: Option<String>,
}

/// Build the project. Returns the path to the binary that was built.
pub fn build(opts: BuildOptions) -> Result<std::path::PathBuf, anyhow::Error> {
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

    let bin_path = format!("target/{target_path}{profile}/integration-test");
    Ok(PathBuf::from(bin_path))
}

/// Build and run the project
pub fn run(opts: Options) -> Result<(), anyhow::Error> {
    // build our ebpf program followed by our application
    build_ebpf(opts.build_ebpf_options()).context("Error while building eBPF program")?;
    let bin_path =
        build(opts.build_options()).context("Error while building userspace application")?;

    // arguments to pass to the application
    let mut run_args: Vec<_> = opts.run_args.iter().map(String::as_str).collect();

    // configure args
    let mut args: Vec<_> = opts.runner.trim().split_terminator(' ').collect();
    args.push(bin_path.to_str().expect("Invalid binary path"));
    args.append(&mut run_args);

    // spawn the command
    let err = Command::new(args.first().expect("No first argument"))
        .args(args.iter().skip(1))
        .exec();

    // we shouldn't get here unless the command failed to spawn
    Err(anyhow::Error::from(err).context(format!("Failed to run `{}`", args.join(" "))))
}
