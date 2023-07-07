use std::{
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::Context as _;
use clap::Parser;

use crate::build_ebpf::{build_ebpf, Architecture, BuildEbpfOptions as BuildOptions};

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

/// Build the project
fn build(release: bool) -> Result<(), anyhow::Error> {
    let mut cmd = Command::new("cargo");
    cmd.arg("build").arg("-p").arg("integration-test");
    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().expect("failed to build userspace");

    match status.code() {
        Some(code) => match code {
            0 => Ok(()),
            code => Err(anyhow::anyhow!("{cmd:?} exited with status code: {code}")),
        },
        None => Err(anyhow::anyhow!("process terminated by signal")),
    }
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
    build_ebpf(BuildOptions {
        target: bpf_target,
        libbpf_dir,
    })
    .context("Error while building eBPF program")?;
    build(release).context("Error while building userspace application")?;
    // profile we are building (release or debug)
    let profile = if release { "release" } else { "debug" };
    let bin_path = Path::new("target").join(profile).join("integration-test");

    let mut args = runner.trim().split_terminator(' ');

    let mut cmd = Command::new(args.next().expect("No first argument"));
    cmd.args(args).arg(bin_path).args(run_args);

    // spawn the command
    let err = cmd.exec();

    // we shouldn't get here unless the command failed to spawn
    Err(anyhow::Error::from(err).context(format!("Failed to run `{cmd:?}`")))
}
