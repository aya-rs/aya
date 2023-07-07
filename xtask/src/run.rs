use std::{
    fmt::Write as _,
    io::BufReader,
    os::unix::process::CommandExt as _,
    path::PathBuf,
    process::{Command, Stdio},
};

use anyhow::Context as _;
use cargo_metadata::{Artifact, CompilerMessage, Message};
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
fn build(release: bool) -> Result<PathBuf, anyhow::Error> {
    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .arg("--tests")
        .arg("--message-format=json")
        .arg("--package=integration-test");
    if release {
        cmd.arg("--release");
    }
    let mut cmd = cmd
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn {cmd:?}"))?;

    let reader = BufReader::new(cmd.stdout.take().unwrap());
    let mut executables = Vec::new();
    let mut compiler_messages = String::new();
    for message in Message::parse_stream(reader) {
        #[allow(clippy::collapsible_match)]
        match message.context("valid JSON")? {
            Message::CompilerArtifact(Artifact { executable, .. }) => {
                if let Some(executable) = executable {
                    executables.push(executable);
                }
            }
            Message::CompilerMessage(CompilerMessage { message, .. }) => {
                assert_eq!(writeln!(&mut compiler_messages, "{message}"), Ok(()));
            }
            _ => {}
        }
    }

    let status = cmd
        .wait()
        .with_context(|| format!("failed to wait for {cmd:?}"))?;

    match status.code() {
        Some(code) => match code {
            0 => match &*executables.into_boxed_slice() {
                [executable] => Ok(executable.into()),
                executables => Err(anyhow::anyhow!(
                    "expected one executable, found {:?}",
                    executables
                )),
            },
            code => Err(anyhow::anyhow!(
                "{cmd:?} exited with status code {code}:\n{compiler_messages}"
            )),
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

    let bin_path = build(release).context("Error while building userspace application")?;
    let mut args = runner.trim().split_terminator(' ');
    let runner = args.next().ok_or(anyhow::anyhow!("no first argument"))?;
    let mut cmd = Command::new(runner);
    cmd.args(args)
        .arg(bin_path)
        .args(run_args)
        .arg("--test-threads=1");

    // spawn the command
    let err = cmd.exec();

    // we shouldn't get here unless the command failed to spawn
    Err(anyhow::Error::from(err).context(format!("Failed to run `{cmd:?}`")))
}
