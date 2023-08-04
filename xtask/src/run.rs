use std::{
    ffi::OsString,
    fmt::Write as _,
    io::BufReader,
    path::PathBuf,
    process::{Child, Command, Stdio},
};

use anyhow::{anyhow, bail, Context as _, Result};
use cargo_metadata::{Artifact, CompilerMessage, Message, Target};
use clap::Parser;
use xtask::AYA_BUILD_INTEGRATION_BPF;

#[derive(Debug, Parser)]
pub struct BuildOptions {
    /// Arguments to pass to `cargo build`.
    #[clap(long)]
    pub cargo_arg: Vec<OsString>,
}

#[derive(Debug, Parser)]
pub struct Options {
    #[command(flatten)]
    pub build_options: BuildOptions,
    /// The command used to wrap your application.
    #[clap(short, long, default_value = "sudo -E")]
    pub runner: String,
    /// Arguments to pass to your application.
    #[clap(last = true)]
    pub run_args: Vec<OsString>,
}

/// Build the project
pub fn build(opts: BuildOptions) -> Result<Vec<(String, PathBuf)>> {
    let BuildOptions { cargo_arg } = opts;
    let mut cmd = Command::new("cargo");
    cmd.env(AYA_BUILD_INTEGRATION_BPF, "true")
        .args([
            "build",
            "--tests",
            "--message-format=json",
            "--package=integration-test",
        ])
        .args(cargo_arg);

    let mut child = cmd
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn {cmd:?}"))?;
    let Child { stdout, .. } = &mut child;

    let stdout = stdout.take().unwrap();
    let stdout = BufReader::new(stdout);
    let mut executables = Vec::new();
    for message in Message::parse_stream(stdout) {
        #[allow(clippy::collapsible_match)]
        match message.context("valid JSON")? {
            Message::CompilerArtifact(Artifact {
                executable,
                target: Target { name, .. },
                ..
            }) => {
                if let Some(executable) = executable {
                    executables.push((name, executable.into()));
                }
            }
            Message::CompilerMessage(CompilerMessage { message, .. }) => {
                println!("{message}");
            }
            Message::TextLine(line) => {
                println!("{line}");
            }
            _ => {}
        }
    }

    let status = child
        .wait()
        .with_context(|| format!("failed to wait for {cmd:?}"))?;
    if status.code() != Some(0) {
        bail!("{cmd:?} failed: {status:?}")
    }
    Ok(executables)
}

/// Build and run the project
pub fn run(opts: Options) -> Result<()> {
    let Options {
        build_options,
        runner,
        run_args,
    } = opts;

    let binaries = build(build_options).context("error while building userspace application")?;
    let mut args = runner.trim().split_terminator(' ');
    let runner = args.next().ok_or(anyhow!("no first argument"))?;
    let args = args.collect::<Vec<_>>();

    let mut failures = String::new();
    for (name, binary) in binaries {
        let mut cmd = Command::new(runner);
        let cmd = cmd
            .args(args.iter())
            .arg(binary)
            .args(run_args.iter())
            .arg("--test-threads=1");

        println!("{name} running {cmd:?}");

        let status = cmd
            .status()
            .with_context(|| format!("failed to run {cmd:?}"))?;
        if status.code() != Some(0) {
            writeln!(&mut failures, "{name} failed: {status:?}").context("String write failed")?
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow!("failures:\n{}", failures))
    }
}
