use std::{
    fmt::Write as _,
    io::BufReader,
    path::PathBuf,
    process::{Child, Command, Stdio},
};

use anyhow::{bail, Context as _, Result};
use cargo_metadata::{Artifact, CompilerMessage, Message, Target};
use clap::Parser;

#[derive(Debug, Parser)]
pub struct BuildOptions {
    /// Pass --release to `cargo build`.
    #[clap(long)]
    pub release: bool,
    /// Pass --target to `cargo build`.
    #[clap(long)]
    pub target: Option<String>,
}

#[derive(Debug, Parser)]
pub struct Options {
    #[command(flatten)]
    pub build_options: BuildOptions,
    /// The command used to wrap your application.
    #[clap(short, long, default_value = "sudo -E")]
    pub runner: String,
    /// Arguments to pass to your application.
    #[clap(name = "args", last = true)]
    pub run_args: Vec<String>,
}

/// Build the project
pub fn build(opts: BuildOptions) -> Result<Vec<(String, PathBuf)>> {
    let BuildOptions { release, target } = opts;
    let mut cmd = Command::new("cargo");
    cmd.env("AYA_BUILD_INTEGRATION_BPF", "true").args([
        "build",
        "--tests",
        "--message-format=json",
        "--package=integration-test",
    ]);
    if release {
        cmd.arg("--release");
    }
    if let Some(target) = target {
        cmd.args(["--target", &target]);
    }

    let mut child = cmd
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn {cmd:?}"))?;
    let Child { stdout, .. } = &mut child;

    // Infallible because we passed Stdio::piped().
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
    match status.code() {
        Some(code) => match code {
            0 => {}
            code => bail!("{cmd:?} exited with status code {code}"),
        },
        None => bail!("{cmd:?} terminated by signal"),
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
    let runner = args.next().ok_or(anyhow::anyhow!("no first argument"))?;
    let args = args.collect::<Vec<_>>();

    let mut failures = String::new();
    for (name, binary) in binaries {
        let mut cmd = Command::new(runner);
        let cmd = cmd
            .args(args.iter())
            .arg(binary)
            .args(run_args.iter())
            .arg("--test-threads=1");

        println!("{} running {cmd:?}", name);

        let status = cmd
            .status()
            .with_context(|| format!("failed to run {cmd:?}"))?;
        match status.code() {
            Some(code) => match code {
                0 => {}
                code => writeln!(&mut failures, "{} exited with status code {code}", name)
                    .context("String write failed")?,
            },
            None => writeln!(&mut failures, "{} terminated by signal", name)
                .context("String write failed")?,
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("failures:\n{}", failures))
    }
}
