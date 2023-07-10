use std::{
    fmt::Write as _,
    io::BufReader,
    path::PathBuf,
    process::{Command, Stdio},
};

use anyhow::{Context as _, Result};
use cargo_metadata::{Artifact, CompilerMessage, Message, Target};
use clap::Parser;

#[derive(Debug, Copy, Clone)]
pub enum Architecture {
    BpfEl,
    BpfEb,
}

impl std::str::FromStr for Architecture {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "bpfel-unknown-none" => Architecture::BpfEl,
            "bpfeb-unknown-none" => Architecture::BpfEb,
            _ => return Err("invalid target"),
        })
    }
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Architecture::BpfEl => "bpfel-unknown-none",
            Architecture::BpfEb => "bpfeb-unknown-none",
        })
    }
}

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
    /// Arguments to pass to your application
    #[clap(name = "args", last = true)]
    pub run_args: Vec<String>,
}

/// Build the project
fn build(release: bool) -> Result<Vec<(PathBuf, PathBuf)>> {
    let mut cmd = Command::new("cargo");
    cmd.args([
        "build",
        "--tests",
        "--message-format=json",
        "--package=integration-test",
    ]);
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
            Message::CompilerArtifact(Artifact {
                executable,
                target: Target { src_path, .. },
                ..
            }) => {
                if let Some(executable) = executable {
                    executables.push((src_path.into(), executable.into()));
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
            0 => Ok(executables),
            code => Err(anyhow::anyhow!(
                "{cmd:?} exited with status code {code}:\n{compiler_messages}"
            )),
        },
        None => Err(anyhow::anyhow!("{cmd:?} terminated by signal")),
    }
}

/// Build and run the project
pub fn run(opts: Options) -> Result<()> {
    let Options {
        bpf_target,
        release,
        runner,
        run_args,
    } = opts;

    let metadata = cargo_metadata::MetadataCommand::new()
        .exec()
        .context("cargo metadata")?;
    let dir = metadata
        .workspace_root
        .into_std_path_buf()
        .join("test")
        .join("integration-ebpf");

    crate::docs::exec(
        Command::new("cargo")
            .current_dir(&dir)
            .args(["+nightly", "build", "--release", "--target"])
            .arg(bpf_target.to_string())
            .args(["-Z", "build-std=core"])
            .current_dir(&dir),
    )?;

    let binaries = build(release).context("error while building userspace application")?;
    let mut args = runner.trim().split_terminator(' ');
    let runner = args.next().ok_or(anyhow::anyhow!("no first argument"))?;
    let args = args.collect::<Vec<_>>();

    let mut failures = String::new();
    for (src_path, binary) in binaries {
        let mut cmd = Command::new(runner);
        let cmd = cmd
            .args(args.iter())
            .arg(binary)
            .args(run_args.iter())
            .arg("--test-threads=1");

        println!("{} running {cmd:?}", src_path.display());

        let status = cmd
            .status()
            .with_context(|| format!("failed to run {cmd:?}"))?;
        match status.code() {
            Some(code) => match code {
                0 => {}
                code => assert_eq!(
                    writeln!(
                        &mut failures,
                        "{} exited with status code {code}",
                        src_path.display()
                    ),
                    Ok(())
                ),
            },
            None => assert_eq!(
                writeln!(&mut failures, "{} terminated by signal", src_path.display()),
                Ok(())
            ),
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("failures:\n{}", failures))
    }
}
