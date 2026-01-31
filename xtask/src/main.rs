mod clippy;
mod codegen;
mod docs;
mod public_api;
mod run;

use std::process::{Command, Output};

use anyhow::{Context as _, Result, bail};
use cargo_metadata::{Metadata, MetadataCommand};
use clap::Parser;
use xtask::{LIBBPF_DIR, exec};

#[derive(Parser)]
pub struct XtaskOptions {
    #[clap(subcommand)]
    command: Subcommand,
}

#[derive(Parser)]
enum Subcommand {
    Clippy(clippy::Options),
    Codegen(codegen::Options),
    Docs,
    IntegrationTest(run::Options),
    PublicApi(public_api::Options),
}

fn main() -> Result<()> {
    let XtaskOptions { command } = Parser::parse();

    let metadata = MetadataCommand::new()
        .no_deps()
        .exec()
        .context("failed to run cargo metadata")?;
    let Metadata { workspace_root, .. } = &metadata;

    let mut libbpf_submodule_status = Command::new("git");
    let output = libbpf_submodule_status
        .arg("-C")
        .arg(workspace_root)
        .arg("submodule")
        .arg("status")
        .arg(LIBBPF_DIR)
        .output()
        .with_context(|| format!("failed to run {libbpf_submodule_status:?}"))?;
    let Output { status, .. } = &output;
    if !status.success() {
        bail!("{libbpf_submodule_status:?} failed: {output:?}")
    }
    let Output { stdout, .. } = output;
    if !stdout.starts_with(b" ") {
        // Initialize the submodules.
        exec(Command::new("git").arg("-C").arg(workspace_root).args([
            "submodule",
            "update",
            "--init",
        ]))?;
    }

    let libbpf_dir = workspace_root.join(LIBBPF_DIR);
    let libbpf_dir = libbpf_dir.as_std_path();

    match command {
        Subcommand::Clippy(opts) => clippy::run(opts, workspace_root.as_std_path()),
        Subcommand::Codegen(opts) => codegen::codegen(opts, libbpf_dir),
        Subcommand::Docs => docs::docs(metadata),
        Subcommand::IntegrationTest(opts) => run::run(opts, workspace_root.as_std_path()),
        Subcommand::PublicApi(opts) => public_api::public_api(opts, metadata),
    }
}
