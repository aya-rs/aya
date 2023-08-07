mod codegen;
mod docs;
mod public_api;
mod run;

use anyhow::{Context as _, Result};
use cargo_metadata::{Metadata, MetadataCommand};
use clap::Parser;
use std::process::Command;
use xtask::{exec, LIBBPF_DIR};

#[derive(Parser)]
pub struct XtaskOptions {
    #[clap(subcommand)]
    command: Subcommand,
}

#[derive(Parser)]
enum Subcommand {
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

    // Initialize the submodules.
    exec(Command::new("git").arg("-C").arg(workspace_root).args([
        "submodule",
        "update",
        "--init",
    ]))?;
    let libbpf_dir = workspace_root.join(LIBBPF_DIR);
    let libbpf_dir = libbpf_dir.as_std_path();

    match command {
        Subcommand::Codegen(opts) => codegen::codegen(opts, libbpf_dir),
        Subcommand::Docs => docs::docs(metadata),
        Subcommand::IntegrationTest(opts) => run::run(opts),
        Subcommand::PublicApi(opts) => public_api::public_api(opts, metadata),
    }
}
