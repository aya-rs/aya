mod clippy;
mod docs;
mod http;
mod public_api;
mod run;
mod ubuntu_mainline;

use std::process::Command;

use anyhow::{Context as _, Result};
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

    match command {
        Subcommand::Clippy(opts) => clippy::run(opts, workspace_root.as_std_path()),
        Subcommand::Docs => docs::docs(metadata),
        Subcommand::IntegrationTest(opts) => {
            // Integration BPF compilation consumes these headers.
            exec(Command::new("git").arg("-C").arg(workspace_root).args([
                "submodule",
                "update",
                "--init",
                "--",
                LIBBPF_DIR,
            ]))?;
            run::run(opts, workspace_root.as_std_path())
        }
        Subcommand::PublicApi(opts) => public_api::public_api(opts, metadata),
    }
}
