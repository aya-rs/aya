mod clippy;
mod codegen;
mod docs;
mod http;
mod public_api;
mod run;
mod ubuntu_mainline;

use std::process::Command;

use anyhow::{Context as _, Result};
use cargo_metadata::MetadataCommand;
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
    Codegen(Box<codegen::Options>),
    Docs,
    IntegrationTest(run::Options),
    PublicApi(public_api::Options),
}

fn main() -> Result<()> {
    let XtaskOptions { command } = Parser::parse();

    let metadata = || {
        MetadataCommand::new()
            .no_deps()
            .exec()
            .context("failed to run cargo metadata")
    };

    match command {
        Subcommand::Clippy(opts) => clippy::run(opts, metadata()?.workspace_root.as_std_path()),
        Subcommand::Codegen(opts) => codegen::codegen(*opts),
        Subcommand::Docs => docs::docs(metadata()?),
        Subcommand::IntegrationTest(opts) => {
            let metadata = metadata()?;
            let workspace_root = metadata.workspace_root.as_std_path();
            // Integration BPF compilation consumes these headers.
            exec(Command::new("git").arg("-C").arg(workspace_root).args([
                "submodule",
                "update",
                "--init",
                "--",
                LIBBPF_DIR,
            ]))?;
            run::run(opts, workspace_root)
        }
        Subcommand::PublicApi(opts) => public_api::public_api(opts, metadata()?),
    }
}
