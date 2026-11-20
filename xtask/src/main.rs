mod clippy;
mod codegen;
mod docs;
mod http;
mod public_api;
mod run;
mod ubuntu_mainline;

use anyhow::{Context as _, Result};
use cargo_metadata::MetadataCommand;
use clap::Parser;

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
            run::run(opts, metadata()?.workspace_root.as_std_path())
        }
        Subcommand::PublicApi(opts) => public_api::public_api(opts, metadata()?),
    }
}
