mod codegen;
mod docs;
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
    BuildIntegrationTest(run::BuildOptions),
    IntegrationTest(run::Options),
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
        Subcommand::BuildIntegrationTest(opts) => {
            let binaries = run::build(opts)?;
            let mut stdout = std::io::stdout();
            for (_name, binary) in binaries {
                use std::{io::Write as _, os::unix::ffi::OsStrExt as _};

                stdout.write_all(binary.as_os_str().as_bytes())?;
                stdout.write_all("\n".as_bytes())?;
            }
            Ok(())
        }
        Subcommand::IntegrationTest(opts) => run::run(opts),
    }
}
