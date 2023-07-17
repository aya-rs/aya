mod codegen;
mod docs;
mod libbpf;
mod run;

use clap::Parser;

#[derive(Parser)]
pub struct XtaskOptions {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser)]
enum Command {
    Codegen(codegen::Options),
    Docs,
    BuildIntegrationTest(run::BuildOptions),
    IntegrationTest(run::Options),
}

fn main() -> anyhow::Result<()> {
    let XtaskOptions { command } = Parser::parse();

    match command {
        Command::Codegen(opts) => codegen::codegen(opts),
        Command::Docs => docs::docs(),
        Command::BuildIntegrationTest(opts) => {
            let binaries = run::build(opts)?;
            let mut stdout = std::io::stdout();
            for (_name, binary) in binaries {
                use std::{io::Write as _, os::unix::ffi::OsStrExt as _};

                stdout.write_all(binary.as_os_str().as_bytes())?;
                stdout.write_all("\n".as_bytes())?;
            }
            Ok(())
        }
        Command::IntegrationTest(opts) => run::run(opts),
    }
}
