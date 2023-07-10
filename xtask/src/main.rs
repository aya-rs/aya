mod codegen;
mod docs;
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
    IntegrationTest(run::Options),
}

fn main() -> anyhow::Result<()> {
    let XtaskOptions { command } = Parser::parse();

    match command {
        Command::Codegen(opts) => codegen::codegen(opts),
        Command::Docs => docs::docs(),
        Command::IntegrationTest(opts) => run::run(opts),
    }
}
