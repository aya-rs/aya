mod build_ebpf;
mod codegen;
mod docs;
mod run;
pub(crate) mod utils;

use std::process::exit;

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

fn main() {
    let XtaskOptions { command } = Parser::parse();

    let ret = match command {
        Command::Codegen(opts) => codegen::codegen(opts),
        Command::Docs => docs::docs(),
        Command::IntegrationTest(opts) => run::run(opts),
    };

    if let Err(e) = ret {
        eprintln!("{e:#}");
        exit(1);
    }
}
