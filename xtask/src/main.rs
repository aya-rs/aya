mod codegen;
mod docs;

use std::process::exit;

use clap::Parser;
#[derive(Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser)]
enum Command {
    Codegen(codegen::Options),
    Docs,
}

fn main() {
    let opts = Options::parse();

    use Command::*;
    let ret = match opts.command {
        Codegen(opts) => codegen::codegen(opts),
        Docs => docs::docs(),
    };

    if let Err(e) = ret {
        eprintln!("{:#}", e);
        exit(1);
    }
}
