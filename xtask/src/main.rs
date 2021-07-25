mod codegen;
mod examples;

use std::process::exit;

use structopt::StructOpt;
#[derive(StructOpt)]
pub struct Options {
    #[structopt(subcommand)]
    command: Command,
}

#[derive(StructOpt)]
enum Command {
    Codegen(codegen::Options),
    Examples(examples::Options),
}

fn main() {
    let opts = Options::from_args();

    use Command::*;
    let ret = match opts.command {
        Codegen(opts) => codegen::codegen(opts),
        Examples(opts) => examples::examples(opts),
    };

    if let Err(e) = ret {
        eprintln!("{:#}", e);
        exit(1);
    }
}
