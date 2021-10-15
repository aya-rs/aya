mod build_ebpf;

use std::process::exit;

use structopt::StructOpt;
#[derive(StructOpt)]
pub struct Options {
    #[structopt(subcommand)]
    command: Command,
}

#[derive(StructOpt)]
enum Command {
    BuildEbpf(build_ebpf::Options),
}

fn main() {
    let opts = Options::from_args();

    use Command::*;
    let ret = match opts.command {
        BuildEbpf(opts) => build_ebpf::build(opts),
    };

    if let Err(e) = ret {
        eprintln!("{:#}", e);
        exit(1);
    }
}
