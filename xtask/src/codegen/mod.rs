mod aya_bpf;
pub mod getters;

use structopt::StructOpt;

#[derive(StructOpt)]
pub struct Options {
    #[structopt(subcommand)]
    command: Command,
}

#[derive(StructOpt)]
enum Command {
    #[structopt(name = "aya-bpf")]
    AyaBpf(aya_bpf::CodegenOptions),
}

pub fn codegen(opts: Options) -> Result<(), anyhow::Error> {
    use Command::*;
    match opts.command {
        AyaBpf(opts) => aya_bpf::codegen(opts),
    }
}
