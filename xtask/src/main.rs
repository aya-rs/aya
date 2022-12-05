mod build_ebpf;
mod build_test;
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
    BuildIntegrationTest(build_test::Options),
    BuildIntegrationTestEbpf(build_ebpf::BuildEbpfOptions),
    IntegrationTest(run::Options),
}

fn main() {
    let opts = XtaskOptions::parse();

    use Command::*;
    let ret = match opts.command {
        Codegen(opts) => codegen::codegen(opts),
        Docs => docs::docs(),
        BuildIntegrationTest(opts) => build_test::build_test(opts),
        BuildIntegrationTestEbpf(opts) => build_ebpf::build_ebpf(opts),
        IntegrationTest(opts) => run::run(opts),
    };

    if let Err(e) = ret {
        eprintln!("{:#}", e);
        exit(1);
    }
}
