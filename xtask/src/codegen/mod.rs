mod aya_bpf_bindings;
mod helpers;

use structopt::StructOpt;

#[derive(Debug, Copy, Clone)]
pub enum Architecture {
    X86_64,
    AArch64,
}

impl std::str::FromStr for Architecture {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "x86_64" => Architecture::X86_64,
            "aarch64" => Architecture::AArch64,
            _ => return Err("invalid architecture".to_owned()),
        })
    }
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Architecture::X86_64 => "x86_64",
            Architecture::AArch64 => "aarch64",
        })
    }
}

#[derive(StructOpt)]
pub struct Options {
    #[structopt(subcommand)]
    command: Command,
}

#[derive(StructOpt)]
enum Command {
    #[structopt(name = "aya-bpf-bindings")]
    AyaBpfBindings(aya_bpf_bindings::CodegenOptions),
}

pub fn codegen(opts: Options) -> Result<(), anyhow::Error> {
    use Command::*;
    match opts.command {
        AyaBpfBindings(opts) => aya_bpf_bindings::codegen(opts),
    }
}
