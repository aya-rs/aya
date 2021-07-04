mod aya;
mod aya_bpf_bindings;
mod helpers;

use std::path::PathBuf;

use structopt::StructOpt;

const SUPPORTED_ARCHS: &[Architecture] = &[
    Architecture::X86_64,
    Architecture::ARMv7,
    Architecture::AArch64,
];

#[derive(Debug, Copy, Clone)]
pub enum Architecture {
    X86_64,
    ARMv7,
    AArch64,
}

impl Architecture {
    pub fn supported() -> &'static [Architecture] {
        SUPPORTED_ARCHS
    }
}

impl std::str::FromStr for Architecture {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "x86_64" => Architecture::X86_64,
            "armv7" => Architecture::ARMv7,
            "aarch64" => Architecture::AArch64,
            _ => return Err("invalid architecture".to_owned()),
        })
    }
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Architecture::X86_64 => "x86_64",
            Architecture::ARMv7 => "armv7",
            Architecture::AArch64 => "aarch64",
        })
    }
}

#[derive(StructOpt)]
pub struct Options {
    #[structopt(long)]
    libbpf_dir: PathBuf,

    #[structopt(subcommand)]
    command: Option<Command>,
}

#[derive(StructOpt)]
enum Command {
    #[structopt(name = "aya")]
    Aya,
    #[structopt(name = "aya-bpf-bindings")]
    AyaBpfBindings,
}

pub fn codegen(opts: Options) -> Result<(), anyhow::Error> {
    use Command::*;
    match opts.command {
        Some(Aya) => aya::codegen(&opts),
        Some(AyaBpfBindings) => aya_bpf_bindings::codegen(&opts),
        None => {
            aya::codegen(&opts)?;
            aya_bpf_bindings::codegen(&opts)
        }
    }
}
