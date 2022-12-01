mod aya;
mod aya_bpf_bindings;
mod helpers;

use std::path::PathBuf;

use clap::Parser;

const SUPPORTED_ARCHS: &[Architecture] = &[
    Architecture::X86_64,
    Architecture::ARMv7,
    Architecture::AArch64,
    Architecture::RISCV64,
];

#[derive(Debug, Copy, Clone)]
pub enum Architecture {
    X86_64,
    ARMv7,
    AArch64,
    RISCV64,
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
            "riscv64" => Architecture::RISCV64,
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
            Architecture::RISCV64 => "riscv64",
        })
    }
}

#[derive(Parser)]
pub struct Options {
    #[arg(long, action)]
    libbpf_dir: PathBuf,

    // sysroot options. Default to ubuntu headers installed by the
    // libc6-dev-{arm64,armel}-cross packages.
    #[arg(long, default_value = "/usr/include/x86_64-linux-gnu", action)]
    x86_64_sysroot: PathBuf,

    #[arg(long, default_value = "/usr/aarch64-linux-gnu/include", action)]
    aarch64_sysroot: PathBuf,

    #[arg(long, default_value = "/usr/arm-linux-gnueabi/include", action)]
    armv7_sysroot: PathBuf,

    #[arg(long, default_value = "/usr/riscv64-linux-gnu/include", action)]
    riscv64_sysroot: PathBuf,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand)]
enum Command {
    #[command(name = "aya")]
    Aya,
    #[command(name = "aya-bpf-bindings")]
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
