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
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "x86_64" => Architecture::X86_64,
            "armv7" => Architecture::ARMv7,
            "aarch64" => Architecture::AArch64,
            "riscv64" => Architecture::RISCV64,
            _ => return Err("invalid architecture"),
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

// sysroot options. Default to ubuntu headers installed by the
// libc6-dev-{arm64,armel}-cross packages.
#[derive(Parser)]
pub struct SysrootOptions {
    #[arg(long, default_value = "/usr/include/x86_64-linux-gnu", action)]
    x86_64_sysroot: PathBuf,

    #[arg(long, default_value = "/usr/aarch64-linux-gnu/include", action)]
    aarch64_sysroot: PathBuf,

    #[arg(long, default_value = "/usr/arm-linux-gnueabi/include", action)]
    armv7_sysroot: PathBuf,

    #[arg(long, default_value = "/usr/riscv64-linux-gnu/include", action)]
    riscv64_sysroot: PathBuf,
}

#[derive(Parser)]
pub struct Options {
    #[command(flatten)]
    sysroot_options: SysrootOptions,

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
    let Options {
        sysroot_options,
        command,
    } = opts;
    match command {
        Some(command) => match command {
            Command::Aya => aya::codegen(&sysroot_options),
            Command::AyaBpfBindings => aya_bpf_bindings::codegen(&sysroot_options),
        },
        None => {
            aya::codegen(&sysroot_options)?;
            aya_bpf_bindings::codegen(&sysroot_options)
        }
    }
}
