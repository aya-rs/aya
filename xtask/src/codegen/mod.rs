mod aya;
mod aya_ebpf_bindings;
mod helpers;

use std::path::{Path, PathBuf};

use clap::Parser;

const SUPPORTED_ARCHS: &[Architecture] = &[
    Architecture::X86_64,
    Architecture::ARMv7,
    Architecture::AArch64,
    Architecture::RISCV64,
    Architecture::PowerPC64,
    Architecture::S390X,
];

#[derive(Debug, Copy, Clone)]
pub enum Architecture {
    X86_64,
    ARMv7,
    AArch64,
    RISCV64,
    PowerPC64,
    S390X,
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
            "powerpc64" => Architecture::PowerPC64,
            "s390x" => Architecture::S390X,
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
            Architecture::PowerPC64 => "powerpc64",
            Architecture::S390X => "s390x",
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

    #[arg(long, default_value = "/usr/powerpc64le-linux-gnu/include", action)]
    powerpc64_sysroot: PathBuf,

    #[arg(long, default_value = "/usr/s390x-linux-gnu/include", action)]
    s390x_sysroot: PathBuf,
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
    #[command(name = "aya-ebpf-bindings")]
    AyaEbpfBindings,
}

pub fn codegen(opts: Options, libbpf_dir: &Path) -> Result<(), anyhow::Error> {
    let Options {
        sysroot_options,
        command,
    } = opts;
    match command {
        Some(command) => match command {
            Command::Aya => aya::codegen(&sysroot_options, libbpf_dir),
            Command::AyaEbpfBindings => aya_ebpf_bindings::codegen(&sysroot_options, libbpf_dir),
        },
        None => {
            aya::codegen(&sysroot_options, libbpf_dir)?;
            aya_ebpf_bindings::codegen(&sysroot_options, libbpf_dir)
        }
    }
}
