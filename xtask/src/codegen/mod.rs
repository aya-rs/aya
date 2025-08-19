mod aya;
mod aya_ebpf_bindings;
mod helpers;

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use clap::Parser;

const SUPPORTED_ARCHS: &[Architecture] = &[
    Architecture::Mips,
    Architecture::X86_64,
    Architecture::ARMv7,
    Architecture::AArch64,
    Architecture::RISCV64,
    Architecture::PowerPC64,
    Architecture::S390X,
    Architecture::LoongArch64,
];

#[derive(Debug, Copy, Clone)]
pub enum Architecture {
    X86_64,
    ARMv7,
    AArch64,
    RISCV64,
    PowerPC64,
    S390X,
    Mips,
    LoongArch64,
}

impl Architecture {
    pub fn supported() -> &'static [Architecture] {
        SUPPORTED_ARCHS
    }

    pub fn target(&self) -> &'static str {
        match self {
            Architecture::AArch64 => "aarch64-unknown-linux-gnu",
            Architecture::ARMv7 => "armv7-unknown-linux-gnu",
            Architecture::LoongArch64 => "loongarch64-unknown-linux-gnu",
            Architecture::Mips => "mips-unknown-linux-gnu",
            Architecture::PowerPC64 => "powerpc64le-unknown-linux-gnu",
            Architecture::RISCV64 => "riscv64-unknown-linux-gnu",
            Architecture::S390X => "s390x-unknown-linux-gnu",
            Architecture::X86_64 => "x86_64-unknown-linux-gnu",
        }
    }
}

impl std::str::FromStr for Architecture {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "aarch64" => Architecture::AArch64,
            "armv7" => Architecture::ARMv7,
            "loongarch64" => Architecture::LoongArch64,
            "mips" => Architecture::Mips,
            "powerpc64" => Architecture::PowerPC64,
            "riscv64" => Architecture::RISCV64,
            "s390x" => Architecture::S390X,
            "x86_64" => Architecture::X86_64,
            _ => return Err("invalid architecture"),
        })
    }
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Architecture::AArch64 => "aarch64",
            Architecture::ARMv7 => "armv7",
            Architecture::LoongArch64 => "loongarch64",
            Architecture::Mips => "mips",
            Architecture::PowerPC64 => "powerpc64",
            Architecture::RISCV64 => "riscv64",
            Architecture::S390X => "s390x",
            Architecture::X86_64 => "x86_64",
        })
    }
}

// sysroot options. Default to ubuntu headers installed by the
// libc6-dev-{arm64,armel}-cross packages.
#[derive(Parser)]
pub struct SysrootOptions {
    #[arg(long, default_value = "/usr/aarch64-linux-gnu/include", action)]
    aarch64_sysroot: PathBuf,

    #[arg(long, default_value = "/usr/arm-linux-gnueabi/include", action)]
    armv7_sysroot: PathBuf,

    #[arg(long, default_value = "/usr/loongarch64-linux-gnu/include", action)]
    loongarch64_sysroot: PathBuf,

    #[arg(long, default_value = "/usr/mips-linux-gnu/include", action)]
    mips_sysroot: PathBuf,

    #[arg(long, default_value = "/usr/powerpc64le-linux-gnu/include", action)]
    powerpc64_sysroot: PathBuf,

    #[arg(long, default_value = "/usr/riscv64-linux-gnu/include", action)]
    riscv64_sysroot: PathBuf,

    #[arg(long, default_value = "/usr/s390x-linux-gnu/include", action)]
    s390x_sysroot: PathBuf,

    #[arg(long, default_value = "/usr/include/x86_64-linux-gnu", action)]
    x86_64_sysroot: PathBuf,
}

#[derive(Parser)]
pub struct Options {
    #[clap(flatten)]
    sysroot_options: SysrootOptions,

    #[clap(subcommand)]
    command: Option<Target>,
}

#[derive(clap::Subcommand)]
enum Target {
    #[command(name = "aya")]
    Aya,
    #[command(name = "aya-ebpf-bindings")]
    AyaEbpfBindings,
}

pub fn codegen(opts: Options, libbpf_dir: &Path) -> Result<()> {
    let Options {
        sysroot_options,
        command,
    } = opts;

    match command {
        Some(command) => match command {
            Target::Aya => aya::codegen(&sysroot_options, libbpf_dir).context("aya"),
            Target::AyaEbpfBindings => aya_ebpf_bindings::codegen(&sysroot_options, libbpf_dir)
                .context("aya_ebpf_bindings"),
        },
        None => {
            aya::codegen(&sysroot_options, libbpf_dir).context("aya")?;
            aya_ebpf_bindings::codegen(&sysroot_options, libbpf_dir)
                .context("aya_ebpf_bindings")?;
            Ok(())
        }
    }
}
