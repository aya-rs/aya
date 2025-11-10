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
pub(crate) enum Architecture {
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
    pub(crate) fn supported() -> &'static [Self] {
        SUPPORTED_ARCHS
    }

    pub(crate) fn target(&self) -> &'static str {
        match self {
            Self::AArch64 => "aarch64-unknown-linux-gnu",
            Self::ARMv7 => "armv7-unknown-linux-gnu",
            Self::LoongArch64 => "loongarch64-unknown-linux-gnu",
            Self::Mips => "mips-unknown-linux-gnu",
            Self::PowerPC64 => "powerpc64le-unknown-linux-gnu",
            Self::RISCV64 => "riscv64-unknown-linux-gnu",
            Self::S390X => "s390x-unknown-linux-gnu",
            Self::X86_64 => "x86_64-unknown-linux-gnu",
        }
    }
}

impl std::str::FromStr for Architecture {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "aarch64" => Self::AArch64,
            "armv7" => Self::ARMv7,
            "loongarch64" => Self::LoongArch64,
            "mips" => Self::Mips,
            "powerpc64" => Self::PowerPC64,
            "riscv64" => Self::RISCV64,
            "s390x" => Self::S390X,
            "x86_64" => Self::X86_64,
            _ => return Err("invalid architecture"),
        })
    }
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AArch64 => "aarch64",
            Self::ARMv7 => "armv7",
            Self::LoongArch64 => "loongarch64",
            Self::Mips => "mips",
            Self::PowerPC64 => "powerpc64",
            Self::RISCV64 => "riscv64",
            Self::S390X => "s390x",
            Self::X86_64 => "x86_64",
        })
    }
}

// sysroot options. Default to ubuntu headers installed by the
// libc6-dev-{arm64,armel}-cross packages.
#[derive(Parser)]
pub(crate) struct SysrootOptions {
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
pub(crate) struct Options {
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

pub(crate) fn codegen(opts: Options, libbpf_dir: &Path) -> Result<()> {
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
