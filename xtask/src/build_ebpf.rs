use std::{path::PathBuf, process::Command};

use anyhow::Result;
use clap::Parser;

use crate::utils::{exec, workspace_root};

#[derive(Debug, Copy, Clone)]
pub enum Architecture {
    BpfEl,
    BpfEb,
}

impl std::str::FromStr for Architecture {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "bpfel-unknown-none" => Architecture::BpfEl,
            "bpfeb-unknown-none" => Architecture::BpfEb,
            _ => return Err("invalid target"),
        })
    }
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Architecture::BpfEl => "bpfel-unknown-none",
            Architecture::BpfEb => "bpfeb-unknown-none",
        })
    }
}

#[derive(Debug, Parser)]
pub struct BuildEbpfOptions {
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub target: Architecture,
}

pub fn build_ebpf(opts: BuildEbpfOptions) -> Result<()> {
    let BuildEbpfOptions { target } = opts;

    let mut dir = PathBuf::from(workspace_root());
    dir.push("test/integration-ebpf");

    exec(
        Command::new("cargo")
            .current_dir(&dir)
            .args(["+nightly", "build", "--release", "--target"])
            .arg(target.to_string())
            .args(["-Z", "build-std=core"])
            .current_dir(&dir),
    )
}
