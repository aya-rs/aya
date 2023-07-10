use std::{
    borrow::Cow,
    env,
    ffi::{OsStr, OsString},
    fs,
    path::{Path, PathBuf},
    process::Command,
};

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
    /// Libbpf dir, required for compiling C code
    #[clap(long, action)]
    pub libbpf_dir: PathBuf,
}

pub fn build_ebpf(opts: BuildEbpfOptions) -> Result<()> {
    build_rust_ebpf(&opts)?;
    build_c_ebpf(&opts)
}

fn build_rust_ebpf(opts: &BuildEbpfOptions) -> Result<()> {
    let BuildEbpfOptions {
        target,
        libbpf_dir: _,
    } = opts;

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

fn get_libbpf_headers(libbpf_dir: &Path, include_path: &Path) -> Result<()> {
    fs::create_dir_all(include_path)?;
    let mut includedir = OsString::new();
    includedir.push("INCLUDEDIR=");
    includedir.push(include_path);
    exec(
        Command::new("make")
            .current_dir(libbpf_dir.join("src"))
            .arg(includedir)
            .arg("install_headers"),
    )
}

fn build_c_ebpf(opts: &BuildEbpfOptions) -> Result<()> {
    let BuildEbpfOptions { target, libbpf_dir } = opts;

    let mut src = PathBuf::from(workspace_root());
    src.push("test/integration-ebpf/src/bpf");

    let mut out_path = PathBuf::from(workspace_root());
    out_path.push("target");
    out_path.push(target.to_string());
    out_path.push("release");

    let include_path = out_path.join("include");
    get_libbpf_headers(libbpf_dir, &include_path)?;
    let files = fs::read_dir(&src).unwrap();
    for file in files {
        let p = file.unwrap().path();
        if let Some(ext) = p.extension() {
            if ext == "c" {
                let mut out = PathBuf::from(&out_path);
                out.push(p.file_name().unwrap());
                out.set_extension("o");
                compile_with_clang(&p, &out, &include_path)?;
            }
        }
    }
    Ok(())
}

/// Build eBPF programs with clang and libbpf headers.
fn compile_with_clang(src: &Path, out: &Path, include_path: &Path) -> Result<()> {
    let clang: Cow<'_, _> = match env::var_os("CLANG") {
        Some(val) => val.into(),
        None => OsStr::new("/usr/bin/clang").into(),
    };
    let arch = match env::consts::ARCH {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        arch => arch,
    };
    exec(
        Command::new(clang)
            .arg("-I")
            .arg(include_path)
            .args(["-g", "-O2", "-target", "bpf", "-c"])
            .arg(format!("-D__TARGET_ARCH_{arch}"))
            .arg(src)
            .arg("-o")
            .arg(out),
    )
}
