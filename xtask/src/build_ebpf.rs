use std::{
    borrow::Cow,
    env,
    ffi::{OsStr, OsString},
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use anyhow::{bail, Context};
use clap::Parser;

use crate::utils::workspace_root;

#[derive(Debug, Copy, Clone)]
pub enum Architecture {
    BpfEl,
    BpfEb,
}

impl std::str::FromStr for Architecture {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "bpfel-unknown-none" => Architecture::BpfEl,
            "bpfeb-unknown-none" => Architecture::BpfEb,
            _ => return Err("invalid target".to_owned()),
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

pub fn build_ebpf(opts: BuildEbpfOptions) -> anyhow::Result<()> {
    build_rust_ebpf(&opts)?;
    build_c_ebpf(&opts)
}

fn build_rust_ebpf(opts: &BuildEbpfOptions) -> anyhow::Result<()> {
    let mut dir = PathBuf::from(workspace_root());
    dir.push("test/integration-ebpf");

    let target = format!("--target={}", opts.target);
    let args = vec![
        "+nightly",
        "build",
        "--release",
        "--verbose",
        target.as_str(),
        "-Z",
        "build-std=core",
    ];
    let status = Command::new("cargo")
        .current_dir(&dir)
        .args(&args)
        .status()
        .expect("failed to build bpf program");
    assert!(status.success());
    Ok(())
}

fn get_libbpf_headers<P: AsRef<Path>>(libbpf_dir: P, include_path: P) -> anyhow::Result<()> {
    let dir = include_path.as_ref();
    fs::create_dir_all(dir)?;
    let mut includedir = OsString::new();
    includedir.push("INCLUDEDIR=");
    includedir.push(dir.as_os_str());
    let status = Command::new("make")
        .current_dir(libbpf_dir.as_ref().join("src"))
        .arg(includedir)
        .arg("install_headers")
        .status()
        .expect("failed to build get libbpf headers");
    assert!(status.success());
    Ok(())
}

fn build_c_ebpf(opts: &BuildEbpfOptions) -> anyhow::Result<()> {
    let mut src = PathBuf::from(workspace_root());
    src.push("test/integration-ebpf/src/bpf");

    let mut out_path = PathBuf::from(workspace_root());
    out_path.push("target");
    out_path.push(opts.target.to_string());
    out_path.push("release");

    let include_path = out_path.join("include");
    get_libbpf_headers(&opts.libbpf_dir, &include_path)?;
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
fn compile_with_clang<P: Clone + AsRef<Path>>(
    src: P,
    out: P,
    include_path: P,
) -> anyhow::Result<()> {
    let clang: Cow<'_, _> = match env::var_os("CLANG") {
        Some(val) => val.into(),
        None => OsStr::new("/usr/bin/clang").into(),
    };
    let arch = match env::consts::ARCH {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        arch => arch,
    };
    let mut cmd = Command::new(clang);
    cmd.arg("-v")
        .arg("-I")
        .arg(include_path.as_ref())
        .arg("-g")
        .arg("-O2")
        .arg("-target")
        .arg("bpf")
        .arg("-c")
        .arg(format!("-D__TARGET_ARCH_{arch}"))
        .arg(src.as_ref().as_os_str())
        .arg("-o")
        .arg(out.as_ref().as_os_str());

    let Output {
        status,
        stdout,
        stderr,
    } = cmd.output().context("Failed to execute clang")?;
    if !status.success() {
        bail!(
            "Failed to compile eBPF programs\n \
            stdout=\n \
            {}\n \
            stderr=\n \
            {}\n",
            String::from_utf8(stdout).unwrap(),
            String::from_utf8(stderr).unwrap()
        );
    }

    Ok(())
}
