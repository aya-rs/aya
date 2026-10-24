mod aya;
mod aya_ebpf_bindings;
mod helpers;

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context as _, Result};
use bindgen::{Builder, Formatter};
use clap::Parser;
use xtask::exec;

#[derive(Parser)]
struct Options {
    #[arg(long)]
    target: String,
    #[arg(long)]
    libc_headers: PathBuf,
    #[arg(long)]
    kernel_headers: PathBuf,
    #[arg(long)]
    libbpf_dir: PathBuf,
    #[arg(long)]
    builtin_headers: PathBuf,
    #[arg(long = "elf-clang-arg")]
    elf_clang_args: Vec<String>,
    #[arg(long)]
    aya_header: PathBuf,
    #[arg(long)]
    ebpf_header: PathBuf,
    #[arg(long)]
    aya_output: PathBuf,
    #[arg(long)]
    ebpf_output: PathBuf,
    #[arg(long)]
    helpers_output: PathBuf,
    #[arg(long)]
    btf_output: Option<PathBuf>,
    #[arg(long)]
    rustfmt: PathBuf,
    #[arg(long)]
    rustfmt_config: PathBuf,
}

impl Options {
    fn builder(&self, builder: Builder, scratch: &Path) -> Builder {
        let Self {
            target,
            libc_headers,
            kernel_headers,
            libbpf_dir,
            builtin_headers,
            elf_clang_args,
            aya_header: _,
            ebpf_header: _,
            aya_output: _,
            ebpf_output: _,
            helpers_output: _,
            btf_output: _,
            rustfmt: _,
            rustfmt_config: _,
        } = self;
        let builder = builder
            .detect_include_paths(false)
            .formatter(Formatter::None)
            .clang_macro_fallback_build_dir(scratch)
            .clang_args(["-target", target, "-nostdinc"])
            // libbpf's UAPI and compatibility headers take precedence over the
            // generic kernel headers, just as in the original generator.
            .clang_args(["-I", libbpf_dir.join("include/uapi").to_str().unwrap()])
            .clang_args(["-I", libbpf_dir.join("include").to_str().unwrap()])
            .clang_args(["-I", libbpf_dir.join("src").to_str().unwrap()])
            .clang_args(["-isystem", builtin_headers.to_str().unwrap()])
            .clang_args(["-isystem", libc_headers.to_str().unwrap()])
            .clang_args(["-isystem", kernel_headers.to_str().unwrap()]);
        builder.clang_args(elf_clang_args)
    }
}

fn main() -> Result<()> {
    let opts = Options::parse();
    let scratch = tempfile::tempdir().context("create macro evaluation directory")?;
    aya::codegen(&opts, scratch.path()).context("generate userspace bindings")?;
    aya_ebpf_bindings::codegen(&opts, scratch.path()).context("generate eBPF bindings")?;

    let Options {
        target: _,
        libc_headers: _,
        kernel_headers: _,
        libbpf_dir: _,
        builtin_headers: _,
        elf_clang_args: _,
        aya_header: _,
        ebpf_header: _,
        aya_output,
        ebpf_output,
        helpers_output,
        btf_output,
        rustfmt,
        rustfmt_config,
    } = opts;
    // Format after helper rewriting; bindgen's intermediate formatting does
    // not cover the transformed eBPF bindings and helpers.
    exec(
        Command::new(rustfmt)
            .args(["--edition", "2024", "--config", "skip_children=true"])
            .arg("--config-path")
            .arg(rustfmt_config)
            .args([aya_output, ebpf_output, helpers_output])
            .args(btf_output),
    )
}
