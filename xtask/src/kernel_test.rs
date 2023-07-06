use std::{
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::Context as _;
use clap::Parser;
use itertools::Itertools;

use crate::{build_ebpf, integration_test};

#[derive(Debug, Parser)]
pub struct Options {
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub bpf_target: build_ebpf::Architecture,
    /// Build and run the release target
    #[clap(long)]
    pub release: bool,
    /// libbpf directory
    #[clap(long, action)]
    pub libbpf_dir: PathBuf,
    /// Kernel version to use.
    #[clap(name = "kernel-version", long)]
    pub kernel_version: String,
    /// Path to the kerneltest root.
    #[clap(name = "kerneltest-root", long, default_value = "kerneltest")]
    pub kerneltest_root: String,
    /// Arguments to pass to your application
    #[clap(name = "args", last = true)]
    pub run_args: Vec<String>,
}

/// MUSL_TARGET is the target triple for the musl libc
/// platform. It defaults to statically linking binaries.
/// We need a statically linked binary to run in the initramfs
/// created by bluebox.
const MUSL_TARGET: &str = "x86_64-unknown-linux-musl";

pub(crate) fn kernel_test(opts: Options) -> Result<(), anyhow::Error> {
    let Options {
        bpf_target,
        release,
        libbpf_dir,
        run_args,
        kernel_version,
        kerneltest_root,
    } = opts;
    build_ebpf::build_ebpf(build_ebpf::BuildEbpfOptions {
        target: bpf_target,
        libbpf_dir,
    })
    .context("failed to build ebpf")?;
    let integration_test_bin = integration_test::build(integration_test::BuildOptions {
        release,
        target: Some(String::from(MUSL_TARGET)),
    })?;
    let initramfs_path = build_initramfs(&kerneltest_root, &integration_test_bin, &run_args)?;
    let kernel_image_path = get_kernel(&kernel_version, &kerneltest_root)?;
    run(&initramfs_path, &kernel_image_path)
}

const BLUEBOX_BINARY: &str = "bluebox";

fn build_initramfs(
    kerneltest_root: &str,
    integration_test_bin: &str,
    integration_test_args: &[String],
) -> Result<String, anyhow::Error> {
    let args = match integration_test_args {
        [] => String::new(),
        _ => std::iter::once(":\"")
            .chain(itertools::Itertools::intersperse(
                integration_test_args.iter().map(|v| v.as_str()),
                " ",
            ))
            .chain(std::iter::once("\""))
            .collect_vec()
            .join(""),
    };
    let initramfs_path = [kerneltest_root, "initramfs.cpio"].join(std::path::MAIN_SEPARATOR_STR);
    which::which(BLUEBOX_BINARY)
        .with_context(|| format!("{BLUEBOX_BINARY} not found"))
        .context("try installing with `go install github.com/florianl/bluebox@latest`")?;
    let args = format!("{integration_test_bin}{args}");
    match Command::new(BLUEBOX_BINARY)
        .arg("-e")
        .arg(&args)
        .arg("-o")
        .arg(&initramfs_path)
        .status()
    {
        Err(err) => Err(anyhow::anyhow!("failed to build initramfs: {}", err)),
        Ok(status) if !status.success() => Err(anyhow::anyhow!(
            "failed to build initramfs: status code {}",
            status
        )),
        Ok(_) => Ok(initramfs_path),
    }
}

fn get_kernel(kernel_version: &str, kerneltest_root: &str) -> Result<String, anyhow::Error> {
    let kernel_name = format!("linux-{}.bz", kernel_version);
    let image_path_str =
        [kerneltest_root, "kernels", &kernel_name].join(std::path::MAIN_SEPARATOR_STR);
    let image_path = Path::new(&image_path_str);
    if image_path.exists() && image_path.is_file() {
        return Ok(image_path_str);
    }

    let mut tmp = tempfile::NamedTempFile::new().context("creating temp file for kernel image")?;
    let url = format!(
        "https://github.com/cilium/ci-kernels/raw/a15c0b2aa7cf32640c03764fa79b0a815608ddce/linux-{kernel_version}.bz"
    );

    reqwest::blocking::get(&url)
        .and_then(|v| v.error_for_status())
        .with_context(|| format!("fetching kernel at {}", &url))?
        .copy_to(&mut tmp)
        .context("writing kernel file")?;
    tmp.persist_noclobber(image_path)
        .context(format!("persisting kernel file {:?}", &image_path))?;
    Ok(image_path_str)
}

const QEMU_BINARY: &str = "qemu-system-x86_64";

fn run(initramfs: &str, kernel_image: &str) -> Result<(), anyhow::Error> {
    which::which(QEMU_BINARY).with_context(|| format!("{QEMU_BINARY} not found"))?;
    let args = vec![
        "-no-reboot",
        "-append",
        "printk.devkmsg=on kernel.panic=-1 crashkernel=256M",
        "-kernel",
        kernel_image,
        "-initrd",
        initramfs,
        "-nographic",
        "-append",
        "console=ttyS0",
        "-m",
        "1.5G",
    ];
    match Command::new(QEMU_BINARY).args(args).status() {
        Err(err) => Err(anyhow::anyhow!("failed to run qemu: {}", err)),
        Ok(status) if !status.success() => Err(anyhow::anyhow!("failed to run qemu: {}", status)),
        Ok(_) => Ok(()),
    }
}
