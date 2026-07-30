use std::{ffi::OsString, process::Command};

use anyhow::Result;
use clap::Parser;
use xtask::exec;

#[derive(Parser)]
pub(crate) struct Options {
    #[clap(last = true)]
    args: Vec<OsString>,
}

pub(crate) fn run(opts: Options) -> Result<()> {
    let Options { args } = opts;

    // `-C panic=abort` because "unwinding panics are not supported without
    // std"; integration-ebpf contains `#[no_std]` binaries.
    //
    // `-Zpanic_abort_tests` because "building tests with panic=abort is not
    // supported without `-Zpanic_abort_tests`"; Cargo does this automatically
    // when panic=abort is set via profile but we want to preserve unwinding at
    // runtime - here we are just running clippy so we don't care about
    // unwinding behavior.
    //
    // `+nightly` because "the option `Z` is only accepted on the nightly
    // compiler".
    let mut cmd = Command::new("cargo");
    cmd.args(["+nightly", "hack", "clippy"]);
    cmd.args(&args);
    cmd.args([
        "--all-targets",
        "--feature-powerset",
        "--",
        "--deny",
        "warnings",
        "-C",
        "panic=abort",
        "-Zpanic_abort_tests",
    ]);
    exec(&mut cmd)?;

    let base_rustdocflags = "--no-run -Z unstable-options --test-builder clippy-driver";
    let mut cmd = Command::new("cargo");
    cmd.args(["+nightly", "hack", "test", "--doc"]);
    cmd.args(&args);
    cmd.args(["--feature-powerset"]);
    cmd.env("CLIPPY_ARGS", "--deny=warnings");
    cmd.env("RUSTDOCFLAGS", base_rustdocflags);
    exec(&mut cmd)?;

    let ebpf_packages = [
        "aya-ebpf",
        "aya-ebpf-bindings",
        "aya-log-ebpf",
        "integration-ebpf",
    ];

    for arch in [
        "aarch64",
        "arm",
        "loongarch64",
        "mips",
        "mips64",
        "powerpc64",
        "riscv64",
        "s390x",
        "x86_64",
    ] {
        let rustflags = format!("--cfg bpf_target_arch=\"{arch}\"");

        for target in ["bpfeb-unknown-none", "bpfel-unknown-none"] {
            let mut cmd = Command::new("cargo");
            cmd.args([
                "+nightly",
                "hack",
                "clippy",
                "--target",
                target,
                "-Zbuild-std=core",
                "--feature-powerset",
            ]);
            for package in ebpf_packages {
                cmd.args(["--package", package]);
            }
            cmd.args(["--", "--deny", "warnings"]);
            cmd.env("CLIPPY_ARGS", "--deny=warnings");
            cmd.env("RUSTFLAGS", &rustflags);
            exec(&mut cmd)?;
        }

        let mut cmd = Command::new("cargo");
        cmd.args(["+nightly", "hack", "test", "--doc", "--feature-powerset"]);
        cmd.args(&args);
        for package in ebpf_packages {
            cmd.args(["--package", package]);
        }
        cmd.env("CLIPPY_ARGS", "--deny=warnings");
        cmd.env("RUSTFLAGS", &rustflags);
        cmd.env("RUSTDOCFLAGS", format!("{base_rustdocflags} {rustflags}"));
        exec(&mut cmd)?;
    }

    Ok(())
}
