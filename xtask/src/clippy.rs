use std::{ffi::OsString, path::Path, process::Command};

use anyhow::Result;
use clap::Parser;
use xtask::{exec, libbpf_sys_env};

#[derive(Parser)]
pub(crate) struct Options {
    #[clap(last = true)]
    args: Vec<OsString>,
}

pub(crate) fn run(opts: Options, workspace_root: &Path) -> Result<()> {
    let Options { args } = opts;

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
    libbpf_sys_env(workspace_root, &mut cmd);
    exec(&mut cmd)?;

    let base_rustdocflags = "--no-run -Z unstable-options --test-builder clippy-driver";
    let mut cmd = Command::new("cargo");
    cmd.args(["+nightly", "hack", "test", "--doc"]);
    cmd.args(&args);
    cmd.args(["--feature-powerset"]);
    libbpf_sys_env(workspace_root, &mut cmd);
    cmd.env("CLIPPY_ARGS", "--deny=warnings");
    cmd.env("RUSTDOCFLAGS", base_rustdocflags);
    exec(&mut cmd)?;

    let archs = [
        "aarch64",
        "arm",
        "loongarch64",
        "mips",
        "powerpc64",
        "riscv64",
        "s390x",
        "x86_64",
    ];
    let targets = ["bpfeb-unknown-none", "bpfel-unknown-none"];

    for arch in archs {
        let rustflags = format!("--cfg bpf_target_arch=\"{arch}\"");

        for target in targets {
            let mut cmd = Command::new("cargo");
            cmd.args([
                "+nightly",
                "hack",
                "clippy",
                "--target",
                target,
                "-Zbuild-std=core",
                "--package",
                "aya-ebpf",
                "--package",
                "aya-ebpf-bindings",
                "--package",
                "aya-log-ebpf",
                "--package",
                "integration-ebpf",
                "--feature-powerset",
                "--",
                "--deny",
                "warnings",
            ]);
            libbpf_sys_env(workspace_root, &mut cmd);
            cmd.env("CLIPPY_ARGS", "--deny=warnings");
            cmd.env("RUSTFLAGS", &rustflags);
            exec(&mut cmd)?;
        }

        let mut cmd = Command::new("cargo");
        cmd.args(["+nightly", "hack", "test", "--doc"]);
        cmd.args(&args);
        cmd.args([
            "--package",
            "aya-ebpf",
            "--package",
            "aya-ebpf-bindings",
            "--package",
            "aya-log-ebpf",
            "--package",
            "integration-ebpf",
            "--feature-powerset",
        ]);
        libbpf_sys_env(workspace_root, &mut cmd);
        cmd.env("CLIPPY_ARGS", "--deny=warnings");
        cmd.env("RUSTFLAGS", &rustflags);
        cmd.env("RUSTDOCFLAGS", format!("{base_rustdocflags} {rustflags}"));
        exec(&mut cmd)?;
    }

    Ok(())
}
