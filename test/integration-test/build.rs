use std::{
    env,
    ffi::OsString,
    fs,
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
};

use aya_build::cargo_metadata::{Metadata, MetadataCommand, Package, Target, TargetKind};
use xtask::{exec, AYA_BUILD_INTEGRATION_BPF, LIBBPF_DIR};

/// This file, along with the xtask crate, allows analysis tools such as `cargo check`, `cargo
/// clippy`, and even `cargo build` to work as users expect. Prior to this file's existence, this
/// crate's undeclared dependency on artifacts from `integration-ebpf` would cause build (and `cargo check`,
/// and `cargo clippy`) failures until the user ran certain other commands in the workspace. Conversely,
/// those same tools (e.g. cargo test --no-run) would produce stale results if run naively because
/// they'd make use of artifacts from a previous build of `integration-ebpf`.
///
/// Note that this solution is imperfect: in particular it has to balance correctness with
/// performance; an environment variable is used to replace true builds of `integration-ebpf` with
/// stubs to preserve the property that code generation and linking (in `integration-ebpf`) do not
/// occur on metadata-only actions such as `cargo check` or `cargo clippy` of this crate. This means
/// that naively attempting to `cargo test --no-run` this crate will produce binaries that fail at
/// runtime because the stubs are inadequate for actually running the tests.
fn main() {
    println!("cargo:rerun-if-env-changed={}", AYA_BUILD_INTEGRATION_BPF);

    // TODO(https://github.com/rust-lang/cargo/issues/4001): generalize this and move it to
    // aya-build if we can determine that we're in a check build.
    let build_integration_bpf = env::var(AYA_BUILD_INTEGRATION_BPF)
        .as_deref()
        .map(str::parse)
        .map(Result::unwrap)
        .unwrap_or_default();

    let Metadata { packages, .. } = MetadataCommand::new().no_deps().exec().unwrap();
    let integration_ebpf_package = packages
        .into_iter()
        .find(|Package { name, .. }| name == "integration-ebpf")
        .unwrap();

    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR").unwrap();
    let manifest_dir = PathBuf::from(manifest_dir);
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = PathBuf::from(out_dir);

    const C_BPF: &[(&str, bool)] = &[
        ("ext.bpf.c", false),
        ("iter.bpf.c", true),
        ("main.bpf.c", false),
        ("multimap-btf.bpf.c", false),
        ("reloc.bpf.c", true),
        ("text_64_64_reloc.c", false),
        ("variables_reloc.bpf.c", false),
    ];

    if build_integration_bpf {
        let endian = env::var_os("CARGO_CFG_TARGET_ENDIAN").unwrap();
        let target = if endian == "big" {
            "bpfeb"
        } else if endian == "little" {
            "bpfel"
        } else {
            panic!("unsupported endian={:?}", endian)
        };

        let libbpf_dir = manifest_dir
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join(LIBBPF_DIR);
        println!("cargo:rerun-if-changed={}", libbpf_dir.to_str().unwrap());

        let libbpf_headers_dir = out_dir.join("libbpf_headers");

        let mut includedir = OsString::new();
        includedir.push("INCLUDEDIR=");
        includedir.push(&libbpf_headers_dir);

        exec(
            Command::new("make")
                .arg("-C")
                .arg(libbpf_dir.join("src"))
                .arg(includedir)
                .arg("install_headers"),
        )
        .unwrap();

        let bpf_dir = manifest_dir.join("bpf");

        let mut target_arch = OsString::new();
        target_arch.push("-D__TARGET_ARCH_");

        let arch = env::var_os("CARGO_CFG_TARGET_ARCH").unwrap();
        if arch == "x86_64" {
            target_arch.push("x86");
        } else if arch == "aarch64" {
            target_arch.push("arm64");
        } else {
            target_arch.push(&arch);
        };

        // NB: libbpf's documentation suggests that vmlinux.h be generated by running `bpftool btf
        // dump file /sys/kernel/btf/vmlinux format c`; this allows CO-RE to work.
        //
        // However in our tests we do not make use of kernel data structures, and so any vmlinux.h
        // which defines the constants we need (e.g. `__u8`, `__u64`, `BPF_MAP_TYPE_ARRAY`,
        // `BPF_ANY`, `XDP_PASS`, `XDP_DROP`, etc.) will suffice. Since we already have a libbpf
        // submodule which happens to include such a file, we use it.
        let libbpf_vmlinux_dir = libbpf_dir.join(".github/actions/build-selftests");

        let clang = || {
            let mut cmd = Command::new("clang");
            cmd.arg("-nostdlibinc")
                .arg("-I")
                .arg(&libbpf_headers_dir)
                .arg("-I")
                .arg(&libbpf_vmlinux_dir)
                .args(["-g", "-O2", "-target", target, "-c"])
                .arg(&target_arch);
            cmd
        };

        for (src, build_btf) in C_BPF {
            let dst = out_dir.join(src).with_extension("o");
            let src = bpf_dir.join(src);
            println!("cargo:rerun-if-changed={}", src.to_str().unwrap());

            exec(clang().arg(&src).arg("-o").arg(&dst)).unwrap();

            if *build_btf {
                let mut cmd = clang();
                let mut child = cmd
                    .arg("-DTARGET")
                    .arg(&src)
                    .args(["-o", "-"])
                    .stdout(Stdio::piped())
                    .spawn()
                    .unwrap_or_else(|err| panic!("failed to spawn {cmd:?}: {err}"));

                let Child { stdout, .. } = &mut child;
                let stdout = stdout.take().unwrap();

                let dst = dst.with_extension("target.o");

                let mut output = OsString::new();
                output.push(".BTF=");
                output.push(dst);
                exec(
                    // NB: objcopy doesn't support reading from stdin, so we have to use llvm-objcopy.
                    Command::new("llvm-objcopy")
                        .arg("--dump-section")
                        .arg(output)
                        .arg("-")
                        .stdin(stdout),
                )
                .unwrap();

                let output = child
                    .wait_with_output()
                    .unwrap_or_else(|err| panic!("failed to wait for {cmd:?}: {err}"));
                let Output { status, .. } = &output;
                assert_eq!(status.code(), Some(0), "{cmd:?} failed: {output:?}");
            }
        }

        aya_build::build_ebpf([integration_ebpf_package]);
    } else {
        for (src, build_btf) in C_BPF {
            let dst = out_dir.join(src).with_extension("o");
            fs::write(&dst, []).unwrap_or_else(|err| panic!("failed to create {dst:?}: {err}"));
            if *build_btf {
                let dst = dst.with_extension("target.o");
                fs::write(&dst, []).unwrap_or_else(|err| panic!("failed to create {dst:?}: {err}"));
            }
        }

        let Package { targets, .. } = integration_ebpf_package;
        for Target { name, kind, .. } in targets {
            if *kind != [TargetKind::Bin] {
                continue;
            }
            let dst = out_dir.join(name);
            fs::write(&dst, []).unwrap_or_else(|err| panic!("failed to create {dst:?}: {err}"));
        }
    }
}
