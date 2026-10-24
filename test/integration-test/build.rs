use std::{
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
};

use anyhow::{Context as _, Ok, Result, anyhow};
use cargo_metadata::{Metadata, MetadataCommand, Package, Target, TargetKind};
// Keep these build dependencies in Cargo's graph to invalidate eBPF artifacts after source changes.
use integration_ebpf as _;
use integration_ebpf_jumptable as _;
use object::Object as _;
use xtask::{AYA_BUILD_INTEGRATION_BPF, LIBBPF_DIR, exec, install_libbpf_headers_cmd};

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
fn ebpf_package<'a>(
    package: &'a Package,
    rustflags: &'a [&'a str],
) -> Result<aya_build::Package<'a>> {
    let Package {
        name,
        manifest_path,
        ..
    } = package;
    Ok(aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        rustflags,
        ..Default::default()
    })
}

fn bin_names(package: &Package) -> impl Iterator<Item = &str> {
    let Package { targets, .. } = package;
    targets.iter().filter_map(|Target { name, kind, .. }| {
        (*kind == [TargetKind::Bin]).then_some(name.as_str())
    })
}

fn main() -> Result<()> {
    println!("cargo::rerun-if-env-changed={AYA_BUILD_INTEGRATION_BPF}");

    // TODO(https://github.com/rust-lang/cargo/issues/4001): generalize this and move it to
    // aya-build if we can determine that we're in a check build.
    let build_integration_bpf = env::var_os(AYA_BUILD_INTEGRATION_BPF)
        .map(|build_integration_bpf| {
            let build_integration_bpf = std::str::from_utf8(
                build_integration_bpf.as_encoded_bytes(),
            )
            .with_context(|| {
                format!(
                    "{AYA_BUILD_INTEGRATION_BPF}={}",
                    build_integration_bpf.display()
                )
            })?;
            let build_integration_bpf = build_integration_bpf
                .parse()
                .with_context(|| format!("{AYA_BUILD_INTEGRATION_BPF}={build_integration_bpf}"))?;
            Ok(build_integration_bpf)
        })
        .transpose()?
        .unwrap_or_default();

    let Metadata {
        packages,
        workspace_root,
        ..
    } = MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let find_package = |package_name: &str| {
        packages
            .iter()
            .find(|Package { name, .. }| name.as_str() == package_name)
            .ok_or_else(|| anyhow!("{package_name} package not found"))
    };
    let integration_ebpf_package = find_package("integration-ebpf")?;
    // Built with the flags that make LLVM emit jump tables; keep them synchronized with
    // test/integration-ebpf-jumptable/BUILD.bazel. bpf-linker ignores LLVM flags its LLVM does
    // not understand (older than 22) rather than failing, so the produced objects are checked for
    // a `.jumptables` section below. Unlike the system clang, bpf-linker is installed by the test
    // setup, so a missing table is a toolchain error rather than a reason to skip.
    let integration_ebpf_jumptable_package = find_package("integration-ebpf-jumptable")?;
    const JUMP_TABLE_RUSTFLAGS: &[&str] = &[
        "-Ctarget-cpu=v4",
        "-Clink-arg=--llvm-args=-bpf-min-jump-table-entries=4",
    ];

    const CARGO_MANIFEST_DIR: &str = "CARGO_MANIFEST_DIR";
    let manifest_dir =
        env::var_os(CARGO_MANIFEST_DIR).ok_or_else(|| anyhow!("{CARGO_MANIFEST_DIR} not set"))?;
    let manifest_dir = PathBuf::from(manifest_dir);

    const OUT_DIR: &str = "OUT_DIR";
    let out_dir = env::var_os(OUT_DIR).ok_or_else(|| anyhow!("{OUT_DIR} not set"))?;
    let out_dir = PathBuf::from(out_dir);

    // Keep this list synchronized with C_BPF_OBJECTS in BUILD.bazel. The Boolean controls whether
    // to build the additional .BTF section used by the corresponding relocation test; the slice
    // holds extra clang flags for the source.
    //
    // `jumptable.bpf.c` only exercises jump tables (`.jumptables` section + `gotox`) when LLVM is
    // told to use them; clang older than LLVM 22 rejects these flags, in which case an empty object
    // is written and the corresponding test skips itself.
    const C_BPF: &[(&str, bool, &[&str])] = &[
        ("ext.bpf.c", false, &[]),
        ("iter.bpf.c", true, &[]),
        ("main.bpf.c", false, &[]),
        ("ringbuf-btf.bpf.c", true, &[]),
        ("enum_signed_32_checked_variants_reloc.bpf.c", true, &[]),
        ("enum_signed_32_reloc.bpf.c", true, &[]),
        ("enum_signed_64_checked_variants_reloc.bpf.c", true, &[]),
        ("enum_signed_64_reloc.bpf.c", true, &[]),
        ("enum_unsigned_32_checked_variants_reloc.bpf.c", true, &[]),
        ("enum_unsigned_32_reloc.bpf.c", true, &[]),
        ("enum_unsigned_64_checked_variants_reloc.bpf.c", true, &[]),
        ("enum_unsigned_64_reloc.bpf.c", true, &[]),
        ("field_reloc.bpf.c", true, &[]),
        ("flex_array_reloc.bpf.c", true, &[]),
        ("nonfinal_zero_array_reloc.bpf.c", false, &[]),
        ("nested_array_bounds_reloc.bpf.c", false, &[]),
        ("target_fixed_array_reloc.bpf.c", true, &[]),
        ("target_nonfinal_zero_array_reloc.bpf.c", true, &[]),
        ("pointer_reloc.bpf.c", true, &[]),
        ("struct_flavors_reloc.bpf.c", true, &[]),
        ("text_64_64_reloc.c", false, &[]),
        ("variables_reloc.bpf.c", false, &[]),
        ("func_info_missing_callee.bpf.c", false, &[]),
        ("func_info_missing_program.bpf.c", false, &[]),
        ("func_info_absent.bpf.c", false, &[]),
        ("ksyms.bpf.c", true, &[]),
        ("ksyms_strong.bpf.c", true, &[]),
        ("ksyms_typed_missing_var.bpf.c", true, &[]),
        ("ksyms_typed_missing_kfunc.bpf.c", true, &[]),
        ("ksyms_typeless_missing.bpf.c", true, &[]),
        (
            "jumptable.bpf.c",
            false,
            &["-mcpu=v4", "-mllvm", "-bpf-min-jump-table-entries=4"],
        ),
    ];
    const C_BPF_HEADERS: &[&str] = &["reloc.h", "struct_with_scalars.h"];

    if build_integration_bpf {
        const CARGO_CFG_TARGET_ENDIAN: &str = "CARGO_CFG_TARGET_ENDIAN";
        let endian = env::var_os(CARGO_CFG_TARGET_ENDIAN)
            .ok_or_else(|| anyhow!("{CARGO_CFG_TARGET_ENDIAN} not set"))?;
        let target = if endian == "big" {
            "bpfeb"
        } else if endian == "little" {
            "bpfel"
        } else {
            return Err(anyhow!("unsupported endian={}", endian.display()));
        };

        let libbpf_dir = workspace_root.join(LIBBPF_DIR);
        println!("cargo::rerun-if-changed={libbpf_dir}");

        let libbpf_headers_dir = out_dir.join("libbpf_headers");
        let mut cmd = install_libbpf_headers_cmd(&libbpf_dir, &libbpf_headers_dir);
        cmd.stdout(Stdio::null());
        exec(&mut cmd)?;

        let bpf_dir = manifest_dir.join("bpf");

        let mut target_arch = OsString::new();
        target_arch.push("-D__TARGET_ARCH_");

        const CARGO_CFG_TARGET_ARCH: &str = "CARGO_CFG_TARGET_ARCH";
        let arch = env::var_os(CARGO_CFG_TARGET_ARCH)
            .ok_or_else(|| anyhow!("{CARGO_CFG_TARGET_ARCH} not set"))?;
        if arch == "x86_64" {
            target_arch.push("x86");
        } else if arch == "aarch64" {
            target_arch.push("arm64");
        } else {
            target_arch.push(&arch);
        }

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

        let rerun_if_changed = |path: &Path| {
            use std::{io::Write as _, os::unix::ffi::OsStrExt as _};

            let mut stdout = std::io::stdout().lock();
            stdout.write_all(b"cargo::rerun-if-changed=")?;
            stdout.write_all(path.as_os_str().as_bytes())?;
            stdout.write_all(b"\n")?;

            Ok(())
        };

        for hdr in C_BPF_HEADERS {
            let hdr = bpf_dir.join(hdr);
            let exists = hdr
                .try_exists()
                .with_context(|| format!("{}", hdr.display()))?;
            anyhow::ensure!(exists, "{}", hdr.display());
            rerun_if_changed(&hdr).with_context(|| format!("{}", hdr.display()))?;
        }

        // Compiles an empty translation unit from stdin to learn whether clang accepts `flags`.
        let clang_accepts = |flags: &[&str]| -> Result<bool> {
            let mut cmd = clang();
            cmd.args(flags)
                .args(["-x", "c", "-", "-o", "/dev/null"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let status = cmd
                .status()
                .with_context(|| format!("failed to run {cmd:?}"))?;
            Ok(status.success())
        };

        for (src, build_btf, copts) in C_BPF {
            let dst = out_dir.join(src).with_extension("o");
            let src = bpf_dir.join(src);

            rerun_if_changed(&src).with_context(|| format!("{}", src.display()))?;

            if !copts.is_empty() && !clang_accepts(copts)? {
                println!(
                    "cargo::warning=clang rejected `{}`; writing empty {}",
                    copts.join(" "),
                    dst.display()
                );
                fs::write(&dst, [])
                    .with_context(|| format!("failed to create {}", dst.display()))?;
                continue;
            }

            exec(clang().args(*copts).arg(&src).arg("-o").arg(&dst))?;

            if *build_btf {
                let mut cmd = clang();
                let mut child = cmd
                    .args(*copts)
                    .arg("-DTARGET")
                    .arg(&src)
                    .args(["-o", "-"])
                    .stdout(Stdio::piped())
                    .spawn()
                    .with_context(|| format!("failed to spawn {cmd:?}"))?;

                let Child { stdout, .. } = &mut child;
                let stdout = stdout.take().expect("stdout");

                let dst = dst.with_extension("target.o");

                let mut output = OsString::new();
                output.push(".BTF=");
                output.push(dst);
                exec(
                    // NB: objcopy doesn't support reading from stdin, so we have to use llvm-objcopy.
                    Command::new(
                        env::var_os("LLVM_OBJCOPY").unwrap_or_else(|| "llvm-objcopy".into()),
                    )
                    .arg("--dump-section")
                    .arg(output)
                    .arg("-")
                    .stdin(stdout)
                    .stdout(Stdio::null()),
                )?;

                let output = child
                    .wait_with_output()
                    .with_context(|| format!("failed to wait for {cmd:?}"))?;
                let Output { status, .. } = &output;
                if !status.success() {
                    return Err(anyhow!("{cmd:?} failed: {status:?}"));
                }
            }
        }

        aya_build::build_ebpf(
            [
                ebpf_package(integration_ebpf_package, &[])?,
                ebpf_package(integration_ebpf_jumptable_package, JUMP_TABLE_RUSTFLAGS)?,
            ],
            aya_build::Toolchain::default(),
        )?;

        for name in bin_names(integration_ebpf_jumptable_package) {
            let path = out_dir.join(name);
            let data = fs::read(&path).with_context(|| format!("{}", path.display()))?;
            let file =
                object::File::parse(&*data).with_context(|| format!("{}", path.display()))?;
            anyhow::ensure!(
                file.section_by_name(".jumptables").is_some(),
                "bpf-linker did not emit jump tables for {name}; it must be built against LLVM 22 or newer"
            );
        }
    } else {
        for (src, build_btf, _copts) in C_BPF {
            let dst = out_dir.join(src).with_extension("o");
            fs::write(&dst, []).with_context(|| format!("failed to create {}", dst.display()))?;
            if *build_btf {
                let dst = dst.with_extension("target.o");
                fs::write(&dst, [])
                    .with_context(|| format!("failed to create {}", dst.display()))?;
            }
        }

        for name in [integration_ebpf_package, integration_ebpf_jumptable_package]
            .into_iter()
            .flat_map(bin_names)
        {
            let dst = out_dir.join(name);
            fs::write(&dst, []).with_context(|| format!("failed to create {}", dst.display()))?;
        }
    }
    Ok(())
}
