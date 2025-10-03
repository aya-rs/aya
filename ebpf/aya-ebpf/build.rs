use std::{
    env,
    ffi::OsStr,
    fs, io,
    path::PathBuf,
    process::{Command, Output},
};

fn main() -> aya_build::Result<()> {
    println!("cargo::rustc-check-cfg=cfg(generic_const_exprs)");
    println!("cargo::rustc-check-cfg=cfg(runtime_symbol_lint)");
    if rustversion::cfg!(since(1.98)) {
        println!("cargo:rustc-cfg=runtime_symbol_lint");
    }
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");
    println!("cargo:rerun-if-env-changed=RUSTC_BOOTSTRAP");
    if probe_generic_const_exprs()? {
        println!("cargo:rustc-cfg=generic_const_exprs");
    }

    aya_build::emit_bpf_target_arch_cfg()
}

fn probe_generic_const_exprs() -> io::Result<bool> {
    let rustc = env::var_os("RUSTC").ok_or_else(|| io::Error::other("RUSTC is not set"))?;
    let target = env::var_os("TARGET").ok_or_else(|| io::Error::other("TARGET is not set"))?;
    let out_dir = env::var_os("OUT_DIR").ok_or_else(|| io::Error::other("OUT_DIR is not set"))?;
    let out_dir = PathBuf::from(out_dir);
    let source = out_dir.join("generic_const_exprs.rs");
    // A build-std target such as BPF may not have core in its sysroot yet.
    fs::write(
        &source,
        "#![no_core]
#![feature(no_core, generic_const_exprs)]
#![allow(incomplete_features, unused_features)]
",
    )?;

    let mut command = Command::new(rustc);
    for name in ["RUSTC_WORKSPACE_WRAPPER", "RUSTC_WRAPPER"] {
        println!("cargo:rerun-if-env-changed={name}");
        if let Some(wrapper) = env::var_os(name).filter(|wrapper| !wrapper.is_empty()) {
            let mut wrapped = Command::new(wrapper);
            wrapped.arg(command.get_program()).args(command.get_args());
            command = wrapped;
        }
    }
    // rustc uses the first --cap-lints value. Keep the fallback warning visible
    // even when the caller's flags contain --cap-lints=allow.
    command.arg("--cap-lints=warn");
    let rustflags = env::var_os("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    if !rustflags.is_empty() {
        command.args(
            rustflags
                .as_encoded_bytes()
                .split(|&byte| byte == b'\x1f')
                .map(|flag| {
                    // SAFETY: these bytes came from OsStr and were split only at ASCII boundaries.
                    unsafe { OsStr::from_encoded_bytes_unchecked(flag) }
                }),
        );
    }
    let Output {
        status,
        stdout: _,
        stderr,
    } = command
        .args([
            "--crate-name=aya_ebpf",
            "--crate-type=lib",
            "--emit=metadata",
            // Unlike --cap-lints, the last warnings lint level takes effect.
            "-W",
            "warnings",
        ])
        .arg("--target")
        .arg(target)
        .arg("--out-dir")
        .arg(out_dir)
        .arg(source)
        .output()?;

    // The next solver currently accepts this feature by warning and falling
    // back to coherence for this crate, leaving downstream crates incompatible.
    // Require a warning-free probe as well as successful compilation:
    // https://github.com/rust-lang/rust/issues/160895
    Ok(status.success() && stderr.is_empty())
}
