use anyhow::anyhow;
use std::path::PathBuf;

use aya_tool::{bindgen, write_to_file};

use crate::codegen::{Architecture, Options};

pub fn codegen(opts: &Options) -> Result<(), anyhow::Error> {
    codegen_bindings(opts)
}

fn codegen_bindings(opts: &Options) -> Result<(), anyhow::Error> {
    let types = [
        // Registers
        "pt_regs",
        "user_pt_regs",
    ];

    let dir = PathBuf::from("aya-common");
    let generated = dir.join("src/generated");

    let builder = || {
        bindgen::user_builder()
            .header(dir.join("include/linux_wrapper.h").to_string_lossy())
            .clang_args(&[
                "-I",
                &*opts.libbpf_dir.join("include/uapi").to_string_lossy(),
            ])
            .clang_args(&["-I", &*opts.libbpf_dir.join("include").to_string_lossy()])
    };

    for arch in Architecture::supported() {
        let mut bindgen = builder();

        // Set target triple. This will set the right flags (which you can see
        // running clang -target=X  -E - -dM </dev/null)
        let target = match arch {
            Architecture::X86_64 => "x86_64-unknown-linux-gnu",
            Architecture::ARMv7 => "armv7-unknown-linux-gnu",
            Architecture::AArch64 => "aarch64-unknown-linux-gnu",
            Architecture::RISCV64 => "riscv64-unknown-linux-gnu",
        };
        bindgen = bindgen.clang_args(&["-target", target]);

        // Set the sysroot. This is needed to ensure that the correct arch
        // specific headers are imported.
        let sysroot = match arch {
            Architecture::X86_64 => &opts.x86_64_sysroot,
            Architecture::ARMv7 => &opts.armv7_sysroot,
            Architecture::AArch64 => &opts.aarch64_sysroot,
            Architecture::RISCV64 => &opts.riscv64_sysroot,
        };
        bindgen = bindgen.clang_args(&["-I", &*sysroot.to_string_lossy()]);

        for x in &types {
            bindgen = bindgen.allowlist_type(x);
        }

        let bindings = bindgen
            .generate()
            .map_err(|_| anyhow!("bindgen failed"))?
            .to_string();

        // write the bindings, with the original helpers removed
        write_to_file(
            &generated.join(format!("linux_bindings_{}.rs", arch)),
            &bindings.to_string(),
        )?;
    }

    Ok(())
}
