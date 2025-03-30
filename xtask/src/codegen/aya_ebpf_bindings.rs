use std::{
    fs::{File, create_dir_all},
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result};
use aya_tool::bindgen;
use proc_macro2::TokenStream;
use quote::ToTokens as _;
use syn::{Item, parse_str};
use xtask::install_libbpf_headers;

use crate::codegen::{
    Architecture, SysrootOptions,
    helpers::{expand_helpers, extract_helpers},
};

pub fn codegen(opts: &SysrootOptions, libbpf_dir: &Path) -> Result<()> {
    let SysrootOptions {
        aarch64_sysroot,
        armv7_sysroot,
        loongarch64_sysroot,
        mips_sysroot,
        powerpc64_sysroot,
        riscv64_sysroot,
        s390x_sysroot,
        x86_64_sysroot,
    } = opts;

    let tmp_dir = tempfile::tempdir().context("tempdir failed")?;
    let libbpf_headers_dir = tmp_dir.path().join("libbpf_headers");

    install_libbpf_headers(libbpf_dir, &libbpf_headers_dir)?;

    let dir = PathBuf::from("ebpf/aya-ebpf-bindings");

    let builder = || {
        let mut bindgen = bindgen::bpf_builder()
            .header(dir.join("include/bindings.h").to_str().unwrap())
            .clang_args(["-I", libbpf_dir.join("include/uapi").to_str().unwrap()])
            .clang_args(["-I", libbpf_dir.join("include").to_str().unwrap()])
            .clang_args(["-I", libbpf_headers_dir.to_str().unwrap()])
            // aya-tool uses aya_ebpf::cty. We can't use that here since aya-bpf
            // depends on aya-ebpf-bindings so it would create a circular dep.
            .ctypes_prefix("::aya_ebpf_cty")
            // we define our own version which is compatible with both libbpf
            // and iproute2.
            .blocklist_type("bpf_map_def")
            // BPF_F_LINK is defined twice. Once in an anonymous enum
            // which bindgen will constify, and once via #define macro
            // which generates a duplicate const.
            .blocklist_var("BPF_F_LINK")
            // open aya-ebpf-bindings/.../bindings.rs and look for mod
            // _bindgen, those are anonymous enums
            .constified_enum("BPF_F_.*")
            .constified_enum("BPF_REG_.*")
            .constified_enum("BPF_CSUM_.*")
            .constified_enum("BPF_ADJ_.*")
            .constified_enum("BPF_SK_.*")
            .constified_enum("BPF_RB_.*")
            .constified_enum("BPF_RINGBUF_.*")
            .constified_enum("BPF_SOCK_.*")
            .constified_enum("BPF_TCP_.*")
            .constified_enum("BPF_DEVCG_.*")
            .constified_enum("BPF_FIB_.*")
            .constified_enum("BPF_FLOW_.*");

        let types = [
            "bpf_.*",
            "sk_action",
            "pt_regs",
            "user_pt_regs",
            "user_regs_struct",
            "xdp_action",
            "tcx_action_base",
        ];
        let vars = ["BPF_.*", "bpf_.*", "TC_ACT_.*", "SOL_SOCKET", "SO_.*"];

        for x in &types {
            bindgen = bindgen.allowlist_type(x);
        }

        for x in &vars {
            bindgen = bindgen.allowlist_var(x);
        }

        bindgen
    };

    for arch in Architecture::supported() {
        let mut bindgen = builder();

        // Set target triple. This will set the right flags (which you can see
        // running clang -target=X  -E - -dM </dev/null)
        let target = match arch {
            Architecture::AArch64 => "aarch64-unknown-linux-gnu",
            Architecture::ARMv7 => "armv7-unknown-linux-gnu",
            Architecture::LoongArch64 => "loongarch64-unknown-linux-gnu",
            Architecture::Mips => "mips-unknown-linux-gnu",
            Architecture::PowerPC64 => "powerpc64le-unknown-linux-gnu",
            Architecture::RISCV64 => "riscv64-unknown-linux-gnu",
            Architecture::S390X => "s390x-unknown-linux-gnu",
            Architecture::X86_64 => "x86_64-unknown-linux-gnu",
        };
        bindgen = bindgen.clang_args(["-target", target]);

        // Set the sysroot. This is needed to ensure that the correct arch
        // specific headers are imported.
        let sysroot = match arch {
            Architecture::AArch64 => aarch64_sysroot,
            Architecture::ARMv7 => armv7_sysroot,
            Architecture::LoongArch64 => loongarch64_sysroot,
            Architecture::Mips => mips_sysroot,
            Architecture::PowerPC64 => powerpc64_sysroot,
            Architecture::RISCV64 => riscv64_sysroot,
            Architecture::S390X => s390x_sysroot,
            Architecture::X86_64 => x86_64_sysroot,
        };
        bindgen = bindgen.clang_args(["-I", sysroot.to_str().unwrap()]);

        let bindings = bindgen.generate().context("bindgen failed")?;
        let bindings = bindings.to_string();

        let mut tree = parse_str::<syn::File>(&bindings).unwrap();

        let (indexes, helpers) = extract_helpers(&tree.items);
        let helpers = expand_helpers(&helpers);
        for index in indexes {
            tree.items[index] = Item::Verbatim(TokenStream::new())
        }

        let generated = dir.join("src").join(arch.to_string());
        create_dir_all(&generated)?;

        // write the bindings, with the original helpers removed
        //
        // write the new helpers as expanded by expand_helpers()
        for (path, code) in [
            (
                generated.join("bindings.rs"),
                &tree.to_token_stream().to_string(),
            ),
            (
                generated.join("helpers.rs"),
                &format!("use super::bindings::*; {helpers}"),
            ),
        ] {
            use std::io::Write as _;

            let mut file = File::create(path)?;
            file.write_all(code.as_bytes())?;
        }
    }

    Ok(())
}
