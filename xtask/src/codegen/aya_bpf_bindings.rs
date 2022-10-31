use anyhow::anyhow;
use proc_macro2::TokenStream;
use quote::ToTokens;
use std::path::PathBuf;

use aya_tool::{bindgen, write_to_file_fmt};
use syn::{parse_str, Item};

use crate::codegen::{
    helpers::{expand_helpers, extract_helpers},
    Architecture, Options,
};

pub fn codegen(opts: &Options) -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("bpf/aya-bpf-bindings");

    let builder = || {
        let mut bindgen = bindgen::bpf_builder()
            .header(&*dir.join("include/bindings.h").to_string_lossy())
            // aya-tool uses aya_bpf::cty. We can't use that here since aya-bpf
            // depends on aya-bpf-bindings so it would create a circular dep.
            .ctypes_prefix("::aya_bpf_cty")
            .clang_args(&[
                "-I",
                &*opts.libbpf_dir.join("include/uapi").to_string_lossy(),
            ])
            .clang_args(&["-I", &*opts.libbpf_dir.join("include").to_string_lossy()])
            .clang_args(&["-I", &*opts.libbpf_dir.join("src").to_string_lossy()])
            // open aya-bpf-bindings/.../bindings.rs and look for mod
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
            "xdp_action",
        ];
        let vars = ["BPF_.*", "bpf_.*", "TC_ACT_.*", "SOL_SOCKET", "SO_.*"];

        for x in &types {
            bindgen = bindgen.allowlist_type(x);
        }

        // we define our own version which is compatible with both libbpf and
        // iproute2
        bindgen = bindgen.blocklist_type("bpf_map_def");

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

        let bindings = bindgen
            .generate()
            .map_err(|_| anyhow!("bindgen failed"))?
            .to_string();

        let mut tree = parse_str::<syn::File>(&bindings).unwrap();
        let (indexes, helpers) = extract_helpers(&tree.items);
        let helpers = expand_helpers(&helpers);
        for index in indexes {
            tree.items[index] = Item::Verbatim(TokenStream::new())
        }

        let generated = dir.join("src").join(arch.to_string());
        // write the bindings, with the original helpers removed
        write_to_file_fmt(
            generated.join("bindings.rs"),
            &tree.to_token_stream().to_string(),
        )?;

        // write the new helpers as expanded by expand_helpers()
        write_to_file_fmt(
            generated.join("helpers.rs"),
            &format!("use super::bindings::*; {}", helpers),
        )?;
    }

    Ok(())
}
