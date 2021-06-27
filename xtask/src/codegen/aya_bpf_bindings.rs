use anyhow::anyhow;
use proc_macro2::TokenStream;
use quote::ToTokens;
use std::path::PathBuf;

use aya_gen::{
    bindgen,
    btf_types::c_header_from_btf,
    getters::{generate_getters_for_items, read_getter},
    write_to_file, write_to_file_fmt,
};
use syn::{parse_str, Item};

use crate::codegen::{
    helpers::{expand_helpers, extract_helpers},
    Architecture, Options,
};

pub fn codegen(opts: &Options) -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("bpf/aya-bpf-bindings");
    let vmlinux = c_header_from_btf(&*opts.btf)?;
    write_to_file(&dir.join("include").join("vmlinux.h"), &vmlinux)?;

    let builder = || {
        let mut bindgen = bindgen::bpf_builder()
            .header(&*dir.join("include/bindings.h").to_string_lossy())
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

        let types = ["bpf_map_.*", "sk_action", "pt_regs", "xdp_action"];
        let vars = ["BPF_.*", "bpf_.*", "TC_ACT_.*", "SOL_SOCKET", "SO_.*"];

        for x in &types {
            bindgen = bindgen.allowlist_type(x);
        }

        for x in &vars {
            bindgen = bindgen.allowlist_var(x);
        }

        bindgen
    };

    // from BTF we can't generate bindings for macros like TC_ACT_OK, macro_bindings.h is for bindgen to do the work.
    let marcro_bindings_builder = || {
        let mut bindgen =
            bindgen::bpf_builder().header(&*dir.join("include/macro_bindings.h").to_string_lossy());

        let vars = ["TC_ACT_.*"];
        for x in &vars {
            bindgen = bindgen.allowlist_var(x);
        }

        bindgen
    };

    for arch in Architecture::supported() {
        let generated = dir.join("src").join(arch.to_string());

        let mut bindings = builder()
            .generate()
            .map_err(|_| anyhow!("bindgen failed"))?
            .to_string();
        let marcro_bindings = marcro_bindings_builder()
            .generate()
            .map_err(|_| anyhow!("bindgen failed"))?
            .to_string();
        bindings.push_str(&marcro_bindings);
        let mut tree = parse_str::<syn::File>(&bindings).unwrap();
        let (indexes, helpers) = extract_helpers(&tree.items);
        let helpers = expand_helpers(&helpers);
        for index in indexes {
            tree.items[index] = Item::Verbatim(TokenStream::new())
        }

        // write the bindings, with the original helpers removed
        write_to_file_fmt(
            &generated.join("bindings.rs"),
            &tree.to_token_stream().to_string(),
        )?;

        // write the new helpers as expanded by expand_helpers()
        write_to_file_fmt(
            &generated.join("helpers.rs"),
            &format!("use super::bindings::*; {}", helpers.to_string()),
        )?;

        // write the bpf_probe_read() getters
        let bpf_probe_read = syn::parse_str("crate::bpf_probe_read").unwrap();
        write_to_file_fmt(
            &generated.join("getters.rs"),
            &format!(
                "use super::bindings::*; {}",
                &generate_getters_for_items(&tree.items, |getter| {
                    read_getter(getter, &bpf_probe_read)
                })
                .to_string()
            ),
        )?;
    }

    Ok(())
}
