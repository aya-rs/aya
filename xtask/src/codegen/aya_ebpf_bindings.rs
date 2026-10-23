use std::{fs::File, path::Path};

use anyhow::{Context as _, Result};
use aya_tool::bindgen;
use proc_macro2::TokenStream;
use quote::ToTokens as _;
use syn::{Item, parse_str};

use crate::{
    Options,
    helpers::{expand_helpers, extract_helpers},
};

pub(crate) fn codegen(opts: &Options, scratch: &Path) -> Result<()> {
    let mut bindgen = opts
        .builder(bindgen::bpf_builder(), scratch)
        .header(opts.ebpf_header.to_str().unwrap())
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
    let vars = [
        "BPF_.*",
        "bpf_.*",
        "PERF_MAX_STACK_DEPTH",
        "TC_ACT_.*",
        "SOL_SOCKET",
        "SO_.*",
    ];

    for x in &types {
        bindgen = bindgen.allowlist_type(x);
    }

    for x in &vars {
        bindgen = bindgen.allowlist_var(x);
    }

    let bindings = bindgen.generate().context("bindgen failed")?;
    let bindings = bindings.to_string();

    let mut tree = parse_str::<syn::File>(&bindings).unwrap();

    let (indexes, helpers) = extract_helpers(&tree.items);
    let helpers = expand_helpers(&helpers);
    for index in indexes {
        tree.items[index] = Item::Verbatim(TokenStream::new())
    }

    // write the bindings, with the original helpers removed
    //
    // write the new helpers as expanded by expand_helpers()
    for (path, code) in [
        (&opts.ebpf_output, &tree.to_token_stream().to_string()),
        (
            &opts.helpers_output,
            &format!("use super::bindings::*; {helpers}"),
        ),
    ] {
        use std::io::Write as _;

        let mut file = File::create(path)?;
        file.write_all(code.as_bytes())?;
    }
    Ok(())
}
