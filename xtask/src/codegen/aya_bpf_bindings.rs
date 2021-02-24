use anyhow::anyhow;
use proc_macro2::TokenStream;
use quote::ToTokens;
use std::path::PathBuf;
use structopt::StructOpt;

use aya_gen::getters::{generate_getters_for_items, probe_read_getter};
use syn::{parse_str, Item};

use crate::codegen::{
    bindings::{self, bindgen},
    helpers::{expand_helpers, extract_helpers},
    Architecture,
};

#[derive(StructOpt)]
pub struct CodegenOptions {
    #[structopt(long)]
    arch: Architecture,

    #[structopt(long)]
    libbpf_dir: PathBuf,
}

pub fn codegen(opts: CodegenOptions) -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("bpf/aya-bpf-bindings");
    let generated = dir.join("src").join(opts.arch.to_string());

    let types = ["bpf_map_.*"];
    let vars = ["BPF_.*", "bpf_.*"];
    let mut cmd = bindgen(&types, &vars);
    cmd.arg(&*dir.join("include/bindings.h").to_string_lossy());
    cmd.arg("--");
    cmd.arg("-I").arg(opts.libbpf_dir.join("src"));

    let output = cmd.output()?;
    let bindings = std::str::from_utf8(&output.stdout)?;

    if !output.status.success() {
        eprintln!("{}", std::str::from_utf8(&output.stderr)?);
        return Err(anyhow!("bindgen failed: {}", output.status));
    }

    let mut tree = parse_str::<syn::File>(bindings).unwrap();
    let (indexes, helpers) = extract_helpers(&tree.items);
    let helpers = expand_helpers(&helpers);
    for index in indexes {
        tree.items[index] = Item::Verbatim(TokenStream::new())
    }

    bindings::write(
        &tree.to_token_stream().to_string(),
        "",
        &generated.join("bindings.rs"),
    )?;

    bindings::write(
        &helpers.to_string(),
        "use super::bindings::*;",
        &generated.join("helpers.rs"),
    )?;

    let bpf_probe_read = syn::parse_str("crate::bpf_probe_read").unwrap();
    bindings::write(
        &generate_getters_for_items(&tree.items, |getter| {
            probe_read_getter(getter, &bpf_probe_read)
        })
        .to_string(),
        "use super::bindings::*;",
        &generated.join("getters.rs"),
    )?;

    Ok(())
}
