use std::{env, path::PathBuf};

use xtask::{create_symlink_to_binary, AYA_BUILD_INTEGRATION_BPF};

fn main() {
    println!("cargo:rerun-if-env-changed={}", AYA_BUILD_INTEGRATION_BPF);

    let build_integration_bpf = env::var(AYA_BUILD_INTEGRATION_BPF)
        .as_deref()
        .map(str::parse)
        .map(Result::unwrap)
        .unwrap_or_default();

    if build_integration_bpf {
        let out_dir = env::var_os("OUT_DIR").unwrap();
        let out_dir = PathBuf::from(out_dir);
        let bpf_linker_symlink = create_symlink_to_binary(&out_dir, "bpf-linker").unwrap();
        println!(
            "cargo:rerun-if-changed={}",
            bpf_linker_symlink.to_str().unwrap()
        );
    }
}
