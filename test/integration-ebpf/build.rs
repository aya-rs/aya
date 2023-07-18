use std::{env, path::PathBuf};
use xtask::create_symlink_to_binary;

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = PathBuf::from(out_dir);
    let bpf_linker_symlink = create_symlink_to_binary(&out_dir, "bpf-linker").unwrap();
    println!(
        "cargo:rerun-if-changed={}",
        bpf_linker_symlink.to_str().unwrap()
    );
}
