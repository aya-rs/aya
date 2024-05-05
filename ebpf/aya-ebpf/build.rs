use std::env;

fn main() {
    check_rust_version();
    println!("cargo:rerun-if-env-changed=CARGO_CFG_BPF_TARGET_ARCH");
    if let Ok(arch) = env::var("CARGO_CFG_BPF_TARGET_ARCH") {
        println!("cargo:rustc-cfg=bpf_target_arch=\"{arch}\"");
    } else {
        let arch = env::var("HOST").unwrap();
        let arch = arch.split_once('-').map_or(&*arch, |x| x.0);
        println!("cargo:rustc-cfg=bpf_target_arch=\"{arch}\"");
    }
    println!("cargo::rustc-check-cfg=cfg(bpf_target_arch, values(\"x86_64\",\"arm\",\"aarch64\",\"riscv64\"))");
    println!("cargo::rustc-check-cfg=cfg(unstable)");
}

#[rustversion::nightly]
fn check_rust_version() {
    println!("cargo:rustc-cfg=unstable");
}

#[rustversion::not(nightly)]
fn check_rust_version() {}
