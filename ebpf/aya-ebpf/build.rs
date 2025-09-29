use std::env;

fn main() {
    check_rust_version();
    println!("cargo:rerun-if-env-changed=CARGO_CFG_BPF_TARGET_ARCH");
    if let Ok(arch) = env::var("CARGO_CFG_BPF_TARGET_ARCH") {
        println!("cargo:rustc-cfg=bpf_target_arch=\"{arch}\"");
    } else {
        let arch = env::var("HOST").unwrap();
        let mut arch = arch.split_once('-').map_or(&*arch, |x| x.0);
        if arch.starts_with("riscv64") {
            arch = "riscv64";
        }
        println!("cargo:rustc-cfg=bpf_target_arch=\"{arch}\"");
    }
    print!("cargo::rustc-check-cfg=cfg(bpf_target_arch, values(");
    for arch in [
        "aarch64",
        "arm",
        "loongarch64",
        "mips",
        "powerpc64",
        "riscv64",
        "s390x",
        "x86_64",
    ] {
        print!("\"{arch}\",");
    }
    println!("))");

    println!("cargo::rustc-check-cfg=cfg(generic_const_exprs)");
}

#[rustversion::nightly]
fn check_rust_version() {
    // TODO(https://github.com/rust-lang/rust/issues/141492): restore this.
    // println!("cargo:rustc-cfg=generic_const_exprs");
}

#[rustversion::not(nightly)]
fn check_rust_version() {}
