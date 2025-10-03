fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_CFG_BPF_TARGET_ARCH");
    println!("cargo:rerun-if-env-changed=HOST");

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

    if let Some(arch) = std::env::var_os("CARGO_CFG_BPF_TARGET_ARCH") {
        let arch = arch.to_str().unwrap();
        println!("cargo:rustc-cfg=bpf_target_arch=\"{arch}\"");
    } else if let Some(host) = std::env::var_os("HOST") {
        let host = host.to_str().unwrap();
        let mut arch = host.split_once('-').map_or(host, |(arch, _rest)| arch);
        if arch.starts_with("riscv64") {
            arch = "riscv64";
        }
        println!("cargo:rustc-cfg=bpf_target_arch=\"{arch}\"");
    }

    println!("cargo::rustc-check-cfg=cfg(generic_const_exprs)");
    check_rust_version();
}

#[rustversion::nightly]
fn check_rust_version() {
    println!("cargo:rustc-cfg=generic_const_exprs");
}

#[rustversion::not(nightly)]
fn check_rust_version() {}
