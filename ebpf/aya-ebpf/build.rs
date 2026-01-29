fn main() {
    println!("cargo::rustc-check-cfg=cfg(generic_const_exprs)");
    check_rust_version();

    aya_build::emit_bpf_target_arch_cfg()
}

#[rustversion::nightly]
fn check_rust_version() {
    println!("cargo:rustc-cfg=generic_const_exprs");
}

#[rustversion::not(nightly)]
fn check_rust_version() {}
