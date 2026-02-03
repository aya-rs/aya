fn main() -> aya_build::Result<()> {
    println!("cargo::rustc-check-cfg=cfg(generic_const_exprs)");
    check_rust_version();

    aya_build::emit_bpf_target_arch_cfg()
}

#[rustversion::nightly]
const fn check_rust_version() {
    // TODO(https://github.com/rust-lang/rust/issues/141492): restore this.
    // println!("cargo:rustc-cfg=generic_const_exprs");
}

#[rustversion::not(nightly)]
const fn check_rust_version() {}
