fn main() -> aya_build::Result<()> {
    println!("cargo::rustc-check-cfg=cfg(runtime_symbol_lint)");
    if rustversion::cfg!(since(1.98)) {
        println!("cargo:rustc-cfg=runtime_symbol_lint");
    }

    aya_build::emit_bpf_target_arch_cfg()
}
