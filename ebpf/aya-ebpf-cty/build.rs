fn main() -> aya_build::Result<()> {
    println!("cargo::rustc-check-cfg=cfg(target_arch, values(\"asmjs\",\"nvptx\",\"xtensa\"))");

    aya_build::emit_bpf_target_arch_cfg()
}
