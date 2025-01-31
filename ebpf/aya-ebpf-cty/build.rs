use std::env;

fn main() {
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
    println!("cargo::rustc-check-cfg=cfg(bpf_target_arch, values(\"x86_64\",\"arm\",\"aarch64\",\"riscv64\",\"powerpc64\",\"s390x\",\"mips\"))");
    println!("cargo::rustc-check-cfg=cfg(target_arch, values(\"asmjs\",\"nvptx\",\"xtensa\"))");
}
