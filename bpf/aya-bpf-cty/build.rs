use std::env;

fn main() {
    if !env::var("CARGO_CFG_BPF_TARGET_ARCH").is_ok() {
        let arch = env::var("HOST").unwrap();
        let arch = arch.splitn(2, "-").next().unwrap();
        println!("cargo:rustc-cfg=bpf_target_arch=\"{}\"", arch);
    }
}
