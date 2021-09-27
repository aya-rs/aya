use std::env;

fn main() {
    if env::var("CARGO_CFG_BPF_TARGET_ARCH").is_err() {
        let arch = env::var("HOST").unwrap();
        let arch = arch.split_once('-').map_or(&*arch, |x| x.0);
        println!("cargo:rustc-cfg=bpf_target_arch=\"{}\"", arch);
    }
}
