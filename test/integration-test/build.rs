use std::{env, ffi::OsString, path::PathBuf, process::Command};

fn main() {
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR").unwrap();
    let manifest_dir = PathBuf::from(manifest_dir);
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = PathBuf::from(out_dir);

    let bpf_dir = manifest_dir.join("bpf");
    let libbpf_include_dir = manifest_dir.join("libbpf").join("include");

    let endian = env::var_os("CARGO_CFG_TARGET_ENDIAN").unwrap();
    let target = if endian == "big" {
        "bpfeb"
    } else if endian == "little" {
        "bpfel"
    } else {
        panic!("unsupported endian={:?}", endian)
    };

    let mut target_arch = OsString::new();
    target_arch.push("-D__TARGET_ARCH_");

    let arch = env::var_os("CARGO_CFG_TARGET_ARCH").unwrap();
    if arch == "x86_64" {
        target_arch.push("x86");
    } else if arch == "aarch64" {
        target_arch.push("arm64");
    } else {
        target_arch.push(arch);
    };

    for (src, dst) in [
        ("ext.bpf.c", "ext.bpf.o"),
        ("main.bpf.c", "main.bpf.o"),
        ("multimap-btf.bpf.c", "multimap-btf.bpf.o"),
        ("text_64_64_reloc.c", "text_64_64_reloc.o"),
    ] {
        let src = bpf_dir.join(src);
        let out = out_dir.join(dst);
        let mut cmd = Command::new("clang");
        cmd.arg("-I")
            .arg(&libbpf_include_dir)
            .args(["-g", "-O2", "-target", target, "-c"])
            .arg(&target_arch)
            .arg(src)
            .arg("-o")
            .arg(out);
        let status = cmd
            .status()
            .unwrap_or_else(|err| panic!("failed to run {cmd:?}: {err}"));
        match status.code() {
            Some(code) => match code {
                0 => {}
                code => panic!("{cmd:?} exited with code {code}"),
            },
            None => panic!("{cmd:?} terminated by signal"),
        }
    }
}
