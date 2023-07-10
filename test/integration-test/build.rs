use std::{
    env,
    ffi::OsString,
    fmt::Write as _,
    fs::copy,
    io::BufReader,
    path::PathBuf,
    process::{Command, Stdio},
};

use cargo_metadata::{Artifact, CompilerMessage, Message, Target};

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

    let ebpf_dir = manifest_dir.parent().unwrap().join("integration-ebpf");
    let target = format!("{target}-unknown-none");

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&ebpf_dir).args([
        "build",
        "-Z",
        "build-std=core",
        "--release",
        "--message-format=json",
        "--target",
        &target,
    ]);
    let mut cmd = cmd
        .stdout(Stdio::piped())
        .spawn()
        .unwrap_or_else(|err| panic!("failed to spawn {cmd:?}: {err}"));

    let reader = BufReader::new(cmd.stdout.take().unwrap());
    let mut executables = Vec::new();
    let mut compiler_messages = String::new();
    for message in Message::parse_stream(reader) {
        #[allow(clippy::collapsible_match)]
        match message.expect("valid JSON") {
            Message::CompilerArtifact(Artifact {
                executable,
                target: Target { name, .. },
                ..
            }) => {
                if let Some(executable) = executable {
                    executables.push((name, executable.into_std_path_buf()));
                }
            }
            Message::CompilerMessage(CompilerMessage { message, .. }) => {
                writeln!(&mut compiler_messages, "{message}").unwrap()
            }
            _ => {}
        }
    }

    let status = cmd
        .wait()
        .unwrap_or_else(|err| panic!("failed to wait for {cmd:?}: {err}"));

    match status.code() {
        Some(code) => match code {
            0 => {}
            code => panic!("{cmd:?} exited with status code {code}:\n{compiler_messages}"),
        },
        None => panic!("{cmd:?} terminated by signal"),
    }

    for (name, binary) in executables {
        let dst = out_dir.join(name);
        let _: u64 = copy(&binary, &dst)
            .unwrap_or_else(|err| panic!("failed to copy {binary:?} to {dst:?}: {err}"));
    }
}
