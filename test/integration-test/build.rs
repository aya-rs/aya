use std::{
    env,
    ffi::OsString,
    fmt::Write as _,
    fs,
    io::BufReader,
    path::PathBuf,
    process::{Child, Command, Stdio},
};

use cargo_metadata::{
    Artifact, CompilerMessage, Message, Metadata, MetadataCommand, Package, Target,
};

fn main() {
    const AYA_BUILD_INTEGRATION_BPF: &str = "AYA_BUILD_INTEGRATION_BPF";

    println!("cargo:rerun-if-env-changed={}", AYA_BUILD_INTEGRATION_BPF);

    let build_integration_bpf = match env::var_os(AYA_BUILD_INTEGRATION_BPF) {
        None => false,
        Some(s) => {
            let s = s.to_str().unwrap();
            s.parse::<bool>().unwrap()
        }
    };

    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR").unwrap();
    let manifest_dir = PathBuf::from(manifest_dir);
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = PathBuf::from(out_dir);

    let endian = env::var_os("CARGO_CFG_TARGET_ENDIAN").unwrap();
    let target = if endian == "big" {
        "bpfeb"
    } else if endian == "little" {
        "bpfel"
    } else {
        panic!("unsupported endian={:?}", endian)
    };

    const C_BPF_PROBES: &[(&str, &str)] = &[
        ("ext.bpf.c", "ext.bpf.o"),
        ("main.bpf.c", "main.bpf.o"),
        ("multimap-btf.bpf.c", "multimap-btf.bpf.o"),
        ("text_64_64_reloc.c", "text_64_64_reloc.o"),
    ];

    let c_bpf_probes = C_BPF_PROBES
        .iter()
        .map(|(src, dst)| (src, out_dir.join(dst)));

    if build_integration_bpf {
        let libbpf_dir = manifest_dir
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("libbpf");

        let libbpf_headers_dir = out_dir.join("libbpf_headers");

        let mut includedir = OsString::new();
        includedir.push("INCLUDEDIR=");
        includedir.push(&libbpf_headers_dir);

        let mut cmd = Command::new("make");
        cmd.arg("-C")
            .arg(libbpf_dir.join("src"))
            .arg(includedir)
            .arg("install_headers");
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

        let bpf_dir = manifest_dir.join("bpf");

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

        for (src, dst) in c_bpf_probes {
            let src = bpf_dir.join(src);
            println!("cargo:rerun-if-changed={}", src.to_str().unwrap());
            let mut cmd = Command::new("clang");
            cmd.arg("-I")
                .arg(&libbpf_headers_dir)
                .args(["-g", "-O2", "-target", target, "-c"])
                .arg(&target_arch)
                .arg(src)
                .arg("-o")
                .arg(dst);
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
        println!("cargo:rerun-if-changed={}", ebpf_dir.to_str().unwrap());
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
        let mut child = cmd
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|err| panic!("failed to spawn {cmd:?}: {err}"));
        let Child { stdout, .. } = &mut child;
        let stdout = stdout.take().unwrap();
        let reader = BufReader::new(stdout);
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

        let status = child
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
            let _: u64 = fs::copy(&binary, &dst)
                .unwrap_or_else(|err| panic!("failed to copy {binary:?} to {dst:?}: {err}"));
        }
    } else {
        for (_src, dst) in c_bpf_probes {
            fs::write(&dst, []).unwrap_or_else(|err| panic!("failed to create {dst:?}: {err}"));
        }

        let Metadata { packages, .. } = MetadataCommand::new().no_deps().exec().unwrap();
        for Package { name, targets, .. } in packages {
            if name != "integration-ebpf" {
                continue;
            }
            for Target { name, kind, .. } in targets {
                if kind != ["bin"] {
                    continue;
                }
                let dst = out_dir.join(name);
                fs::write(&dst, []).unwrap_or_else(|err| panic!("failed to create {dst:?}: {err}"));
            }
        }
    }
}
