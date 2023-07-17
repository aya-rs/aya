use std::{
    collections::{HashMap, HashSet},
    env,
    ffi::OsString,
    fmt::Write as _,
    fs,
    io::BufReader,
    path::PathBuf,
    process::{Child, Command, Stdio},
};

use cargo_metadata::{
    Artifact, CompilerMessage, Dependency, Message, Metadata, MetadataCommand, Package, Target,
};
use which::which;

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

    const INTEGRATION_EBPF_PACKAGE: &str = "integration-ebpf";

    let Metadata { packages, .. } = MetadataCommand::new().no_deps().exec().unwrap();
    let packages: HashMap<String, _> = packages
        .into_iter()
        .map(|package| {
            let Package { name, .. } = &package;
            (name.clone(), package)
        })
        .collect();

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

        let target = format!("{target}-unknown-none");

        // Teach cargo about our dependencies.
        let mut visited = HashSet::new();
        let mut frontier = vec![INTEGRATION_EBPF_PACKAGE];
        while let Some(package) = frontier.pop() {
            if !visited.insert(package) {
                continue;
            }
            let Package { dependencies, .. } = packages.get(package).unwrap();
            for Dependency { name, path, .. } in dependencies {
                if let Some(path) = path {
                    println!("cargo:rerun-if-changed={}", path.as_str());
                    frontier.push(name);
                }
            }
        }

        // Create a symlink in the out directory to work around the fact that cargo ignores anything
        // in `$CARGO_HOME`, which is also where `cargo install` likes to place binaries. Cargo will
        // stat through the symlink and discover that bpf-linker has changed.
        //
        // This was introduced in https://github.com/rust-lang/cargo/commit/99f841c.
        {
            let bpf_linker = which("bpf-linker").unwrap();
            let bpf_linker_symlink = out_dir.join("bpf-linker");
            match fs::remove_file(&bpf_linker_symlink) {
                Ok(()) => {}
                Err(err) => {
                    if err.kind() != std::io::ErrorKind::NotFound {
                        panic!("failed to remove symlink: {err}")
                    }
                }
            }
            std::os::unix::fs::symlink(&bpf_linker, &bpf_linker_symlink).unwrap();
            println!(
                "cargo:rerun-if-changed={}",
                bpf_linker_symlink.to_str().unwrap()
            );
        }

        let mut cmd = Command::new("cargo");
        cmd.args([
            "build",
            "-p",
            "integration-ebpf",
            "-Z",
            "build-std=core",
            "--release",
            "--message-format=json",
            "--target",
            &target,
        ]);

        // Workaround for https://github.com/rust-lang/cargo/issues/6412 where cargo flocks itself.
        let ebpf_target_dir = out_dir.join("integration-ebpf");
        cmd.arg("--target-dir").arg(&ebpf_target_dir);

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

        let Package { targets, .. } = packages.get(INTEGRATION_EBPF_PACKAGE).unwrap();
        for Target { name, kind, .. } in targets {
            if *kind != ["bin"] {
                continue;
            }
            let dst = out_dir.join(name);
            fs::write(&dst, []).unwrap_or_else(|err| panic!("failed to create {dst:?}: {err}"));
        }
    }
}
