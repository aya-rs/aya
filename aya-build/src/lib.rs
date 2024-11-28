use std::{
    env, fs,
    io::{BufRead as _, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
};

// Re-export `cargo_metadata` to having to encode the version downstream and risk mismatches.
pub use cargo_metadata;
use cargo_metadata::{Artifact, CompilerMessage, Message, Package, Target};

/// Build binary artifacts produced by `packages`.
///
/// This would be better expressed as one or more [artifact-dependencies][bindeps] but issues such
/// as:
///
/// * <https://github.com/rust-lang/cargo/issues/12374>
/// * <https://github.com/rust-lang/cargo/issues/12375>
/// * <https://github.com/rust-lang/cargo/issues/12385>
///
/// prevent their use for the time being.
///
/// [bindeps]: https://doc.rust-lang.org/nightly/cargo/reference/unstable.html?highlight=feature#artifact-dependencies
pub fn build_ebpf(packages: impl IntoIterator<Item = Package>) {
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

    let arch = env::var_os("CARGO_CFG_TARGET_ARCH").unwrap();

    let target = format!("{target}-unknown-none");

    for Package {
        name,
        manifest_path,
        ..
    } in packages
    {
        let dir = manifest_path.parent().unwrap();

        // We have a build-dependency on `name`, so cargo will automatically rebuild us if `name`'s
        // *library* target or any of its dependencies change. Since we depend on `name`'s *binary*
        // targets, that only gets us half of the way. This stanza ensures cargo will rebuild us on
        // changes to the binaries too, which gets us the rest of the way.
        println!("cargo:rerun-if-changed={}", dir.as_str());

        let mut cmd = Command::new("cargo");
        cmd.args([
            "+nightly",
            "build",
            "--package",
            &name,
            "-Z",
            "build-std=core",
            "--bins",
            "--message-format=json",
            "--release",
            "--target",
            &target,
        ]);

        cmd.env("CARGO_CFG_BPF_TARGET_ARCH", &arch);

        // Workaround to make sure that the correct toolchain is used.
        for key in ["RUSTC", "RUSTC_WORKSPACE_WRAPPER"] {
            cmd.env_remove(key);
        }

        // Workaround for https://github.com/rust-lang/cargo/issues/6412 where cargo flocks itself.
        let target_dir = out_dir.join(name);
        cmd.arg("--target-dir").arg(&target_dir);

        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|err| panic!("failed to spawn {cmd:?}: {err}"));
        let Child { stdout, stderr, .. } = &mut child;

        // Trampoline stdout to cargo warnings.
        let stderr = stderr.take().unwrap();
        let stderr = BufReader::new(stderr);
        let stderr = std::thread::spawn(move || {
            for line in stderr.lines() {
                let line = line.unwrap();
                println!("cargo:warning={line}");
            }
        });

        let stdout = stdout.take().unwrap();
        let stdout = BufReader::new(stdout);
        let mut executables = Vec::new();
        for message in Message::parse_stream(stdout) {
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
                    for line in message.rendered.unwrap_or_default().split('\n') {
                        println!("cargo:warning={line}");
                    }
                }
                Message::TextLine(line) => {
                    println!("cargo:warning={line}");
                }
                _ => {}
            }
        }

        let status = child
            .wait()
            .unwrap_or_else(|err| panic!("failed to wait for {cmd:?}: {err}"));
        assert_eq!(status.code(), Some(0), "{cmd:?} failed: {status:?}");

        stderr.join().map_err(std::panic::resume_unwind).unwrap();

        for (name, binary) in executables {
            let dst = out_dir.join(name);
            let _: u64 = fs::copy(&binary, &dst)
                .unwrap_or_else(|err| panic!("failed to copy {binary:?} to {dst:?}: {err}"));
        }
    }
}
