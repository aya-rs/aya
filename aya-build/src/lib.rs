use std::{
    env, fs,
    io::{BufRead as _, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
};

use anyhow::{Context as _, Result, anyhow};

pub struct Package<'a> {
    pub name: &'a str,
    pub root_dir: &'a str,
}

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
pub fn build_ebpf<'a, I>(packages: I, toolchain: Toolchain<'a>) -> Result<()>
where
    I: IntoIterator<Item = Package<'a>>,
{
    let out_dir = env::var_os("OUT_DIR").ok_or(anyhow!("OUT_DIR not set"))?;
    let out_dir = PathBuf::from(out_dir);

    let endian =
        env::var_os("CARGO_CFG_TARGET_ENDIAN").ok_or(anyhow!("CARGO_CFG_TARGET_ENDIAN not set"))?;
    let target = if endian == "big" {
        "bpfeb"
    } else if endian == "little" {
        "bpfel"
    } else {
        return Err(anyhow!("unsupported endian={endian:?}"));
    };

    let arch =
        env::var_os("CARGO_CFG_TARGET_ARCH").ok_or(anyhow!("CARGO_CFG_TARGET_ARCH not set"))?;

    let target = format!("{target}-unknown-none");

    for Package { name, root_dir } in packages {
        // We have a build-dependency on `name`, so cargo will automatically rebuild us if `name`'s
        // *library* target or any of its dependencies change. Since we depend on `name`'s *binary*
        // targets, that only gets us half of the way. This stanza ensures cargo will rebuild us on
        // changes to the binaries too, which gets us the rest of the way.
        println!("cargo:rerun-if-changed={root_dir}");

        let mut cmd = Command::new("rustup");
        cmd.args([
            "run",
            toolchain.as_str(),
            "cargo",
            "build",
            "--package",
            name,
            "-Z",
            "build-std=core",
            "--bins",
            "--message-format=json",
            "--release",
            "--target",
            &target,
        ]);

        cmd.env("CARGO_CFG_BPF_TARGET_ARCH", &arch);
        cmd.env(
            "CARGO_ENCODED_RUSTFLAGS",
            ["debuginfo=2", "link-arg=--btf"]
                .into_iter()
                .flat_map(|flag| ["-C", flag])
                .fold(String::new(), |mut acc, flag| {
                    if !acc.is_empty() {
                        acc.push('\x1f');
                    }
                    acc.push_str(flag);
                    acc
                }),
        );

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
            .with_context(|| format!("failed to spawn {cmd:?}"))?;
        let Child { stdout, stderr, .. } = &mut child;

        // Trampoline stdout to cargo warnings.
        let stderr = stderr.take().expect("stderr");
        let stderr = BufReader::new(stderr);
        let stderr = std::thread::spawn(move || {
            for line in stderr.lines() {
                let line = line.expect("read line");
                println!("cargo:warning={line}");
            }
        });

        let stdout = stdout.take().expect("stdout");
        let stdout = BufReader::new(stdout);
        let mut executables = Vec::new();
        for message in cargo_metadata::Message::parse_stream(stdout) {
            #[expect(clippy::collapsible_match)]
            match message.expect("valid JSON") {
                cargo_metadata::Message::CompilerArtifact(cargo_metadata::Artifact {
                    executable,
                    target: cargo_metadata::Target { name, .. },
                    ..
                }) => {
                    if let Some(executable) = executable {
                        executables.push((name, executable.into_std_path_buf()));
                    }
                }
                cargo_metadata::Message::CompilerMessage(cargo_metadata::CompilerMessage {
                    message,
                    ..
                }) => {
                    for line in message.rendered.unwrap_or_default().split('\n') {
                        println!("cargo:warning={line}");
                    }
                }
                cargo_metadata::Message::TextLine(line) => {
                    println!("cargo:warning={line}");
                }
                _ => {}
            }
        }

        let status = child
            .wait()
            .with_context(|| format!("failed to wait for {cmd:?}"))?;
        if !status.success() {
            return Err(anyhow!("{cmd:?} failed: {status:?}"));
        }

        match stderr.join().map_err(std::panic::resume_unwind) {
            Ok(()) => {}
            Err(err) => match err {},
        }

        for (name, binary) in executables {
            let dst = out_dir.join(name);
            let _: u64 = fs::copy(&binary, &dst)
                .with_context(|| format!("failed to copy {binary:?} to {dst:?}"))?;
        }
    }
    Ok(())
}

/// The toolchain to use for building eBPF programs.
#[derive(Default)]
pub enum Toolchain<'a> {
    /// The latest nightly toolchain i.e. `nightly`.
    #[default]
    Nightly,
    /// A custom toolchain e.g. `nightly-2021-01-01`.
    ///
    /// The toolchain specifier is passed to `rustup run` and therefore should _not_ have a preceding `+`.
    Custom(&'a str),
}

impl<'a> Toolchain<'a> {
    fn as_str(&self) -> &'a str {
        match self {
            Toolchain::Nightly => "nightly",
            Toolchain::Custom(toolchain) => toolchain,
        }
    }
}

/// Emit cfg flags that describe the desired BPF target architecture.
pub fn emit_bpf_target_arch_cfg() {
    println!("cargo:rerun-if-env-changed=CARGO_CFG_BPF_TARGET_ARCH");
    let bpf_target_arch = env::var_os("CARGO_CFG_BPF_TARGET_ARCH");
    let target_arch = env::var_os("CARGO_CFG_TARGET_ARCH");
    let arch = if let Some(bpf_target_arch) = bpf_target_arch.as_ref() {
        bpf_target_arch.to_str().unwrap()
    } else {
        let target_arch = target_arch.as_ref().unwrap().to_str().unwrap();
        if target_arch.starts_with("riscv64") {
            "riscv64"
        } else {
            target_arch
        }
    };
    println!("cargo:rustc-cfg=bpf_target_arch=\"{arch}\"");

    print!("cargo::rustc-check-cfg=cfg(bpf_target_arch, values(");
    for value in [
        "aarch64",
        "arm",
        "loongarch64",
        "mips",
        "powerpc64",
        "riscv64",
        "s390x",
        "x86_64",
    ] {
        print!("\"{value}\",");
    }
    println!("))");
}
