use std::{
    borrow::Cow,
    env,
    ffi::{OsStr, OsString},
    fs,
    io::{BufRead as _, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
};

pub use anyhow::Result;
use anyhow::{Context as _, anyhow};
use cargo_metadata::{Artifact, CompilerMessage, Message, Target};
use rustc_version::Channel;
use which::which;

#[derive(Default)]
pub struct Package<'a> {
    pub name: &'a str,
    pub root_dir: &'a str,
    pub no_default_features: bool,
    pub features: &'a [&'a str],
}

fn target_arch_fixup(target_arch: Cow<'_, str>) -> Cow<'_, str> {
    if target_arch.starts_with("riscv64") {
        "riscv64".into()
    } else {
        target_arch
    }
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
#[expect(clippy::print_stdout, reason = "println! is used for cargo:warning")]
pub fn build_ebpf<'a>(
    packages: impl IntoIterator<Item = Package<'a>>,
    toolchain: Toolchain<'a>,
) -> Result<()> {
    const AYA_BUILD_SKIP: &str = "AYA_BUILD_SKIP";
    println!("cargo:rerun-if-env-changed={AYA_BUILD_SKIP}");
    if let Some(aya_build_skip) = env::var_os(AYA_BUILD_SKIP)
        && (aya_build_skip.eq("1") || aya_build_skip.eq_ignore_ascii_case("true"))
    {
        println!(
            "cargo:warning={AYA_BUILD_SKIP}={}; skipping eBPF build",
            aya_build_skip.display()
        );
        return Ok(());
    }

    const OUT_DIR: &str = "OUT_DIR";
    let out_dir = env::var_os(OUT_DIR).ok_or_else(|| anyhow!("{OUT_DIR} not set"))?;
    let out_dir = PathBuf::from(out_dir);

    const CARGO_CFG_TARGET_ENDIAN: &str = "CARGO_CFG_TARGET_ENDIAN";
    let endian = env::var_os(CARGO_CFG_TARGET_ENDIAN)
        .ok_or_else(|| anyhow!("{CARGO_CFG_TARGET_ENDIAN} not set"))?;
    let target = if endian == "big" {
        "bpfeb"
    } else if endian == "little" {
        "bpfel"
    } else {
        return Err(anyhow!("unsupported endian={}", endian.display()));
    };

    const TARGET_ARCH: &str = "CARGO_CFG_TARGET_ARCH";
    let bpf_target_arch =
        env::var_os(TARGET_ARCH).ok_or_else(|| anyhow!("{TARGET_ARCH} not set"))?;
    let bpf_target_arch = bpf_target_arch.into_string().map_err(|bpf_target_arch| {
        anyhow!(
            "OsString::into_string({TARGET_ARCH}={})",
            bpf_target_arch.display()
        )
    })?;
    let bpf_target_arch = target_arch_fixup(bpf_target_arch.into());
    let target = format!("{target}-unknown-none");

    const RUSTUP: &str = "rustup";
    let rustup = which(RUSTUP);
    let prefix: &[_] = match rustup.as_ref() {
        Ok(rustup) => &[
            rustup.as_os_str(),
            OsStr::new("run"),
            OsStr::new(toolchain.as_str()),
        ],
        Err(err) => {
            println!("cargo:warning=which({RUSTUP})={err}; proceeding with current toolchain");
            &[]
        }
    };

    let cmd = |program| match prefix {
        [] => Command::new(program),
        [wrapper, args @ ..] => {
            let mut cmd = Command::new(wrapper);
            cmd.args(args).arg(program);
            cmd
        }
    };

    let rustc_version::VersionMeta {
        semver: _,
        commit_hash: _,
        commit_date: _,
        build_date: _,
        channel,
        host: _,
        short_version_string: _,
        llvm_version: _,
    } = rustc_version::VersionMeta::for_command(cmd("rustc"))
        .context("failed to get rustc version meta")?;

    for Package {
        name,
        root_dir,
        no_default_features,
        features,
    } in packages
    {
        // We have a build-dependency on `name`, so cargo will automatically rebuild us if `name`'s
        // *library* target or any of its dependencies change. Since we depend on `name`'s *binary*
        // targets, that only gets us half of the way. This stanza ensures cargo will rebuild us on
        // changes to the binaries too, which gets us the rest of the way.
        println!("cargo:rerun-if-changed={root_dir}");

        let mut cmd = cmd("cargo");
        cmd.args([
            "build",
            "--package",
            name,
            "--bins",
            "--message-format=json",
            "--release",
            "--target",
            &target,
        ]);

        if channel == Channel::Nightly {
            cmd.args(["-Z", "build-std=core"]);
        }

        if no_default_features {
            cmd.arg("--no-default-features");
        }

        cmd.args(["--features", &features.join(",")]);

        {
            const SEPARATOR: &str = "\x1f";

            let mut rustflags = OsString::new();

            for s in [
                "--cfg=bpf_target_arch=\"",
                &bpf_target_arch,
                "\"",
                SEPARATOR,
                "-Cdebuginfo=2",
                SEPARATOR,
                "-Clink-arg=--btf",
            ] {
                rustflags.push(s);
            }

            cmd.env("CARGO_ENCODED_RUSTFLAGS", rustflags);
        }

        // Workaround to make sure that the correct toolchain is used.
        for key in ["RUSTC", "RUSTC_WORKSPACE_WRAPPER"] {
            cmd.env_remove(key);
        }

        // Workaround for https://github.com/rust-lang/cargo/issues/6412 where cargo flocks itself.
        //
        // Keep the cargo `--target-dir` separate from `OUT_DIR`'s output artifacts. Otherwise, if
        // the package name matches a bin target name, `target_dir` would collide with the file we
        // later copy to `OUT_DIR/<bin-name>`, causing `fs::copy` to fail with EISDIR.
        let target_dir = out_dir.join("aya-build").join("target").join(name);
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
        for message in Message::parse_stream(stdout) {
            #[expect(clippy::collapsible_match, reason = "better captures intent")]
            match message.with_context(|| anyhow!("cargo stdout stream contains invalid JSON"))? {
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
            let _: u64 = fs::copy(&binary, &dst).with_context(|| {
                format!("failed to copy {} to {}", binary.display(), dst.display())
            })?;
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
    const fn as_str(&self) -> &'a str {
        match self {
            Self::Nightly => "nightly",
            Self::Custom(toolchain) => toolchain,
        }
    }
}

/// Emit cfg flags that describe the desired BPF target architecture.
#[expect(clippy::print_stdout, reason = "println! is used for cargo:warning")]
pub fn emit_bpf_target_arch_cfg() -> Result<()> {
    // The presence of this environment variable indicates that `--cfg
    // bpf_target_arch="..."` was passed to the compiler, so we don't need to
    // emit it again. Note that we cannot *set* this environment variable - it
    // is set by cargo.
    const BPF_TARGET_ARCH: &str = "CARGO_CFG_BPF_TARGET_ARCH";
    println!("cargo:rerun-if-env-changed={BPF_TARGET_ARCH}");

    // Users may directly set this environment variable in situations where
    // using RUSTFLAGS to set `--cfg bpf_target_arch="..."` is not possible or
    // not ergonomic. In contrast to RUSTFLAGS this mechanism reuses the target
    // cache for all values, producing many more invalidations.
    const AYA_BPF_TARGET_ARCH: &str = "AYA_BPF_TARGET_ARCH";
    println!("cargo:rerun-if-env-changed={AYA_BPF_TARGET_ARCH}");

    const HOST: &str = "HOST";
    println!("cargo:rerun-if-env-changed={HOST}");

    if env::var_os(BPF_TARGET_ARCH).is_none() {
        let host = env::var_os(HOST).ok_or_else(|| anyhow!("{HOST} not set"))?;
        let host = host
            .into_string()
            .map_err(|host| anyhow!("OsString::into_string({HOST}={})", host.display()))?;
        let host = host.as_str();

        let bpf_target_arch = if let Some(bpf_target_arch) = env::var_os(AYA_BPF_TARGET_ARCH) {
            bpf_target_arch
                .into_string()
                .map_err(|bpf_target_arch| {
                    anyhow!(
                        "OsString::into_string({AYA_BPF_TARGET_ARCH}={})",
                        bpf_target_arch.display()
                    )
                })?
                .into()
        } else {
            target_arch_fixup(
                host.split_once('-')
                    .map_or(host, |(arch, _rest)| arch)
                    .into(),
            )
        };
        println!("cargo:rustc-cfg=bpf_target_arch=\"{bpf_target_arch}\"");
    }

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

    Ok(())
}
