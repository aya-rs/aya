#![allow(clippy::print_stdout, reason = "xtask is a CLI tool")]
#![allow(clippy::print_stderr, reason = "xtask is a CLI tool")]
#![allow(clippy::use_debug, reason = "debug output aids troubleshooting")]

use std::{
    env,
    ffi::{OsStr, OsString},
    fmt::{Arguments, Write as _},
    fs::{self, OpenOptions},
    io::{BufRead as _, BufReader, Write as _},
    ops::Deref as _,
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Output, Stdio},
    sync::{Arc, Mutex},
    thread,
};

use anyhow::{Context as _, Result, anyhow, bail};
use cargo_metadata::{Artifact, CompilerMessage, Message, Target};
use clap::{Parser, ValueEnum};
use walkdir::WalkDir;
use xtask::{AYA_BUILD_INTEGRATION_BPF, Errors, libbpf_sys_env};

use crate::{
    http::HttpClient,
    ubuntu_mainline::{
        KernelArchitecture, KernelPackage, download_ubuntu_mainline_kernel_packages,
    },
};

const GEN_INIT_CPIO_PATCH: &str = include_str!("../patches/gen_init_cpio.c.macos.diff");
// We build gen_init_cpio as a host-side tool for creating the VM
// initramfs. Pin the source file because we apply GEN_INIT_CPIO_PATCH
// below and need stable patch input.
// https://github.com/torvalds/linux/blob/v6.18/usr/gen_init_cpio.c
const GEN_INIT_CPIO_VERSION: &str = "v6.18";
const GEN_INIT_CPIO_PATH: &str = "usr/gen_init_cpio.c";

struct GitHubLogGroup;

impl GitHubLogGroup {
    fn new(title: Arguments<'_>) -> Option<Self> {
        if env::var_os("GITHUB_ACTIONS").is_none_or(|value| value != "true") {
            return None;
        }

        println!("::group::{title}");
        Some(Self)
    }
}

impl Drop for GitHubLogGroup {
    fn drop(&mut self) {
        println!("::endgroup::");
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum TestProfile {
    Dev,
    Release,
}

impl TestProfile {
    const DEFAULTS: &'static [Self] = &[Self::Dev, Self::Release];

    const fn cargo_profile(self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Release => "release",
        }
    }
}

#[derive(Parser)]
enum Environment {
    /// Runs the integration tests locally.
    Local {
        /// The command used to wrap your application.
        #[clap(short, long, default_value = "sudo -E")]
        runner: String,
    },
    /// Runs the integration tests in a VM.
    VM {
        /// The cache directory in which to store intermediate artifacts.
        #[clap(long)]
        cache_dir: PathBuf,

        /// Ubuntu Mainline architecture to resolve kernel version arguments for.
        #[clap(long, value_enum)]
        kernel_arch: KernelArchitecture,

        /// Test binary build profile to run. Defaults to both dev and release.
        #[clap(long = "test-profile", value_enum, value_name = "PROFILE")]
        test_profile: Option<TestProfile>,

        /// Ubuntu Mainline versions such as 5.15 or 6.6.
        #[clap(required = true, value_name = "VERSION")]
        kernels: Vec<String>,
    },
}

const INTEGRATION_TEST_PACKAGE: &str = "integration-test";

#[derive(Parser)]
pub(crate) struct Options {
    #[clap(subcommand)]
    environment: Environment,

    /// The package whose tests to build and run.
    #[clap(short = 'p', long, global = true, default_value = INTEGRATION_TEST_PACKAGE)]
    package: String,

    /// Arguments to pass to your application.
    #[clap(global = true, last = true)]
    run_args: Vec<OsString>,
}

pub(crate) fn build<F>(target: Option<&str>, f: F) -> Result<Vec<(String, PathBuf)>>
where
    F: FnOnce(&mut Command) -> &mut Command,
{
    // Always use rust-lld in case we're cross-compiling.
    let mut cargo = Command::new("cargo");
    cargo.args(["build", "--message-format=json"]);
    if let Some(target) = target {
        cargo.args(["--target", target]);
    }
    f(&mut cargo);

    let mut cargo_child = cargo
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn {cargo:?}"))?;
    let Child { stdout, .. } = &mut cargo_child;

    let stdout = stdout.take().unwrap();
    let stdout = BufReader::new(stdout);
    let mut executables = Vec::new();
    for message in Message::parse_stream(stdout) {
        #[expect(clippy::collapsible_match, reason = "better captures intent")]
        match message.context("valid JSON")? {
            Message::CompilerArtifact(Artifact {
                executable,
                target: Target { name, .. },
                ..
            }) => {
                if let Some(executable) = executable {
                    executables.push((name, executable.into()));
                }
            }
            Message::CompilerMessage(CompilerMessage { message, .. }) => {
                if let Some(rendered) = message.rendered {
                    print!("{rendered}");
                }
            }
            Message::TextLine(line) => {
                println!("{line}");
            }
            _ => {}
        }
    }

    let status = cargo_child
        .wait()
        .with_context(|| format!("failed to wait for {cargo:?}"))?;
    if status.code() != Some(0) {
        bail!("{cargo:?} failed: {status:?}")
    }
    Ok(executables)
}

/// Build and run the project.
pub(crate) fn run(opts: Options, workspace_root: &Path) -> Result<()> {
    let Options {
        environment,
        package,
        run_args,
    } = opts;

    type Binary = (String, PathBuf);

    let binaries = |package: &str,
                    target: Option<&str>,
                    envs: &[(&OsStr, &OsStr)],
                    test_profiles: &[TestProfile]|
     -> Result<Vec<(&'static str, Vec<Binary>)>> {
        test_profiles
            .iter()
            .copied()
            .map(|profile| {
                let profile = profile.cargo_profile();
                let binaries = build(target, |cmd| {
                    if package == INTEGRATION_TEST_PACKAGE {
                        cmd.env(AYA_BUILD_INTEGRATION_BPF, "true");
                        libbpf_sys_env(workspace_root, cmd);
                    }
                    cmd.envs(envs.iter().copied()).args([
                        "--package",
                        package,
                        "--tests",
                        "--profile",
                        profile,
                    ])
                })?;
                anyhow::Ok((profile, binaries))
            })
            .collect()
    };

    // Use --test-threads=1 to prevent tests from interacting with shared
    // kernel state due to the lack of inter-test isolation.
    let default_args = ["--test-threads=1"];
    let run_args = default_args
        .iter()
        .map(OsStr::new)
        .chain(run_args.iter().map(OsString::as_os_str));

    match environment {
        Environment::Local { runner } => {
            let mut args = runner.trim().split_terminator(' ');
            let runner = args.next().ok_or_else(|| anyhow!("no first argument"))?;

            let binaries = binaries(&package, None, &[], TestProfile::DEFAULTS)?;

            let mut failures = String::new();
            for (profile, binaries) in binaries {
                for (name, binary) in binaries {
                    let mut cmd = Command::new(runner);
                    cmd.args(args.clone())
                        .arg(binary)
                        .args(run_args.clone())
                        .env("RUST_BACKTRACE", "1")
                        .env("RUST_LOG", "debug");

                    println!("{profile}:{name} running {cmd:?}");

                    let status = cmd
                        .status()
                        .with_context(|| format!("failed to run {cmd:?}"))?;
                    if status.code() != Some(0) {
                        writeln!(&mut failures, "{profile}:{name} failed: {status:?}")
                            .context("String write failed")?
                    }
                }
            }
            if failures.is_empty() {
                Ok(())
            } else {
                Err(anyhow!("failures:\n{failures}"))
            }
        }
        Environment::VM {
            cache_dir,
            kernel_arch,
            test_profile,
            kernels,
        } => {
            // The user has asked us to run the tests on a VM. This is involved; strap in.
            //
            // We need tools to build the initramfs; we use gen_init_cpio from the Linux repository,
            // taking care to cache it.
            //
            // We resolve Ubuntu Mainline kernel versions for the requested
            // architecture. We then build the init program and our test
            // binaries for that architecture, and use
            // gen_init_cpio to build an initramfs containing the test binaries.
            // We're ready to run the VM.
            //
            // We start QEMU with the provided kernel image and the initramfs we built.
            //
            // We consume the output of QEMU, looking for the output of our init program. This is
            // the only way to distinguish success from failure. We batch up the errors across all
            // VM images and report to the user.
            //
            // The end.

            fs::create_dir_all(&cache_dir).context("failed to create cache dir")?;
            let http_client = HttpClient::new();

            let gen_init_cpio = cache_dir.join("gen_init_cpio");
            {
                let source_dir = cache_dir
                    .join("gen_init_cpio-source")
                    .join(GEN_INIT_CPIO_VERSION);
                let dest_path = source_dir.join("gen_init_cpio.c");
                let etag_path = source_dir.join("gen_init_cpio.etag");
                let gen_init_cpio_url = format!(
                    "https://raw.githubusercontent.com/torvalds/linux/{GEN_INIT_CPIO_VERSION}/{GEN_INIT_CPIO_PATH}"
                );
                http_client.download_to_path(&gen_init_cpio_url, &dest_path, &etag_path)?;

                let mut patch = Command::new("patch");
                patch
                    .current_dir(&source_dir)
                    .args(["--quiet", "--forward", "--output", "-"])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped());
                let mut patch_child = patch
                    .spawn()
                    .with_context(|| format!("failed to spawn {patch:?}"))?;

                let Child { stdin, stdout, .. } = &mut patch_child;
                let mut stdin = stdin.take().unwrap();
                stdin
                    .write_all(GEN_INIT_CPIO_PATCH.as_bytes())
                    .with_context(|| format!("failed to write to {patch:?} stdin"))?;
                drop(stdin); // Must explicitly close to signal EOF.
                let stdout = stdout.take().unwrap();

                let mut clang = Command::new("clang");
                clang
                    .args(["-g", "-O2", "-x", "c", "-", "-o"])
                    .arg(&gen_init_cpio)
                    .stdin(stdout);
                let clang_child = clang
                    .spawn()
                    .with_context(|| format!("failed to spawn {clang:?}"))?;

                let output = patch_child
                    .wait_with_output()
                    .with_context(|| format!("failed to wait for {patch:?}"))?;
                let Output { status, .. } = &output;
                if status.code() != Some(0) {
                    bail!("{patch:?} failed: {output:?}")
                }

                let output = clang_child
                    .wait_with_output()
                    .with_context(|| format!("failed to wait for {clang:?}"))?;
                let Output { status, .. } = &output;
                if status.code() != Some(0) {
                    bail!("{clang:?} failed: {output:?}")
                }
            }

            let extraction_root = tempfile::tempdir().context("tempdir failed")?;
            let kernel_packages = download_ubuntu_mainline_kernel_packages(
                &http_client,
                &cache_dir,
                extraction_root.path(),
                kernel_arch,
                &kernels,
            )?;

            let mut errors = Vec::new();
            for kernel_package in kernel_packages {
                let KernelPackage {
                    base,
                    kernel_image,
                    config,
                    modules_dir,
                    system_map,
                } = kernel_package;
                // Fold each kernel's integration test output in GitHub Actions.
                let _github_group =
                    GitHubLogGroup::new(format_args!("VM integration tests on {}", base.display()));

                // Fixed VM launch configuration for each supported kernel
                // architecture.
                let (guest_arch, machine, cpu, console) = match kernel_arch {
                    KernelArchitecture::Amd64 => (
                        "x86_64",
                        None,
                        cfg!(target_arch = "x86_64").then_some("host"),
                        "ttyS0",
                    ),
                    KernelArchitecture::Arm64 => (
                        "aarch64",
                        Some("virt"),
                        // NB: we'd prefer to write:
                        //
                        // ```
                        // Some(if cfg!(target_arch = "aarch64") {
                        //   "host"
                        // } else {
                        //   "neoverse-n1"
                        // }))
                        // ```
                        //
                        // but that only works in the presence of KVM or HVF and
                        // Github arm64 runners do not support nested
                        // virtualization. Since we aren't doing our own KVM/HVF
                        // detection (we let QEMU pick the best accelerator), we
                        // hardcode the emulated cpu.
                        //
                        // We use neoverse-n1 since it's relatively new but not
                        // too new. We used to use "max" and let QEMU pick the
                        // newest available cpu, until one day that triggered a
                        // QEMU bug that broke CI.
                        Some("neoverse-n1"),
                        "ttyAMA0",
                    ),
                };

                let target = format!("{guest_arch}-unknown-linux-musl");

                let test_distro_args = [
                    "--package",
                    "test-distro",
                    "--release",
                    "--features",
                    "xz2,zstd",
                ];
                let test_distro: Vec<(String, PathBuf)> =
                    build(Some(&target), |cmd| cmd.args(test_distro_args))
                        .context("building test-distro package failed")?;

                // Set up cross compilation.
                //
                // See https://github.com/libbpf/libbpf-sys/issues/137.
                let mut extra;
                let envs: &[_] = if package == INTEGRATION_TEST_PACKAGE {
                    const LIBBPF_SYS_EXTRA_CFLAGS: &str = "LIBBPF_SYS_EXTRA_CFLAGS";
                    extra = OsString::new();
                    extra.push(format!(
                        "-idirafter /usr/include/{guest_arch}-linux-gnu -idirafter /usr/include",
                    ));
                    if guest_arch == "aarch64" {
                        extra.push(" -mno-outline-atomics");
                    }
                    if let Some(existing) = env::var_os(LIBBPF_SYS_EXTRA_CFLAGS) {
                        extra.push(" ");
                        extra.push(existing);
                    }
                    &[(OsStr::new(LIBBPF_SYS_EXTRA_CFLAGS), extra.as_os_str())]
                } else {
                    &[]
                };

                let test_profiles = test_profile
                    .as_ref()
                    .map_or(TestProfile::DEFAULTS, std::slice::from_ref);
                let binaries = binaries(&package, Some(&target), envs, test_profiles)?;

                let tmp_dir = tempfile::tempdir().context("tempdir failed")?;

                let initrd_image = tmp_dir.path().join("qemu-initramfs.img");
                let initrd_image_file = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&initrd_image)
                    .with_context(|| {
                        format!("failed to create {} for writing", initrd_image.display())
                    })?;

                let mut gen_init_cpio = Command::new(&gen_init_cpio);
                let mut gen_init_cpio_child = gen_init_cpio
                    .arg("-")
                    .stdin(Stdio::piped())
                    .stdout(initrd_image_file)
                    .spawn()
                    .with_context(|| format!("failed to spawn {gen_init_cpio:?}"))?;
                let Child { stdin, .. } = &mut gen_init_cpio_child;
                let stdin = Arc::new(stdin.take().unwrap());
                use std::os::unix::ffi::OsStrExt as _;

                // Send input into gen_init_cpio for directories
                //
                // dir  /bin                  755 0 0
                let write_dir = |out_path: &Path| {
                    for bytes in [b"dir ", out_path.as_os_str().as_bytes(), b" ", b"755 0 0\n"] {
                        stdin.deref().write_all(bytes).expect("write");
                    }
                };

                // Send input into gen_init_cpio for files
                //
                // file /init    path-to-init 755 0 0
                let write_file = |out_path: &Path, in_path: &Path, mode: &str| {
                    for bytes in [
                        b"file ",
                        out_path.as_os_str().as_bytes(),
                        b" ",
                        in_path.as_os_str().as_bytes(),
                        b" ",
                        mode.as_bytes(),
                        b"\n",
                    ] {
                        stdin.deref().write_all(bytes).expect("write");
                    }
                };

                write_dir(Path::new("/bin"));
                write_dir(Path::new("/sbin"));
                write_dir(Path::new("/boot"));
                write_dir(Path::new("/lib"));
                write_dir(Path::new("/lib/modules"));

                write_file(Path::new("/boot/config"), &config, "644 0 0");
                if let Some(name) = config.file_name() {
                    write_file(&Path::new("/boot").join(name), &config, "644 0 0");
                }

                write_file(Path::new("/boot/System.map"), &system_map, "644 0 0");
                if let Some(name) = system_map.file_name() {
                    write_file(&Path::new("/boot").join(name), &system_map, "644 0 0");
                }

                for (name, path) in &test_distro {
                    if name == "init" {
                        write_file(Path::new("/init"), path, "755 0 0");
                    } else {
                        write_file(&Path::new("/sbin").join(name), path, "755 0 0");
                    }
                }

                // At this point we need to make a slight detour!
                // Preparing the `modules.alias` file inside the VM as part of
                // `/init` is slow. It's faster to prepare it here.
                let mut cargo = Command::new("cargo");
                let output = cargo
                    .arg("run")
                    .args(test_distro_args)
                    .args(["--bin", "depmod", "--", "-b"])
                    .arg(&modules_dir)
                    .output()
                    .with_context(|| format!("failed to run {cargo:?}"))?;
                let Output { status, .. } = &output;
                if status.code() != Some(0) {
                    bail!("{cargo:?} failed: {output:?}")
                }

                // Now our modules.alias file is built, we can recursively
                // walk the modules directory and add all the files to the
                // initramfs.
                for entry in WalkDir::new(&modules_dir) {
                    let entry = entry.context("read_dir failed")?;
                    let path = entry.path();
                    let metadata = entry.metadata().context("metadata failed")?;
                    let out_path = Path::new("/lib/modules").join(
                        path.strip_prefix(&modules_dir).with_context(|| {
                            format!(
                                "strip prefix {} failed for {}",
                                path.display(),
                                modules_dir.display()
                            )
                        })?,
                    );
                    #[expect(
                        clippy::filetype_is_file,
                        reason = "we only want to copy regular files"
                    )]
                    if metadata.file_type().is_dir() {
                        write_dir(&out_path);
                    } else if metadata.file_type().is_file() {
                        write_file(&out_path, path, "644 0 0");
                    }
                }

                for (profile, binaries) in binaries {
                    for (name, binary) in binaries {
                        let name = format!("{profile}-{name}");
                        let path = tmp_dir.path().join(&name);
                        fs::copy(&binary, &path).with_context(|| {
                            format!("copy({}, {}) failed", binary.display(), path.display())
                        })?;
                        let out_path = Path::new("/bin").join(&name);
                        write_file(&out_path, &path, "755 0 0");
                    }
                }

                // Must explicitly close to signal EOF.
                drop(stdin);

                let output = gen_init_cpio_child
                    .wait_with_output()
                    .with_context(|| format!("failed to wait for {gen_init_cpio:?}"))?;
                let Output { status, .. } = &output;
                if status.code() != Some(0) {
                    bail!("{gen_init_cpio:?} failed: {output:?}")
                }

                let mut qemu = Command::new(format!("qemu-system-{guest_arch}"));
                if let Some(machine) = machine {
                    qemu.args(["-machine", machine]);
                }
                if let Some(cpu) = cpu {
                    qemu.args(["-cpu", cpu]);
                }
                for accel in ["kvm", "hvf", "tcg"] {
                    qemu.args(["-accel", accel]);
                }
                let console = OsStr::new(console);
                let mut kernel_args = std::iter::once(("console", console))
                    .chain(run_args.clone().map(|run_arg| ("init.arg", run_arg)))
                    .enumerate()
                    .fold(OsString::new(), |mut acc, (i, (k, v))| {
                        if i != 0 {
                            acc.push(" ");
                        }
                        acc.push(k);
                        acc.push("=");
                        acc.push(v);
                        acc
                    });
                // We sometimes see kernel panics containing:
                //
                // [    0.064000] Kernel panic - not syncing: IO-APIC + timer doesn't work!  Boot with apic=debug and send a report.  Then try booting with the 'noapic' option.
                //
                // Heed the advice and boot with noapic. We don't know why this happens.
                kernel_args.push(" noapic");
                // Activate BPF LSM so `#[lsm]` programs actually run their hooks.
                // Without this, `CONFIG_BPF_LSM=y` kernels still leave `bpf`
                // out of `/sys/kernel/security/lsm` and LSM tests exercise
                // only load/attach, missing runtime regressions.
                kernel_args.push(" lsm=bpf");
                // Ubuntu Mainline arm64 packages can make the initramfs large
                // enough that 1G fails to unpack it, leaving a broken rootfs.
                qemu.args(["-no-reboot", "-nographic", "-m", "2048M", "-smp", "2"])
                    .arg("-append")
                    .arg(kernel_args)
                    .arg("-kernel")
                    .arg(&kernel_image)
                    .arg("-initrd")
                    .arg(&initrd_image);
                let mut qemu_child = qemu
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .with_context(|| format!("failed to spawn {qemu:?}"))?;
                let Child {
                    stdin,
                    stdout,
                    stderr,
                    ..
                } = &mut qemu_child;
                let stdin = stdin.take().unwrap();
                let stdin = Arc::new(Mutex::new(stdin));
                let stdout = stdout.take().unwrap();
                let stdout = BufReader::new(stdout);
                let stderr = stderr.take().unwrap();
                let stderr = BufReader::new(stderr);

                const TERMINATE_AFTER_COUNT: &[(&str, usize)] = &[
                    ("end Kernel panic", 0),
                    ("rcu: RCU grace-period kthread stack dump:", 0),
                    ("watchdog: BUG: soft lockup", 1),
                ];
                let mut counts = [0; TERMINATE_AFTER_COUNT.len()];

                let mut terminate_if_kernel_hang =
                    move |line: &str, stdin: &Arc<Mutex<ChildStdin>>| -> Result<()> {
                        if let Some(i) = TERMINATE_AFTER_COUNT
                            .iter()
                            .position(|(marker, _)| line.contains(marker))
                        {
                            counts[i] += 1;

                            let (marker, max) = TERMINATE_AFTER_COUNT[i];
                            if counts[i] > max {
                                println!("{marker} detected > {max} times; terminating QEMU");
                                let mut stdin = stdin.lock().unwrap();
                                stdin
                                    .write_all(&[0x01, b'x'])
                                    .context("failed to write to stdin")?;
                                drop(stdin);
                                println!("waiting for QEMU to terminate");
                            }
                        }
                        Ok(())
                    };

                let stderr = {
                    let stdin = Arc::clone(&stdin);
                    thread::Builder::new()
                        .spawn(move || {
                            for line in stderr.lines() {
                                let line = line.context("failed to read line from stderr")?;
                                eprintln!("{line}");
                                terminate_if_kernel_hang(&line, &stdin)?;
                            }
                            anyhow::Ok(())
                        })
                        .unwrap()
                };

                let mut outcome = None;
                for line in stdout.lines() {
                    let line = line.context("failed to read line from stdout")?;
                    println!("{line}");
                    terminate_if_kernel_hang(&line, &stdin)?;
                    // The init program will print "init: success" or "init: failure" to indicate
                    // the outcome of running the binaries it found in /bin.
                    if let Some(line) = line.strip_prefix("init: ") {
                        let previous = match line {
                            "success" => outcome.replace(Ok(())),
                            "failure" => outcome.replace(Err(())),
                            line => bail!("unexpected init output: {line}"),
                        };
                        if let Some(previous) = previous {
                            bail!("multiple exit status: previous={previous:?}, current={line}");
                        }
                    }
                }

                let status = qemu_child
                    .wait()
                    .with_context(|| format!("failed to wait for {qemu:?}"))?;

                stderr.join().unwrap()?;

                if status.code() != Some(0) {
                    bail!("{qemu:?} failed: {status}")
                }

                let outcome = outcome.ok_or_else(|| anyhow!("init did not exit"))?;
                match outcome {
                    Ok(()) => {}
                    Err(()) => {
                        errors.push(anyhow!("VM binaries failed on {}", kernel_image.display()))
                    }
                }
            }
            if errors.is_empty() {
                Ok(())
            } else {
                Err(Errors::new(errors).into())
            }
        }
    }
}
