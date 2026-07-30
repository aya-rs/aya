#![allow(clippy::print_stdout, reason = "xtask is a CLI tool")]
#![allow(clippy::print_stderr, reason = "xtask is a CLI tool")]
#![allow(clippy::use_debug, reason = "debug output aids troubleshooting")]

use std::{
    env,
    ffi::{OsStr, OsString},
    fmt::{Arguments, Write as _},
    fs::{self, File, OpenOptions},
    io::{BufRead as _, BufReader, Write},
    os::unix::ffi::OsStrExt as _,
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Output, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, anyhow, bail};
use aya_multierror::Errors;
use cargo_metadata::{Artifact, CompilerMessage, Message, Target};
use clap::Parser;
use nix::sys::stat::{Mode, SFlag};
use walkdir::WalkDir;
use xtask::AYA_BUILD_INTEGRATION_BPF;

use crate::{
    http::HttpClient,
    ubuntu_mainline::{
        KernelArchitecture, KernelPackage, download_ubuntu_mainline_kernel_packages,
    },
};

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

/// Magic bytes of a newc archive, according to the [initramfs buffer format][initramfs-format]
/// specification.
///
/// [initramfs-format]: https://github.com/torvalds/linux/blob/v7.1/Documentation/driver-api/early-userspace/buffer-format.rst
const NEWC_MAGIC: &[u8] = b"070701";

/// Length of the newc header, according to the [initramfs buffer format][initramfs-format]
/// specification.
///
/// The 13 numeric fields contain 32-bit values, but they are not stored as four-byte binary
/// integers. Each value is encoded as exactly eight ASCII hexadecimal bytes. Eight hexadecimal
/// digits cover the full range of a `u32`; using a `u64` could produce more than eight digits and
/// violate the fixed-width format. The header is therefore the six-byte magic followed by 13
/// eight-byte fields.
///
/// [initramfs-format]: https://github.com/torvalds/linux/blob/v7.1/Documentation/driver-api/early-userspace/buffer-format.rst
const NEWC_HEADER_LEN: u64 =
    // Magic bytes.
    6 +
        // 13 fields encoded as eight ASCII hexadecimal bytes:
        //
        // * inode
        // * mode
        // * UID
        // * GID
        // * nlink
        // * mtime
        // * file_size
        // * dev_major
        // * dev_minor
        // * rdev_major
        // * rdev_minor
        // * name_len
        // * checksum
        //
        // See `CpioArchiveBuilder::append` for details about the purpose of these fields.
        13 * 8;

struct CpioArchiveBuilder<W: Write> {
    current_inode: u32,
    inner: W,
}

impl<W: Write> CpioArchiveBuilder<W> {
    const fn new(inner: W) -> Self {
        Self {
            current_inode: 0,
            inner,
        }
    }

    /// Adds a new entry to this archive. The `name` must be relative to the
    /// root (it must not start with `/`). The `nlink` parameter sets the number
    /// of hard links for the entry.
    fn append(
        &mut self,
        name: &[u8],
        file_type: SFlag,
        mode: Mode,
        mtime: u32,
        source: Option<&Path>,
        nlink: u32,
    ) -> Result<()> {
        fn write_padding<W: Write>(writer: &mut W, len: u64) -> Result<()> {
            const ZEROES: [u8; 3] = [0; 3];

            let padding = ((4 - (len % 4)) % 4) as usize;
            writer.write_all(&ZEROES[..padding])?;
            Ok(())
        }

        let Self {
            current_inode,
            inner,
        } = self;

        let name_len = name
            .len()
            // `namesize` attribute in cpio header needs to include the null byte.
            .checked_add(1)
            .ok_or_else(|| {
                anyhow!(
                    "adding a null byte to name `{}` with length {} overflows",
                    OsStr::from_bytes(name).display(),
                    name.len()
                )
            })?;
        let name_len_u32 = u32::try_from(name_len)
            .with_context(|| format!("name length {name_len} does not fit in u32"))?;
        let file_size = if let Some(source) = &source {
            let file_size = fs::metadata(source)
                .with_context(|| format!("failed to get metadata for {}", source.display()))?
                .len();
            u32::try_from(file_size)
                .with_context(|| format!("cpio file size {file_size} does not fit in `u32`"))?
        } else {
            0
        };
        inner.write_all(NEWC_MAGIC)?;
        write!(inner, "{current_inode:08x}")?;
        write!(inner, "{:08x}", file_type.bits() | mode.bits())?;
        // UID and GID, 0 represents `root`.
        write!(inner, "{:08x}", 0)?;
        write!(inner, "{:08x}", 0)?;
        write!(inner, "{nlink:08x}")?;
        write!(inner, "{mtime:08x}")?;
        write!(inner, "{file_size:08x}")?;
        // dev_major/dev_minor: file device number (0 for initramfs files).
        write!(inner, "{:08x}", 0)?;
        write!(inner, "{:08x}", 0)?;
        // rdev_major/rdev_minor: device node number (0 for regular files/directories).
        write!(inner, "{:08x}", 0)?;
        write!(inner, "{:08x}", 0)?;
        write!(inner, "{name_len_u32:08x}")?;
        // Checksum; actual value not required anymore in newc cpio format.
        write!(inner, "{:08x}", 0)?;
        inner.write_all(name)?;
        inner.write_all(b"\0")?;
        write_padding(inner, NEWC_HEADER_LEN + name_len as u64)?;
        if let Some(source) = source {
            let mut src_file = File::open(source)
                .with_context(|| format!("failed to open {}", source.display()))?;
            let copied = std::io::copy(&mut src_file, inner)?;
            if copied != u64::from(file_size) {
                bail!(
                    "cpio size mismatch for {}: header={} bytes, copied={} bytes",
                    source.display(),
                    file_size,
                    copied
                );
            }
            write_padding(inner, copied)?;
        }

        *current_inode = current_inode.checked_add(1).with_context(|| {
            format!(
                "`CpioArchiveBuilder` does not support adding more than {} entries",
                u32::MAX
            )
        })?;

        Ok(())
    }

    /// Adds a directory to this archive. The `path` must be relative to the
    /// root (it must not start with `/`).
    fn append_dir<P>(&mut self, path: P, mode: Mode, mtime: u32) -> Result<()>
    where
        P: AsRef<Path>,
    {
        self.append(
            path.as_ref().as_os_str().as_encoded_bytes(),
            SFlag::S_IFDIR,
            mode,
            mtime,
            None,
            // Directories have two hard links - `.` and `..`.
            2,
        )
    }

    /// Adds a file to this archive, using the contents of `source`. The `path`
    /// must be relative against the root (it must not start from `/`).
    fn append_file<P, S>(&mut self, path: P, source: S, mode: Mode, mtime: u32) -> Result<()>
    where
        P: AsRef<Path>,
        S: AsRef<Path>,
    {
        self.append(
            path.as_ref().as_os_str().as_encoded_bytes(),
            SFlag::S_IFREG,
            mode,
            mtime,
            Some(source.as_ref()),
            // Create the file with only one hard link.
            1,
        )
    }

    /// Adds a trailer entry to this archive. The trailer entry must be the
    /// last one.
    fn append_trailer(&mut self) -> Result<()> {
        self.append(b"TRAILER!!!", SFlag::empty(), Mode::empty(), 0, None, 1)
    }
}

/// Build and run the project.
pub(crate) fn run(opts: Options) -> Result<()> {
    let Options {
        environment,
        package,
        run_args,
    } = opts;

    type Binary = (String, PathBuf);

    let binaries = |package: &str,
                    target: Option<&str>,
                    envs: &[(&OsStr, &OsStr)]|
     -> Result<Vec<(&'static str, Vec<Binary>)>> {
        ["dev", "release"]
            .into_iter()
            .map(|profile| {
                let binaries = build(target, |cmd| {
                    if package == INTEGRATION_TEST_PACKAGE {
                        cmd.env(AYA_BUILD_INTEGRATION_BPF, "true");
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

            let binaries = binaries(&package, None, &[])?;

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
            kernels,
        } => {
            // The user has asked us to run the tests on a VM. This is involved; strap in.
            //
            // We resolve Ubuntu Mainline kernel versions for the requested
            // architecture. We then build the init program and our test
            // binaries for that architecture, and build an initramfs containing the test
            // binaries. We're ready to run the VM.
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

                let binaries = binaries(&package, Some(&target), envs)?;

                let tmp_dir = tempfile::tempdir().context("tempdir failed")?;

                let initrd_image = tmp_dir.path().join("qemu-initramfs.img");
                let initrd_image_file = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&initrd_image)
                    .with_context(|| {
                        format!("failed to create {} for writing", initrd_image.display())
                    })?;
                let mut initrd_archive = CpioArchiveBuilder::new(initrd_image_file);
                let mtime_secs = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                let mtime = u32::try_from(mtime_secs).with_context(|| {
                    format!("cpio supports only `u32` mtimes, got {mtime_secs}")
                })?;
                // Equivalent of 0o644.
                let regular_mode = Mode::S_IRUSR | Mode::S_IWUSR | Mode::S_IRGRP | Mode::S_IROTH;
                // Equivalent of 0x755.
                let executable_mode =
                    Mode::S_IRWXU | Mode::S_IRGRP | Mode::S_IXGRP | Mode::S_IROTH | Mode::S_IXOTH;
                initrd_archive.append_dir("bin", executable_mode, mtime)?;
                initrd_archive.append_dir("boot", executable_mode, mtime)?;
                initrd_archive.append_file("boot/config", &config, regular_mode, mtime)?;
                initrd_archive.append_file("boot/System.map", &system_map, regular_mode, mtime)?;
                initrd_archive.append_dir("lib", executable_mode, mtime)?;
                initrd_archive.append_dir("sbin", executable_mode, mtime)?;
                if let Some(name) = config.file_name() {
                    initrd_archive.append_file(
                        Path::new("boot").join(name),
                        &config,
                        regular_mode,
                        mtime,
                    )?;
                }
                if let Some(name) = system_map.file_name() {
                    initrd_archive.append_file(
                        Path::new("boot").join(name),
                        system_map,
                        regular_mode,
                        mtime,
                    )?;
                }
                for (name, path) in &test_distro {
                    if name == "init" {
                        initrd_archive.append_file(
                            PathBuf::from("init"),
                            path,
                            executable_mode,
                            mtime,
                        )?;
                    } else {
                        initrd_archive.append_file(
                            Path::new("sbin").join(name),
                            path,
                            executable_mode,
                            mtime,
                        )?;
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
                    let out_path = Path::new("lib/modules").join(
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
                        initrd_archive.append_dir(out_path, executable_mode, mtime)?;
                    } else if metadata.file_type().is_file() {
                        initrd_archive.append_file(out_path, path, regular_mode, mtime)?;
                    }
                }

                for (profile, binaries) in binaries {
                    for (name, binary) in binaries {
                        let name = format!("{profile}-{name}");
                        let path = tmp_dir.path().join(&name);
                        fs::copy(&binary, &path).with_context(|| {
                            format!("copy({}, {}) failed", binary.display(), path.display())
                        })?;
                        let out_path = Path::new("bin").join(&name);
                        initrd_archive.append_file(out_path, &path, executable_mode, mtime)?;
                    }
                }

                // Append the required trailer entry as the last one, then
                // write the initramfs to the output file.
                initrd_archive.append_trailer()?;
                drop(initrd_archive);

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
