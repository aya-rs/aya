use std::{
    ffi::OsString,
    fmt::Write as _,
    fs::{OpenOptions, copy, create_dir_all},
    io::{BufRead as _, BufReader, Write as _},
    path::PathBuf,
    process::{Child, ChildStdin, Command, Output, Stdio},
    sync::{Arc, Mutex},
    thread,
};

use anyhow::{Context as _, Result, anyhow, bail};
use cargo_metadata::{Artifact, CompilerMessage, Message, Target};
use clap::Parser;
use xtask::{AYA_BUILD_INTEGRATION_BPF, Errors};

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

        /// The kernel images to use.
        ///
        /// You can download some images with:
        ///
        /// wget --accept-regex '.*/linux-image-[0-9\.-]+-cloud-.*-unsigned*' \
        ///   --recursive ftp://ftp.us.debian.org/debian/pool/main/l/linux/
        ///
        /// You can then extract them with:
        ///
        /// find . -name '*.deb' -print0 \
        /// | xargs -0 -I {} sh -c "dpkg --fsys-tarfile {} \
        ///   | tar --wildcards --extract '*vmlinuz*' --file -"
        #[clap(required = true)]
        kernel_image: Vec<PathBuf>,
    },
}

#[derive(Parser)]
pub struct Options {
    #[clap(subcommand)]
    environment: Environment,
    /// Arguments to pass to your application.
    #[clap(global = true, last = true)]
    run_args: Vec<OsString>,
}

pub fn build<F>(target: Option<&str>, f: F) -> Result<Vec<(String, PathBuf)>>
where
    F: FnOnce(&mut Command) -> &mut Command,
{
    // Always use rust-lld in case we're cross-compiling.
    let mut cmd = Command::new("cargo");
    cmd.args(["build", "--message-format=json"]);
    if let Some(target) = target {
        let config = format!("target.{target}.linker = \"rust-lld\"");
        cmd.args(["--target", target, "--config", &config]);
    }
    f(&mut cmd);

    let mut child = cmd
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn {cmd:?}"))?;
    let Child { stdout, .. } = &mut child;

    let stdout = stdout.take().unwrap();
    let stdout = BufReader::new(stdout);
    let mut executables = Vec::new();
    for message in Message::parse_stream(stdout) {
        #[expect(clippy::collapsible_match)]
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
                for line in message.rendered.unwrap_or_default().split('\n') {
                    println!("cargo:warning={line}");
                }
            }
            Message::TextLine(line) => {
                println!("{line}");
            }
            _ => {}
        }
    }

    let status = child
        .wait()
        .with_context(|| format!("failed to wait for {cmd:?}"))?;
    if status.code() != Some(0) {
        bail!("{cmd:?} failed: {status:?}")
    }
    Ok(executables)
}

/// Build and run the project.
pub fn run(opts: Options) -> Result<()> {
    let Options {
        environment,
        run_args,
    } = opts;

    type Binary = (String, PathBuf);
    fn binaries(target: Option<&str>) -> Result<Vec<(&str, Vec<Binary>)>> {
        ["dev", "release"]
            .into_iter()
            .map(|profile| {
                let binaries = build(target, |cmd| {
                    cmd.env(AYA_BUILD_INTEGRATION_BPF, "true").args([
                        "--package",
                        "integration-test",
                        "--tests",
                        "--profile",
                        profile,
                    ])
                })?;
                anyhow::Ok((profile, binaries))
            })
            .collect()
    }

    // Use --test-threads=1 to prevent tests from interacting with shared
    // kernel state due to the lack of inter-test isolation.
    let default_args = [OsString::from("--test-threads=1")];
    let run_args = default_args.iter().chain(run_args.iter());

    match environment {
        Environment::Local { runner } => {
            let mut args = runner.trim().split_terminator(' ');
            let runner = args.next().ok_or(anyhow!("no first argument"))?;
            let args = args.collect::<Vec<_>>();

            let binaries = binaries(None)?;

            let mut failures = String::new();
            for (profile, binaries) in binaries {
                for (name, binary) in binaries {
                    let mut cmd = Command::new(runner);
                    let cmd = cmd.args(args.iter()).arg(binary).args(run_args.clone());

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
                Err(anyhow!("failures:\n{}", failures))
            }
        }
        Environment::VM {
            cache_dir,
            kernel_image,
        } => {
            // The user has asked us to run the tests on a VM. This is involved; strap in.
            //
            // We need tools to build the initramfs; we use gen_init_cpio from the Linux repository,
            // taking care to cache it.
            //
            // Then we iterate the kernel images, using the `file` program to guess the target
            // architecture. We then build the init program and our test binaries for that
            // architecture, and use gen_init_cpio to build an initramfs containing the test
            // binaries. We're almost ready to run the VM.
            //
            // We consult our OS, our architecture, and the target architecture to determine if
            // hardware acceleration is available, and then start QEMU with the provided kernel
            // image and the initramfs we built.
            //
            // We consume the output of QEMU, looking for the output of our init program. This is
            // the only way to distinguish success from failure. We batch up the errors across all
            // VM images and report to the user. The end.
            create_dir_all(&cache_dir).context("failed to create cache dir")?;
            let gen_init_cpio = cache_dir.join("gen_init_cpio");
            if !gen_init_cpio
                .try_exists()
                .context("failed to check existence of gen_init_cpio")?
            {
                let content = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        reqwest::get("https://github.com/torvalds/linux/raw/refs/heads/master/usr/gen_init_cpio.c")
                        .await?
                        .bytes()
                        .await
                    })
                    .context("failed to download gen_init_cpio.c")?;

                let mut clang = Command::new("clang");
                clang
                    .args(["-g", "-O2", "-x", "c", "-", "-o"])
                    .arg(&gen_init_cpio);
                let mut child = clang
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .with_context(|| format!("failed to spawn {clang:?}"))?;

                let Child { stdin, .. } = &mut child;
                let mut stdin = stdin.take().unwrap();
                stdin
                    .write_all(&content)
                    .with_context(|| format!("failed to write to {clang:?} stdin"))?;
                std::mem::drop(stdin); // Send EOF.

                let output = child
                    .wait_with_output()
                    .with_context(|| format!("failed to wait for {clang:?}"))?;
                let Output { status, .. } = &output;
                if status.code() != Some(0) {
                    bail!("{clang:?} failed: {output:?}")
                }
            }

            let mut errors = Vec::new();
            for kernel_image in kernel_image {
                // Guess the guest architecture.
                let mut cmd = Command::new("file");
                let output = cmd
                    .arg("--brief")
                    .arg(&kernel_image)
                    .output()
                    .with_context(|| format!("failed to run {cmd:?}"))?;
                let Output { status, .. } = &output;
                if status.code() != Some(0) {
                    bail!("{cmd:?} failed: {output:?}")
                }
                let Output { stdout, .. } = output;

                // Now parse the output of the file command, which looks something like
                //
                // - Linux kernel ARM64 boot executable Image, little-endian, 4K pages
                //
                // - Linux kernel x86 boot executable bzImage, version 6.1.0-10-cloud-amd64 [..]

                let stdout = String::from_utf8(stdout)
                    .with_context(|| format!("invalid UTF-8 in {cmd:?} stdout"))?;
                let (_, stdout) = stdout
                    .split_once("Linux kernel")
                    .ok_or_else(|| anyhow!("failed to parse {cmd:?} stdout: {stdout}"))?;
                let (guest_arch, _) = stdout
                    .split_once("boot executable")
                    .ok_or_else(|| anyhow!("failed to parse {cmd:?} stdout: {stdout}"))?;
                let guest_arch = guest_arch.trim();

                let (guest_arch, machine, cpu, console) = match guest_arch {
                    "ARM64" => ("aarch64", Some("virt"), Some("max"), "ttyAMA0"),
                    "x86" => ("x86_64", None, None, "ttyS0"),
                    guest_arch => (guest_arch, None, None, "ttyS0"),
                };

                let target = format!("{guest_arch}-unknown-linux-musl");

                // Build our init program. The contract is that it will run anything it finds in /bin.
                let init = build(Some(&target), |cmd| {
                    cmd.args(["--package", "init", "--profile", "release"])
                })
                .context("building init program failed")?;

                let init = match &*init {
                    [(name, init)] => {
                        if name != "init" {
                            bail!("expected init program to be named init, found {name}")
                        }
                        init
                    }
                    init => bail!("expected exactly one init program, found {init:?}"),
                };

                let binaries = binaries(Some(&target))?;

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
                let mut stdin = stdin.take().unwrap();

                use std::os::unix::ffi::OsStrExt as _;

                // Send input into gen_init_cpio which looks something like
                //
                // file /init    path-to-init 0755 0 0
                // dir  /bin                  0755 0 0
                // file /bin/foo path-to-foo  0755 0 0
                // file /bin/bar path-to-bar  0755 0 0

                for bytes in [
                    "file /init ".as_bytes(),
                    init.as_os_str().as_bytes(),
                    " 0755 0 0\n".as_bytes(),
                    "dir /bin 0755 0 0\n".as_bytes(),
                ] {
                    stdin.write_all(bytes).expect("write");
                }

                for (profile, binaries) in binaries {
                    for (name, binary) in binaries {
                        let name = format!("{}-{}", profile, name);
                        let path = tmp_dir.path().join(&name);
                        copy(&binary, &path).with_context(|| {
                            format!("copy({}, {}) failed", binary.display(), path.display())
                        })?;
                        for bytes in [
                            "file /bin/".as_bytes(),
                            name.as_bytes(),
                            " ".as_bytes(),
                            path.as_os_str().as_bytes(),
                            " 0755 0 0\n".as_bytes(),
                        ] {
                            stdin.write_all(bytes).expect("write");
                        }
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
                let console = OsString::from(console);
                let mut kernel_args = std::iter::once(("console", &console))
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
                qemu.args(["-no-reboot", "-nographic", "-m", "512M", "-smp", "2"])
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
                    move |line: &str, stdin: &Arc<Mutex<ChildStdin>>| -> anyhow::Result<()> {
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
                                println!("waiting for QEMU to terminate");
                            }
                        }
                        Ok(())
                    };

                let stderr = {
                    let stdin = stdin.clone();
                    thread::Builder::new()
                        .spawn(move || {
                            for line in stderr.lines() {
                                let line = line.context("failed to read line from stderr")?;
                                eprintln!("{}", line);
                                terminate_if_kernel_hang(&line, &stdin)?;
                            }
                            anyhow::Ok(())
                        })
                        .unwrap()
                };

                let mut outcome = None;
                for line in stdout.lines() {
                    let line = line.context("failed to read line from stdout")?;
                    println!("{}", line);
                    terminate_if_kernel_hang(&line, &stdin)?;
                    // The init program will print "init: success" or "init: failure" to indicate
                    // the outcome of running the binaries it found in /bin.
                    if let Some(line) = line.strip_prefix("init: ") {
                        let previous = match line {
                            "success" => outcome.replace(Ok(())),
                            "failure" => outcome.replace(Err(())),
                            line => bail!("unexpected init output: {}", line),
                        };
                        if let Some(previous) = previous {
                            bail!("multiple exit status: previous={previous:?}, current={line}");
                        }
                    }
                }

                let output = qemu_child
                    .wait_with_output()
                    .with_context(|| format!("failed to wait for {qemu:?}"))?;
                let Output { status, .. } = &output;
                if status.code() != Some(0) {
                    bail!("{qemu:?} failed: {output:?}")
                }

                stderr.join().unwrap()?;

                let outcome = outcome.ok_or(anyhow!("init did not exit"))?;
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
