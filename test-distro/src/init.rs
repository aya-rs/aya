//! init is the first process started by the kernel.
//!
//! This implementation creates the minimal mounts required to run BPF programs, runs all binaries
//! in /bin, prints a final message ("init: success|failure"), and powers off the machine.

use anyhow::Context as _;

#[derive(Debug)]
struct Errors(Vec<anyhow::Error>);

impl std::fmt::Display for Errors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(errors) = self;
        for (i, error) in errors.iter().enumerate() {
            if i != 0 {
                writeln!(f)?;
            }
            write!(f, "{error:?}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Errors {}

fn run() -> anyhow::Result<()> {
    const RXRXRX: nix::sys::stat::Mode = nix::sys::stat::Mode::empty()
        .union(nix::sys::stat::Mode::S_IRUSR)
        .union(nix::sys::stat::Mode::S_IXUSR)
        .union(nix::sys::stat::Mode::S_IRGRP)
        .union(nix::sys::stat::Mode::S_IXGRP)
        .union(nix::sys::stat::Mode::S_IROTH)
        .union(nix::sys::stat::Mode::S_IXOTH);

    struct Mount {
        source: &'static str,
        target: &'static str,
        fstype: &'static str,
        flags: nix::mount::MsFlags,
        data: Option<&'static str>,
        target_mode: Option<nix::sys::stat::Mode>,
    }

    for Mount {
        source,
        target,
        fstype,
        flags,
        data,
        target_mode,
    } in [
        Mount {
            source: "proc",
            target: "/proc",
            fstype: "proc",
            flags: nix::mount::MsFlags::empty(),
            data: None,
            target_mode: Some(RXRXRX),
        },
        Mount {
            source: "dev",
            target: "/dev",
            fstype: "devtmpfs",
            flags: nix::mount::MsFlags::empty(),
            data: None,
            target_mode: None,
        },
        Mount {
            source: "sysfs",
            target: "/sys",
            fstype: "sysfs",
            flags: nix::mount::MsFlags::empty(),
            data: None,
            target_mode: Some(RXRXRX),
        },
        Mount {
            source: "debugfs",
            target: "/sys/kernel/debug",
            fstype: "debugfs",
            flags: nix::mount::MsFlags::empty(),
            data: None,
            target_mode: None,
        },
        Mount {
            source: "bpffs",
            target: "/sys/fs/bpf",
            fstype: "bpf",
            flags: nix::mount::MsFlags::empty(),
            data: None,
            target_mode: None,
        },
        Mount {
            source: "cgroup2",
            target: "/sys/fs/cgroup",
            fstype: "cgroup2",
            flags: nix::mount::MsFlags::empty(),
            data: None,
            target_mode: None,
        },
        Mount {
            source: "securityfs",
            target: "/sys/kernel/security",
            fstype: "securityfs",
            flags: nix::mount::MsFlags::empty(),
            data: None,
            target_mode: None,
        },
    ] {
        match target_mode {
            None => {
                // Must exist.
                let nix::sys::stat::FileStat { st_mode, .. } = nix::sys::stat::stat(target)
                    .with_context(|| format!("stat({target}) failed"))?;
                let s_flag = nix::sys::stat::SFlag::from_bits_truncate(st_mode);

                if !s_flag.contains(nix::sys::stat::SFlag::S_IFDIR) {
                    anyhow::bail!("{target} is not a directory");
                }
            }
            Some(target_mode) => {
                // Must not exist.
                nix::unistd::mkdir(target, target_mode)
                    .with_context(|| format!("mkdir({target}) failed"))?;
            }
        }
        nix::mount::mount(Some(source), target, Some(fstype), flags, data).with_context(|| {
            format!("mount({source}, {target}, {fstype}, {flags:?}, {data:?}) failed")
        })?;
    }

    // By contract we run everything in /bin and assume they're rust test binaries.
    //
    // If the user requested command line arguments, they're named init.arg={}.

    // Read kernel parameters from /proc/cmdline. They're space separated on a single line.
    let cmdline = std::fs::read_to_string("/proc/cmdline")
        .with_context(|| "read_to_string(/proc/cmdline) failed")?;
    let args = cmdline
        .split_whitespace()
        .filter_map(|parameter| {
            parameter
                .strip_prefix("init.arg=")
                .map(std::ffi::OsString::from)
        })
        .collect::<Vec<_>>();

    // Iterate files in /bin.
    let read_dir = std::fs::read_dir("/bin").context("read_dir(/bin) failed")?;
    let errors = read_dir
        .map(|entry| {
            let entry = entry.context("read_dir(/bin) failed")?;
            let path = entry.path();
            let mut cmd = std::process::Command::new(&path);
            cmd.args(&args)
                .env("RUST_BACKTRACE", "1")
                .env("RUST_LOG", "debug");

            println!("running {cmd:?}");

            let status = cmd
                .status()
                .with_context(|| format!("failed to run {cmd:?}"))?;

            if status.code() == Some(0) {
                Ok(())
            } else {
                Err(anyhow::anyhow!("{cmd:?} failed: {status:?}"))
            }
        })
        .filter_map(|result| {
            // TODO(https://github.com/rust-lang/rust-clippy/issues/14112): Remove this allowance
            // when the lint behaves more sensibly.
            #[expect(clippy::manual_ok_err)]
            match result {
                Ok(()) => None,
                Err(err) => Some(err),
            }
        })
        .collect::<Vec<_>>();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(Errors(errors).into())
    }
}

fn main() {
    match run() {
        Ok(()) => {
            println!("init: success");
        }
        Err(err) => {
            println!("{err:?}");
            println!("init: failure");
        }
    }
    let how = nix::sys::reboot::RebootMode::RB_POWER_OFF;
    let _: std::convert::Infallible = nix::sys::reboot::reboot(how)
        .unwrap_or_else(|err| panic!("reboot({how:?}) failed: {err:?}"));
}
