//! Utilities to run tests

use std::{
    borrow::Cow,
    cell::OnceCell,
    ffi::CString,
    fs,
    io::{self, Write as _},
    path::Path,
    process,
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{Context as _, Result};
use aya::netlink_set_link_up;
use libc::if_nametoindex;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const CGROUP_PROCS: &str = "cgroup.procs";

pub(crate) struct ChildCgroup<'a> {
    parent: &'a Cgroup<'a>,
    path: Cow<'a, Path>,
    fd: OnceCell<fs::File>,
}

pub(crate) enum Cgroup<'a> {
    Root,
    Child(ChildCgroup<'a>),
}

impl Cgroup<'static> {
    pub(crate) fn root() -> Self {
        Self::Root
    }
}

impl<'a> Cgroup<'a> {
    fn path(&self) -> &Path {
        match self {
            Self::Root => Path::new(CGROUP_ROOT),
            Self::Child(ChildCgroup {
                parent: _,
                path,
                fd: _,
            }) => path,
        }
    }

    pub(crate) fn create_child(&'a self, name: &str) -> ChildCgroup<'a> {
        let path = self.path().join(name);
        fs::create_dir(&path).unwrap();

        ChildCgroup {
            parent: self,
            path: path.into(),
            fd: OnceCell::new(),
        }
    }

    pub(crate) fn write_pid(&self, pid: u32) {
        fs::write(self.path().join(CGROUP_PROCS), format!("{pid}\n")).unwrap();
    }
}

impl<'a> ChildCgroup<'a> {
    pub(crate) fn fd(&self) -> &fs::File {
        let Self {
            parent: _,
            path,
            fd,
        } = self;
        fd.get_or_init(|| {
            fs::OpenOptions::new()
                .read(true)
                .open(path.as_ref())
                .unwrap()
        })
    }

    pub(crate) fn into_cgroup(self) -> Cgroup<'a> {
        Cgroup::Child(self)
    }
}

impl Drop for ChildCgroup<'_> {
    #[expect(
        clippy::print_stderr,
        reason = "drop handlers avoid panic-in-panic by logging errors"
    )]
    #[expect(
        clippy::use_debug,
        reason = "debug formatting preserves error context in drop"
    )]
    fn drop(&mut self) {
        let Self {
            parent,
            path,
            fd: _,
        } = self;

        match (|| -> Result<()> {
            let dst = parent.path().join(CGROUP_PROCS);
            let mut dst = fs::OpenOptions::new()
                .append(true)
                .open(&dst)
                .with_context(|| {
                    format!(
                        "fs::OpenOptions::new().append(true).open(\"{}\")",
                        dst.display()
                    )
                })?;
            let pids = path.as_ref().join(CGROUP_PROCS);
            let pids = fs::read_to_string(&pids)
                .with_context(|| format!("fs::read_to_string(\"{}\")", pids.display()))?;
            for pid in pids.split_inclusive('\n') {
                dst.write_all(pid.as_bytes())
                    .with_context(|| format!("dst.write_all(\"{pid}\")"))?;
            }

            fs::remove_dir(&path)
                .with_context(|| format!("fs::remove_dir(\"{}\")", path.display()))?;
            Ok(())
        })() {
            Ok(()) => (),
            Err(err) => {
                // Avoid panic in panic.
                if std::thread::panicking() {
                    eprintln!("{err:?}");
                } else {
                    panic!("{err:?}");
                }
            }
        }
    }
}

pub(crate) struct NetNsGuard {
    name: String,
    old_ns: fs::File,
}

impl NetNsGuard {
    const PERSIST_DIR: &str = "/var/run/netns/";

    #[expect(
        clippy::print_stdout,
        reason = "integration tests print namespace transitions for diagnostics"
    )]
    pub(crate) fn new() -> Self {
        let current_thread_netns_path = format!("/proc/self/task/{}/ns/net", nix::unistd::gettid());
        let old_ns = fs::File::open(&current_thread_netns_path).unwrap_or_else(|err| {
            panic!("fs::File::open(\"{current_thread_netns_path}\"): {err:?}")
        });

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let pid = process::id();
        let name = format!("aya-test-{pid}-{}", COUNTER.fetch_add(1, Ordering::Relaxed));

        fs::create_dir_all(Self::PERSIST_DIR)
            .unwrap_or_else(|err| panic!("fs::create_dir_all(\"{}\"): {err:?}", Self::PERSIST_DIR));
        let ns_path = Path::new(Self::PERSIST_DIR).join(&name);
        let _unused: fs::File = fs::File::create(&ns_path)
            .unwrap_or_else(|err| panic!("fs::File::create(\"{}\"): {err:?}", ns_path.display()));
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET)
            .expect("nix::sched::unshare(CLONE_NEWNET)");

        nix::mount::mount(
            Some(current_thread_netns_path.as_str()),
            &ns_path,
            Some("none"),
            nix::mount::MsFlags::MS_BIND,
            None::<&str>,
        )
        .expect("nix::mount::mount");

        println!("entered network namespace {name}");

        let ns = Self { name, old_ns };

        // By default, the loopback in a new netns is down. Set it up.
        let lo = CString::new("lo").unwrap();
        unsafe {
            let idx = if_nametoindex(lo.as_ptr());
            assert!(
                idx != 0,
                "interface `lo` not found in netns {}: {}",
                ns.name,
                io::Error::last_os_error()
            );
            netlink_set_link_up(idx as i32)
                .unwrap_or_else(|e| panic!("failed to set `lo` up in netns {}: {e}", ns.name));
        }

        ns
    }
}

impl Drop for NetNsGuard {
    #[expect(
        clippy::print_stderr,
        reason = "drop handlers avoid panic-in-panic by logging errors"
    )]
    #[expect(
        clippy::use_debug,
        reason = "debug formatting preserves error context in drop"
    )]
    fn drop(&mut self) {
        let Self { old_ns, name } = self;
        match (|| -> Result<()> {
            nix::sched::setns(old_ns, nix::sched::CloneFlags::CLONE_NEWNET)
                .context("nix::sched::setns(_, CLONE_NEWNET)")?;
            let ns_path = Path::new(Self::PERSIST_DIR).join(&name);
            nix::mount::umount2(&ns_path, nix::mount::MntFlags::MNT_DETACH).with_context(|| {
                format!("nix::mount::umount2(\"{}\", MNT_DETACH)", ns_path.display())
            })?;
            fs::remove_file(&ns_path)
                .with_context(|| format!("fs::remove_file(\"{}\")", ns_path.display()))?;
            Ok(())
        })() {
            Ok(()) => (),
            Err(err) => {
                // Avoid panic in panic.
                if std::thread::panicking() {
                    eprintln!("{err:?}");
                } else {
                    panic!("{err:?}");
                }
            }
        }
    }
}

/// If the `KernelVersion::current >= $version`, `assert!($cond)`, else `assert!(!$cond)`.
macro_rules! kernel_assert {
    ($cond:expr, $version:expr $(,)?) => {
        let current = aya::util::KernelVersion::current().unwrap();
        let required: aya::util::KernelVersion = $version;
        if current >= required {
            assert!($cond, "{current} >= {required}");
        } else {
            assert!(!$cond, "{current} < {required}");
        }
    };
}

pub(crate) use kernel_assert;

/// If the `KernelVersion::current >= $version`, `assert_eq!($left, $right)`, else
/// `assert_ne!($left, $right)`.
macro_rules! kernel_assert_eq {
    ($left:expr, $right:expr, $version:expr $(,)?) => {
        let current = aya::util::KernelVersion::current().unwrap();
        let required: aya::util::KernelVersion = $version;
        if current >= required {
            assert_eq!($left, $right, "{current} >= {required}");
        } else {
            assert_ne!($left, $right, "{current} < {required}");
        }
    };
}

pub(crate) use kernel_assert_eq;
