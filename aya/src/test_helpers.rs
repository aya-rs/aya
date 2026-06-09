//! Utilities to run tests

use std::{
    borrow::Cow,
    cell::OnceCell,
    ffi::CString,
    fs,
    io::{self, Write as _},
    os::fd::{AsFd, BorrowedFd},
    path::Path,
    process,
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{Context as _, Result};
use libc::if_nametoindex;

use crate::netlink_set_link_up;

/// The root cgroup mount point on cgroup v2 systems.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The name of the file used to assign PIDs to a cgroup.
const CGROUP_PROCS: &str = "cgroup.procs";

/// Returns `true` if the system is using cgroup v2, as determined by the
/// presence of `cgroup.controllers` at the root of the cgroup mount.
pub fn is_cgroup2() -> bool {
    // `cgroup.controllers` exists only at the root of a cgroup2 mount.
    Path::new(CGROUP_ROOT).join("cgroup.controllers").exists()
}

/// A handle to a child cgroup created under a [`Cgroup`].
///
/// On drop, the PIDs in this cgroup's `cgroup.procs` are moved back to the
/// parent cgroup and the directory is removed.
pub struct ChildCgroup<'a> {
    /// The parent cgroup under which this child was created.
    parent: &'a Cgroup<'a>,
    /// The filesystem path of this cgroup directory.
    path: Cow<'a, Path>,
    /// Lazily opened file descriptor for this cgroup directory.
    fd: OnceCell<fs::File>,
}

/// A handle representing either the root cgroup or a child cgroup.
///
/// This enum is used to avoid unnecessary reference counting when the root
/// cgroup is the only handle needed.
pub enum Cgroup<'a> {
    /// The root cgroup (`/sys/fs/cgroup`).
    Root,
    /// A child cgroup created via [`Cgroup::create_child`].
    Child(ChildCgroup<'a>),
}

impl Cgroup<'static> {
    /// Returns a handle to the root cgroup.
    pub fn root() -> Self {
        Self::Root
    }
}

impl<'a> Cgroup<'a> {
    /// Returns the filesystem path for this cgroup.
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

    /// Creates a child cgroup with the given name under this cgroup and returns
    /// a [`ChildCgroup`] handle to it.
    ///
    /// # Panics
    ///
    /// Panics if the cgroup directory cannot be created.
    pub fn create_child(&'a self, name: &str) -> ChildCgroup<'a> {
        let path = self.path().join(name);
        fs::create_dir(&path).unwrap();

        ChildCgroup {
            parent: self,
            path: path.into(),
            fd: OnceCell::new(),
        }
    }

    /// Writes the given PID to this cgroup's `cgroup.procs` file, thereby
    /// moving that process into this cgroup.
    ///
    /// # Panics
    ///
    /// Panics if the file cannot be written.
    pub fn write_pid(&self, pid: u32) {
        fs::write(self.path().join(CGROUP_PROCS), format!("{pid}\n")).unwrap();
    }
}

impl<'a> ChildCgroup<'a> {
    /// Returns a reference to a lazily opened file descriptor for this cgroup
    /// directory.
    ///
    /// The file is opened for reading on first call and cached for subsequent
    /// calls.
    ///
    /// # Panics
    ///
    /// Panics if the file cannot be opened.
    pub fn fd(&self) -> &fs::File {
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

    /// Consumes `self` and returns a [`Cgroup::Child`] variant.
    pub fn into_cgroup(self) -> Cgroup<'a> {
        Cgroup::Child(self)
    }
}

impl Drop for ChildCgroup<'_> {
    /// Moves all PIDs from this child cgroup back to the parent cgroup's
    /// `cgroup.procs`, then removes this cgroup's directory.
    ///
    /// If this cgroup is empty, the directory is simply removed. Errors are
    /// logged or cause a panic (depending on whether the runtime is already
    /// unwinding) rather than propagating, to avoid double-panic.
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

/// A guard that creates and enters a new network namespace, restoring the
/// previous namespace on drop.
///
/// The guard also brings up the `lo` (loopback) interface in the new
/// namespace by default, since it is down in freshly created namespaces.
pub struct NetNsGuard {
    /// The name of the persisted network namespace.
    name: String,
    /// File handle to the original network namespace, used for restoration on drop.
    old_ns: fs::File,
    /// File handle to the newly created network namespace.
    new_ns: fs::File,
}

impl NetNsGuard {
    /// The directory where network namespaces are persisted for user-space access.
    const PERSIST_DIR: &str = "/var/run/netns/";

    /// The path to the calling thread's network namespace file.
    const THREAD_NETNS: &str = "/proc/thread-self/ns/net";

    /// Creates a new network namespace guard.
    ///
    /// This creates a new network namespace, persists it under `/var/run/netns/`,
    /// enters it, and brings up the `lo` interface. On drop, the guard restores
    /// the previous namespace and cleans up the persisted namespace entry.
    ///
    /// # Panics
    ///
    /// Panics if any step (creating the namespace, mounting it, or bringing up
    /// `lo`) fails.
    #[expect(
        clippy::print_stdout,
        reason = "integration tests print namespace transitions for diagnostics"
    )]
    pub fn new() -> Self {
        // `/proc/thread-self/ns/net` resolves to the calling thread's netns
        // (`/proc/self/ns/net` would always pin to the main thread's).
        let old_ns = fs::File::open(Self::THREAD_NETNS)
            .unwrap_or_else(|err| panic!("fs::File::open(\"{}\"): {err:?}", Self::THREAD_NETNS));

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

        // Re-open after unshare to capture the freshly entered namespace.
        let new_ns = fs::File::open(Self::THREAD_NETNS)
            .unwrap_or_else(|err| panic!("fs::File::open(\"{}\"): {err:?}", Self::THREAD_NETNS));

        nix::mount::mount(
            Some(Self::THREAD_NETNS),
            &ns_path,
            Some("none"),
            nix::mount::MsFlags::MS_BIND,
            None::<&str>,
        )
        .expect("nix::mount::mount");

        println!("entered network namespace {name}");

        let ns = Self {
            name,
            old_ns,
            new_ns,
        };

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

impl AsFd for NetNsGuard {
    /// Returns a borrowed file descriptor for the new network namespace.
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.new_ns.as_fd()
    }
}

impl Drop for NetNsGuard {
    /// Restores the original network namespace and cleans up the persisted
    /// namespace entry under `/var/run/netns/`.
    ///
    /// Errors are logged or cause a panic (depending on whether the runtime is
    /// already unwinding) rather than propagating, to avoid double-panic.
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
            old_ns,
            name,
            new_ns: _,
        } = self;
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

/// Asserts a condition based on the running kernel version.
///
/// If `KernelVersion::current >= $version`, evaluates to `assert!($cond)`.
/// Otherwise, evaluates to `assert!(!$cond)`.
///
/// This is useful for tests that behave differently across kernel versions.
#[macro_export]
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

/// Asserts equality based on the running kernel version.
///
/// If `KernelVersion::current >= $version`, evaluates to `assert_eq!($left, $right)`.
/// Otherwise, evaluates to `assert_ne!($left, $right)`.
///
/// This is useful for tests that check for behavioral changes introduced in
/// specific kernel versions.
#[macro_export]
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
