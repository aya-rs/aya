//! Utilities to run tests

use std::{
    borrow::Cow,
    fs,
    io::{self, Write as _},
    os::fd::{AsFd, BorrowedFd},
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
};

use libc::if_nametoindex;

use crate::{netlink_set_link_up, sys::NetlinkError};

/// The root cgroup mount point on cgroup v2 systems.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The name of the file used to assign PIDs to a cgroup.
const CGROUP_PROCS: &str = "cgroup.procs";

/// An error type for test helpers.
///
/// This enum covers all failures that can occur during cgroup setup,
/// network namespace creation, and link manipulation in integration tests.
#[derive(Debug, thiserror::Error)]
pub enum AyaTestError {
    /// A filesystem operation failed (open, create, write, remove, etc.).
    #[error("failed to {op}: {path}: {source}")]
    Io {
        /// The operation that failed (e.g. `"create dir"`).
        op: &'static str,
        /// The path involved in the operation.
        path: PathBuf,
        /// Source error.
        #[source]
        source: io::Error,
    },

    /// A syscall failed.
    #[error(
        "syscall {syscall} failed{}: {source}",
        if let Some(path) = &.path {
            format!(": {}", path.display())
        } else {
            String::new()
        }
    )]
    Syscall {
        /// The syscall that failed (e.g. `"nix::sched::unshare"`).
        syscall: &'static str,
        /// The path involved in the syscall, if any.
        path: Option<PathBuf>,
        /// Source error.
        #[source]
        source: nix::errno::Errno,
    },

    /// An error occurred during a netlink operation.
    #[error(transparent)]
    Netlink(#[from] NetlinkError),
}

/// A result type for test helpers.
pub type AyaTestResult<T> = Result<T, AyaTestError>;

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
    pub const fn root() -> Self {
        Self::Root
    }
}

impl<'a> Cgroup<'a> {
    /// Returns the filesystem path for this cgroup.
    fn path(&self) -> &Path {
        match self {
            Self::Root => Path::new(CGROUP_ROOT),
            Self::Child(ChildCgroup { parent: _, path }) => path,
        }
    }

    /// Creates a child cgroup with the given name under this cgroup and returns
    /// a [`ChildCgroup`] handle to it.
    pub fn create_child(&'a self, name: &str) -> AyaTestResult<ChildCgroup<'a>> {
        let path = self.path().join(name);
        fs::create_dir(&path).map_err(|source| AyaTestError::Io {
            op: "create directory",
            path: path.clone(),
            source,
        })?;

        Ok(ChildCgroup {
            parent: self,
            path: path.into(),
        })
    }

    /// Writes the given PID to this cgroup's `cgroup.procs` file, thereby
    /// moving that process into this cgroup.
    pub fn write_pid(&self, pid: u32) -> AyaTestResult<()> {
        let cgroup_procs = self.path().join(CGROUP_PROCS);
        fs::write(&cgroup_procs, format!("{pid}\n")).map_err(move |source| AyaTestError::Io {
            op: "write",
            path: cgroup_procs,
            source,
        })
    }
}

impl<'a> ChildCgroup<'a> {
    /// Reads the cgroup directory and returns its file descriptor.
    pub fn fd(&self) -> AyaTestResult<fs::File> {
        let Self { parent: _, path } = self;
        fs::OpenOptions::new()
            .read(true)
            .open(path.as_ref())
            .map_err(|source| AyaTestError::Io {
                op: "open",
                path: path.to_path_buf(),
                source,
            })
    }

    /// Consumes `self` and returns a [`Cgroup::Child`] variant.
    pub const fn into_cgroup(self) -> Cgroup<'a> {
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
    #[expect(clippy::panic, reason = "drop handlers can't return a result")]
    fn drop(&mut self) {
        use anyhow::{Context as _, Result};

        let Self { parent, path } = self;

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
    #[expect(
        clippy::print_stdout,
        reason = "integration tests print namespace transitions for diagnostics"
    )]
    pub fn new() -> AyaTestResult<Self> {
        // `/proc/thread-self/ns/net` resolves to the calling thread's netns
        // (`/proc/self/ns/net` would always pin to the main thread's).
        let old_ns = fs::File::open(Self::THREAD_NETNS).map_err(|source| AyaTestError::Io {
            op: "open",
            path: PathBuf::from(Self::THREAD_NETNS),
            source,
        })?;

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let pid = process::id();
        let name = format!("aya-test-{pid}-{}", COUNTER.fetch_add(1, Ordering::Relaxed));

        fs::create_dir_all(Self::PERSIST_DIR).map_err(|source| AyaTestError::Io {
            op: "create directory",
            path: PathBuf::from(Self::PERSIST_DIR),
            source,
        })?;
        let ns_path = Path::new(Self::PERSIST_DIR).join(&name);
        let _unused: fs::File = fs::File::create(&ns_path).map_err(|source| AyaTestError::Io {
            op: "create file",
            path: ns_path.clone(),
            source,
        })?;
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).map_err(|source| {
            AyaTestError::Syscall {
                syscall: "unshare",
                path: None,
                source,
            }
        })?;

        // Re-open after unshare to capture the freshly entered namespace.
        let new_ns = fs::File::open(Self::THREAD_NETNS).map_err(|source| AyaTestError::Io {
            op: "open",
            path: PathBuf::from(Self::THREAD_NETNS),
            source,
        })?;

        nix::mount::mount(
            Some(Self::THREAD_NETNS),
            &ns_path,
            Some("none"),
            nix::mount::MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|source| AyaTestError::Syscall {
            syscall: "mount",
            path: Some(ns_path.clone()),
            source,
        })?;

        println!("entered network namespace {name}");

        let ns = Self {
            name,
            old_ns,
            new_ns,
        };

        // By default, the loopback in a new netns is down. Set it up.
        let lo = c"lo";
        unsafe {
            let idx = if_nametoindex(lo.as_ptr());
            if idx == 0 {
                return Err(AyaTestError::Io {
                    op: "lookup interface index",
                    path: PathBuf::from("lo"),
                    source: io::Error::last_os_error(),
                });
            }
            netlink_set_link_up(idx as i32)?;
        }

        Ok(ns)
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
    #[expect(clippy::panic, reason = "drop handlers can't return a result")]
    fn drop(&mut self) {
        use anyhow::{Context as _, Result};

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
        let current = $crate::util::KernelVersion::current().unwrap();
        let required: $crate::util::KernelVersion = $version;
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
        let current = $crate::util::KernelVersion::current().unwrap();
        let required: $crate::util::KernelVersion = $version;
        if current >= required {
            assert_eq!($left, $right, "{current} >= {required}");
        } else {
            assert_ne!($left, $right, "{current} < {required}");
        }
    };
}
