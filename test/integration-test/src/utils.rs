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

use aya::netlink_set_link_up;
use libc::if_nametoindex;
use netns_rs::{NetNs, get_from_current_thread};

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
    fn drop(&mut self) {
        let Self {
            parent,
            path,
            fd: _,
        } = self;

        let pids = fs::read_to_string(path.as_ref().join(CGROUP_PROCS)).unwrap();
        let mut dst = fs::OpenOptions::new()
            .append(true)
            .open(parent.path().join(CGROUP_PROCS))
            .unwrap();
        for pid in pids.split_inclusive('\n') {
            dst.write_all(pid.as_bytes()).unwrap();
        }

        if let Err(e) = fs::remove_dir(&path) {
            eprintln!("failed to remove {}: {e}", path.display());
        }
    }
}

pub(crate) struct NetNsGuard {
    name: String,
    old_ns: NetNs,
    ns: Option<NetNs>,
}

impl NetNsGuard {
    pub(crate) fn new() -> Self {
        let old_ns = get_from_current_thread().expect("Failed to get current netns");

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let pid = process::id();
        let name = format!("aya-test-{pid}-{}", COUNTER.fetch_add(1, Ordering::Relaxed));

        let ns = NetNs::new(&name).unwrap_or_else(|e| panic!("failed to create netns {name}: {e}"));

        ns.enter()
            .unwrap_or_else(|e| panic!("failed to enter network namespace {name}: {e}"));
        println!("entered network namespace {name}");

        let ns = Self {
            old_ns,
            ns: Some(ns),
            name,
        };

        // By default, the loopback in a new netns is down. Set it up.
        let lo = CString::new("lo").unwrap();
        unsafe {
            let idx = if_nametoindex(lo.as_ptr());
            if idx == 0 {
                panic!(
                    "interface `lo` not found in netns {}: {}",
                    ns.name,
                    io::Error::last_os_error()
                );
            }
            netlink_set_link_up(idx as i32)
                .unwrap_or_else(|e| panic!("failed to set `lo` up in netns {}: {e}", ns.name));
        }

        ns
    }
}

impl Drop for NetNsGuard {
    fn drop(&mut self) {
        let Self { old_ns, ns, name } = self;
        // Avoid panic in panic.
        if let Err(e) = old_ns.enter() {
            eprintln!("failed to return to original netns: {e}");
        }
        if let Some(ns) = ns.take() {
            if let Err(e) = ns.remove() {
                eprintln!("failed to remove netns {name}: {e}");
            }
        }
        println!("exited network namespace {name}");
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
