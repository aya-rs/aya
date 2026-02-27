//! Utilities to run tests

use std::{
    borrow::Cow,
    cell::OnceCell,
    ffi::CString,
    fs,
    io::{self, Write as _},
    net::Ipv4Addr,
    os::fd::AsRawFd as _,
    path::Path,
    process,
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{Context as _, Result};
use libc::if_nametoindex;

use crate::netlink;

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
    pub(crate) const IFACE: &str = "veth0";
    const PEER_IFACE: &str = "veth1";
    pub(crate) const IFACE_ADDR: &str = "10.0.0.1";
    pub(crate) const PEER_ADDR: &str = "10.0.0.2";

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

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
            netlink::set_link_up(idx as i32)
                .unwrap_or_else(|e| panic!("failed to set `lo` up in netns {}: {e}", ns.name));
        }

        // Create a veth pair for tests that attach XDP/TC programs. Veth supports
        // native XDP (unlike loopback which only supports SKB/generic mode), so tests
        // exercise the same code path used in production.
        netlink::create_veth_pair(
            &CString::new(Self::IFACE).unwrap(),
            &CString::new(Self::PEER_IFACE).unwrap(),
        )
        .unwrap_or_else(|e| {
            panic!(
                "failed to create veth pair {}/{} in netns {}: {e}",
                Self::IFACE,
                Self::PEER_IFACE,
                ns.name
            )
        });

        // Bring up both ends.
        for iface in [Self::IFACE, Self::PEER_IFACE] {
            let name = CString::new(iface).unwrap();
            unsafe {
                let idx = if_nametoindex(name.as_ptr());
                assert!(
                    idx != 0,
                    "interface `{iface}` not found in netns {}: {}",
                    ns.name,
                    io::Error::last_os_error()
                );
                netlink::set_link_up(idx as i32).unwrap_or_else(|e| {
                    panic!("failed to set `{iface}` up in netns {}: {e}", ns.name)
                });
            }
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

/// Run a closure inside a network namespace identified by a file handle.
///
/// Uses a scoped thread because `setns` changes the network namespace of the
/// *calling* thread — running it on a disposable thread avoids polluting the
/// test thread's namespace.
fn run_in_netns<F, R>(ns_file: &fs::File, f: F) -> R
where
    F: FnOnce() -> R + Send,
    R: Send,
{
    std::thread::scope(|s| {
        s.spawn(|| {
            nix::sched::setns(ns_file, nix::sched::CloneFlags::CLONE_NEWNET)
                .expect("setns to target netns");
            f()
        })
        .join()
        .unwrap()
    })
}

/// A second network namespace connected to the test namespace via the veth pair.
///
/// Creates a topology where `veth0` (10.0.0.1) lives in the test namespace and
/// `veth1` (10.0.0.2) is moved into the peer namespace. Static ARP entries are
/// installed on both sides so that no ARP traffic interferes with XDP programs.
///
/// Must be declared *after* `NetNsGuard` so that it is dropped first (Rust drops
/// locals in reverse declaration order). Dropping the peer namespace also destroys
/// its end of the veth pair.
pub(crate) struct PeerNsGuard {
    name: String,
}

impl PeerNsGuard {
    pub(crate) fn new(netns: &NetNsGuard) -> Self {
        let name = format!("{}-peer", netns.name());

        // Create peer netns: create a persist file, then use a scoped thread
        // to unshare(CLONE_NEWNET) and bind-mount the new ns over the file.
        let ns_path = Path::new(NetNsGuard::PERSIST_DIR).join(&name);
        let _unused: fs::File = fs::File::create(&ns_path)
            .unwrap_or_else(|err| panic!("fs::File::create(\"{}\"): {err:?}", ns_path.display()));
        std::thread::scope(|s| {
            s.spawn(|| {
                nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET)
                    .expect("unshare(CLONE_NEWNET) for peer ns");
                let new_ns_path = format!("/proc/self/task/{}/ns/net", nix::unistd::gettid());
                nix::mount::mount(
                    Some(new_ns_path.as_str()),
                    &ns_path,
                    Some("none"),
                    nix::mount::MsFlags::MS_BIND,
                    None::<&str>,
                )
                .expect("mount-bind peer netns");
            })
            .join()
            .unwrap();
        });

        // Move veth1 into peer netns.
        let peer_iface = CString::new(NetNsGuard::PEER_IFACE).unwrap();
        let peer_ns = fs::File::open(&ns_path)
            .unwrap_or_else(|e| panic!("open(\"{}\"): {e}", ns_path.display()));
        unsafe {
            let idx = if_nametoindex(peer_iface.as_ptr());
            assert!(
                idx != 0,
                "interface `{}` not found: {}",
                NetNsGuard::PEER_IFACE,
                io::Error::last_os_error()
            );
            netlink::set_link_ns(idx as i32, peer_ns.as_raw_fd()).unwrap_or_else(|e| {
                panic!(
                    "failed to move `{}` to netns {name}: {e}",
                    NetNsGuard::PEER_IFACE
                )
            });
        }

        // Assign IP to veth0 in test netns.
        let iface = CString::new(NetNsGuard::IFACE).unwrap();
        let iface_addr: Ipv4Addr = NetNsGuard::IFACE_ADDR.parse().unwrap();
        let peer_addr: Ipv4Addr = NetNsGuard::PEER_ADDR.parse().unwrap();
        unsafe {
            let idx = if_nametoindex(iface.as_ptr());
            assert!(
                idx != 0,
                "interface `{}` not found: {}",
                NetNsGuard::IFACE,
                io::Error::last_os_error()
            );
            netlink::add_addr_v4(idx as i32, iface_addr, 24)
                .unwrap_or_else(|e| panic!("failed to add addr to `{}`: {e}", NetNsGuard::IFACE));
        }

        // Configure veth1 in peer netns: add addr, set link up, set lo up, get MAC.
        let veth1_mac = run_in_netns(&peer_ns, || {
            let peer_iface = CString::new(NetNsGuard::PEER_IFACE).unwrap();
            let lo = CString::new("lo").unwrap();
            unsafe {
                let idx = if_nametoindex(peer_iface.as_ptr());
                assert!(
                    idx != 0,
                    "interface `{}` not found in peer netns: {}",
                    NetNsGuard::PEER_IFACE,
                    io::Error::last_os_error()
                );
                netlink::add_addr_v4(idx as i32, peer_addr, 24).unwrap_or_else(|e| {
                    panic!(
                        "failed to add addr to `{}` in peer netns: {e}",
                        NetNsGuard::PEER_IFACE
                    )
                });
                netlink::set_link_up(idx as i32).unwrap_or_else(|e| {
                    panic!(
                        "failed to set `{}` up in peer netns: {e}",
                        NetNsGuard::PEER_IFACE
                    )
                });

                let lo_idx = if_nametoindex(lo.as_ptr());
                assert!(
                    lo_idx != 0,
                    "interface `lo` not found in peer netns: {}",
                    io::Error::last_os_error()
                );
                netlink::set_link_up(lo_idx as i32)
                    .unwrap_or_else(|e| panic!("failed to set `lo` up in peer netns: {e}"));

                netlink::get_link_mac(idx as i32).unwrap_or_else(|e| {
                    panic!("failed to get MAC of `{}`: {e}", NetNsGuard::PEER_IFACE)
                })
            }
        });

        // Read veth0 MAC in test netns.
        let veth0_mac = unsafe {
            let idx = if_nametoindex(iface.as_ptr());
            assert!(
                idx != 0,
                "interface `{}` not found: {}",
                NetNsGuard::IFACE,
                io::Error::last_os_error()
            );
            netlink::get_link_mac(idx as i32)
                .unwrap_or_else(|e| panic!("failed to get MAC of `{}`: {e}", NetNsGuard::IFACE))
        };

        // Static ARP in test netns: peer IP -> veth1 MAC.
        unsafe {
            let idx = if_nametoindex(iface.as_ptr());
            netlink::add_neigh_v4(idx as i32, peer_addr, veth1_mac).unwrap_or_else(|e| {
                panic!(
                    "failed to add neigh entry for {} on `{}`: {e}",
                    NetNsGuard::PEER_ADDR,
                    NetNsGuard::IFACE
                )
            });
        }

        // Static ARP in peer netns: test IP -> veth0 MAC.
        run_in_netns(&peer_ns, || {
            let peer_iface = CString::new(NetNsGuard::PEER_IFACE).unwrap();
            unsafe {
                let idx = if_nametoindex(peer_iface.as_ptr());
                assert!(
                    idx != 0,
                    "interface `{}` not found in peer netns: {}",
                    NetNsGuard::PEER_IFACE,
                    io::Error::last_os_error()
                );
                netlink::add_neigh_v4(idx as i32, iface_addr, veth0_mac).unwrap_or_else(|e| {
                    panic!(
                        "failed to add neigh entry for {} on `{}`: {e}",
                        NetNsGuard::IFACE_ADDR,
                        NetNsGuard::PEER_IFACE
                    )
                });
            }
        });

        Self { name }
    }

    /// Run a closure inside the peer network namespace.
    ///
    /// Uses a scoped thread because `setns` changes the network namespace of the
    /// *calling* thread — running it on a disposable thread avoids polluting the
    /// test thread's namespace.
    pub(crate) fn run<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R + Send,
        R: Send,
    {
        let peer_ns_path = Path::new(NetNsGuard::PERSIST_DIR).join(&self.name);
        let peer_ns = fs::File::open(&peer_ns_path)
            .unwrap_or_else(|e| panic!("open(\"{}\"): {e}", peer_ns_path.display()));
        run_in_netns(&peer_ns, f)
    }
}

impl Drop for PeerNsGuard {
    #[expect(
        clippy::print_stderr,
        reason = "drop handlers avoid panic-in-panic by logging errors"
    )]
    #[expect(
        clippy::use_debug,
        reason = "debug formatting preserves error context in drop"
    )]
    fn drop(&mut self) {
        let Self { name } = self;
        match (|| -> Result<()> {
            let ns_path = Path::new(NetNsGuard::PERSIST_DIR).join(&name);
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
