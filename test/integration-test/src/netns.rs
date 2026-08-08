//! Peer network namespace connected via a veth pair.
//!
//! `NetNsGuard` itself lives in `aya::test_helpers`. This module adds a second
//! namespace linked to the test namespace by a veth pair, for tests that need a
//! real (native-XDP capable) link rather than loopback.

use std::{
    ffi::CStr,
    fs, io,
    net::Ipv4Addr,
    os::fd::AsRawFd as _,
    path::Path,
    process,
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{Context as _, Result};
use aya::test_helpers::NetNsGuard;
use libc::if_nametoindex;

use crate::netlink;

/// The directory where network namespaces are persisted for user-space access.
///
/// Mirrors the (private) constant of the same name in `aya::test_helpers`;
/// `NetNsGuard::new` is responsible for creating it.
const PERSIST_DIR: &str = "/var/run/netns/";

/// Run a closure inside a network namespace identified by a file handle.
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

/// A second network namespace connected to the test namespace via a veth pair.
///
/// Creates a topology where `veth0` (10.0.0.1) lives in the test namespace and
/// `veth1` (10.0.0.2) is moved into the peer namespace. Static ARP entries are
/// installed on both sides so that no ARP traffic interferes with XDP programs.
///
/// Obtain one together with its test namespace via [`PeerNsGuard::with_netns`],
/// which returns `(NetNsGuard, PeerNsGuard)`. Because locals are dropped in
/// reverse declaration order, binding as `let (_netns, peer) = ...` drops the
/// peer (and its end of the veth pair) before the enclosing namespace.
pub(crate) struct PeerNsGuard {
    name: String,
}

impl PeerNsGuard {
    const IFACE: &CStr = c"veth0";
    const PEER_IFACE: &CStr = c"veth1";
    pub(crate) const IFACE_NAME: &str = "veth0";
    pub(crate) const IFACE_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    pub(crate) const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

    /// Creates a test network namespace and a peer namespace connected to it by
    /// a veth pair.
    ///
    /// Returns `(NetNsGuard, PeerNsGuard)` to keep the 1:1 relationship between
    /// the two: the peer is only reachable through this entry point, and the
    /// tuple binding order guarantees the peer is dropped first.
    pub(crate) fn with_netns() -> (NetNsGuard, Self) {
        let netns = NetNsGuard::new().unwrap();
        let peer = Self::new();
        (netns, peer)
    }

    /// Sets up the veth pair and peer namespace in the *current* network
    /// namespace (the one entered by the enclosing [`NetNsGuard`]).
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let name = format!(
            "aya-test-peer-{}-{}",
            process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );

        // Create a veth pair for tests that attach XDP/TC programs. Veth supports
        // native XDP (unlike loopback which only supports SKB/generic mode), so tests
        // exercise the same code path used in production.
        netlink::create_veth_pair(Self::IFACE, Self::PEER_IFACE).unwrap_or_else(|e| {
            panic!(
                "failed to create veth pair {:?}/{:?}: {e}",
                Self::IFACE,
                Self::PEER_IFACE,
            )
        });

        // Bring up veth0.
        unsafe {
            let idx = if_nametoindex(Self::IFACE.as_ptr());
            assert_ne!(
                idx,
                0,
                "interface `{:?}` not found: {}",
                Self::IFACE,
                io::Error::last_os_error()
            );
            netlink::set_link_up(idx as i32)
                .unwrap_or_else(|e| panic!("failed to set `{:?}` up: {e}", Self::IFACE));
        }

        // Create peer netns: create a persist file, then use a separate thread
        // to unshare(CLONE_NEWNET) and bind-mount the new ns over the file.
        let ns_path = Path::new(PERSIST_DIR).join(&name);
        let _unused: fs::File = fs::File::create(&ns_path)
            .unwrap_or_else(|err| panic!("fs::File::create(\"{}\"): {err:?}", ns_path.display()));
        std::thread::scope(|s| {
            s.spawn(|| {
                nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET)
                    .expect("unshare(CLONE_NEWNET) for peer ns");
                // `/proc/thread-self/ns/net` is this thread's freshly-unshared netns.
                nix::mount::mount(
                    Some("/proc/thread-self/ns/net"),
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
        let peer_ns = fs::File::open(&ns_path)
            .unwrap_or_else(|e| panic!("open(\"{}\"): {e}", ns_path.display()));
        unsafe {
            let idx = if_nametoindex(Self::PEER_IFACE.as_ptr());
            assert_ne!(
                idx,
                0,
                "interface `{:?}` not found: {}",
                Self::PEER_IFACE,
                io::Error::last_os_error()
            );
            netlink::set_link_ns(idx as i32, peer_ns.as_raw_fd()).unwrap_or_else(|e| {
                panic!(
                    "failed to move `{:?}` to netns {name}: {e}",
                    Self::PEER_IFACE
                )
            });
        }

        // Assign IP to veth0 in test netns.
        unsafe {
            let idx = if_nametoindex(Self::IFACE.as_ptr());
            assert_ne!(
                idx,
                0,
                "interface `{:?}` not found: {}",
                Self::IFACE,
                io::Error::last_os_error()
            );
            netlink::add_addr_v4(idx as i32, Self::IFACE_IP, 24)
                .unwrap_or_else(|e| panic!("failed to add addr to `{:?}`: {e}", Self::IFACE));
        }

        // Configure veth1 in peer netns: add addr, set link up, set lo up, get MAC.
        let veth1_mac = run_in_netns(&peer_ns, || unsafe {
            let idx = if_nametoindex(Self::PEER_IFACE.as_ptr());
            assert_ne!(
                idx,
                0,
                "interface `{:?}` not found in peer netns: {}",
                Self::PEER_IFACE,
                io::Error::last_os_error()
            );
            netlink::add_addr_v4(idx as i32, Self::PEER_IP, 24).unwrap_or_else(|e| {
                panic!(
                    "failed to add addr to `{:?}` in peer netns: {e}",
                    Self::PEER_IFACE
                )
            });
            netlink::set_link_up(idx as i32).unwrap_or_else(|e| {
                panic!(
                    "failed to set `{:?}` up in peer netns: {e}",
                    Self::PEER_IFACE
                )
            });

            let lo_idx = if_nametoindex(c"lo".as_ptr());
            assert_ne!(
                lo_idx,
                0,
                "interface `lo` not found in peer netns: {}",
                io::Error::last_os_error()
            );
            netlink::set_link_up(lo_idx as i32)
                .unwrap_or_else(|e| panic!("failed to set `lo` up in peer netns: {e}"));

            netlink::get_link_mac(idx as i32)
                .unwrap_or_else(|e| panic!("failed to get MAC of `{:?}`: {e}", Self::PEER_IFACE))
        });

        // Read veth0 MAC in test netns.
        let veth0_mac = unsafe {
            let idx = if_nametoindex(Self::IFACE.as_ptr());
            assert_ne!(
                idx,
                0,
                "interface `{:?}` not found: {}",
                Self::IFACE,
                io::Error::last_os_error()
            );
            netlink::get_link_mac(idx as i32)
                .unwrap_or_else(|e| panic!("failed to get MAC of `{:?}`: {e}", Self::IFACE))
        };

        // Static ARP in test netns: peer IP -> veth1 MAC.
        unsafe {
            let idx = if_nametoindex(Self::IFACE.as_ptr());
            netlink::add_neigh_v4(idx as i32, Self::PEER_IP, veth1_mac).unwrap_or_else(|e| {
                panic!(
                    "failed to add neigh entry for {} on `{:?}`: {e}",
                    Self::PEER_IP,
                    Self::IFACE
                )
            });
        }

        // Static ARP in peer netns: test IP -> veth0 MAC.
        run_in_netns(&peer_ns, || unsafe {
            let idx = if_nametoindex(Self::PEER_IFACE.as_ptr());
            assert_ne!(
                idx,
                0,
                "interface `{:?}` not found in peer netns: {}",
                Self::PEER_IFACE,
                io::Error::last_os_error()
            );
            netlink::add_neigh_v4(idx as i32, Self::IFACE_IP, veth0_mac).unwrap_or_else(|e| {
                panic!(
                    "failed to add neigh entry for {} on `{:?}`: {e}",
                    Self::IFACE_IP,
                    Self::PEER_IFACE
                )
            });
        });

        Self { name }
    }

    /// Run a closure inside the peer network namespace.
    ///
    /// `f` runs on a separate thread because `setns` affects the calling thread.
    /// `F` is `Send` but not `'static`, so callers can capture references whose
    /// lifetime is bound by this guard.
    pub(crate) fn run<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R + Send,
        R: Send,
    {
        let peer_ns_path = Path::new(PERSIST_DIR).join(&self.name);
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
            let ns_path = Path::new(PERSIST_DIR).join(&name);
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
