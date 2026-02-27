use std::{ffi::CString, fs, io};

use aya::{EbpfLoader, programs::XdpFlags};
use aya_xdp_dispatcher::{EbpfPrograms, XdpDispatcher};
use libc::if_nametoindex;
use uuid::Uuid;

use crate::utils::NetNsGuard;

const RTDIR_FS_XDP: &str = "/sys/fs/bpf/xdp";

fn get_lo_ifindex() -> u32 {
    let lo = CString::new("lo").unwrap();
    let idx = unsafe { if_nametoindex(lo.as_ptr()) };
    if idx == 0 {
        panic!("interface `lo` not found: {}", io::Error::last_os_error());
    }
    idx
}

/// Find the dispatcher directory for `if_index` (named `dispatch-{if_index}-{did}`).
fn find_dispatcher_dir(if_index: u32) -> Option<std::path::PathBuf> {
    let prefix = format!("dispatch-{if_index}-");
    let entries = fs::read_dir(RTDIR_FS_XDP).ok()?;
    for entry in entries.flatten() {
        if entry
            .file_name()
            .to_str()
            .is_some_and(|s| s.starts_with(&prefix))
        {
            return Some(entry.path());
        }
    }
    None
}

/// Count pinned extension programs (`prog{i}-prog`) in the current dispatcher directory.
fn count_pinned_extensions(if_index: u32) -> usize {
    let Some(dir) = find_dispatcher_dir(if_index) else {
        return 0;
    };
    let Ok(entries) = fs::read_dir(&dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with("-prog"))
        })
        .count()
}

fn cleanup_dispatcher(if_index: u32) {
    if let Some(dir) = find_dispatcher_dir(if_index) {
        let _ = fs::remove_dir_all(&dir);
    }
}

#[test_log::test]
fn xdp_dispatcher_single_program() {
    let _netns = NetNsGuard::new();
    let if_index = get_lo_ifindex();

    // Clean up any existing state
    cleanup_dispatcher(if_index);

    let ebpf_id = Uuid::new_v4();
    let mut programs = EbpfPrograms::new(ebpf_id, EbpfLoader::new(), crate::XDP_DISPATCHER_TEST)
        .set_priority("xdp_dispatcher_a", 10);

    {
        let _dispatcher =
            XdpDispatcher::new_with_programs(if_index, XdpFlags::default(), vec![&mut programs])
                .expect("failed to create dispatcher with single program");

        // Verify one extension is pinned
        assert_eq!(
            count_pinned_extensions(if_index),
            1,
            "expected 1 pinned extension"
        );
    }

    // After dispatcher is dropped, no extensions should remain
    assert_eq!(
        count_pinned_extensions(if_index),
        0,
        "expected 0 pinned extensions after drop"
    );
}

#[test_log::test]
fn xdp_dispatcher_multiple_programs_same_loader() {
    let _netns = NetNsGuard::new();
    let if_index = get_lo_ifindex();

    cleanup_dispatcher(if_index);

    let ebpf_id = Uuid::new_v4();
    let mut programs = EbpfPrograms::new(ebpf_id, EbpfLoader::new(), crate::XDP_DISPATCHER_TEST)
        .set_priority("xdp_dispatcher_a", 10)
        .set_priority("xdp_dispatcher_b", 20);

    {
        let _dispatcher =
            XdpDispatcher::new_with_programs(if_index, XdpFlags::default(), vec![&mut programs])
                .expect("failed to create dispatcher with multiple programs");

        assert_eq!(
            count_pinned_extensions(if_index),
            2,
            "expected 2 pinned extensions"
        );
    }

    assert_eq!(
        count_pinned_extensions(if_index),
        0,
        "expected 0 pinned extensions after drop"
    );
}

#[test_log::test]
fn xdp_dispatcher_two_dispatchers_ownership() {
    let _netns = NetNsGuard::new();
    let if_index = get_lo_ifindex();

    cleanup_dispatcher(if_index);

    // Dispatcher 1 loads programs A and B
    let ebpf_id1 = Uuid::new_v4();
    let mut programs1 = EbpfPrograms::new(ebpf_id1, EbpfLoader::new(), crate::XDP_DISPATCHER_TEST)
        .set_priority("xdp_dispatcher_a", 10)
        .set_priority("xdp_dispatcher_b", 20);

    let dispatcher1 =
        XdpDispatcher::new_with_programs(if_index, XdpFlags::default(), vec![&mut programs1])
            .expect("failed to create dispatcher1");

    assert_eq!(
        count_pinned_extensions(if_index),
        2,
        "expected 2 pinned extensions after dispatcher1"
    );

    // Dispatcher 2 loads program C
    let ebpf_id2 = Uuid::new_v4();
    let mut programs2 = EbpfPrograms::new(ebpf_id2, EbpfLoader::new(), crate::XDP_DISPATCHER_TEST)
        .set_priority("xdp_dispatcher_c", 30);

    let dispatcher2 =
        XdpDispatcher::new_with_programs(if_index, XdpFlags::default(), vec![&mut programs2])
            .expect("failed to create dispatcher2");

    // Total should be A, B, C = 3 programs
    assert_eq!(
        count_pinned_extensions(if_index),
        3,
        "expected 3 pinned extensions (A, B, C)"
    );

    // Drop dispatcher1 - only its programs (A, B) should be removed
    drop(dispatcher1);

    // Only C should remain
    assert_eq!(
        count_pinned_extensions(if_index),
        1,
        "expected 1 pinned extension (C) after dropping dispatcher1"
    );

    // Drop dispatcher2 - C should be removed
    drop(dispatcher2);

    assert_eq!(
        count_pinned_extensions(if_index),
        0,
        "expected 0 pinned extensions after dropping all dispatchers"
    );
}

#[test_log::test]
fn xdp_dispatcher_priority_ordering() {
    let _netns = NetNsGuard::new();
    let if_index = get_lo_ifindex();

    cleanup_dispatcher(if_index);

    // Load programs with specific priorities to test ordering
    let ebpf_id = Uuid::new_v4();
    let mut programs = EbpfPrograms::new(ebpf_id, EbpfLoader::new(), crate::XDP_DISPATCHER_TEST)
        // Programs with different priorities - they should be ordered by priority
        .set_priority("xdp_dispatcher_c", 5) // lowest priority, runs first
        .set_priority("xdp_dispatcher_a", 15) // medium priority
        .set_priority("xdp_dispatcher_b", 25); // highest priority, runs last

    {
        let _dispatcher =
            XdpDispatcher::new_with_programs(if_index, XdpFlags::default(), vec![&mut programs])
                .expect("failed to create dispatcher with priority ordering");

        assert_eq!(
            count_pinned_extensions(if_index),
            3,
            "expected 3 pinned extensions"
        );
    }

    assert_eq!(
        count_pinned_extensions(if_index),
        0,
        "expected 0 pinned extensions after drop"
    );
}

#[test_log::test]
fn xdp_dispatcher_interleaved_drops() {
    let _netns = NetNsGuard::new();
    let if_index = get_lo_ifindex();

    cleanup_dispatcher(if_index);

    // Create three dispatchers with different programs
    let ebpf_id1 = Uuid::new_v4();
    let mut programs1 = EbpfPrograms::new(ebpf_id1, EbpfLoader::new(), crate::XDP_DISPATCHER_TEST)
        .set_priority("xdp_dispatcher_a", 10);

    let dispatcher1 =
        XdpDispatcher::new_with_programs(if_index, XdpFlags::default(), vec![&mut programs1])
            .expect("failed to create dispatcher1");

    assert_eq!(count_pinned_extensions(if_index), 1);

    let ebpf_id2 = Uuid::new_v4();
    let mut programs2 = EbpfPrograms::new(ebpf_id2, EbpfLoader::new(), crate::XDP_DISPATCHER_TEST)
        .set_priority("xdp_dispatcher_b", 20);

    let dispatcher2 =
        XdpDispatcher::new_with_programs(if_index, XdpFlags::default(), vec![&mut programs2])
            .expect("failed to create dispatcher2");

    assert_eq!(count_pinned_extensions(if_index), 2);

    let ebpf_id3 = Uuid::new_v4();
    let mut programs3 = EbpfPrograms::new(ebpf_id3, EbpfLoader::new(), crate::XDP_DISPATCHER_TEST)
        .set_priority("xdp_dispatcher_c", 30);

    let dispatcher3 =
        XdpDispatcher::new_with_programs(if_index, XdpFlags::default(), vec![&mut programs3])
            .expect("failed to create dispatcher3");

    assert_eq!(count_pinned_extensions(if_index), 3);

    // Drop the middle dispatcher (2)
    drop(dispatcher2);
    assert_eq!(
        count_pinned_extensions(if_index),
        2,
        "expected 2 extensions (A and C) after dropping dispatcher2"
    );

    // Drop the first dispatcher (1)
    drop(dispatcher1);
    assert_eq!(
        count_pinned_extensions(if_index),
        1,
        "expected 1 extension (C) after dropping dispatcher1"
    );

    // Drop the last dispatcher (3)
    drop(dispatcher3);
    assert_eq!(
        count_pinned_extensions(if_index),
        0,
        "expected 0 extensions after dropping all dispatchers"
    );
}
