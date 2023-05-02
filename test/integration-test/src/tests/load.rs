use std::{convert::TryInto as _, process::Command, thread, time};

use aya::{
    maps::Array,
    programs::{
        links::{FdLink, PinnedLink},
        loaded_programs, KProbe, TracePoint, UProbe, Xdp, XdpFlags,
    },
    util::KernelVersion,
    Bpf,
};

const MAX_RETRIES: u32 = 100;
const RETRY_DURATION_MS: u64 = 10;

#[test]
fn long_name() {
    let mut bpf = Bpf::load(crate::NAME_TEST).unwrap();
    let name_prog: &mut Xdp = bpf
        .program_mut("ihaveaverylongname")
        .unwrap()
        .try_into()
        .unwrap();
    name_prog.load().unwrap();
    name_prog.attach("lo", XdpFlags::default()).unwrap();

    // We used to be able to assert with bpftool that the program name was short.
    // It seem though that it now uses the name from the ELF symbol table instead.
    // Therefore, as long as we were able to load the program, this is good enough.
}

#[test]
fn multiple_btf_maps() {
    let mut bpf = Bpf::load(crate::MULTIMAP_BTF).unwrap();

    let map_1: Array<_, u64> = bpf.take_map("map_1").unwrap().try_into().unwrap();
    let map_2: Array<_, u64> = bpf.take_map("map_2").unwrap().try_into().unwrap();

    let prog: &mut TracePoint = bpf.program_mut("tracepoint").unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach("sched", "sched_switch").unwrap();

    thread::sleep(time::Duration::from_secs(3));

    let key = 0;
    let val_1 = map_1.get(&key, 0).unwrap();
    let val_2 = map_2.get(&key, 0).unwrap();

    assert_eq!(val_1, 24);
    assert_eq!(val_2, 42);
}

fn is_linked(prog_id: &u32) -> bool {
    let output = Command::new("bpftool").args(["link"]).output();
    let output = output.expect("Failed to run 'bpftool link'");
    let stdout = String::from_utf8(output.stdout).unwrap();
    stdout.contains(&prog_id.to_string())
}

macro_rules! assert_loaded_and_linked {
    ($name:literal, $loaded:expr) => {
        for i in 0..(MAX_RETRIES + 1) {
            let id = loaded_programs()
                .find(|prog| prog.as_ref().unwrap().name() == $name.as_bytes())
                .map(|prog| Some(prog.unwrap().id()));
            let mut linked = false;
            if let Some(prog_id) = id {
                linked = is_linked(&prog_id.unwrap());
                if linked == $loaded {
                    break;
                }
            }

            if i == MAX_RETRIES {
                panic!(
                    "Expected (loaded/linked: {}) but found (id: {}, linked: {}",
                    $loaded,
                    id.is_some(),
                    linked
                );
            }
            thread::sleep(time::Duration::from_millis(RETRY_DURATION_MS));
        }
    };
}

macro_rules! assert_loaded {
    ($name:literal, $loaded:expr) => {
        for i in 0..(MAX_RETRIES + 1) {
            let state = loaded_programs().any(|prog| prog.unwrap().name() == $name.as_bytes());
            if state == $loaded {
                break;
            }
            if i == MAX_RETRIES {
                panic!("Expected loaded: {} but was loaded: {}", $loaded, state);
            }
            thread::sleep(time::Duration::from_millis(RETRY_DURATION_MS));
        }
    };
}

#[test]
fn unload_xdp() {
    let mut bpf = Bpf::load(crate::TEST).unwrap();
    let prog: &mut Xdp = bpf.program_mut("test_xdp").unwrap().try_into().unwrap();
    prog.load().unwrap();
    assert_loaded!("test_xdp", true);
    let link = prog.attach("lo", XdpFlags::default()).unwrap();
    {
        let _link_owned = prog.take_link(link).unwrap();
        prog.unload().unwrap();
        assert_loaded_and_linked!("test_xdp", true);
    };

    assert_loaded!("test_xdp", false);
    prog.load().unwrap();

    assert_loaded!("test_xdp", true);
    prog.attach("lo", XdpFlags::default()).unwrap();

    assert_loaded!("test_xdp", true);
    prog.unload().unwrap();

    assert_loaded!("test_xdp", false);
}

#[test]
fn unload_kprobe() {
    let mut bpf = Bpf::load(crate::TEST).unwrap();
    let prog: &mut KProbe = bpf.program_mut("test_kprobe").unwrap().try_into().unwrap();
    prog.load().unwrap();
    assert_loaded!("test_kprobe", true);
    let link = prog.attach("try_to_wake_up", 0).unwrap();
    {
        let _link_owned = prog.take_link(link).unwrap();
        prog.unload().unwrap();
        assert_loaded_and_linked!("test_kprobe", true);
    };

    assert_loaded!("test_kprobe", false);
    prog.load().unwrap();

    assert_loaded!("test_kprobe", true);
    prog.attach("try_to_wake_up", 0).unwrap();

    assert_loaded!("test_kprobe", true);
    prog.unload().unwrap();

    assert_loaded!("test_kprobe", false);
}

#[test]
fn basic_tracepoint() {
    let mut bpf = Bpf::load(crate::TEST).unwrap();
    let prog: &mut TracePoint = bpf
        .program_mut("test_tracepoint")
        .unwrap()
        .try_into()
        .unwrap();

    prog.load().unwrap();
    assert_loaded!("test_tracepoint", true);
    let link = prog.attach("syscalls", "sys_enter_kill").unwrap();

    {
        let _link_owned = prog.take_link(link).unwrap();
        prog.unload().unwrap();
        assert_loaded_and_linked!("test_tracepoint", true);
    };

    assert_loaded!("test_tracepoint", false);
    prog.load().unwrap();

    assert_loaded!("test_tracepoint", true);
    prog.attach("syscalls", "sys_enter_kill").unwrap();

    assert_loaded!("test_tracepoint", true);
    prog.unload().unwrap();

    assert_loaded!("test_tracepoint", false);
}

#[test]
fn basic_uprobe() {
    let mut bpf = Bpf::load(crate::TEST).unwrap();
    let prog: &mut UProbe = bpf.program_mut("test_uprobe").unwrap().try_into().unwrap();

    prog.load().unwrap();
    assert_loaded!("test_uprobe", true);
    let link = prog.attach(Some("sleep"), 0, "libc", None).unwrap();

    {
        let _link_owned = prog.take_link(link).unwrap();
        prog.unload().unwrap();
        assert_loaded_and_linked!("test_uprobe", true);
    };

    assert_loaded!("test_uprobe", false);
    prog.load().unwrap();

    assert_loaded!("test_uprobe", true);
    prog.attach(Some("sleep"), 0, "libc", None).unwrap();

    assert_loaded!("test_uprobe", true);
    prog.unload().unwrap();

    assert_loaded!("test_uprobe", false);
}

#[test]
fn pin_link() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(5, 9, 0) {
        eprintln!("skipping test on kernel {kernel_version:?}, XDP uses netlink");
        return;
    }

    let mut bpf = Bpf::load(crate::TEST).unwrap();
    let prog: &mut Xdp = bpf.program_mut("test_xdp").unwrap().try_into().unwrap();
    prog.load().unwrap();
    let link_id = prog.attach("lo", XdpFlags::default()).unwrap();
    let link = prog.take_link(link_id).unwrap();
    assert_loaded!("test_xdp", true);

    let fd_link: FdLink = link.try_into().unwrap();
    let pinned = fd_link.pin("/sys/fs/bpf/aya-xdp-test-lo").unwrap();

    // because of the pin, the program is still attached
    prog.unload().unwrap();
    assert_loaded!("test_xdp", true);

    // delete the pin, but the program is still attached
    let new_link = pinned.unpin().unwrap();
    assert_loaded!("test_xdp", true);

    // finally when new_link is dropped we're detached
    drop(new_link);
    assert_loaded!("test_xdp", false);
}

#[test]
fn pin_lifecycle() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(5, 18, 0) {
        eprintln!("skipping test on kernel {kernel_version:?}, support for BPF_F_XDP_HAS_FRAGS was added in 5.18.0; see https://github.com/torvalds/linux/commit/c2f2cdb");
        return;
    }

    // 1. Load Program and Pin
    {
        let mut bpf = Bpf::load(crate::PASS).unwrap();
        let prog: &mut Xdp = bpf.program_mut("pass").unwrap().try_into().unwrap();
        prog.load().unwrap();
        prog.pin("/sys/fs/bpf/aya-xdp-test-prog").unwrap();
    }

    // should still be loaded since prog was pinned
    assert_loaded!("pass", true);

    // 2. Load program from bpffs but don't attach it
    {
        let _ = Xdp::from_pin("/sys/fs/bpf/aya-xdp-test-prog").unwrap();
    }

    // should still be loaded since prog was pinned
    assert_loaded!("pass", true);

    // 3. Load program from bpffs and attach
    {
        let mut prog = Xdp::from_pin("/sys/fs/bpf/aya-xdp-test-prog").unwrap();
        let link_id = prog.attach("lo", XdpFlags::default()).unwrap();
        let link = prog.take_link(link_id).unwrap();
        let fd_link: FdLink = link.try_into().unwrap();
        fd_link.pin("/sys/fs/bpf/aya-xdp-test-lo").unwrap();

        // Unpin the program. It will stay attached since its links were pinned.
        prog.unpin().unwrap();
    }

    // should still be loaded since link was pinned
    assert_loaded_and_linked!("pass", true);

    // 4. Load a new version of the program, unpin link, and atomically replace old program
    {
        let mut bpf = Bpf::load(crate::PASS).unwrap();
        let prog: &mut Xdp = bpf.program_mut("pass").unwrap().try_into().unwrap();
        prog.load().unwrap();

        let link = PinnedLink::from_pin("/sys/fs/bpf/aya-xdp-test-lo")
            .unwrap()
            .unpin()
            .unwrap();
        prog.attach_to_link(link.try_into().unwrap()).unwrap();
        assert_loaded!("pass", true);
    }

    // program should be unloaded
    assert_loaded!("pass", false);
}

#[test]
fn pin_lifecycle_tracepoint() {
    // 1. Load Program and Pin
    {
        let mut bpf = Bpf::load(crate::TEST).unwrap();
        let prog: &mut TracePoint = bpf
            .program_mut("test_tracepoint")
            .unwrap()
            .try_into()
            .unwrap();
        prog.load().unwrap();
        prog.pin("/sys/fs/bpf/aya-tracepoint-test-prog").unwrap();
    }

    // should still be loaded since prog was pinned
    assert_loaded!("test_tracepoint", true);

    // 2. Load program from bpffs but don't attach it
    {
        let _ = TracePoint::from_pin("/sys/fs/bpf/aya-tracepoint-test-prog").unwrap();
    }

    // should still be loaded since prog was pinned
    assert_loaded!("test_tracepoint", true);

    // 3. Load program from bpffs and attach
    {
        let mut prog = TracePoint::from_pin("/sys/fs/bpf/aya-tracepoint-test-prog").unwrap();
        let link_id = prog.attach("syscalls", "sys_enter_kill").unwrap();
        let link = prog.take_link(link_id).unwrap();
        let fd_link: FdLink = link.try_into().unwrap();
        fd_link
            .pin("/sys/fs/bpf/aya-tracepoint-test-sys-enter-kill")
            .unwrap();

        // Unpin the program. It will stay attached since its links were pinned.
        prog.unpin().unwrap();
    }

    // should still be loaded since link was pinned
    assert_loaded_and_linked!("test_tracepoint", true);

    // 4. unpin link, and make sure everything is unloaded
    {
        PinnedLink::from_pin("/sys/fs/bpf/aya-tracepoint-test-sys-enter-kill")
            .unwrap()
            .unpin()
            .unwrap();
    }

    // program should be unloaded
    assert_loaded!("test_tracepoint", false);
}

#[test]
fn pin_lifecycle_kprobe() {
    // 1. Load Program and Pin
    {
        let mut bpf = Bpf::load(crate::TEST).unwrap();
        let prog: &mut KProbe = bpf.program_mut("test_kprobe").unwrap().try_into().unwrap();
        prog.load().unwrap();
        prog.pin("/sys/fs/bpf/aya-kprobe-test-prog").unwrap();
    }

    // should still be loaded since prog was pinned
    assert_loaded!("test_kprobe", true);

    // 2. Load program from bpffs but don't attach it
    {
        let _ = KProbe::from_pin(
            "/sys/fs/bpf/aya-kprobe-test-prog",
            aya::programs::ProbeKind::KProbe,
        )
        .unwrap();
    }

    // should still be loaded since prog was pinned
    assert_loaded!("test_kprobe", true);

    // 3. Load program from bpffs and attach
    {
        let mut prog = KProbe::from_pin(
            "/sys/fs/bpf/aya-kprobe-test-prog",
            aya::programs::ProbeKind::KProbe,
        )
        .unwrap();
        let link_id = prog.attach("try_to_wake_up", 0).unwrap();
        let link = prog.take_link(link_id).unwrap();
        let fd_link: FdLink = link.try_into().unwrap();
        fd_link
            .pin("/sys/fs/bpf/aya-kprobe-test-try-to-wake-up")
            .unwrap();

        // Unpin the program. It will stay attached since its links were pinned.
        prog.unpin().unwrap();
    }

    // should still be loaded since link was pinned
    assert_loaded_and_linked!("test_kprobe", true);

    // 4. unpin link, and make sure everything is unloaded
    {
        PinnedLink::from_pin("/sys/fs/bpf/aya-kprobe-test-try-to-wake-up")
            .unwrap()
            .unpin()
            .unwrap();
    }

    // program should be unloaded
    assert_loaded!("test_kprobe", false);
}

#[test]
fn pin_lifecycle_uprobe() {
    // 1. Load Program and Pin
    {
        let mut bpf = Bpf::load(crate::TEST).unwrap();
        let prog: &mut UProbe = bpf.program_mut("test_uprobe").unwrap().try_into().unwrap();
        prog.load().unwrap();
        prog.pin("/sys/fs/bpf/aya-uprobe-test-prog").unwrap();
    }

    // should still be loaded since prog was pinned
    assert_loaded!("test_uprobe", true);

    // 2. Load program from bpffs but don't attach it
    {
        let _ = UProbe::from_pin(
            "/sys/fs/bpf/aya-uprobe-test-prog",
            aya::programs::ProbeKind::UProbe,
        )
        .unwrap();
    }

    // should still be loaded since prog was pinned
    assert_loaded!("test_uprobe", true);

    // 3. Load program from bpffs and attach
    {
        let mut prog = UProbe::from_pin(
            "/sys/fs/bpf/aya-uprobe-test-prog",
            aya::programs::ProbeKind::UProbe,
        )
        .unwrap();
        let link_id = prog.attach(Some("sleep"), 0, "libc", None).unwrap();
        let link = prog.take_link(link_id).unwrap();
        let fd_link: FdLink = link.try_into().unwrap();
        fd_link
            .pin("/sys/fs/bpf/aya-uprobe-test-bash-sleep")
            .unwrap();

        // Unpin the program. It will stay attached since its links were pinned.
        prog.unpin().unwrap();
    }

    // should still be loaded since link was pinned
    assert_loaded_and_linked!("test_uprobe", true);

    // 4. unpin link, and make sure everything is unloaded
    {
        PinnedLink::from_pin("/sys/fs/bpf/aya-uprobe-test-bash-sleep")
            .unwrap()
            .unpin()
            .unwrap();
    }

    // program should be unloaded
    assert_loaded!("test_uprobe", false);
}
