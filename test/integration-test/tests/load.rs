use std::{convert::TryInto as _, thread, time};

use aya::{
    include_bytes_aligned,
    maps::Array,
    programs::{
        links::{FdLink, PinnedLink},
        loaded_programs, KProbe, TracePoint, Xdp, XdpFlags,
    },
    Bpf,
};

mod common;
use common::kernel_version;

const MAX_RETRIES: u32 = 100;
const RETRY_DURATION_MS: u64 = 10;

#[test]
fn long_name() {
    let bytes = include_bytes_aligned!("../../../target/bpfel-unknown-none/release/name_test");
    let mut bpf = Bpf::load(bytes).unwrap();
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
    let bytes =
        include_bytes_aligned!("../../../target/bpfel-unknown-none/release/multimap-btf.bpf.o");
    let mut bpf = Bpf::load(bytes).unwrap();

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
    let bytes = include_bytes_aligned!("../../../target/bpfel-unknown-none/release/test");
    let mut bpf = Bpf::load(bytes).unwrap();
    let prog: &mut Xdp = bpf
        .program_mut("test_unload_xdp")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    assert_loaded!("test_unload_xdp", true);
    let link = prog.attach("lo", XdpFlags::default()).unwrap();
    {
        let _link_owned = prog.take_link(link).unwrap();
        prog.unload().unwrap();
        assert_loaded!("test_unload_xdp", true);
    };

    assert_loaded!("test_unload_xdp", false);
    prog.load().unwrap();

    assert_loaded!("test_unload_xdp", true);
    prog.attach("lo", XdpFlags::default()).unwrap();

    assert_loaded!("test_unload_xdp", true);
    prog.unload().unwrap();

    assert_loaded!("test_unload_xdp", false);
}

#[test]
fn unload_kprobe() {
    let bytes = include_bytes_aligned!("../../../target/bpfel-unknown-none/release/test");
    let mut bpf = Bpf::load(bytes).unwrap();
    let prog: &mut KProbe = bpf
        .program_mut("test_unload_kpr")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    assert_loaded!("test_unload_kpr", true);
    let link = prog.attach("try_to_wake_up", 0).unwrap();
    {
        let _link_owned = prog.take_link(link).unwrap();
        prog.unload().unwrap();
        assert_loaded!("test_unload_kpr", true);
    };

    assert_loaded!("test_unload_kpr", false);
    prog.load().unwrap();

    assert_loaded!("test_unload_kpr", true);
    prog.attach("try_to_wake_up", 0).unwrap();

    assert_loaded!("test_unload_kpr", true);
    prog.unload().unwrap();

    assert_loaded!("test_unload_kpr", false);
}

#[test]
fn pin_link() {
    if kernel_version().unwrap() < (5, 9, 0) {
        eprintln!("skipping test, XDP uses netlink");
        return;
    }

    let bytes = include_bytes_aligned!("../../../target/bpfel-unknown-none/release/test");
    let mut bpf = Bpf::load(bytes).unwrap();
    let prog: &mut Xdp = bpf
        .program_mut("test_unload_xdp")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    let link_id = prog.attach("lo", XdpFlags::default()).unwrap();
    let link = prog.take_link(link_id).unwrap();
    assert_loaded!("test_unload_xdp", true);

    let fd_link: FdLink = link.try_into().unwrap();
    let pinned = fd_link.pin("/sys/fs/bpf/aya-xdp-test-lo").unwrap();

    // because of the pin, the program is still attached
    prog.unload().unwrap();
    assert_loaded!("test_unload_xdp", true);

    // delete the pin, but the program is still attached
    let new_link = pinned.unpin().unwrap();
    assert_loaded!("test_unload_xdp", true);

    // finally when new_link is dropped we're detached
    drop(new_link);
    assert_loaded!("test_unload_xdp", false);
}

#[test]
fn pin_lifecycle() {
    if kernel_version().unwrap() < (5, 9, 0) {
        eprintln!("skipping test, XDP uses netlink");
        return;
    }

    let bytes = include_bytes_aligned!("../../../target/bpfel-unknown-none/release/pass");

    // 1. Load Program and Pin
    {
        let mut bpf = Bpf::load(bytes).unwrap();
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
    assert_loaded!("pass", true);

    // 4. Load a new version of the program, unpin link, and atomically replace old program
    {
        let mut bpf = Bpf::load(bytes).unwrap();
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
