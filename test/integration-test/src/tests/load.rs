use std::{process::Command, thread, time};

use aya::{
    include_bytes_aligned,
    maps::Array,
    programs::{
        links::{FdLink, PinnedLink},
        TracePoint, Xdp, XdpFlags,
    },
    Bpf,
};

use super::{integration_test, IntegrationTest};

const MAX_RETRIES: u32 = 100;
const RETRY_DURATION_MS: u64 = 10;

#[integration_test]
fn long_name() {
    let bytes = include_bytes_aligned!("../../../../target/bpfel-unknown-none/debug/name_test");
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

#[integration_test]
fn multiple_btf_maps() {
    let bytes =
        include_bytes_aligned!("../../../../target/bpfel-unknown-none/debug/multimap-btf.bpf.o");
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

fn is_loaded(name: &str) -> bool {
    let output = Command::new("bpftool").args(["prog"]).output();
    let output = match output {
        Err(e) => panic!("Failed to run 'bpftool prog': {e}"),
        Ok(out) => out,
    };
    let stdout = String::from_utf8(output.stdout).unwrap();
    stdout.contains(name)
}

macro_rules! assert_loaded {
    ($name:literal, $loaded:expr) => {
        for i in 0..(MAX_RETRIES + 1) {
            let state = is_loaded($name);
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

#[integration_test]
fn unload() {
    let bytes = include_bytes_aligned!("../../../../target/bpfel-unknown-none/debug/test");
    let mut bpf = Bpf::load(bytes).unwrap();
    let prog: &mut Xdp = bpf.program_mut("test_unload").unwrap().try_into().unwrap();
    prog.load().unwrap();
    let link = prog.attach("lo", XdpFlags::default()).unwrap();
    {
        let _link_owned = prog.take_link(link);
        prog.unload().unwrap();
        assert_loaded!("test_unload", true);
    };

    assert_loaded!("test_unload", false);
    prog.load().unwrap();

    assert_loaded!("test_unload", true);
    prog.attach("lo", XdpFlags::default()).unwrap();

    assert_loaded!("test_unload", true);
    prog.unload().unwrap();

    assert_loaded!("test_unload", false);
}

#[integration_test]
fn pin_link() {
    let bytes = include_bytes_aligned!("../../../../target/bpfel-unknown-none/debug/test");
    let mut bpf = Bpf::load(bytes).unwrap();
    let prog: &mut Xdp = bpf.program_mut("test_unload").unwrap().try_into().unwrap();
    prog.load().unwrap();
    let link_id = prog.attach("lo", XdpFlags::default()).unwrap();
    let link = prog.take_link(link_id).unwrap();
    assert_loaded!("test_unload", true);

    let fd_link: FdLink = link.try_into().unwrap();
    let pinned = fd_link.pin("/sys/fs/bpf/aya-xdp-test-lo").unwrap();

    // because of the pin, the program is still attached
    prog.unload().unwrap();
    assert_loaded!("test_unload", true);

    // delete the pin, but the program is still attached
    let new_link = pinned.unpin().unwrap();
    assert_loaded!("test_unload", true);

    // finally when new_link is dropped we're detached
    drop(new_link);
    assert_loaded!("test_unload", false);
}

#[integration_test]
fn pin_lifecycle() {
    let bytes = include_bytes_aligned!("../../../../target/bpfel-unknown-none/debug/pass");

    // 1. Load Program and Pin
    {
        let mut bpf = Bpf::load(bytes).unwrap();
        let prog: &mut Xdp = bpf.program_mut("pass").unwrap().try_into().unwrap();
        prog.load().unwrap();
        let link_id = prog.attach("lo", XdpFlags::default()).unwrap();
        let link = prog.take_link(link_id).unwrap();
        let fd_link: FdLink = link.try_into().unwrap();
        fd_link.pin("/sys/fs/bpf/aya-xdp-test-lo").unwrap();
    }

    // should still be loaded since link was pinned
    assert_loaded!("pass", true);

    // 2. Load a new version of the program, unpin link, and atomically replace old program
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
