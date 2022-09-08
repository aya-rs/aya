use std::{process::Command, thread, time};

use aya::{
    include_bytes_aligned,
    maps::{Array, MapRefMut},
    programs::{
        links::{FdLink, PinnedLink},
        TracePoint, Xdp, XdpFlags,
    },
    Bpf,
};

use super::{integration_test, IntegrationTest};

#[integration_test]
fn long_name() -> anyhow::Result<()> {
    let bytes = include_bytes_aligned!("../../../../target/bpfel-unknown-none/debug/name_test");
    let mut bpf = Bpf::load(bytes)?;
    let name_prog: &mut Xdp = bpf.program_mut("ihaveaverylongname").unwrap().try_into()?;
    name_prog.load().unwrap();
    name_prog.attach("lo", XdpFlags::default())?;

    // We used to be able to assert with bpftool that the program name was short.
    // It seem though that it now uses the name from the ELF symbol table instead.
    // Therefore, as long as we were able to load the program, this is good enough.

    Ok(())
}

#[integration_test]
fn multiple_maps() -> anyhow::Result<()> {
    let bytes =
        include_bytes_aligned!("../../../../target/bpfel-unknown-none/debug/multimap.bpf.o");
    let mut bpf = Bpf::load(bytes)?;
    let pass: &mut Xdp = bpf.program_mut("stats").unwrap().try_into().unwrap();
    pass.load().unwrap();
    pass.attach("lo", XdpFlags::default()).unwrap();
    Ok(())
}

#[integration_test]
fn multiple_btf_maps() -> anyhow::Result<()> {
    let bytes =
        include_bytes_aligned!("../../../../target/bpfel-unknown-none/debug/multimap-btf.bpf.o");
    let mut bpf = Bpf::load(bytes)?;

    let map_1: Array<MapRefMut, u64> = Array::try_from(bpf.map_mut("map_1")?)?;
    let map_2: Array<MapRefMut, u64> = Array::try_from(bpf.map_mut("map_2")?)?;

    let prog: &mut TracePoint = bpf.program_mut("tracepoint").unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach("sched", "sched_switch").unwrap();

    thread::sleep(time::Duration::from_secs(3));

    let key = 0;
    let val_1 = map_1.get(&key, 0)?;
    let val_2 = map_2.get(&key, 0)?;

    assert_eq!(val_1, 24);
    assert_eq!(val_2, 42);

    Ok(())
}

fn is_loaded(name: &str) -> bool {
    let output = Command::new("bpftool").args(["prog"]).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    stdout.contains(name)
}

fn assert_loaded(name: &str, loaded: bool) {
    let state = is_loaded(name);
    if state == loaded {
        return;
    }
    panic!("Expected loaded: {} but was loaded: {}", loaded, state);
}

#[integration_test]
fn unload() -> anyhow::Result<()> {
    let bytes = include_bytes_aligned!("../../../../target/bpfel-unknown-none/debug/test");
    let mut bpf = Bpf::load(bytes)?;
    let prog: &mut Xdp = bpf.program_mut("test_unload").unwrap().try_into().unwrap();
    prog.load().unwrap();
    let link = prog.attach("lo", XdpFlags::default()).unwrap();
    {
        let _link_owned = prog.take_link(link);
        prog.unload().unwrap();
        assert_loaded("test_unload", true);
    };

    assert_loaded("test_unload", false);
    prog.load().unwrap();

    assert_loaded("test_unload", true);
    prog.attach("lo", XdpFlags::default()).unwrap();

    assert_loaded("test_unload", true);
    prog.unload().unwrap();

    assert_loaded("test_unload", false);
    Ok(())
}

#[integration_test]
fn pin_link() -> anyhow::Result<()> {
    let bytes = include_bytes_aligned!("../../../../target/bpfel-unknown-none/debug/test");
    let mut bpf = Bpf::load(bytes)?;
    let prog: &mut Xdp = bpf.program_mut("test_unload").unwrap().try_into().unwrap();
    prog.load().unwrap();
    let link_id = prog.attach("lo", XdpFlags::default()).unwrap();
    let link = prog.take_link(link_id)?;
    assert_loaded("test_unload", true);

    let fd_link: FdLink = link.try_into()?;
    let pinned = fd_link.pin("/sys/fs/bpf/aya-xdp-test-lo")?;

    // because of the pin, the program is still attached
    prog.unload()?;
    assert_loaded("test_unload", true);

    // delete the pin, but the program is still attached
    let new_link = pinned.unpin()?;
    assert_loaded("test_unload", true);

    // finally when new_link is dropped we're detached
    drop(new_link);
    assert_loaded("test_unload", false);

    Ok(())
}

#[integration_test]
fn pin_lifecycle() -> anyhow::Result<()> {
    let bytes = include_bytes_aligned!("../../../../target/bpfel-unknown-none/debug/pass");

    // 1. Load Program and Pin
    {
        let mut bpf = Bpf::load(bytes)?;
        let prog: &mut Xdp = bpf.program_mut("pass").unwrap().try_into().unwrap();
        prog.load().unwrap();
        let link_id = prog.attach("lo", XdpFlags::default()).unwrap();
        let link = prog.take_link(link_id)?;
        let fd_link: FdLink = link.try_into()?;
        fd_link.pin("/sys/fs/bpf/aya-xdp-test-lo")?;
    }

    // should still be loaded since link was pinned
    assert_loaded("pass", true);

    // 2. Load a new version of the program, unpin link, and atomically replace old program
    {
        let mut bpf = Bpf::load(bytes)?;
        let prog: &mut Xdp = bpf.program_mut("pass").unwrap().try_into().unwrap();
        prog.load().unwrap();

        let link = PinnedLink::from_path("/sys/fs/bpf/aya-xdp-test-lo")?.unpin()?;
        prog.attach_to_link(link.try_into()?)?;
        assert_loaded("pass", true);
    }

    // program should be unloaded
    assert_loaded("pass", false);

    Ok(())
}
