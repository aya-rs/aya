use std::{convert::TryInto, process::Command};

use aya::{
    include_bytes_aligned,
    programs::{Xdp, XdpFlags},
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

fn is_loaded() -> bool {
    let output = Command::new("bpftool").args(&["prog"]).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    stdout.contains("test_unload")
}

fn assert_loaded(loaded: bool) {
    let state = is_loaded();
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
        assert_loaded(true);
    };

    assert_loaded(false);
    prog.load().unwrap();

    assert_loaded(true);
    prog.attach("lo", XdpFlags::default()).unwrap();

    assert_loaded(true);
    prog.unload().unwrap();

    assert_loaded(false);
    Ok(())
}
