use std::{process::exit, time::Duration};

use aya::{
    include_bytes_aligned,
    programs::{ProgramError, UProbe},
    Bpf,
};
use integration_test_macros::integration_test;

#[integration_test]
fn relocations() {
    let bpf = load_and_attach(
        "test_64_32_call_relocs",
        include_bytes_aligned!("../../../../target/bpfel-unknown-none/release/relocations"),
    );

    trigger_relocations_program();
    std::thread::sleep(Duration::from_millis(100));

    let m = aya::maps::Array::<_, u64>::try_from(bpf.map("RESULTS").unwrap()).unwrap();
    assert_eq!(m.get(&0, 0).unwrap(), 1);
    assert_eq!(m.get(&1, 0).unwrap(), 2);
    assert_eq!(m.get(&2, 0).unwrap(), 3);
}

#[integration_test]
fn text_64_64_reloc() {
    let mut bpf = load_and_attach(
        "test_text_64_64_reloc",
        include_bytes_aligned!("../../../../target/bpfel-unknown-none/release/text_64_64_reloc.o"),
    );

    let mut m = aya::maps::Array::<_, u64>::try_from(bpf.map_mut("RESULTS").unwrap()).unwrap();
    m.set(0, 1, 0).unwrap();
    m.set(1, 2, 0).unwrap();

    trigger_relocations_program();
    std::thread::sleep(Duration::from_millis(100));

    assert_eq!(m.get(&0, 0).unwrap(), 2);
    assert_eq!(m.get(&1, 0).unwrap(), 3);
}

fn load_and_attach(name: &str, bytes: &[u8]) -> Bpf {
    let mut bpf = Bpf::load(bytes).unwrap();

    let prog: &mut UProbe = bpf.program_mut(name).unwrap().try_into().unwrap();
    if let Err(ProgramError::LoadError {
        io_error,
        verifier_log,
    }) = prog.load()
    {
        println!("Failed to load program `{name}`: {io_error}. Verifier log:\n{verifier_log:#}");
        exit(1);
    };

    prog.attach(
        Some("trigger_relocations_program"),
        0,
        "/proc/self/exe",
        None,
    )
    .unwrap();

    bpf
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn trigger_relocations_program() {}
