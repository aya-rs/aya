use std::time::Duration;

use aya::{programs::UProbe, util::KernelVersion, Bpf};

#[test]
fn relocations() {
    let bpf = load_and_attach("test_64_32_call_relocs", crate::RELOCATIONS);

    trigger_relocations_program();
    std::thread::sleep(Duration::from_millis(100));

    let m = aya::maps::Array::<_, u64>::try_from(bpf.map("RESULTS").unwrap()).unwrap();
    assert_eq!(m.get(&0, 0).unwrap(), 1);
    assert_eq!(m.get(&1, 0).unwrap(), 2);
    assert_eq!(m.get(&2, 0).unwrap(), 3);
}

#[test]
fn text_64_64_reloc() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(5, 13, 0) {
        eprintln!("skipping test on kernel {kernel_version:?}, support for bpf_for_each_map_elem was added in 5.13.0; see https://github.com/torvalds/linux/commit/69c087b");
        return;
    }

    let mut bpf = load_and_attach("test_text_64_64_reloc", crate::TEXT_64_64_RELOC);

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
    prog.load().unwrap();

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
pub extern "C" fn trigger_relocations_program() {
    core::hint::black_box(trigger_relocations_program);
}
