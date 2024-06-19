use std::collections::HashSet;

use aya::{programs::UProbe, util::KernelVersion, Ebpf, EbpfLoader};
use aya_obj::generated::bpf_map_type;
use test_log::test;

enum DisableMapRelocation<'a> {
    ByType(bpf_map_type),
    ByName(&'a str),
}

#[test]
fn test_ignored_map_relocation_by_type() {
    let mut ebpf = relocation_load_and_attach("test_ignored_map_relocation", crate::IGNORE_MAP, DisableMapRelocation::ByType(bpf_map_type::BPF_MAP_TYPE_RINGBUF));

    let perf = ebpf
        .take_map("PERFBUF");

    let ring =  ebpf
        .take_map("RINGBUF");

    assert!(perf.is_some());
    assert!(ring.is_none());
}

#[test]
fn test_ignored_map_relocation_by_name() {
    let mut ebpf = relocation_load_and_attach("test_ignored_map_relocation", crate::IGNORE_MAP, DisableMapRelocation::ByName("RINGBUF"));

    let perf = ebpf
        .take_map("PERFBUF");

    let ring =  ebpf
        .take_map("RINGBUF");

    assert!(perf.is_some());
    assert!(ring.is_none());
}

#[test]
fn relocations() {
    let bpf = load_and_attach("test_64_32_call_relocs", crate::RELOCATIONS);

    trigger_relocations_program();

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

    assert_eq!(m.get(&0, 0).unwrap(), 2);
    assert_eq!(m.get(&1, 0).unwrap(), 3);
}

fn relocation_load_and_attach(name: &str, bytes: &[u8], disable_type: DisableMapRelocation) -> Ebpf {
    let mut ebpf = match disable_type {
        DisableMapRelocation::ByType(bmt) => {
            let mut set = HashSet::new();
            set.insert(bmt);
            EbpfLoader::new()
                .ignore_maps_by_type(set)
                .set_global("RINGBUF_SUPPORTED", &0, true)
                .load(bytes)
                .unwrap()
        }
        DisableMapRelocation::ByName(name) => {
            EbpfLoader::new()
                .ignore_maps_by_name(&[name])
                .set_global("RINGBUF_SUPPORTED", &0, true)
                .load(bytes)
                .unwrap()
        }
    };

    let prog: &mut UProbe = ebpf.program_mut(name).unwrap().try_into().unwrap();
    prog.load().unwrap();

    prog.attach(
        Some("trigger_relocations_program"),
        0,
        "/proc/self/exe",
        None,
    )
    .unwrap();

    ebpf
}

fn load_and_attach(name: &str, bytes: &[u8]) -> Ebpf {
    let mut bpf = Ebpf::load(bytes).unwrap();

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
