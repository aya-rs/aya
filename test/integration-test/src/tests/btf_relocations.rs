use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use aya::{
    Ebpf, EbpfLoader, Endianness,
    maps::Array,
    programs::{UProbe, uprobe::UProbeScope},
};
use aya_obj::btf::Btf;
use rstest::rstest;

#[rstest]
#[case(
    crate::ENUM_SIGNED_32_RELOC_BPF,
    crate::ENUM_SIGNED_32_RELOC_BTF,
    -0x7BBBBBBBi32 as u64
)]
#[case(
    crate::ENUM_SIGNED_32_CHECKED_VARIANTS_RELOC_BPF,
    crate::ENUM_SIGNED_32_CHECKED_VARIANTS_RELOC_BTF,
    -0x7BBBBBBBi32 as u64
)]
#[case(
    crate::ENUM_SIGNED_64_RELOC_BPF,
    crate::ENUM_SIGNED_64_RELOC_BTF,
    -0xCCCCCCCDDDDDDDDi64 as u64
)]
#[case(
    crate::ENUM_SIGNED_64_CHECKED_VARIANTS_RELOC_BPF,
    crate::ENUM_SIGNED_64_CHECKED_VARIANTS_RELOC_BTF,
    -0xCCCCCCCDDDDDDDi64 as u64
)]
#[case(
    crate::ENUM_UNSIGNED_32_RELOC_BPF,
    crate::ENUM_UNSIGNED_32_RELOC_BTF,
    0xBBBBBBBB
)]
#[case(
    crate::ENUM_UNSIGNED_32_CHECKED_VARIANTS_RELOC_BPF,
    crate::ENUM_UNSIGNED_32_CHECKED_VARIANTS_RELOC_BTF,
    0xBBBBBBBB
)]
#[case(
    crate::ENUM_UNSIGNED_64_RELOC_BPF,
    crate::ENUM_UNSIGNED_64_RELOC_BTF,
    0xCCCCCCCCDDDDDDDD
)]
#[case(
    crate::ENUM_UNSIGNED_64_CHECKED_VARIANTS_RELOC_BPF,
    crate::ENUM_UNSIGNED_64_CHECKED_VARIANTS_RELOC_BTF,
    0xCCCCCCCCDDDDDDDD
)]
#[case(crate::FIELD_RELOC_BPF, crate::FIELD_RELOC_BTF, 1)]
#[case(crate::POINTER_RELOC_BPF, crate::POINTER_RELOC_BTF, 21)]
#[case(crate::STRUCT_FLAVORS_RELOC_BPF, crate::STRUCT_FLAVORS_RELOC_BTF, 2)]
#[test_attr(test_log::test)]
fn relocation_tests(#[case] bpf: &[u8], #[case] btf: &[u8], #[case] expected: u64) {
    let btf = Btf::parse(btf, Endianness::default()).unwrap();

    let bpf = EbpfLoader::new().btf(&btf).load(bpf).unwrap();

    assert_relocation(bpf, expected);
}

#[test_log::test]
fn lazy_btf_source_is_cached() {
    let calls = Arc::new(AtomicUsize::new(0));
    let source_calls = Arc::clone(&calls);
    let mut loader = EbpfLoader::new();
    loader.btf_source(move || {
        source_calls.fetch_add(1, Ordering::Relaxed);
        Ok::<_, std::io::Error>(crate::FIELD_RELOC_BTF)
    });

    let bpf = loader.load(crate::FIELD_RELOC_BPF).unwrap();
    let _second_bpf = loader.load(crate::FIELD_RELOC_BPF).unwrap();

    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_relocation(bpf, 1);
}

#[test_log::test]
fn btf_source_is_not_called_when_unneeded() {
    let calls = Arc::new(AtomicUsize::new(0));
    let source_calls = Arc::clone(&calls);
    let mut loader = EbpfLoader::new();
    loader.btf_source(move || {
        source_calls.fetch_add(1, Ordering::Relaxed);
        Ok::<_, std::io::Error>(crate::FIELD_RELOC_BTF)
    });

    // RINGBUF_BTF contains BTF map definitions but no CO-RE relocations or typed ksyms. If that
    // changes, replace it with an object that does not require target BTF.
    let _bpf = loader.load(crate::RINGBUF_BTF).unwrap();

    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

fn assert_relocation(mut bpf: Ebpf, expected: u64) {
    let program: &mut UProbe = bpf.program_mut("program").unwrap().try_into().unwrap();
    program.load().unwrap();
    program
        .attach(
            "trigger_btf_relocations_program",
            "/proc/self/exe",
            UProbeScope::AllProcesses,
        )
        .unwrap();

    trigger_btf_relocations_program();

    let output_map: Array<_, u64> = bpf.take_map("output_map").unwrap().try_into().unwrap();
    let key = 0;
    assert_eq!(output_map.get(&key, 0).unwrap(), expected)
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_btf_relocations_program() {
    core::hint::black_box(trigger_btf_relocations_program);
}
