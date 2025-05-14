use aya::{Btf, EbpfLoader, Endianness, maps::Array, programs::UProbe, util::KernelVersion};
use test_case::test_case;

#[test_case(crate::ENUM_SIGNED_32_RELOC_BPF, None, Some((KernelVersion::new(6, 0, 0), "https://github.com/torvalds/linux/commit/6089fb3")), -0x7AAAAAAAi32 as u64)]
#[test_case(crate::ENUM_SIGNED_32_RELOC_BPF, Some(crate::ENUM_SIGNED_32_RELOC_BTF), Some((KernelVersion::new(6, 0, 0), "https://github.com/torvalds/linux/commit/6089fb3")), -0x7BBBBBBBi32 as u64)]
#[test_case(crate::ENUM_SIGNED_32_CHECKED_VARIANTS_RELOC_BPF, None, Some((KernelVersion::new(6, 0, 0), "https://github.com/torvalds/linux/commit/6089fb3")), -0x7AAAAAAAi32 as u64)]
#[test_case(crate::ENUM_SIGNED_32_CHECKED_VARIANTS_RELOC_BPF, Some(crate::ENUM_SIGNED_32_CHECKED_VARIANTS_RELOC_BTF), Some((KernelVersion::new(6, 0, 0), "https://github.com/torvalds/linux/commit/6089fb3")), -0x7BBBBBBBi32 as u64)]
#[test_case(crate::ENUM_SIGNED_64_RELOC_BPF, None, Some((KernelVersion::new(6, 0, 0), "https://github.com/torvalds/linux/commit/6089fb3")), -0xAAAAAAABBBBBBBBi64 as u64)]
#[test_case(crate::ENUM_SIGNED_64_RELOC_BPF, Some(crate::ENUM_SIGNED_64_RELOC_BTF), Some((KernelVersion::new(6, 0, 0), "https://github.com/torvalds/linux/commit/6089fb3")), -0xCCCCCCCDDDDDDDDi64 as u64)]
#[test_case(crate::ENUM_SIGNED_64_CHECKED_VARIANTS_RELOC_BPF, None, Some((KernelVersion::new(6, 0, 0), "https://github.com/torvalds/linux/commit/6089fb3")), -0xAAAAAAABBBBBBBi64 as u64)]
#[test_case(crate::ENUM_SIGNED_64_CHECKED_VARIANTS_RELOC_BPF, Some(crate::ENUM_SIGNED_64_CHECKED_VARIANTS_RELOC_BTF), Some((KernelVersion::new(6, 0, 0), "https://github.com/torvalds/linux/commit/6089fb3")), -0xCCCCCCCDDDDDDDi64 as u64)]
#[test_case(crate::ENUM_UNSIGNED_32_RELOC_BPF, None, None, 0xAAAAAAAA)]
#[test_case(
    crate::ENUM_UNSIGNED_32_RELOC_BPF,
    Some(crate::ENUM_UNSIGNED_32_RELOC_BTF),
    None,
    0xBBBBBBBB
)]
#[test_case(
    crate::ENUM_UNSIGNED_32_CHECKED_VARIANTS_RELOC_BPF,
    None,
    None,
    0xAAAAAAAA
)]
#[test_case(
    crate::ENUM_UNSIGNED_32_CHECKED_VARIANTS_RELOC_BPF,
    Some(crate::ENUM_UNSIGNED_32_CHECKED_VARIANTS_RELOC_BTF),
    None,
    0xBBBBBBBB
)]
#[test_case(crate::ENUM_UNSIGNED_64_RELOC_BPF, None, Some((KernelVersion::new(6, 0, 0), "https://github.com/torvalds/linux/commit/6089fb3")), 0xAAAAAAAABBBBBBBB)]
#[test_case(crate::ENUM_UNSIGNED_64_RELOC_BPF, Some(crate::ENUM_UNSIGNED_64_RELOC_BTF), Some((KernelVersion::new(6, 0, 0), "https://github.com/torvalds/linux/commit/6089fb3")), 0xCCCCCCCCDDDDDDDD)]
#[test_case(crate::ENUM_UNSIGNED_64_CHECKED_VARIANTS_RELOC_BPF, None, Some((KernelVersion::new(6, 0, 0), "https://github.com/torvalds/linux/commit/6089fb3")), 0xAAAAAAAABBBBBBBB)]
#[test_case(crate::ENUM_UNSIGNED_64_CHECKED_VARIANTS_RELOC_BPF, Some(crate::ENUM_UNSIGNED_64_CHECKED_VARIANTS_RELOC_BTF), Some((KernelVersion::new(6, 0, 0), "https://github.com/torvalds/linux/commit/6089fb3")), 0xCCCCCCCCDDDDDDDD)]
#[test_case(crate::FIELD_RELOC_BPF, None, None, 2)]
#[test_case(crate::FIELD_RELOC_BPF, Some(crate::FIELD_RELOC_BTF), None, 1)]
#[test_case(crate::POINTER_RELOC_BPF, None, None, 42)]
#[test_case(crate::POINTER_RELOC_BPF, Some(crate::POINTER_RELOC_BTF), None, 21)]
#[test_case(crate::STRUCT_FLAVORS_RELOC_BPF, None, None, 1)]
#[test_case(
    crate::STRUCT_FLAVORS_RELOC_BPF,
    Some(crate::STRUCT_FLAVORS_RELOC_BTF),
    None,
    2
)]
fn relocation_tests(
    bpf: &[u8],
    btf: Option<&[u8]>,
    required_kernel_version: Option<(KernelVersion, &str)>,
    expected: u64,
) {
    if let Some((required_kernel_version, commit)) = required_kernel_version {
        let current_kernel_version = KernelVersion::current().unwrap();
        if current_kernel_version < required_kernel_version {
            eprintln!(
                "skipping test on kernel {current_kernel_version:?}, support was added in {required_kernel_version:?}; see {commit}"
            );
            return;
        }
    }
    let mut bpf = EbpfLoader::new()
        .btf(
            btf.map(|btf| Btf::parse(btf, Endianness::default()).unwrap())
                .as_ref(),
        )
        .load(bpf)
        .unwrap();
    let program: &mut UProbe = bpf.program_mut("program").unwrap().try_into().unwrap();
    program.load().unwrap();
    program
        .attach(
            "trigger_btf_relocations_program",
            "/proc/self/exe",
            None,
            None,
        )
        .unwrap();

    trigger_btf_relocations_program();

    let output_map: Array<_, u64> = bpf.take_map("output_map").unwrap().try_into().unwrap();
    let key = 0;
    assert_eq!(output_map.get(&key, 0).unwrap(), expected)
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn trigger_btf_relocations_program() {
    core::hint::black_box(trigger_btf_relocations_program);
}
