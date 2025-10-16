use aya::{EbpfLoader, Endianness, maps::Array, programs::UProbe};
use aya_obj::btf::Btf;
use test_case::test_case;

#[derive(Debug)]
enum Requirements {}

#[test_case(crate::ENUM_SIGNED_32_RELOC_BPF, None, None,-0x7AAAAAAAi32 as u64)]
#[test_case(crate::ENUM_SIGNED_32_RELOC_BPF, Some(crate::ENUM_SIGNED_32_RELOC_BTF),  None, -0x7BBBBBBBi32 as u64)]
#[test_case(crate::ENUM_SIGNED_32_CHECKED_VARIANTS_RELOC_BPF, None, None,-0x7AAAAAAAi32 as u64)]
#[test_case(crate::ENUM_SIGNED_32_CHECKED_VARIANTS_RELOC_BPF, Some(crate::ENUM_SIGNED_32_CHECKED_VARIANTS_RELOC_BTF),  None, -0x7BBBBBBBi32 as u64)]
#[test_case(crate::ENUM_SIGNED_64_RELOC_BPF, None, None,-0xAAAAAAABBBBBBBBi64 as u64)]
#[test_case(crate::ENUM_SIGNED_64_RELOC_BPF, Some(crate::ENUM_SIGNED_64_RELOC_BTF),  None, -0xCCCCCCCDDDDDDDDi64 as u64)]
#[test_case(crate::ENUM_SIGNED_64_CHECKED_VARIANTS_RELOC_BPF, None, None,-0xAAAAAAABBBBBBBi64 as u64)]
#[test_case(crate::ENUM_SIGNED_64_CHECKED_VARIANTS_RELOC_BPF, Some(crate::ENUM_SIGNED_64_CHECKED_VARIANTS_RELOC_BTF),  None, -0xCCCCCCCDDDDDDDi64 as u64)]
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
#[test_case(crate::ENUM_UNSIGNED_64_RELOC_BPF, None, None, 0xAAAAAAAABBBBBBBB)]
#[test_case(
    crate::ENUM_UNSIGNED_64_RELOC_BPF,
    Some(crate::ENUM_UNSIGNED_64_RELOC_BTF),
    None,
    0xCCCCCCCCDDDDDDDD
)]
#[test_case(
    crate::ENUM_UNSIGNED_64_CHECKED_VARIANTS_RELOC_BPF,
    None,
    None,
    0xAAAAAAAABBBBBBBB
)]
#[test_case(
    crate::ENUM_UNSIGNED_64_CHECKED_VARIANTS_RELOC_BPF,
    Some(crate::ENUM_UNSIGNED_64_CHECKED_VARIANTS_RELOC_BTF),
    None,
    0xCCCCCCCCDDDDDDDD
)]
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
#[test_log::test]
fn relocation_tests(
    bpf: &[u8],
    btf: Option<&[u8]>,
    requirements: Option<Requirements>,
    expected: u64,
) {
    let features = aya::features();

    let btf = btf.map(|btf| Btf::parse(btf, Endianness::default()).unwrap());

    let mut bpf = match EbpfLoader::new().btf(btf.as_ref()).load(bpf) {
        Ok(bpf) => {
            if let Some(requirements) = requirements {
                // We'll want to panic here if we expect some feature we don't have.
                match requirements {}
            }
            bpf
        }
        Err(err) => panic!(
            "err={err:?} requirements={requirements:?} features={:?}",
            features.btf()
        ),
    };

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
extern "C" fn trigger_btf_relocations_program() {
    core::hint::black_box(trigger_btf_relocations_program);
}
