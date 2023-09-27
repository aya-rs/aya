use aya::{maps::Array, programs::UProbe, util::KernelVersion, BpfLoader, Btf, Endianness};
use test_case::test_case;

#[test_case("enum_signed_32", false, Some((KernelVersion::new(6, 0, 0), "https://github.com/torvalds/linux/commit/6089fb3")), -0x7AAAAAAAi32 as u64)]
#[test_case("enum_signed_32", true, Some((KernelVersion::new(6, 0, 0), "https://github.com/torvalds/linux/commit/6089fb3")), -0x7BBBBBBBi32 as u64)]
#[test_case("enum_signed_64", false, Some((KernelVersion::new(6, 0, 0), "https://github.com/torvalds/linux/commit/6089fb3")), -0xAAAAAAABBBBBBBBi64 as u64)]
#[test_case("enum_signed_64", true, Some((KernelVersion::new(6, 0, 0), "https://github.com/torvalds/linux/commit/6089fb3")), -0xCCCCCCCDDDDDDDDi64 as u64)]
#[test_case("enum_unsigned_32", false, None, 0xAAAAAAAA)]
#[test_case("enum_unsigned_32", true, None, 0xBBBBBBBB)]
#[test_case("enum_unsigned_64", false, Some((KernelVersion::new(6, 0, 0), "https://github.com/torvalds/linux/commit/6089fb3")), 0xAAAAAAAABBBBBBBB)]
#[test_case("enum_unsigned_64", true, Some((KernelVersion::new(6, 0, 0), "https://github.com/torvalds/linux/commit/6089fb3")), 0xCCCCCCCCDDDDDDDD)]
#[test_case("field", false, None, 2)]
#[test_case("field", true, None, 1)]
#[test_case("pointer", false, None, 42)]
#[test_case("pointer", true, None, 21)]
#[test_case("struct_flavors", false, None, 1)]
#[test_case("struct_flavors", true, None, 2)]
fn relocation_tests(
    program: &str,
    with_relocations: bool,
    required_kernel_version: Option<(KernelVersion, &str)>,
    expected: u64,
) {
    if let Some((required_kernel_version, commit)) = required_kernel_version {
        let current_kernel_version = KernelVersion::current().unwrap();
        if current_kernel_version < required_kernel_version {
            eprintln!("skipping test on kernel {current_kernel_version:?}, support for {program} was added in {required_kernel_version:?}; see {commit}");
            return;
        }
    }
    let mut bpf = BpfLoader::new()
        .btf(
            with_relocations
                .then(|| Btf::parse(crate::RELOC_BTF, Endianness::default()).unwrap())
                .as_ref(),
        )
        .load(crate::RELOC_BPF)
        .unwrap();
    let program: &mut UProbe = bpf.program_mut(program).unwrap().try_into().unwrap();
    program.load().unwrap();
    program
        .attach(
            Some("trigger_btf_relocations_program"),
            0,
            "/proc/self/exe",
            None,
        )
        .unwrap();

    trigger_btf_relocations_program();

    let output_map: Array<_, u64> = bpf.take_map("output_map").unwrap().try_into().unwrap();
    let key = 0;
    assert_eq!(output_map.get(&key, 0).unwrap(), expected)
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn trigger_btf_relocations_program() {
    core::hint::black_box(trigger_btf_relocations_program);
}
