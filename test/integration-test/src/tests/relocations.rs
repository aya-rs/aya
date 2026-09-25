use std::error::Error as _;

use assert_matches::assert_matches;
use aya::{
    Ebpf, EbpfError,
    programs::{SocketFilter, UProbe, Xdp, uprobe::UProbeScope},
    util::KernelVersion,
};
use aya_obj::relocation::RelocationError;
use rstest::rstest;

#[rstest]
#[case::missing_callee(crate::FUNC_INFO_MISSING_CALLEE)]
#[case::missing_program(crate::FUNC_INFO_MISSING_PROGRAM)]
#[test_log::test]
fn mismatched_func_info(#[case] bytes: &[u8]) {
    let error = Ebpf::load(bytes).unwrap_err();
    let error = assert_matches!(error, EbpfError::RelocationError(error) => error);
    let error = error.source().unwrap();
    let error = error.downcast_ref::<RelocationError>().unwrap();
    let name = assert_matches!(error, RelocationError::FunctionInfoMismatch { name } => name);
    assert_eq!(name, "callee");
}

#[test_log::test]
fn absent_func_info() {
    let mut bpf = Ebpf::load(crate::FUNC_INFO_ABSENT).unwrap();
    let program: &mut SocketFilter = bpf.program_mut("entry").unwrap().try_into().unwrap();
    program.load().unwrap();
}

#[test_log::test]
fn relocations() {
    let bpf = load_and_attach("test_64_32_call_relocs", crate::RELOCATIONS);

    trigger_relocations_program();

    let m = aya::maps::Array::<_, u64>::try_from(bpf.map("RESULTS").unwrap()).unwrap();
    assert_eq!(m.get(&0, 0).unwrap(), 1);
    assert_eq!(m.get(&1, 0).unwrap(), 2);
    assert_eq!(m.get(&2, 0).unwrap(), 3);
    assert_eq!(m.get(&3, 0).unwrap(), 5);
}

#[test_log::test]
fn text_64_64_reloc() {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(5, 13, 0) {
        eprintln!(
            "skipping test on kernel {kernel_version:?}, support for bpf_for_each_map_elem was added in 5.13.0; see https://github.com/torvalds/linux/commit/69c087ba6"
        );
        return;
    }

    let mut bpf = load_and_attach("test_text_64_64_reloc", crate::TEXT_64_64_RELOC);

    let mut m = aya::maps::Array::<_, u64>::try_from(bpf.map_mut("RESULTS").unwrap()).unwrap();
    m.set(0, &1, 0).unwrap();
    m.set(1, &2, 0).unwrap();

    trigger_relocations_program();

    assert_eq!(m.get(&0, 0).unwrap(), 2);
    assert_eq!(m.get(&1, 0).unwrap(), 3);
}

#[test_log::test]
fn variables_reloc() {
    let mut bpf = Ebpf::load(crate::VARIABLES_RELOC).unwrap();
    let prog: &mut Xdp = bpf
        .program_mut("variables_reloc")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
}

fn load_and_attach(name: &str, bytes: &[u8]) -> Ebpf {
    let mut bpf = Ebpf::load(bytes).unwrap();

    let prog: &mut UProbe = bpf.program_mut(name).unwrap().try_into().unwrap();
    prog.load().unwrap();

    prog.attach(
        ["trigger_relocations_program"],
        "/proc/self/exe",
        UProbeScope::AllProcesses,
    )
    .unwrap();

    bpf
}

#[unsafe(no_mangle)]
#[inline(never)]
extern "C" fn trigger_relocations_program() {
    core::hint::black_box(trigger_relocations_program);
}
