use aya::{Btf, EbpfLoader, programs::StructOps, util::KernelVersion};
use aya_obj::{
    btf::{BtfError, BtfKind, BtfType},
    generated::bpf_prog_type::BPF_PROG_TYPE_STRUCT_OPS,
};
use libbpf_rs::btf::types::{Func, Linkage};
use rstest::rstest;

#[rstest]
#[case::sleepable_init("init")]
#[case::void_exit("exit")]
#[test_attr(test_log::test)]
fn sched_ext_callbacks(#[case] callback: &str) {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(6, 12, 0) {
        eprintln!("skipping test on kernel {kernel_version:?}, sched_ext requires kernel >= 6.12");
        return;
    }

    let btf = Btf::from_sys_fs().unwrap();
    let type_id = match btf.id_by_type_name_kind("sched_ext_ops", BtfKind::Struct) {
        Ok(type_id) => type_id,
        Err(BtfError::UnknownBtfTypeName { .. }) => {
            eprintln!("skipping test, kernel was built without CONFIG_SCHED_CLASS_EXT");
            return;
        }
        Err(err) => panic!("failed to find sched_ext_ops: {err:?}"),
    };
    let BtfType::Struct(ops) = btf.type_by_id(type_id).unwrap() else {
        panic!("sched_ext_ops is not a struct");
    };
    let member_index = ops
        .members
        .iter()
        .position(|member| btf.string_at(member.name_offset).unwrap() == callback)
        .unwrap_or_else(|| panic!("sched_ext_ops has no {callback} callback"));

    let mut bpf = EbpfLoader::new().btf(&btf).load(crate::STRUCT_OPS).unwrap();
    let program_name = format!("scx_{callback}");
    let program: &mut StructOps = bpf.program_mut(&program_name).unwrap().try_into().unwrap();
    program.load(type_id, member_index as u32).unwrap();
    let info = program.info().unwrap();
    assert_eq!(info.program_type(), BPF_PROG_TYPE_STRUCT_OPS);

    // Inspect the BTF actually loaded into the kernel so a loader-side rewrite
    // to static linkage cannot hide a verifier regression.
    let loaded_btf = libbpf_rs::Btf::from_prog_id(info.id()).unwrap();
    let function = loaded_btf.type_by_name::<Func<'_>>(&program_name).unwrap();
    assert_eq!(function.linkage(), Linkage::Global);
}
