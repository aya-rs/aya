use aya::{Btf, Ebpf, programs::Lsm, sys::is_program_supported};

#[test]
fn lsm() {
    if !is_program_supported(aya::programs::ProgramType::Lsm).unwrap() {
        eprintln!("LSM programs are not supported");
        return;
    }
    if !std::fs::read_to_string("/sys/kernel/security/lsm")
        .unwrap()
        .contains("bpf")
    {
        eprintln!("bpf is not enabled in LSM");
        return;
    }

    let btf = Btf::from_sys_fs().unwrap();
    if let Err(e) = btf.id_by_type_name_kind("bpf_lsm_bpf", aya_obj::btf::BtfKind::Func) {
        eprintln!("bpf_lsm_bpf is not found in BTF: {e}");
        return;
    }

    let mut bpf: Ebpf = Ebpf::load(crate::TEST).unwrap();
    let prog = bpf.program_mut("test_file_open").unwrap();
    let prog: &mut Lsm = prog.try_into().unwrap();
    prog.load("file_open", &btf).unwrap();

    assert_matches::assert_matches!(std::fs::File::open("/proc/self/exe"), Ok(_));

    prog.attach().unwrap();

    assert_matches::assert_matches!(std::fs::File::open("/proc/self/exe"), Err(e) => assert_eq!(
        e.kind(), std::io::ErrorKind::PermissionDenied)
    );
}
