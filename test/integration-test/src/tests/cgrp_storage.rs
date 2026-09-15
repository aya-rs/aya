use assert_matches::assert_matches;
use aya::{
    Ebpf,
    maps::{CgrpStorage, MapError, MapType},
    programs::{BtfTracePoint, ProgramError, ProgramType},
    sys::{SyscallError, is_program_supported},
    test_helpers::Cgroup,
};
use integration_common::local_storage::SENTINEL;
use test_log::test;

#[test]
fn cgrp_storage() {
    let missing = super::unsupported_map_names([(MapType::CgrpStorage, &["CGRP_STORAGE"][..])]);
    let Some(mut bpf) =
        super::map_load_or_expect_unsupported(Ebpf::load(crate::CGRP_STORAGE), &missing)
    else {
        return;
    };

    let Some(btf) = super::kernel_btf() else {
        return;
    };
    let tracing_supported = is_program_supported(ProgramType::Tracing).unwrap();
    let prog: &mut BtfTracePoint = bpf
        .program_mut("cgrp_storage_test")
        .unwrap()
        .try_into()
        .unwrap();
    let load_result = prog.load("cgroup_mkdir", &btf);
    if !tracing_supported {
        match load_result {
            Ok(()) => {
                assert_matches!(prog.attach(), Err(ProgramError::SyscallError(SyscallError { call, io_error })) => {
                    assert_eq!(call, "bpf_raw_tracepoint_open");
                    assert_eq!(io_error.raw_os_error(), Some(524));
                });
            }
            Err(ProgramError::LoadError {
                io_error,
                verifier_log,
            }) => {
                assert_eq!(io_error.raw_os_error(), Some(libc::EINVAL));
                assert!(verifier_log.to_string().is_empty(), "{verifier_log}");
            }
            Err(error) => panic!("unexpected tracing program failure: {error}"),
        }
        return;
    }
    load_result.unwrap();
    prog.attach().unwrap();

    // Creating a cgroup fires `cgroup_mkdir`, populating its storage.
    let root = Cgroup::root().unwrap();
    let cgroup = root.create_child("aya-test-cgrp-storage").unwrap();
    let cgroup_fd = cgroup.fd().unwrap();

    let mut storage =
        CgrpStorage::<_, u64>::try_from(bpf.map_mut("CGRP_STORAGE").unwrap()).unwrap();
    assert_matches!(storage.get(&cgroup_fd, 0), Ok(value) => {
        assert_eq!(value, SENTINEL);
    });
    storage.remove(&cgroup_fd).unwrap();
    assert_matches!(storage.get(&cgroup_fd, 0), Err(MapError::KeyNotFound));
}
