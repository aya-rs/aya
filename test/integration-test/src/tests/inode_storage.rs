use assert_matches::assert_matches;
use aya::{
    Ebpf,
    maps::{Array, InodeStorage, MapError, MapType},
    programs::{Lsm, LsmAttachType, ProgramError, ProgramType},
    sys::{SyscallError, is_program_supported},
};
use aya_obj::btf::BtfError;
use integration_common::local_storage::SENTINEL;
use test_log::test;

#[test]
fn inode_storage() {
    let missing = super::unsupported_map_names([(MapType::InodeStorage, &["INODE_STORAGE"][..])]);
    let Some(mut bpf) =
        super::map_load_or_expect_unsupported(Ebpf::load(crate::INODE_STORAGE), &missing)
    else {
        return;
    };

    let Some(btf) = super::kernel_btf() else {
        return;
    };
    {
        let mut target_tgid: Array<_, u32> =
            Array::try_from(bpf.map_mut("TARGET_TGID").unwrap()).unwrap();
        target_tgid.set(0, &std::process::id(), 0).unwrap();
    }
    let lsm_supported = is_program_supported(ProgramType::Lsm(LsmAttachType::Mac)).unwrap();
    let link_id = {
        let lsm: &mut Lsm = bpf
            .program_mut("inode_storage_test")
            .unwrap()
            .try_into()
            .unwrap();
        let load_result = lsm.load("inode_permission", &btf);
        if !lsm_supported {
            match load_result {
                Ok(()) => {
                    assert_matches!(lsm.attach(), Err(ProgramError::SyscallError(SyscallError { call, io_error })) => {
                        assert_eq!(call, "bpf_raw_tracepoint_open");
                        assert_eq!(io_error.raw_os_error(), Some(524));
                    });
                }
                Err(ProgramError::Btf(BtfError::UnknownBtfTypeName { type_name })) => {
                    assert_eq!(type_name, "bpf_lsm_inode_permission");
                }
                Err(ProgramError::LoadError {
                    io_error,
                    verifier_log,
                }) => {
                    assert_eq!(io_error.raw_os_error(), Some(libc::EINVAL));
                    assert!(verifier_log.to_string().is_empty(), "{verifier_log}");
                }
                Err(error) => panic!("unexpected LSM program failure: {error}"),
            }
            return;
        }
        load_result.unwrap();
        lsm.attach().unwrap()
    };

    // A loaded and attached LSM program only receives hooks while the BPF LSM
    // module is active.
    let bpf_lsm_active = std::fs::read_to_string("/sys/kernel/security/lsm")
        .unwrap()
        .split(',')
        .any(|module| module.trim() == "bpf");

    // Opening a file fires `inode_permission` for its inode under this process.
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("aya-inode-storage");
    std::fs::write(&path, b"aya").unwrap();
    let file = std::fs::File::open(&path).unwrap();

    let mut storage =
        InodeStorage::<_, u64>::try_from(bpf.map_mut("INODE_STORAGE").unwrap()).unwrap();
    if bpf_lsm_active {
        assert_matches!(storage.get(&file, 0), Ok(value) => {
            assert_eq!(value, SENTINEL);
        });
        storage.remove(&file).unwrap();
    }
    assert_matches!(storage.get(&file, 0), Err(MapError::KeyNotFound));

    let lsm: &mut Lsm = bpf
        .program_mut("inode_storage_test")
        .unwrap()
        .try_into()
        .unwrap();
    lsm.detach(link_id).unwrap();
}
