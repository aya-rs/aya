use std::fs::File;

use assert_matches::assert_matches;
use aya::{
    Btf, Ebpf, EbpfError,
    maps::{Array, InodeStorage, MapError, MapType},
    programs::{Lsm, LsmAttachType, ProgramError, ProgramType},
    sys::{SyscallError, is_map_supported, is_program_supported},
    util::KernelVersion,
};
use integration_common::local_storage::SENTINEL;
use test_log::test;

use super::is_bpf_lsm_active;

#[test]
fn inode_storage() {
    let config = procfs::kernel_config().unwrap();
    let available = KernelVersion::current().unwrap() >= KernelVersion::new(5, 10, 0)
        && matches!(
            config.get("CONFIG_BPF_LSM"),
            Some(procfs::ConfigSetting::Yes)
        );
    // The configured BPF LSM may still be disabled at boot. Only query securityfs where
    // BPF LSM is available; configurations without it may not expose securityfs at all.
    let active = available && is_bpf_lsm_active();
    let supported = is_map_supported(MapType::InodeStorage).unwrap();
    if !available {
        assert!(
            !supported,
            "inode storage requires Linux 5.10 and CONFIG_BPF_LSM=y"
        );
    } else if active {
        assert!(supported, "an initialized BPF LSM supports inode storage");
    }

    // Boot-initialization checks were backported, so kernel version alone cannot determine
    // inode-storage support. Verify the probe against actual map creation and its rejection.
    let result = Ebpf::load(crate::INODE_STORAGE);
    if !supported {
        let Err(error) = result else {
            panic!("inode storage loaded despite a negative capability probe");
        };
        assert_matches!(error, EbpfError::MapError(error) => {
            assert_matches!(error, MapError::CreateError { name, io_error } => {
                assert_eq!(name, "INODE_STORAGE");
                let errno = if available { libc::EOPNOTSUPP } else { libc::EINVAL };
                assert_eq!(io_error.raw_os_error(), Some(errno));
            });
        });
        return;
    }

    let btf = Btf::from_sys_fs().unwrap();
    let mut bpf = result.unwrap();
    {
        let mut target_tgid: Array<_, u32> =
            Array::try_from(bpf.map_mut("TARGET_TGID").unwrap()).unwrap();
        target_tgid.set(0, &std::process::id(), 0).unwrap();
    }
    let link_id = {
        let lsm: &mut Lsm = bpf
            .program_mut("inode_storage_test")
            .unwrap()
            .try_into()
            .unwrap();
        lsm.load("inode_permission", &btf).unwrap();
        let result = lsm.attach();
        if !is_program_supported(ProgramType::Lsm(LsmAttachType::Mac)).unwrap() {
            assert_matches!(result, Err(ProgramError::SyscallError(SyscallError { call, io_error })) => {
                assert_eq!(call, "bpf_raw_tracepoint_open");
                assert_eq!(io_error.raw_os_error(), Some(524));
            });
            return;
        }
        result.unwrap()
    };

    // Opening a file fires `inode_permission` for its inode under this process.
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("aya-inode-storage");
    std::fs::write(&path, b"aya").unwrap();
    let file = File::open(&path).unwrap();

    // Older kernels allowed these maps without initializing their inode security storage.
    // Check the hook's absence through RAN; even a storage lookup can touch the invalid blob.
    let ran = Array::<_, u32>::try_from(bpf.map("RAN").unwrap()).unwrap();
    assert_eq!(ran.get(&0, 0).unwrap(), u32::from(active));
    if active {
        let mut storage =
            InodeStorage::<_, u64>::try_from(bpf.map_mut("INODE_STORAGE").unwrap()).unwrap();
        assert_matches!(storage.get(&file, 0), Ok(value) => {
            assert_eq!(value, SENTINEL);
        });
        storage.remove(&file).unwrap();
        assert_matches!(storage.get(&file, 0), Err(MapError::KeyNotFound));
    }
    let lsm: &mut Lsm = bpf
        .program_mut("inode_storage_test")
        .unwrap()
        .try_into()
        .unwrap();
    lsm.detach(link_id).unwrap();
}
