//! Test feature probing against kernel version.

use aya::{
    Btf,
    maps::MapType,
    programs::ProgramType,
    sys::{is_map_supported, is_program_supported},
    util::KernelVersion,
};
use procfs::kernel_config;

use crate::utils::kernel_assert;

#[test_log::test]
fn probe_supported_programs() {
    let current = aya::util::KernelVersion::current().unwrap();
    let kernel_config = kernel_config().unwrap();

    macro_rules! is_supported {
        ($prog_type:expr) => {
            is_program_supported($prog_type).unwrap()
        };
    }

    let kern_version = KernelVersion::new(3, 19, 0);
    kernel_assert!(is_supported!(ProgramType::SocketFilter), kern_version);

    let kern_version = KernelVersion::new(4, 1, 0);
    kernel_assert!(is_supported!(ProgramType::KProbe), kern_version);
    kernel_assert!(is_supported!(ProgramType::SchedClassifier), kern_version);
    kernel_assert!(is_supported!(ProgramType::SchedAction), kern_version);

    let kern_version = KernelVersion::new(4, 7, 0);
    kernel_assert!(is_supported!(ProgramType::TracePoint), kern_version);

    let kern_version = KernelVersion::new(4, 8, 0);
    kernel_assert!(is_supported!(ProgramType::Xdp), kern_version);

    let kern_version = KernelVersion::new(4, 9, 0);
    kernel_assert!(is_supported!(ProgramType::PerfEvent), kern_version);

    let kern_version = KernelVersion::new(4, 10, 0);
    kernel_assert!(is_supported!(ProgramType::CgroupSkb), kern_version);
    kernel_assert!(is_supported!(ProgramType::CgroupSock), kern_version);
    kernel_assert!(is_supported!(ProgramType::LwtInput), kern_version);
    kernel_assert!(is_supported!(ProgramType::LwtOutput), kern_version);
    kernel_assert!(is_supported!(ProgramType::LwtXmit), kern_version);

    let kern_version = KernelVersion::new(4, 13, 0);
    kernel_assert!(is_supported!(ProgramType::SockOps), kern_version);

    let kern_version = KernelVersion::new(4, 14, 0);
    kernel_assert!(is_supported!(ProgramType::SkSkb), kern_version);

    let kern_version = KernelVersion::new(4, 15, 0);
    kernel_assert!(is_supported!(ProgramType::CgroupDevice), kern_version);

    let kern_version = KernelVersion::new(4, 17, 0);
    kernel_assert!(is_supported!(ProgramType::SkMsg), kern_version);
    kernel_assert!(is_supported!(ProgramType::RawTracePoint), kern_version);
    kernel_assert!(is_supported!(ProgramType::CgroupSockAddr), kern_version);

    let kern_version = KernelVersion::new(4, 18, 0);
    kernel_assert!(is_supported!(ProgramType::LwtSeg6local), kern_version);

    if current >= kern_version {
        // `lirc_mode2` requires CONFIG_BPF_LIRC_MODE2=y
        let lirc_mode2_config = matches!(
            kernel_config.get("CONFIG_BPF_LIRC_MODE2"),
            Some(procfs::ConfigSetting::Yes)
        );
        assert_eq!(
            is_supported!(ProgramType::LircMode2),
            lirc_mode2_config,
            "current={current}"
        );
        if !lirc_mode2_config {
            eprintln!("CONFIG_BPF_LIRC_MODE2 required for lirc_mode2 program type");
        }
    } else {
        assert!(
            !is_supported!(ProgramType::LircMode2),
            "{current} < {kern_version}"
        );
    }

    let kern_version = KernelVersion::new(4, 19, 0);
    kernel_assert!(is_supported!(ProgramType::SkReuseport), kern_version);

    let kern_version = KernelVersion::new(4, 20, 0);
    kernel_assert!(is_supported!(ProgramType::FlowDissector), kern_version);

    let kern_version = KernelVersion::new(5, 2, 0);
    kernel_assert!(is_supported!(ProgramType::CgroupSysctl), kern_version);
    kernel_assert!(
        is_supported!(ProgramType::RawTracePointWritable),
        kern_version
    );

    let kern_version = KernelVersion::new(5, 3, 0);
    kernel_assert!(is_supported!(ProgramType::CgroupSockopt), kern_version);

    let kern_version = KernelVersion::new(5, 5, 0);
    kernel_assert!(is_supported!(ProgramType::Tracing), kern_version); // Requires `CONFIG_DEBUG_INFO_BTF=y`

    let kern_version = KernelVersion::new(5, 6, 0);
    kernel_assert!(is_supported!(ProgramType::StructOps), kern_version);
    kernel_assert!(is_supported!(ProgramType::Extension), kern_version);

    let kern_version = KernelVersion::new(5, 7, 0);
    // `lsm` requires `CONFIG_DEBUG_INFO_BTF=y` & `CONFIG_BPF_LSM=y`
    // Ways to check if `CONFIG_BPF_LSM` is enabled:
    // - kernel config has `CONFIG_BPF_LSM=y`, but config is not always exposed.
    // - an LSM hook is present in BTF, e.g. `bpf_lsm_bpf`. hooks are found in `bpf_lsm.c`
    if current >= kern_version {
        let lsm_enabled = matches!(
            kernel_config.get("CONFIG_BPF_LSM"),
            Some(procfs::ConfigSetting::Yes)
        ) || Btf::from_sys_fs()
            .and_then(|btf| btf.id_by_type_name_kind("bpf_lsm_bpf", aya_obj::btf::BtfKind::Func))
            .is_ok();
        assert_eq!(
            is_supported!(ProgramType::Lsm),
            lsm_enabled,
            "current={current}"
        );
        if !lsm_enabled {
            eprintln!("CONFIG_BPF_LSM required for lsm program type");
        }
    } else {
        assert!(
            !is_supported!(ProgramType::Lsm),
            "{current} < {kern_version}"
        );
    }

    let kern_version = KernelVersion::new(5, 9, 0);
    kernel_assert!(is_supported!(ProgramType::SkLookup), kern_version);

    let kern_version = KernelVersion::new(5, 14, 0);
    kernel_assert!(is_supported!(ProgramType::Syscall), kern_version);

    let kern_version = KernelVersion::new(6, 4, 0);
    kernel_assert!(is_supported!(ProgramType::Netfilter), kern_version);
}

#[test_log::test]
fn probe_supported_maps() {
    macro_rules! is_supported {
        ($map_type:expr) => {
            is_map_supported($map_type).unwrap()
        };
    }

    let kern_version = KernelVersion::new(3, 19, 0);
    kernel_assert!(is_supported!(MapType::Hash), kern_version);
    kernel_assert!(is_supported!(MapType::Array), kern_version);

    let kern_version = KernelVersion::new(4, 2, 0);
    kernel_assert!(is_supported!(MapType::ProgramArray), kern_version);

    let kern_version = KernelVersion::new(4, 3, 0);
    kernel_assert!(is_supported!(MapType::PerfEventArray), kern_version);

    let kern_version = KernelVersion::new(4, 6, 0);
    kernel_assert!(is_supported!(MapType::PerCpuHash), kern_version);
    kernel_assert!(is_supported!(MapType::PerCpuArray), kern_version);
    kernel_assert!(is_supported!(MapType::StackTrace), kern_version);

    let kern_version = KernelVersion::new(4, 8, 0);
    kernel_assert!(is_supported!(MapType::CgroupArray), kern_version);

    let kern_version = KernelVersion::new(4, 10, 0);
    kernel_assert!(is_supported!(MapType::LruHash), kern_version);
    kernel_assert!(is_supported!(MapType::LruPerCpuHash), kern_version);

    let kern_version = KernelVersion::new(4, 11, 0);
    kernel_assert!(is_supported!(MapType::LpmTrie), kern_version);

    let kern_version = KernelVersion::new(4, 12, 0);
    kernel_assert!(is_supported!(MapType::ArrayOfMaps), kern_version);
    kernel_assert!(is_supported!(MapType::HashOfMaps), kern_version);

    let kern_version = KernelVersion::new(4, 14, 0);
    kernel_assert!(is_supported!(MapType::DevMap), kern_version);
    kernel_assert!(is_supported!(MapType::SockMap), kern_version);

    let kern_version = KernelVersion::new(4, 15, 0);
    kernel_assert!(is_supported!(MapType::CpuMap), kern_version);

    let kern_version = KernelVersion::new(4, 18, 0);
    kernel_assert!(is_supported!(MapType::XskMap), kern_version);
    kernel_assert!(is_supported!(MapType::SockHash), kern_version);

    let kern_version = KernelVersion::new(4, 19, 0);
    kernel_assert!(is_supported!(MapType::CgroupStorage), kern_version);
    kernel_assert!(is_supported!(MapType::ReuseportSockArray), kern_version);

    let kern_version = KernelVersion::new(4, 20, 0);
    kernel_assert!(is_supported!(MapType::PerCpuCgroupStorage), kern_version);
    kernel_assert!(is_supported!(MapType::Queue), kern_version);
    kernel_assert!(is_supported!(MapType::Stack), kern_version);

    let kern_version = KernelVersion::new(5, 2, 0);
    kernel_assert!(is_supported!(MapType::SkStorage), kern_version);

    let kern_version = KernelVersion::new(5, 4, 0);
    kernel_assert!(is_supported!(MapType::DevMapHash), kern_version);

    let kern_version = KernelVersion::new(5, 6, 0);
    kernel_assert!(is_supported!(MapType::StructOps), kern_version);

    let kern_version = KernelVersion::new(5, 8, 0);
    kernel_assert!(is_supported!(MapType::RingBuf), kern_version);

    let kern_version = KernelVersion::new(5, 10, 0);
    kernel_assert!(is_supported!(MapType::InodeStorage), kern_version); // Requires `CONFIG_BPF_LSM=y`

    let kern_version = KernelVersion::new(5, 11, 0);
    kernel_assert!(is_supported!(MapType::TaskStorage), kern_version);

    let kern_version = KernelVersion::new(5, 16, 0);
    kernel_assert!(is_supported!(MapType::BloomFilter), kern_version);

    let kern_version = KernelVersion::new(6, 1, 0);
    kernel_assert!(is_supported!(MapType::UserRingBuf), kern_version);

    let kern_version = KernelVersion::new(6, 2, 0);
    kernel_assert!(is_supported!(MapType::CgrpStorage), kern_version);

    let kern_version = KernelVersion::new(6, 9, 0);
    kernel_assert!(is_supported!(MapType::Arena), kern_version);
}
