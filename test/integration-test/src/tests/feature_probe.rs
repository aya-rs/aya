//! Test feature probing against kernel version.

use std::io::ErrorKind;

use assert_matches::assert_matches;
use aya::{
    Btf,
    maps::MapType,
    programs::{LsmAttachType, ProgramError, ProgramType},
    sys::{BpfHelper, is_helper_supported, is_map_supported, is_program_supported},
    util::KernelVersion,
};
use procfs::kernel_config;

use crate::utils::kernel_assert;

#[test_log::test]
fn probe_supported_programs() {
    let current = KernelVersion::current().unwrap();
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

    {
        let kern_version = if cfg!(target_arch = "aarch64") {
            KernelVersion::new(6, 4, 0)
        } else {
            KernelVersion::new(5, 7, 0)
        };
        // `lsm` requires `CONFIG_DEBUG_INFO_BTF=y` & `CONFIG_BPF_LSM=y`
        // Ways to check if `CONFIG_BPF_LSM` is enabled:
        // - kernel config has `CONFIG_BPF_LSM=y`, but config is not always exposed.
        // - an LSM hook is present in BTF, e.g. `bpf_lsm_bpf`. hooks are found in `bpf_lsm.c`
        if current >= kern_version {
            let lsm_enabled = matches!(
                kernel_config.get("CONFIG_BPF_LSM"),
                Some(procfs::ConfigSetting::Yes)
            ) || Btf::from_sys_fs()
                .and_then(|btf| {
                    btf.id_by_type_name_kind("bpf_lsm_bpf", aya_obj::btf::BtfKind::Func)
                })
                .is_ok();
            assert_eq!(
                is_supported!(ProgramType::Lsm(LsmAttachType::Mac)),
                lsm_enabled,
                "current={current}"
            );
            if !lsm_enabled {
                eprintln!("CONFIG_BPF_LSM required for lsm program type");
            }
        } else {
            assert!(
                !is_supported!(ProgramType::Lsm(LsmAttachType::Mac)),
                "{current} < {kern_version}"
            );
        }
    }

    let kern_version = KernelVersion::new(5, 9, 0);
    kernel_assert!(is_supported!(ProgramType::SkLookup), kern_version);

    let kern_version = KernelVersion::new(5, 14, 0);
    kernel_assert!(is_supported!(ProgramType::Syscall), kern_version);

    let kern_version = KernelVersion::new(6, 4, 0);
    kernel_assert!(is_supported!(ProgramType::Netfilter), kern_version);
}

#[test_log::test]
fn probe_supported_helpers() {
    macro_rules! is_supported {
        ($prog_type:expr, $helper:expr) => {
            match is_helper_supported($prog_type, $helper) {
                Ok(supported) => supported,
                Err(ProgramError::SyscallError(err))
                    if err.io_error.kind() == ErrorKind::PermissionDenied =>
                {
                    eprintln!("BPF_PROG_LOAD permission required for helper probing");
                    return;
                }
                Err(err) => panic!("unexpected helper probe error: {err:?}"),
            }
        };
    }

    macro_rules! assert_helper_supported_if {
        ($kern_version:expr, $is_enabled:expr, $prog_type:expr, $helper:expr $(,)?) => {
            let current = KernelVersion::current().unwrap();
            let required: KernelVersion = $kern_version;
            let supported = is_supported!($prog_type, $helper);
            if current >= required {
                assert_eq!(
                    supported,
                    $is_enabled,
                    "{} >= {}: {} support for {}",
                    current,
                    required,
                    stringify!($prog_type),
                    stringify!($helper)
                );
            } else {
                assert!(
                    !supported,
                    "{} < {}: {} should not support {}",
                    current,
                    required,
                    stringify!($prog_type),
                    stringify!($helper)
                );
            }
        };
    }

    macro_rules! assert_helper_supported {
        ($kern_version:expr, $prog_type:expr, $helper:expr $(,)?) => {
            assert_helper_supported_if!($kern_version, true, $prog_type, $helper);
        };
    }

    macro_rules! assert_helper_probe_unsupported {
        ($prog_type:expr, $helper:expr $(,)?) => {
            assert_matches!(
                is_helper_supported($prog_type, $helper),
                Err(ProgramError::UnexpectedProgramType)
            );
        };
    }

    let kernel_config = kernel_config().unwrap();
    let lirc_mode2_config = matches!(
        kernel_config.get("CONFIG_BPF_LIRC_MODE2"),
        Some(procfs::ConfigSetting::Yes)
    );
    let bpf_kprobe_override_config = matches!(
        kernel_config.get("CONFIG_BPF_KPROBE_OVERRIDE"),
        Some(procfs::ConfigSetting::Yes)
    );

    // https://docs.ebpf.io/linux/helper-function/
    //
    // The KernelVersion passed to assert_helper_supported! is when the selected
    // (ProgramType, BpfHelper) pair became valid. The inline version comments
    // are only the first kernel versions for the program type and helper.
    assert_helper_supported!(
        KernelVersion::new(3, 19, 0),
        ProgramType::SocketFilter,           // >= v3.19
        BpfHelper::BPF_FUNC_map_lookup_elem  // >= v3.18
    );
    assert_helper_supported!(
        KernelVersion::new(3, 19, 0),
        ProgramType::SocketFilter,           // >= v3.19
        BpfHelper::BPF_FUNC_map_update_elem  // >= v3.18
    );
    assert_helper_supported!(
        KernelVersion::new(3, 19, 0),
        ProgramType::SocketFilter,           // >= v3.19
        BpfHelper::BPF_FUNC_map_delete_elem  // >= v3.19
    );
    assert_helper_supported!(
        KernelVersion::new(4, 1, 0),
        ProgramType::KProbe,            // >= v4.1
        BpfHelper::BPF_FUNC_probe_read  // >= v4.1
    );
    assert_helper_supported!(
        KernelVersion::new(4, 1, 0),
        ProgramType::KProbe,              // >= v4.1
        BpfHelper::BPF_FUNC_ktime_get_ns  // >= v4.1
    );
    assert_helper_supported!(
        KernelVersion::new(4, 1, 0),
        ProgramType::KProbe,              // >= v4.1
        BpfHelper::BPF_FUNC_trace_printk  // >= v4.1
    );
    assert_helper_supported!(
        KernelVersion::new(4, 1, 0),
        ProgramType::SocketFilter,           // >= v3.19
        BpfHelper::BPF_FUNC_get_prandom_u32  // >= v4.1
    );
    assert_helper_supported!(
        KernelVersion::new(4, 1, 0),
        ProgramType::SocketFilter,                // >= v3.19
        BpfHelper::BPF_FUNC_get_smp_processor_id  // >= v4.1
    );
    assert_helper_supported!(
        KernelVersion::new(4, 1, 0),
        ProgramType::SchedAction,            // >= v4.1
        BpfHelper::BPF_FUNC_skb_store_bytes  // >= v4.1
    );
    assert!(
        !is_supported!(
            ProgramType::SocketFilter,
            BpfHelper::BPF_FUNC_skb_store_bytes
        ),
        "SocketFilter should not support BPF_FUNC_skb_store_bytes"
    );
    assert_helper_supported!(
        KernelVersion::new(4, 1, 0),
        ProgramType::SchedAction,            // >= v4.1
        BpfHelper::BPF_FUNC_l3_csum_replace  // >= v4.1
    );
    assert_helper_supported!(
        KernelVersion::new(4, 1, 0),
        ProgramType::SchedAction,            // >= v4.1
        BpfHelper::BPF_FUNC_l4_csum_replace  // >= v4.1
    );
    assert_helper_supported!(
        KernelVersion::new(4, 2, 0),
        ProgramType::SocketFilter,     // >= v3.19
        BpfHelper::BPF_FUNC_tail_call  // >= v4.2
    );
    assert_helper_supported!(
        KernelVersion::new(4, 2, 0),
        ProgramType::SchedAction,           // >= v4.1
        BpfHelper::BPF_FUNC_clone_redirect  // >= v4.2
    );
    assert_helper_supported!(
        KernelVersion::new(4, 2, 0),
        ProgramType::KProbe,                      // >= v4.1
        BpfHelper::BPF_FUNC_get_current_pid_tgid  // >= v4.2
    );
    assert_helper_supported!(
        KernelVersion::new(4, 2, 0),
        ProgramType::KProbe,                     // >= v4.1
        BpfHelper::BPF_FUNC_get_current_uid_gid  // >= v4.2
    );
    assert_helper_supported!(
        KernelVersion::new(4, 2, 0),
        ProgramType::KProbe,                  // >= v4.1
        BpfHelper::BPF_FUNC_get_current_comm  // >= v4.2
    );
    assert_helper_supported!(
        KernelVersion::new(4, 3, 0),
        ProgramType::SchedAction,               // >= v4.1
        BpfHelper::BPF_FUNC_get_cgroup_classid  // >= v4.3
    );
    assert_helper_supported!(
        KernelVersion::new(4, 3, 0),
        ProgramType::SchedAction,          // >= v4.1
        BpfHelper::BPF_FUNC_skb_vlan_push  // >= v4.3
    );
    assert_helper_supported!(
        KernelVersion::new(4, 3, 0),
        ProgramType::SchedAction,         // >= v4.1
        BpfHelper::BPF_FUNC_skb_vlan_pop  // >= v4.3
    );
    assert_helper_supported!(
        KernelVersion::new(4, 3, 0),
        ProgramType::SchedAction,               // >= v4.1
        BpfHelper::BPF_FUNC_skb_get_tunnel_key  // >= v4.3
    );
    assert_helper_supported!(
        KernelVersion::new(4, 3, 0),
        ProgramType::SchedAction,               // >= v4.1
        BpfHelper::BPF_FUNC_skb_set_tunnel_key  // >= v4.3
    );
    assert_helper_supported!(
        KernelVersion::new(4, 3, 0),
        ProgramType::KProbe,                 // >= v4.1
        BpfHelper::BPF_FUNC_perf_event_read  // >= v4.3
    );
    assert_helper_supported!(
        KernelVersion::new(4, 4, 0),
        ProgramType::SchedAction,     // >= v4.1
        BpfHelper::BPF_FUNC_redirect  // >= v4.4
    );
    assert!(
        !is_supported!(ProgramType::SocketFilter, BpfHelper::BPF_FUNC_redirect),
        "SocketFilter should not support BPF_FUNC_redirect"
    );
    assert_helper_supported!(
        KernelVersion::new(4, 4, 0),
        ProgramType::SchedAction,            // >= v4.1
        BpfHelper::BPF_FUNC_get_route_realm  // >= v4.4
    );
    assert_helper_supported!(
        KernelVersion::new(4, 4, 0),
        ProgramType::KProbe,                   // >= v4.1
        BpfHelper::BPF_FUNC_perf_event_output  // >= v4.4
    );
    assert_helper_supported!(
        KernelVersion::new(4, 5, 0),
        ProgramType::SocketFilter,          // >= v3.19
        BpfHelper::BPF_FUNC_skb_load_bytes  // >= v4.5
    );
    assert_helper_supported!(
        KernelVersion::new(4, 6, 0),
        ProgramType::KProbe,             // >= v4.1
        BpfHelper::BPF_FUNC_get_stackid  // >= v4.6
    );
    assert_helper_supported!(
        KernelVersion::new(4, 6, 0),
        ProgramType::SchedAction,      // >= v4.1
        BpfHelper::BPF_FUNC_csum_diff  // >= v4.6
    );
    assert_helper_supported!(
        KernelVersion::new(4, 6, 0),
        ProgramType::SchedAction,               // >= v4.1
        BpfHelper::BPF_FUNC_skb_get_tunnel_opt  // >= v4.6
    );
    assert_helper_supported!(
        KernelVersion::new(4, 6, 0),
        ProgramType::SchedAction,               // >= v4.1
        BpfHelper::BPF_FUNC_skb_set_tunnel_opt  // >= v4.6
    );
    assert_helper_supported!(
        KernelVersion::new(4, 8, 0),
        ProgramType::SchedAction,             // >= v4.1
        BpfHelper::BPF_FUNC_skb_change_proto  // >= v4.8
    );
    assert_helper_supported!(
        KernelVersion::new(4, 8, 0),
        ProgramType::SchedAction,            // >= v4.1
        BpfHelper::BPF_FUNC_skb_change_type  // >= v4.8
    );
    assert_helper_supported!(
        KernelVersion::new(4, 8, 0),
        ProgramType::SchedAction,             // >= v4.1
        BpfHelper::BPF_FUNC_skb_under_cgroup  // >= v4.8
    );
    assert_helper_supported!(
        KernelVersion::new(4, 8, 0),
        ProgramType::SchedAction,            // >= v4.1
        BpfHelper::BPF_FUNC_get_hash_recalc  // >= v4.8
    );
    assert_helper_supported!(
        KernelVersion::new(4, 8, 0),
        ProgramType::SocketFilter,            // >= v3.19
        BpfHelper::BPF_FUNC_get_current_task  // >= v4.8
    );
    assert_helper_supported!(
        KernelVersion::new(4, 8, 0),
        ProgramType::KProbe,                  // >= v4.1
        BpfHelper::BPF_FUNC_probe_write_user  // >= v4.8
    );
    assert_helper_supported!(
        KernelVersion::new(4, 9, 0),
        ProgramType::KProbe,                           // >= v4.1
        BpfHelper::BPF_FUNC_current_task_under_cgroup  // >= v4.9
    );
    assert_helper_supported!(
        KernelVersion::new(4, 9, 0),
        ProgramType::SchedAction,            // >= v4.1
        BpfHelper::BPF_FUNC_skb_change_tail  // >= v4.9
    );
    assert_helper_supported!(
        KernelVersion::new(4, 9, 0),
        ProgramType::SchedAction,          // >= v4.1
        BpfHelper::BPF_FUNC_skb_pull_data  // >= v4.9
    );
    assert_helper_supported!(
        KernelVersion::new(4, 9, 0),
        ProgramType::SchedAction,        // >= v4.1
        BpfHelper::BPF_FUNC_csum_update  // >= v4.9
    );
    assert_helper_supported!(
        KernelVersion::new(4, 9, 0),
        ProgramType::SchedAction,             // >= v4.1
        BpfHelper::BPF_FUNC_set_hash_invalid  // >= v4.9
    );
    assert_helper_supported!(
        KernelVersion::new(4, 10, 0),
        ProgramType::SocketFilter,            // >= v3.19
        BpfHelper::BPF_FUNC_get_numa_node_id  // >= v4.10
    );
    assert_helper_supported!(
        KernelVersion::new(4, 10, 0),
        ProgramType::LwtXmit,                // >= v4.10
        BpfHelper::BPF_FUNC_skb_change_head  // >= v4.10
    );
    assert_helper_supported!(
        KernelVersion::new(4, 10, 0),
        ProgramType::Xdp,                    // >= v4.8
        BpfHelper::BPF_FUNC_xdp_adjust_head  // >= v4.10
    );
    assert_helper_supported!(
        KernelVersion::new(4, 11, 0),
        ProgramType::KProbe,                // >= v4.1
        BpfHelper::BPF_FUNC_probe_read_str  // >= v4.11
    );
    assert_helper_supported!(
        KernelVersion::new(4, 12, 0),
        ProgramType::SocketFilter,             // >= v3.19
        BpfHelper::BPF_FUNC_get_socket_cookie  // >= v4.12
    );
    assert_helper_supported!(
        KernelVersion::new(4, 12, 0),
        ProgramType::SocketFilter,          // >= v3.19
        BpfHelper::BPF_FUNC_get_socket_uid  // >= v4.12
    );
    assert_helper_supported!(
        KernelVersion::new(4, 13, 0),
        ProgramType::SchedAction,     // >= v4.1
        BpfHelper::BPF_FUNC_set_hash  // >= v4.13
    );
    assert_helper_supported!(
        KernelVersion::new(4, 13, 0),
        ProgramType::SockOps,           // >= v4.13
        BpfHelper::BPF_FUNC_setsockopt  // >= v4.13
    );
    assert_helper_supported!(
        KernelVersion::new(4, 13, 0),
        ProgramType::SchedAction,            // >= v4.1
        BpfHelper::BPF_FUNC_skb_adjust_room  // >= v4.13
    );
    assert_helper_supported!(
        KernelVersion::new(4, 14, 0),
        ProgramType::Xdp,                 // >= v4.8
        BpfHelper::BPF_FUNC_redirect_map  // >= v4.14
    );
    assert_helper_supported!(
        KernelVersion::new(4, 14, 0),
        ProgramType::SkSkb,                  // >= v4.14
        BpfHelper::BPF_FUNC_sk_redirect_map  // >= v4.14
    );
    assert_helper_supported!(
        KernelVersion::new(4, 14, 0),
        ProgramType::SockOps,                // >= v4.13
        BpfHelper::BPF_FUNC_sock_map_update  // >= v4.14
    );
    assert_helper_supported!(
        KernelVersion::new(4, 15, 0),
        ProgramType::Xdp,                    // >= v4.8
        BpfHelper::BPF_FUNC_xdp_adjust_meta  // >= v4.15
    );
    assert_helper_supported!(
        KernelVersion::new(4, 15, 0),
        ProgramType::KProbe,                       // >= v4.1
        BpfHelper::BPF_FUNC_perf_event_read_value  // >= v4.15
    );
    assert_helper_supported!(
        KernelVersion::new(4, 15, 0),
        ProgramType::PerfEvent,                   // >= v4.9
        BpfHelper::BPF_FUNC_perf_prog_read_value  // >= v4.15
    );
    assert_helper_supported!(
        KernelVersion::new(4, 15, 0),
        ProgramType::SockOps,           // >= v4.13
        BpfHelper::BPF_FUNC_getsockopt  // >= v4.15
    );
    assert_helper_supported_if!(
        KernelVersion::new(4, 16, 0),
        bpf_kprobe_override_config,
        ProgramType::KProbe,                 // >= v4.1
        BpfHelper::BPF_FUNC_override_return  // >= v4.16
    );
    assert_helper_supported!(
        KernelVersion::new(4, 16, 0),
        ProgramType::SockOps,                      // >= v4.13
        BpfHelper::BPF_FUNC_sock_ops_cb_flags_set  // >= v4.16
    );
    assert_helper_supported!(
        KernelVersion::new(4, 17, 0),
        ProgramType::SkMsg,                   // >= v4.17
        BpfHelper::BPF_FUNC_msg_redirect_map  // >= v4.17
    );
    assert_helper_supported!(
        KernelVersion::new(4, 17, 0),
        ProgramType::SkMsg,                  // >= v4.17
        BpfHelper::BPF_FUNC_msg_apply_bytes  // >= v4.17
    );
    assert_helper_supported!(
        KernelVersion::new(4, 17, 0),
        ProgramType::SkMsg,                 // >= v4.17
        BpfHelper::BPF_FUNC_msg_cork_bytes  // >= v4.17
    );
    assert_helper_supported!(
        KernelVersion::new(4, 17, 0),
        ProgramType::SkMsg,                // >= v4.17
        BpfHelper::BPF_FUNC_msg_pull_data  // >= v4.17
    );
    assert_helper_supported!(
        KernelVersion::new(4, 17, 0),
        ProgramType::CgroupSockAddr, // >= v4.17
        BpfHelper::BPF_FUNC_bind     // >= v4.17
    );
    assert_helper_supported!(
        KernelVersion::new(4, 18, 0),
        ProgramType::Xdp,                    // >= v4.8
        BpfHelper::BPF_FUNC_xdp_adjust_tail  // >= v4.18
    );
    assert_helper_supported!(
        KernelVersion::new(4, 18, 0),
        ProgramType::SchedAction,               // >= v4.1
        BpfHelper::BPF_FUNC_skb_get_xfrm_state  // >= v4.18
    );
    assert_helper_supported!(
        KernelVersion::new(4, 18, 0),
        ProgramType::KProbe,           // >= v4.1
        BpfHelper::BPF_FUNC_get_stack  // >= v4.18
    );
    assert_helper_supported!(
        KernelVersion::new(4, 18, 0),
        ProgramType::SocketFilter,                   // >= v3.19
        BpfHelper::BPF_FUNC_skb_load_bytes_relative  // >= v4.18
    );
    assert_helper_supported!(
        KernelVersion::new(4, 18, 0),
        ProgramType::SchedAction,       // >= v4.1
        BpfHelper::BPF_FUNC_fib_lookup  // >= v4.18
    );
    assert_helper_supported!(
        KernelVersion::new(4, 18, 0),
        ProgramType::SockOps,                 // >= v4.13
        BpfHelper::BPF_FUNC_sock_hash_update  // >= v4.18
    );
    assert_helper_supported!(
        KernelVersion::new(4, 18, 0),
        ProgramType::SkMsg,                    // >= v4.17
        BpfHelper::BPF_FUNC_msg_redirect_hash  // >= v4.18
    );
    assert_helper_supported!(
        KernelVersion::new(4, 18, 0),
        ProgramType::SkSkb,                   // >= v4.14
        BpfHelper::BPF_FUNC_sk_redirect_hash  // >= v4.18
    );
    assert_helper_supported!(
        KernelVersion::new(4, 18, 0),
        ProgramType::LwtInput,              // >= v4.10
        BpfHelper::BPF_FUNC_lwt_push_encap  // >= v4.18
    );
    assert_helper_supported!(
        KernelVersion::new(4, 18, 0),
        ProgramType::LwtSeg6local,                // >= v4.18
        BpfHelper::BPF_FUNC_lwt_seg6_store_bytes  // >= v4.18
    );
    assert_helper_supported!(
        KernelVersion::new(4, 18, 0),
        ProgramType::LwtSeg6local,               // >= v4.18
        BpfHelper::BPF_FUNC_lwt_seg6_adjust_srh  // >= v4.18
    );
    assert_helper_supported!(
        KernelVersion::new(4, 18, 0),
        ProgramType::LwtSeg6local,           // >= v4.18
        BpfHelper::BPF_FUNC_lwt_seg6_action  // >= v4.18
    );
    assert_helper_supported_if!(
        KernelVersion::new(4, 18, 0),
        lirc_mode2_config,
        ProgramType::LircMode2,        // >= v4.18
        BpfHelper::BPF_FUNC_rc_repeat  // >= v4.18
    );
    assert_helper_supported_if!(
        KernelVersion::new(4, 18, 0),
        lirc_mode2_config,
        ProgramType::LircMode2,         // >= v4.18
        BpfHelper::BPF_FUNC_rc_keydown  // >= v4.18
    );
    assert_helper_supported!(
        KernelVersion::new(4, 18, 0),
        ProgramType::SchedAction,          // >= v4.1
        BpfHelper::BPF_FUNC_skb_cgroup_id  // >= v4.18
    );
    assert_helper_supported!(
        KernelVersion::new(4, 18, 0),
        ProgramType::CgroupSock,                   // >= v4.10
        BpfHelper::BPF_FUNC_get_current_cgroup_id  // >= v4.18
    );
    assert_helper_supported!(
        KernelVersion::new(4, 19, 0),
        ProgramType::CgroupSkb,                // >= v4.10
        BpfHelper::BPF_FUNC_get_local_storage  // >= v4.19
    );
    assert_helper_supported!(
        KernelVersion::new(4, 19, 0),
        ProgramType::SkReuseport,                // >= v4.19
        BpfHelper::BPF_FUNC_sk_select_reuseport  // >= v4.19
    );
    assert_helper_supported!(
        KernelVersion::new(4, 19, 0),
        ProgramType::SchedAction,                   // >= v4.1
        BpfHelper::BPF_FUNC_skb_ancestor_cgroup_id  // >= v4.19
    );
    assert_helper_supported!(
        KernelVersion::new(4, 20, 0),
        ProgramType::SchedAction,          // >= v4.1
        BpfHelper::BPF_FUNC_sk_lookup_tcp  // >= v4.20
    );
    assert_helper_supported!(
        KernelVersion::new(4, 20, 0),
        ProgramType::SchedAction,          // >= v4.1
        BpfHelper::BPF_FUNC_sk_lookup_udp  // >= v4.20
    );
    assert_helper_supported!(
        KernelVersion::new(4, 20, 0),
        ProgramType::SchedAction,       // >= v4.1
        BpfHelper::BPF_FUNC_sk_release  // >= v4.20
    );
    assert_helper_supported!(
        KernelVersion::new(4, 20, 0),
        ProgramType::SocketFilter,         // >= v3.19
        BpfHelper::BPF_FUNC_map_push_elem  // >= v4.20
    );
    assert_helper_supported!(
        KernelVersion::new(4, 20, 0),
        ProgramType::SocketFilter,        // >= v3.19
        BpfHelper::BPF_FUNC_map_pop_elem  // >= v4.20
    );
    assert_helper_supported!(
        KernelVersion::new(4, 20, 0),
        ProgramType::SocketFilter,         // >= v3.19
        BpfHelper::BPF_FUNC_map_peek_elem  // >= v4.20
    );
    assert_helper_supported!(
        KernelVersion::new(4, 20, 0),
        ProgramType::SkMsg,                // >= v4.17
        BpfHelper::BPF_FUNC_msg_push_data  // >= v4.20
    );
    assert_helper_supported!(
        KernelVersion::new(5, 0, 0),
        ProgramType::SkMsg,               // >= v4.17
        BpfHelper::BPF_FUNC_msg_pop_data  // >= v5.0
    );
    assert_helper_supported_if!(
        KernelVersion::new(5, 0, 0),
        lirc_mode2_config,
        ProgramType::LircMode2,             // >= v4.18
        BpfHelper::BPF_FUNC_rc_pointer_rel  // >= v5.0
    );
    assert_helper_supported!(
        KernelVersion::new(5, 1, 0),
        ProgramType::SchedAction,      // >= v4.1
        BpfHelper::BPF_FUNC_spin_lock  // >= v5.1
    );
    assert_helper_supported!(
        KernelVersion::new(5, 1, 0),
        ProgramType::SchedAction,        // >= v4.1
        BpfHelper::BPF_FUNC_spin_unlock  // >= v5.1
    );
    assert_helper_supported!(
        KernelVersion::new(5, 1, 0),
        ProgramType::SchedAction,        // >= v4.1
        BpfHelper::BPF_FUNC_sk_fullsock  // >= v5.1
    );
    assert_helper_supported!(
        KernelVersion::new(5, 1, 0),
        ProgramType::SchedAction,     // >= v4.1
        BpfHelper::BPF_FUNC_tcp_sock  // >= v5.1
    );
    assert_helper_supported!(
        KernelVersion::new(5, 1, 0),
        ProgramType::SchedAction,           // >= v4.1
        BpfHelper::BPF_FUNC_skb_ecn_set_ce  // >= v5.1
    );
    assert_helper_supported!(
        KernelVersion::new(5, 1, 0),
        ProgramType::SchedAction,              // >= v4.1
        BpfHelper::BPF_FUNC_get_listener_sock  // >= v5.1
    );
    assert_helper_supported!(
        KernelVersion::new(5, 2, 0),
        ProgramType::SchedAction,           // >= v4.1
        BpfHelper::BPF_FUNC_skc_lookup_tcp  // >= v5.2
    );
    assert_helper_supported!(
        KernelVersion::new(5, 2, 0),
        ProgramType::SchedAction,                // >= v4.1
        BpfHelper::BPF_FUNC_tcp_check_syncookie  // >= v5.2
    );
    assert_helper_supported!(
        KernelVersion::new(5, 2, 0),
        ProgramType::CgroupSysctl,           // >= v5.2
        BpfHelper::BPF_FUNC_sysctl_get_name  // >= v5.2
    );
    assert_helper_supported!(
        KernelVersion::new(5, 2, 0),
        ProgramType::CgroupSysctl,                    // >= v5.2
        BpfHelper::BPF_FUNC_sysctl_get_current_value  // >= v5.2
    );
    assert_helper_supported!(
        KernelVersion::new(5, 2, 0),
        ProgramType::CgroupSysctl,                // >= v5.2
        BpfHelper::BPF_FUNC_sysctl_get_new_value  // >= v5.2
    );
    assert_helper_supported!(
        KernelVersion::new(5, 2, 0),
        ProgramType::CgroupSysctl,                // >= v5.2
        BpfHelper::BPF_FUNC_sysctl_set_new_value  // >= v5.2
    );
    assert_helper_supported!(
        KernelVersion::new(5, 2, 0),
        ProgramType::CgroupSysctl,  // >= v5.2
        BpfHelper::BPF_FUNC_strtol  // >= v5.2
    );
    assert_helper_supported!(
        KernelVersion::new(5, 2, 0),
        ProgramType::CgroupSysctl,   // >= v5.2
        BpfHelper::BPF_FUNC_strtoul  // >= v5.2
    );
    assert_helper_supported!(
        KernelVersion::new(5, 2, 0),
        ProgramType::SchedAction,           // >= v4.1
        BpfHelper::BPF_FUNC_sk_storage_get  // >= v5.2
    );
    assert_helper_supported!(
        KernelVersion::new(5, 2, 0),
        ProgramType::SchedAction,              // >= v4.1
        BpfHelper::BPF_FUNC_sk_storage_delete  // >= v5.2
    );
    assert_helper_supported!(
        KernelVersion::new(5, 3, 0),
        ProgramType::KProbe,             // >= v4.1
        BpfHelper::BPF_FUNC_send_signal  // >= v5.3
    );
    assert_helper_supported!(
        KernelVersion::new(5, 4, 0),
        ProgramType::SchedAction,              // >= v4.1
        BpfHelper::BPF_FUNC_tcp_gen_syncookie  // >= v5.4
    );
    assert_helper_supported!(
        KernelVersion::new(5, 5, 0),
        ProgramType::KProbe,                 // >= v4.1
        BpfHelper::BPF_FUNC_probe_read_user  // >= v5.5
    );
    assert_helper_supported!(
        KernelVersion::new(5, 5, 0),
        ProgramType::KProbe,                   // >= v4.1
        BpfHelper::BPF_FUNC_probe_read_kernel  // >= v5.5
    );
    assert_helper_supported!(
        KernelVersion::new(5, 5, 0),
        ProgramType::KProbe,                     // >= v4.1
        BpfHelper::BPF_FUNC_probe_read_user_str  // >= v5.5
    );
    assert_helper_supported!(
        KernelVersion::new(5, 5, 0),
        ProgramType::KProbe,                       // >= v4.1
        BpfHelper::BPF_FUNC_probe_read_kernel_str  // >= v5.5
    );
    assert_helper_supported!(
        KernelVersion::new(5, 6, 0),
        ProgramType::KProbe,                    // >= v4.1
        BpfHelper::BPF_FUNC_send_signal_thread  // >= v5.6
    );
    assert_helper_supported!(
        KernelVersion::new(5, 6, 0),
        ProgramType::SocketFilter,     // >= v3.19
        BpfHelper::BPF_FUNC_jiffies64  // >= v5.6
    );
    assert_helper_supported!(
        KernelVersion::new(5, 7, 0),
        ProgramType::PerfEvent,                  // >= v4.9
        BpfHelper::BPF_FUNC_read_branch_records  // >= v5.7
    );
    assert_helper_supported!(
        KernelVersion::new(5, 7, 0),
        ProgramType::KProbe,                         // >= v4.1
        BpfHelper::BPF_FUNC_get_ns_current_pid_tgid  // >= v5.7
    );
    assert_helper_supported!(
        KernelVersion::new(5, 7, 0),
        ProgramType::CgroupSock,              // >= v4.10
        BpfHelper::BPF_FUNC_get_netns_cookie  // >= v5.7
    );
    assert_helper_supported!(
        KernelVersion::new(5, 7, 0),
        ProgramType::CgroupSock,                            // >= v4.10
        BpfHelper::BPF_FUNC_get_current_ancestor_cgroup_id  // >= v5.7
    );
    assert_helper_supported!(
        KernelVersion::new(5, 7, 0),
        ProgramType::SchedAction,      // >= v4.1
        BpfHelper::BPF_FUNC_sk_assign  // >= v5.7
    );
    assert_helper_supported!(
        KernelVersion::new(5, 8, 0),
        ProgramType::SocketFilter,             // >= v3.19
        BpfHelper::BPF_FUNC_ktime_get_boot_ns  // >= v5.8
    );
    assert_helper_supported!(
        KernelVersion::new(5, 8, 0),
        ProgramType::CgroupSkb,           // >= v4.10
        BpfHelper::BPF_FUNC_sk_cgroup_id  // >= v5.8
    );
    assert_helper_supported!(
        KernelVersion::new(5, 8, 0),
        ProgramType::CgroupSkb,                    // >= v4.10
        BpfHelper::BPF_FUNC_sk_ancestor_cgroup_id  // >= v5.8
    );
    assert_helper_supported!(
        KernelVersion::new(5, 8, 0),
        ProgramType::SocketFilter,          // >= v3.19
        BpfHelper::BPF_FUNC_ringbuf_output  // >= v5.8
    );
    assert_helper_supported!(
        KernelVersion::new(5, 8, 0),
        ProgramType::SocketFilter,           // >= v3.19
        BpfHelper::BPF_FUNC_ringbuf_reserve  // >= v5.8
    );
    assert_helper_supported!(
        KernelVersion::new(5, 8, 0),
        ProgramType::SocketFilter,          // >= v3.19
        BpfHelper::BPF_FUNC_ringbuf_submit  // >= v5.8
    );
    assert_helper_supported!(
        KernelVersion::new(5, 8, 0),
        ProgramType::SocketFilter,           // >= v3.19
        BpfHelper::BPF_FUNC_ringbuf_discard  // >= v5.8
    );
    assert_helper_supported!(
        KernelVersion::new(5, 8, 0),
        ProgramType::SocketFilter,         // >= v3.19
        BpfHelper::BPF_FUNC_ringbuf_query  // >= v5.8
    );
    assert_helper_supported!(
        KernelVersion::new(5, 8, 0),
        ProgramType::SchedAction,       // >= v4.1
        BpfHelper::BPF_FUNC_csum_level  // >= v5.8
    );
    assert_helper_supported!(
        KernelVersion::new(5, 9, 0),
        ProgramType::SockOps,                 // >= v4.13
        BpfHelper::BPF_FUNC_skc_to_tcp6_sock  // >= v5.9
    );
    assert_helper_supported!(
        KernelVersion::new(5, 9, 0),
        ProgramType::SockOps,                // >= v4.13
        BpfHelper::BPF_FUNC_skc_to_tcp_sock  // >= v5.9
    );
    assert_helper_supported!(
        KernelVersion::new(5, 9, 0),
        ProgramType::SockOps,                         // >= v4.13
        BpfHelper::BPF_FUNC_skc_to_tcp_timewait_sock  // >= v5.9
    );
    assert_helper_supported!(
        KernelVersion::new(5, 9, 0),
        ProgramType::SockOps,                        // >= v4.13
        BpfHelper::BPF_FUNC_skc_to_tcp_request_sock  // >= v5.9
    );
    assert_helper_supported!(
        KernelVersion::new(5, 9, 0),
        ProgramType::SockOps,                 // >= v4.13
        BpfHelper::BPF_FUNC_skc_to_udp6_sock  // >= v5.9
    );
    assert_helper_supported!(
        KernelVersion::new(5, 9, 0),
        ProgramType::KProbe,                // >= v4.1
        BpfHelper::BPF_FUNC_get_task_stack  // >= v5.9
    );
    assert_helper_supported!(
        KernelVersion::new(5, 10, 0),
        ProgramType::SockOps,             // >= v4.13
        BpfHelper::BPF_FUNC_load_hdr_opt  // >= v5.10
    );
    assert_helper_supported!(
        KernelVersion::new(5, 10, 0),
        ProgramType::SockOps,              // >= v4.13
        BpfHelper::BPF_FUNC_store_hdr_opt  // >= v5.10
    );
    assert_helper_supported!(
        KernelVersion::new(5, 10, 0),
        ProgramType::SockOps,                // >= v4.13
        BpfHelper::BPF_FUNC_reserve_hdr_opt  // >= v5.10
    );
    assert_helper_supported!(
        KernelVersion::new(5, 14, 0),
        // `copy_from_user` is available only to sleepable programs.
        ProgramType::Syscall,               // >= v5.14
        BpfHelper::BPF_FUNC_copy_from_user  // >= v5.10
    );
    assert_helper_supported!(
        KernelVersion::new(5, 10, 0),
        ProgramType::SocketFilter,        // >= v3.19
        BpfHelper::BPF_FUNC_snprintf_btf  // >= v5.10
    );
    assert_helper_supported!(
        KernelVersion::new(5, 10, 0),
        ProgramType::SchedAction,               // >= v4.1
        BpfHelper::BPF_FUNC_skb_cgroup_classid  // >= v5.10
    );
    assert_helper_supported!(
        KernelVersion::new(5, 10, 0),
        ProgramType::SchedAction,           // >= v4.1
        BpfHelper::BPF_FUNC_redirect_neigh  // >= v5.10
    );
    assert_helper_supported!(
        KernelVersion::new(5, 10, 0),
        ProgramType::SocketFilter,       // >= v3.19
        BpfHelper::BPF_FUNC_per_cpu_ptr  // >= v5.10
    );
    assert_helper_supported!(
        KernelVersion::new(5, 10, 0),
        ProgramType::SocketFilter,        // >= v3.19
        BpfHelper::BPF_FUNC_this_cpu_ptr  // >= v5.10
    );
    assert_helper_supported!(
        KernelVersion::new(5, 10, 0),
        ProgramType::SchedAction,          // >= v4.1
        BpfHelper::BPF_FUNC_redirect_peer  // >= v5.10
    );
    assert_helper_supported!(
        KernelVersion::new(5, 11, 0),
        ProgramType::KProbe,                  // >= v4.1
        BpfHelper::BPF_FUNC_task_storage_get  // >= v5.11
    );
    assert_helper_supported!(
        KernelVersion::new(5, 11, 0),
        ProgramType::KProbe,                     // >= v4.1
        BpfHelper::BPF_FUNC_task_storage_delete  // >= v5.11
    );
    assert_helper_supported!(
        KernelVersion::new(5, 11, 0),
        ProgramType::SocketFilter,                // >= v3.19
        BpfHelper::BPF_FUNC_get_current_task_btf  // >= v5.11
    );
    assert_helper_supported!(
        KernelVersion::new(5, 11, 0),
        ProgramType::CgroupSock,                 // >= v4.10
        BpfHelper::BPF_FUNC_ktime_get_coarse_ns  // >= v5.11
    );
    assert_helper_supported!(
        KernelVersion::new(5, 12, 0),
        ProgramType::SchedAction,      // >= v4.1
        BpfHelper::BPF_FUNC_check_mtu  // >= v5.12
    );
    assert_helper_supported!(
        KernelVersion::new(5, 13, 0),
        ProgramType::SocketFilter,             // >= v3.19
        BpfHelper::BPF_FUNC_for_each_map_elem  // >= v5.13
    );
    assert_helper_supported!(
        KernelVersion::new(5, 13, 0),
        ProgramType::SocketFilter,    // >= v3.19
        BpfHelper::BPF_FUNC_snprintf  // >= v5.13
    );
    assert_helper_supported!(
        KernelVersion::new(5, 14, 0),
        ProgramType::Syscall,        // >= v5.14
        BpfHelper::BPF_FUNC_sys_bpf  // >= v5.14
    );
    assert_helper_supported!(
        KernelVersion::new(5, 14, 0),
        ProgramType::Syscall,                      // >= v5.14
        BpfHelper::BPF_FUNC_btf_find_by_name_kind  // >= v5.14
    );
    assert_helper_supported!(
        KernelVersion::new(5, 14, 0),
        ProgramType::Syscall,          // >= v5.14
        BpfHelper::BPF_FUNC_sys_close  // >= v5.14
    );
    assert_helper_supported!(
        KernelVersion::new(5, 15, 0),
        ProgramType::SocketFilter,      // >= v3.19
        BpfHelper::BPF_FUNC_timer_init  // >= v5.15
    );
    assert_helper_supported!(
        KernelVersion::new(5, 15, 0),
        ProgramType::SocketFilter,              // >= v3.19
        BpfHelper::BPF_FUNC_timer_set_callback  // >= v5.15
    );
    assert_helper_supported!(
        KernelVersion::new(5, 15, 0),
        ProgramType::SocketFilter,       // >= v3.19
        BpfHelper::BPF_FUNC_timer_start  // >= v5.15
    );
    assert_helper_supported!(
        KernelVersion::new(5, 15, 0),
        ProgramType::SocketFilter,        // >= v3.19
        BpfHelper::BPF_FUNC_timer_cancel  // >= v5.15
    );
    assert_helper_supported!(
        KernelVersion::new(5, 15, 0),
        ProgramType::KProbe,             // >= v4.1
        BpfHelper::BPF_FUNC_get_func_ip  // >= v5.15
    );
    assert_helper_supported!(
        KernelVersion::new(5, 15, 0),
        ProgramType::KProbe,                   // >= v4.1
        BpfHelper::BPF_FUNC_get_attach_cookie  // >= v5.15
    );
    assert_helper_supported!(
        KernelVersion::new(5, 15, 0),
        ProgramType::SocketFilter,        // >= v3.19
        BpfHelper::BPF_FUNC_task_pt_regs  // >= v5.15
    );
    assert_helper_supported!(
        KernelVersion::new(5, 16, 0),
        ProgramType::KProbe,                     // >= v4.1
        BpfHelper::BPF_FUNC_get_branch_snapshot  // >= v5.16
    );
    assert_helper_supported!(
        KernelVersion::new(5, 16, 0),
        ProgramType::SocketFilter,         // >= v3.19
        BpfHelper::BPF_FUNC_trace_vprintk  // >= v5.16
    );
    assert_helper_supported!(
        KernelVersion::new(5, 16, 0),
        ProgramType::SockOps,                 // >= v4.13
        BpfHelper::BPF_FUNC_skc_to_unix_sock  // >= v5.16
    );
    assert_helper_supported!(
        KernelVersion::new(5, 16, 0),
        ProgramType::Syscall,                     // >= v5.14
        BpfHelper::BPF_FUNC_kallsyms_lookup_name  // >= v5.16
    );
    assert_helper_supported!(
        KernelVersion::new(5, 17, 0),
        ProgramType::KProbe,          // >= v4.1
        BpfHelper::BPF_FUNC_find_vma  // >= v5.17
    );
    assert_helper_supported!(
        KernelVersion::new(5, 17, 0),
        ProgramType::SocketFilter, // >= v3.19
        BpfHelper::BPF_FUNC_loop   // >= v5.17
    );
    assert_helper_supported!(
        KernelVersion::new(5, 17, 0),
        ProgramType::SocketFilter,   // >= v3.19
        BpfHelper::BPF_FUNC_strncmp  // >= v5.17
    );
    assert_helper_supported!(
        KernelVersion::new(5, 18, 0),
        ProgramType::CgroupSockopt,     // >= v5.3
        BpfHelper::BPF_FUNC_get_retval  // >= v5.18
    );
    assert_helper_supported!(
        KernelVersion::new(5, 18, 0),
        ProgramType::CgroupSockopt,     // >= v5.3
        BpfHelper::BPF_FUNC_set_retval  // >= v5.18
    );
    assert_helper_supported!(
        KernelVersion::new(5, 18, 0),
        ProgramType::Xdp,                     // >= v4.8
        BpfHelper::BPF_FUNC_xdp_get_buff_len  // >= v5.18
    );
    assert_helper_supported!(
        KernelVersion::new(5, 18, 0),
        ProgramType::Xdp,                   // >= v4.8
        BpfHelper::BPF_FUNC_xdp_load_bytes  // >= v5.18
    );
    assert_helper_supported!(
        KernelVersion::new(5, 18, 0),
        ProgramType::Xdp,                    // >= v4.8
        BpfHelper::BPF_FUNC_xdp_store_bytes  // >= v5.18
    );
    assert_helper_supported!(
        KernelVersion::new(5, 18, 0),
        // `copy_from_user_task` is available only to sleepable programs.
        ProgramType::Syscall,                    // >= v5.14
        BpfHelper::BPF_FUNC_copy_from_user_task  // >= v5.18
    );
    assert_helper_supported!(
        KernelVersion::new(5, 18, 0),
        ProgramType::SchedAction,           // >= v4.1
        BpfHelper::BPF_FUNC_skb_set_tstamp  // >= v5.18
    );
    assert_helper_supported!(
        KernelVersion::new(5, 19, 0),
        ProgramType::SocketFilter,     // >= v3.19
        BpfHelper::BPF_FUNC_kptr_xchg  // >= v5.19
    );
    assert_helper_supported!(
        KernelVersion::new(5, 19, 0),
        ProgramType::SocketFilter,                  // >= v3.19
        BpfHelper::BPF_FUNC_map_lookup_percpu_elem  // >= v5.19
    );
    assert_helper_supported!(
        KernelVersion::new(5, 19, 0),
        ProgramType::SocketFilter,           // >= v3.19
        BpfHelper::BPF_FUNC_dynptr_from_mem  // >= v5.19
    );
    assert_helper_supported!(
        KernelVersion::new(5, 19, 0),
        ProgramType::SocketFilter,                  // >= v3.19
        BpfHelper::BPF_FUNC_ringbuf_reserve_dynptr  // >= v5.19
    );
    assert_helper_supported!(
        KernelVersion::new(5, 19, 0),
        ProgramType::SocketFilter,                 // >= v3.19
        BpfHelper::BPF_FUNC_ringbuf_submit_dynptr  // >= v5.19
    );
    assert_helper_supported!(
        KernelVersion::new(5, 19, 0),
        ProgramType::SocketFilter,                  // >= v3.19
        BpfHelper::BPF_FUNC_ringbuf_discard_dynptr  // >= v5.19
    );
    assert_helper_supported!(
        KernelVersion::new(5, 19, 0),
        ProgramType::SocketFilter,       // >= v3.19
        BpfHelper::BPF_FUNC_dynptr_read  // >= v5.19
    );
    assert_helper_supported!(
        KernelVersion::new(5, 19, 0),
        ProgramType::SocketFilter,        // >= v3.19
        BpfHelper::BPF_FUNC_dynptr_write  // >= v5.19
    );
    assert_helper_supported!(
        KernelVersion::new(5, 19, 0),
        ProgramType::SocketFilter,       // >= v3.19
        BpfHelper::BPF_FUNC_dynptr_data  // >= v5.19
    );
    assert_helper_supported!(
        KernelVersion::new(6, 0, 0),
        ProgramType::SchedClassifier,                   // >= v4.1
        BpfHelper::BPF_FUNC_tcp_raw_gen_syncookie_ipv4  // >= v6.0
    );
    assert_helper_supported!(
        KernelVersion::new(6, 0, 0),
        ProgramType::SchedClassifier,                   // >= v4.1
        BpfHelper::BPF_FUNC_tcp_raw_gen_syncookie_ipv6  // >= v6.0
    );
    assert_helper_supported!(
        KernelVersion::new(6, 0, 0),
        ProgramType::SchedClassifier,                     // >= v4.1
        BpfHelper::BPF_FUNC_tcp_raw_check_syncookie_ipv4  // >= v6.0
    );
    assert_helper_supported!(
        KernelVersion::new(6, 0, 0),
        ProgramType::SchedClassifier,                     // >= v4.1
        BpfHelper::BPF_FUNC_tcp_raw_check_syncookie_ipv6  // >= v6.0
    );
    assert_helper_supported!(
        KernelVersion::new(6, 1, 0),
        ProgramType::SocketFilter,            // >= v3.19
        BpfHelper::BPF_FUNC_ktime_get_tai_ns  // >= v6.1
    );
    assert_helper_supported!(
        KernelVersion::new(6, 1, 0),
        ProgramType::SocketFilter,              // >= v3.19
        BpfHelper::BPF_FUNC_user_ringbuf_drain  // >= v6.1
    );
    assert_helper_supported!(
        KernelVersion::new(6, 2, 0),
        ProgramType::SocketFilter,            // >= v3.19
        BpfHelper::BPF_FUNC_cgrp_storage_get  // >= v6.2
    );
    assert_helper_supported!(
        KernelVersion::new(6, 2, 0),
        ProgramType::SocketFilter,               // >= v3.19
        BpfHelper::BPF_FUNC_cgrp_storage_delete  // >= v6.2
    );
    // These helpers existed before SocketFilter support was added for them:
    // SocketFilter was added in v3.19, BPF_FUNC_get_current_pid_tgid was added
    // in v4.2, and BPF_FUNC_get_netns_cookie was added in v5.7.
    assert_helper_supported!(
        KernelVersion::new(6, 10, 0),
        ProgramType::SocketFilter,                // >= v3.19
        BpfHelper::BPF_FUNC_get_current_pid_tgid  // >= v4.2
    );
    assert_helper_supported!(
        KernelVersion::new(6, 15, 0),
        ProgramType::SocketFilter,            // >= v3.19
        BpfHelper::BPF_FUNC_get_netns_cookie  // >= v5.7
    );

    // These program types require a real attach or BTF target.
    assert_helper_probe_unsupported!(
        ProgramType::Extension,
        BpfHelper::BPF_FUNC_map_lookup_elem // >= v3.18
    );
    assert_helper_probe_unsupported!(
        ProgramType::StructOps,
        BpfHelper::BPF_FUNC_tcp_send_ack // >= v5.6
    );
    // bpf_skb_output and bpf_xdp_output are exposed through BPF_PROG_TYPE_TRACING,
    // not legacy BPF_PROG_TYPE_RAW_TRACEPOINT:
    // https://github.com/torvalds/linux/blob/v6.14/kernel/trace/bpf_trace.c#L1981-L1991
    assert_helper_probe_unsupported!(
        ProgramType::Tracing,
        BpfHelper::BPF_FUNC_skb_output // >= v5.5
    );
    assert_helper_probe_unsupported!(
        ProgramType::Tracing,
        BpfHelper::BPF_FUNC_xdp_output // >= v5.7
    );
    assert_helper_probe_unsupported!(
        ProgramType::Tracing,
        BpfHelper::BPF_FUNC_seq_printf // >= v5.8
    );
    assert_helper_probe_unsupported!(
        ProgramType::Tracing,
        BpfHelper::BPF_FUNC_seq_write // >= v5.8
    );
    assert_helper_probe_unsupported!(
        ProgramType::Lsm(LsmAttachType::Mac),
        BpfHelper::BPF_FUNC_inode_storage_get // >= v5.10
    );
    assert_helper_probe_unsupported!(
        ProgramType::Lsm(LsmAttachType::Mac),
        BpfHelper::BPF_FUNC_inode_storage_delete // >= v5.10
    );
    assert_helper_probe_unsupported!(
        ProgramType::Tracing,
        BpfHelper::BPF_FUNC_d_path // >= v5.10
    );
    assert!(
        !is_supported!(ProgramType::KProbe, BpfHelper::BPF_FUNC_d_path),
        "KProbe should not support BPF_FUNC_d_path without an attach target"
    );
    assert_helper_probe_unsupported!(
        ProgramType::Tracing,
        BpfHelper::BPF_FUNC_seq_printf_btf // >= v5.10
    );
    assert_helper_probe_unsupported!(
        ProgramType::Lsm(LsmAttachType::Mac),
        BpfHelper::BPF_FUNC_bprm_opts_set // >= v5.11
    );
    assert_helper_probe_unsupported!(
        ProgramType::Lsm(LsmAttachType::Mac),
        BpfHelper::BPF_FUNC_ima_inode_hash // >= v5.11
    );
    assert_helper_probe_unsupported!(
        ProgramType::Tracing,
        BpfHelper::BPF_FUNC_sock_from_file // >= v5.11
    );
    assert_helper_probe_unsupported!(
        ProgramType::Tracing,
        BpfHelper::BPF_FUNC_get_func_arg // >= v5.17
    );
    assert_helper_probe_unsupported!(
        ProgramType::Tracing,
        BpfHelper::BPF_FUNC_get_func_ret // >= v5.17
    );
    assert_helper_probe_unsupported!(
        ProgramType::Tracing,
        BpfHelper::BPF_FUNC_get_func_arg_cnt // >= v5.17
    );
    assert_helper_probe_unsupported!(
        ProgramType::Lsm(LsmAttachType::Mac),
        BpfHelper::BPF_FUNC_ima_file_hash // >= v5.18
    );
    assert_helper_probe_unsupported!(
        ProgramType::Tracing,
        BpfHelper::BPF_FUNC_skc_to_mptcp_sock // >= v5.19
    );
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
