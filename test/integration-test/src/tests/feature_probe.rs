//! Test feature probing against kernel version.

use assert_matches::assert_matches;
use aya::{Btf, maps::MapType, programs::ProgramType, sys::feature_probe::*, util::KernelVersion};
use procfs::kernel_config;

#[test]
fn probe_supported_programs() {
    let current = KernelVersion::current().unwrap();
    let kernel_config = kernel_config().unwrap_or_default();

    let socket_filter = is_program_supported(ProgramType::SocketFilter);
    if current >= KernelVersion::new(3, 19, 0) {
        assert_matches!(socket_filter, Ok(true));
    } else {
        assert_matches!(socket_filter, Ok(false));
    }

    let kprobe = is_program_supported(ProgramType::KProbe);
    let sched_cls = is_program_supported(ProgramType::SchedClassifier);
    let sched_act = is_program_supported(ProgramType::SchedAction);
    if current >= KernelVersion::new(4, 1, 0) {
        assert_matches!(kprobe, Ok(true));
        assert_matches!(sched_cls, Ok(true));
        assert_matches!(sched_act, Ok(true));
    } else {
        assert_matches!(kprobe, Ok(false));
        assert_matches!(sched_cls, Ok(false));
        assert_matches!(sched_act, Ok(false));
    }

    let tracepoint = is_program_supported(ProgramType::TracePoint);
    if current >= KernelVersion::new(4, 7, 0) {
        assert_matches!(tracepoint, Ok(true));
    } else {
        assert_matches!(tracepoint, Ok(false));
    }

    let xdp = is_program_supported(ProgramType::Xdp);
    if current >= KernelVersion::new(4, 8, 0) {
        assert_matches!(xdp, Ok(true));
    } else {
        assert_matches!(xdp, Ok(false));
    }

    let perf_event = is_program_supported(ProgramType::PerfEvent);
    if current >= KernelVersion::new(4, 9, 0) {
        assert_matches!(perf_event, Ok(true));
    } else {
        assert_matches!(perf_event, Ok(false));
    }

    let cgroup_skb = is_program_supported(ProgramType::CgroupSkb);
    let cgroup_sock = is_program_supported(ProgramType::CgroupSock);
    let lwt_in = is_program_supported(ProgramType::LwtInput);
    let lwt_out = is_program_supported(ProgramType::LwtOutput);
    let lwt_xmit = is_program_supported(ProgramType::LwtXmit);
    if current >= KernelVersion::new(4, 10, 0) {
        assert_matches!(cgroup_skb, Ok(true));
        assert_matches!(cgroup_sock, Ok(true));
        assert_matches!(lwt_in, Ok(true));
        assert_matches!(lwt_out, Ok(true));
        assert_matches!(lwt_xmit, Ok(true));
    } else {
        assert_matches!(cgroup_skb, Ok(false));
        assert_matches!(cgroup_sock, Ok(false));
        assert_matches!(lwt_in, Ok(false));
        assert_matches!(lwt_out, Ok(false));
        assert_matches!(lwt_xmit, Ok(false));
    }

    let sock_ops = is_program_supported(ProgramType::SockOps);
    if current >= KernelVersion::new(4, 13, 0) {
        assert_matches!(sock_ops, Ok(true));
    } else {
        assert_matches!(sock_ops, Ok(false));
    }

    let sk_skb = is_program_supported(ProgramType::SkSkb);
    if current >= KernelVersion::new(4, 14, 0) {
        assert_matches!(sk_skb, Ok(true));
    } else {
        assert_matches!(sk_skb, Ok(false));
    }

    let cgroup_device = is_program_supported(ProgramType::CgroupDevice);
    if current >= KernelVersion::new(4, 15, 0) {
        assert_matches!(cgroup_device, Ok(true));
    } else {
        assert_matches!(cgroup_device, Ok(false));
    }

    let sk_msg = is_program_supported(ProgramType::SkMsg);
    let raw_tp = is_program_supported(ProgramType::RawTracePoint);
    let cgroup_sock_addr = is_program_supported(ProgramType::CgroupSockAddr);
    if current >= KernelVersion::new(4, 17, 0) {
        assert_matches!(sk_msg, Ok(true));
        assert_matches!(raw_tp, Ok(true));
        assert_matches!(cgroup_sock_addr, Ok(true));
    } else {
        assert_matches!(sk_msg, Ok(false));
        assert_matches!(raw_tp, Ok(false));
        assert_matches!(cgroup_sock_addr, Ok(false));
    }

    let lwt_seg6local = is_program_supported(ProgramType::LwtSeg6local);
    let lirc_mode2 = is_program_supported(ProgramType::LircMode2); // Requires CONFIG_BPF_LIRC_MODE2=y
    if current >= KernelVersion::new(4, 18, 0) {
        assert_matches!(lwt_seg6local, Ok(true));

        let lirc_mode2_config = matches!(
            kernel_config.get("CONFIG_BPF_LIRC_MODE2"),
            Some(procfs::ConfigSetting::Yes)
        );
        assert_matches!(lirc_mode2, Ok(lirc_mode2) if lirc_mode2 == lirc_mode2_config);
        if !lirc_mode2_config {
            eprintln!("CONFIG_BPF_LIRC_MODE2 required for lirc_mode2 program type");
        }
    } else {
        assert_matches!(lwt_seg6local, Ok(false));
        assert_matches!(lirc_mode2, Ok(false));
    }

    let sk_reuseport = is_program_supported(ProgramType::SkReuseport);
    if current >= KernelVersion::new(4, 19, 0) {
        assert_matches!(sk_reuseport, Ok(true));
    } else {
        assert_matches!(sk_reuseport, Ok(false));
    }

    let flow_dissector = is_program_supported(ProgramType::FlowDissector);
    if current >= KernelVersion::new(4, 20, 0) {
        assert_matches!(flow_dissector, Ok(true));
    } else {
        assert_matches!(flow_dissector, Ok(false));
    }

    let cgroup_sysctl = is_program_supported(ProgramType::CgroupSysctl);
    let raw_tp_writable = is_program_supported(ProgramType::RawTracePointWritable);
    if current >= KernelVersion::new(5, 2, 0) {
        assert_matches!(cgroup_sysctl, Ok(true));
        assert_matches!(raw_tp_writable, Ok(true));
    } else {
        assert_matches!(cgroup_sysctl, Ok(false));
        assert_matches!(raw_tp_writable, Ok(false));
    }

    let cgroup_sockopt = is_program_supported(ProgramType::CgroupSockopt);
    if current >= KernelVersion::new(5, 3, 0) {
        assert_matches!(cgroup_sockopt, Ok(true));
    } else {
        assert_matches!(cgroup_sockopt, Ok(false));
    }

    let tracing = is_program_supported(ProgramType::Tracing); // Requires `CONFIG_DEBUG_INFO_BTF=y`
    if current >= KernelVersion::new(5, 5, 0) {
        assert_matches!(tracing, Ok(true));
    } else {
        assert_matches!(tracing, Ok(false));
    }

    let struct_ops = is_program_supported(ProgramType::StructOps);
    let extension = is_program_supported(ProgramType::Extension);
    if current >= KernelVersion::new(5, 6, 0) {
        assert_matches!(struct_ops, Ok(true));
        assert_matches!(extension, Ok(true));
    } else {
        assert_matches!(struct_ops, Ok(false));
        assert_matches!(extension, Ok(false));
    }

    let lsm = is_program_supported(ProgramType::Lsm); // Requires `CONFIG_DEBUG_INFO_BTF=y` & `CONFIG_BPF_LSM=y`
    if current >= KernelVersion::new(5, 7, 0) {
        // Ways to check if `CONFIG_BPF_LSM` is enabled:
        // - kernel config has `CONFIG_BPF_LSM=y`, but config is not always exposed.
        // - an LSM hooks is present in BTF, e.g. `bpf_lsm_bpf`. hooks are found in `bpf_lsm.c`
        let lsm_enabled = matches!(
            kernel_config.get("CONFIG_BPF_LSM"),
            Some(procfs::ConfigSetting::Yes)
        ) || Btf::from_sys_fs()
            .and_then(|btf| btf.id_by_type_name_kind("bpf_lsm_bpf", aya_obj::btf::BtfKind::Func))
            .is_ok();

        assert_matches!(lsm, Ok(lsm_supported) if lsm_supported == lsm_enabled);
        if !lsm_enabled {
            eprintln!("CONFIG_BPF_LSM required for lsm program type");
        }
    } else {
        assert_matches!(lsm, Ok(false));
    }

    let sk_lookup = is_program_supported(ProgramType::SkLookup);
    if current >= KernelVersion::new(5, 9, 0) {
        assert_matches!(sk_lookup, Ok(true));
    } else {
        assert_matches!(sk_lookup, Ok(false));
    }

    let syscall = is_program_supported(ProgramType::Syscall);
    if current >= KernelVersion::new(5, 14, 0) {
        assert_matches!(syscall, Ok(true));
    } else {
        assert_matches!(syscall, Ok(false));
    }

    let netfilter = is_program_supported(ProgramType::Netfilter);
    if current >= KernelVersion::new(6, 4, 0) {
        assert_matches!(netfilter, Ok(true));
    } else {
        assert_matches!(netfilter, Ok(false));
    }
}

#[test]
fn probe_supported_maps() {
    let current = KernelVersion::current().unwrap();

    let hash = is_map_supported(MapType::Hash);
    let array = is_map_supported(MapType::Array);
    if current >= KernelVersion::new(3, 19, 0) {
        assert_matches!(hash, Ok(true));
        assert_matches!(array, Ok(true));
    } else {
        assert_matches!(hash, Ok(false));
        assert_matches!(array, Ok(false));
    }

    let prog_array = is_map_supported(MapType::ProgramArray);
    if current >= KernelVersion::new(4, 2, 0) {
        assert_matches!(prog_array, Ok(true));
    } else {
        assert_matches!(prog_array, Ok(false));
    }

    let perf_event_array = is_map_supported(MapType::PerfEventArray);
    if current >= KernelVersion::new(4, 3, 0) {
        assert_matches!(perf_event_array, Ok(true));
    } else {
        assert_matches!(perf_event_array, Ok(false));
    }

    let per_cpu_hash = is_map_supported(MapType::PerCpuHash);
    let per_cpu_array = is_map_supported(MapType::PerCpuArray);
    let stack_trace = is_map_supported(MapType::StackTrace);
    if current >= KernelVersion::new(4, 6, 0) {
        assert_matches!(per_cpu_hash, Ok(true));
        assert_matches!(per_cpu_array, Ok(true));
        assert_matches!(stack_trace, Ok(true));
    } else {
        assert_matches!(per_cpu_hash, Ok(false));
        assert_matches!(per_cpu_array, Ok(false));
        assert_matches!(stack_trace, Ok(false));
    }

    let cgroup_array = is_map_supported(MapType::CgroupArray);
    if current >= KernelVersion::new(4, 8, 0) {
        assert_matches!(cgroup_array, Ok(true));
    } else {
        assert_matches!(cgroup_array, Ok(false));
    }

    let lru_hash = is_map_supported(MapType::LruHash);
    let lru_per_cpu_hash = is_map_supported(MapType::LruPerCpuHash);
    if current >= KernelVersion::new(4, 10, 0) {
        assert_matches!(lru_hash, Ok(true));
        assert_matches!(lru_per_cpu_hash, Ok(true));
    } else {
        assert_matches!(lru_hash, Ok(false));
        assert_matches!(lru_per_cpu_hash, Ok(false));
    }

    let lpm_trie = is_map_supported(MapType::LpmTrie);
    if current >= KernelVersion::new(4, 11, 0) {
        assert_matches!(lpm_trie, Ok(true));
    } else {
        assert_matches!(lpm_trie, Ok(false));
    }

    let array_of_maps = is_map_supported(MapType::ArrayOfMaps);
    let hash_of_maps = is_map_supported(MapType::HashOfMaps);
    if current >= KernelVersion::new(4, 12, 0) {
        assert_matches!(array_of_maps, Ok(true));
        assert_matches!(hash_of_maps, Ok(true));
    } else {
        assert_matches!(array_of_maps, Ok(false));
        assert_matches!(hash_of_maps, Ok(false));
    }

    let dev_map = is_map_supported(MapType::DevMap);
    let sock_map = is_map_supported(MapType::SockMap);
    if current >= KernelVersion::new(4, 14, 0) {
        assert_matches!(dev_map, Ok(true));
        assert_matches!(sock_map, Ok(true));
    } else {
        assert_matches!(dev_map, Ok(false));
        assert_matches!(sock_map, Ok(false));
    }

    let cpu_map = is_map_supported(MapType::CpuMap);
    if current >= KernelVersion::new(4, 15, 0) {
        assert_matches!(cpu_map, Ok(true));
    } else {
        assert_matches!(cpu_map, Ok(false));
    }

    let xsk_map = is_map_supported(MapType::XskMap);
    let sock_hash = is_map_supported(MapType::SockHash);
    if current >= KernelVersion::new(4, 18, 0) {
        assert_matches!(xsk_map, Ok(true));
        assert_matches!(sock_hash, Ok(true));
    } else {
        assert_matches!(xsk_map, Ok(false));
        assert_matches!(sock_hash, Ok(false));
    }

    let cgroup_storage = is_map_supported(MapType::CgroupStorage);
    let reuseport_sock_array = is_map_supported(MapType::ReuseportSockArray);
    if current >= KernelVersion::new(4, 19, 0) {
        assert_matches!(cgroup_storage, Ok(true));
        assert_matches!(reuseport_sock_array, Ok(true));
    } else {
        assert_matches!(cgroup_storage, Ok(false));
        assert_matches!(reuseport_sock_array, Ok(false));
    }

    let per_cpu_cgroup_storage = is_map_supported(MapType::PerCpuCgroupStorage);
    let queue = is_map_supported(MapType::Queue);
    let stack = is_map_supported(MapType::Stack);
    if current >= KernelVersion::new(4, 20, 0) {
        assert_matches!(per_cpu_cgroup_storage, Ok(true));
        assert_matches!(queue, Ok(true));
        assert_matches!(stack, Ok(true));
    } else {
        assert_matches!(per_cpu_cgroup_storage, Ok(false));
        assert_matches!(queue, Ok(false));
        assert_matches!(stack, Ok(false));
    }

    let sk_storage = is_map_supported(MapType::SkStorage);
    if current >= KernelVersion::new(5, 2, 0) {
        assert_matches!(sk_storage, Ok(true));
    } else {
        assert_matches!(sk_storage, Ok(false));
    }

    let devmap_hash = is_map_supported(MapType::DevMapHash);
    if current >= KernelVersion::new(5, 4, 0) {
        assert_matches!(devmap_hash, Ok(true));
    } else {
        assert_matches!(devmap_hash, Ok(false));
    }

    let struct_ops = is_map_supported(MapType::StructOps);
    if current >= KernelVersion::new(5, 6, 0) {
        assert_matches!(struct_ops, Ok(true));
    } else {
        assert_matches!(struct_ops, Ok(false));
    }

    let ring_buf = is_map_supported(MapType::RingBuf);
    if current >= KernelVersion::new(5, 8, 0) {
        assert_matches!(ring_buf, Ok(true));
    } else {
        assert_matches!(ring_buf, Ok(false));
    }

    let inode_storage = is_map_supported(MapType::InodeStorage); // Requires `CONFIG_BPF_LSM=y`
    if current >= KernelVersion::new(5, 10, 0) {
        assert_matches!(inode_storage, Ok(true));
    } else {
        assert_matches!(inode_storage, Ok(false));
    }

    let task_storage = is_map_supported(MapType::TaskStorage);
    if current >= KernelVersion::new(5, 11, 0) {
        assert_matches!(task_storage, Ok(true));
    } else {
        assert_matches!(task_storage, Ok(false));
    }

    let bloom_filter = is_map_supported(MapType::BloomFilter);
    if current >= KernelVersion::new(5, 16, 0) {
        assert_matches!(bloom_filter, Ok(true));
    } else {
        assert_matches!(bloom_filter, Ok(false));
    }

    let user_ring_buf = is_map_supported(MapType::UserRingBuf);
    if current >= KernelVersion::new(6, 1, 0) {
        assert_matches!(user_ring_buf, Ok(true));
    } else {
        assert_matches!(user_ring_buf, Ok(false));
    }

    let cgrp_storage = is_map_supported(MapType::CgrpStorage);
    if current >= KernelVersion::new(6, 2, 0) {
        assert_matches!(cgrp_storage, Ok(true));
    } else {
        assert_matches!(cgrp_storage, Ok(false));
    }

    let arena = is_map_supported(MapType::Arena);
    if current >= KernelVersion::new(6, 9, 0) {
        assert_matches!(arena, Ok(true));
    } else {
        assert_matches!(arena, Ok(false));
    }
}
