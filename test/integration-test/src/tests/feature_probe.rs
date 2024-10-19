//! Test feature probing against kernel version.

use std::path::Path;

use assert_matches::assert_matches;
use aya::{programs::ProgramType, sys::feature_probe::*, util::KernelVersion};

use super::load::RETRY_DURATION;

// TODO: Enable certain CONFIG_* options when compiling the image for VM tests.
#[test]
fn probe_supported_programs() {
    let current = KernelVersion::current().unwrap();

    let socket_filter = retry(3, || is_program_supported(ProgramType::SocketFilter));
    if current >= KernelVersion::new(3, 19, 0) {
        assert_matches!(socket_filter, Ok(true));
    } else {
        assert_matches!(socket_filter, Ok(false));
    }

    let kprobe = retry(3, || is_program_supported(ProgramType::KProbe));
    let sched_cls = retry(3, || is_program_supported(ProgramType::SchedClassifier));
    let sched_act = retry(3, || is_program_supported(ProgramType::SchedAction));
    if current >= KernelVersion::new(4, 1, 0) {
        assert_matches!(kprobe, Ok(true));
        assert_matches!(sched_cls, Ok(true));
        assert_matches!(sched_act, Ok(true));
    } else {
        assert_matches!(kprobe, Ok(false));
        assert_matches!(sched_cls, Ok(false));
        assert_matches!(sched_act, Ok(false));
    }

    let tracepoint = retry(3, || is_program_supported(ProgramType::TracePoint));
    if current >= KernelVersion::new(4, 7, 0) {
        assert_matches!(tracepoint, Ok(true));
    } else {
        assert_matches!(tracepoint, Ok(false));
    }

    let xdp = retry(3, || is_program_supported(ProgramType::Xdp));
    if current >= KernelVersion::new(4, 8, 0) {
        assert_matches!(xdp, Ok(true));
    } else {
        assert_matches!(xdp, Ok(false));
    }

    let perf_event = retry(3, || is_program_supported(ProgramType::PerfEvent));
    if current >= KernelVersion::new(4, 9, 0) {
        assert_matches!(perf_event, Ok(true));
    } else {
        assert_matches!(perf_event, Ok(false));
    }

    let cgroup_skb = retry(3, || is_program_supported(ProgramType::CgroupSkb));
    let cgroup_sock = retry(3, || is_program_supported(ProgramType::CgroupSock));
    let lwt_in = retry(3, || is_program_supported(ProgramType::LwtInput));
    let lwt_out = retry(3, || is_program_supported(ProgramType::LwtOutput));
    let lwt_xmit = retry(3, || is_program_supported(ProgramType::LwtXmit));
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

    let sock_ops = retry(3, || is_program_supported(ProgramType::SockOps));
    if current >= KernelVersion::new(4, 13, 0) {
        assert_matches!(sock_ops, Ok(true));
    } else {
        assert_matches!(sock_ops, Ok(false));
    }

    let sk_skb = retry(3, || is_program_supported(ProgramType::SkSkb));
    if current >= KernelVersion::new(4, 14, 0) {
        assert_matches!(sk_skb, Ok(true));
    } else {
        assert_matches!(sk_skb, Ok(false));
    }

    let cgroup_device = retry(3, || is_program_supported(ProgramType::CgroupDevice));
    if current >= KernelVersion::new(4, 15, 0) {
        assert_matches!(cgroup_device, Ok(true));
    } else {
        assert_matches!(cgroup_device, Ok(false));
    }

    let sk_msg = retry(3, || is_program_supported(ProgramType::SkMsg));
    let raw_tp = retry(3, || is_program_supported(ProgramType::RawTracePoint));
    let cgroup_sock_addr = retry(3, || is_program_supported(ProgramType::CgroupSockAddr));
    if current >= KernelVersion::new(4, 17, 0) {
        assert_matches!(sk_msg, Ok(true));
        assert_matches!(raw_tp, Ok(true));
        assert_matches!(cgroup_sock_addr, Ok(true));
    } else {
        assert_matches!(sk_msg, Ok(false));
        assert_matches!(raw_tp, Ok(false));
        assert_matches!(cgroup_sock_addr, Ok(false));
    }

    let lwt_seg6local = retry(3, || is_program_supported(ProgramType::LwtSeg6local));
    // Requires `CONFIG_BPF_LIRC_MODE2=y`.
    // let lirc_mode2 = is_program_supported(ProgramType::LircMode2);
    if current >= KernelVersion::new(4, 18, 0) {
        assert_matches!(lwt_seg6local, Ok(true));
        // assert_matches!(lirc_mode2, Ok(true));
    } else {
        assert_matches!(lwt_seg6local, Ok(false));
        // assert_matches!(lirc_mode2, Ok(false));
    }

    let sk_reuseport = retry(3, || is_program_supported(ProgramType::SkReuseport));
    if current >= KernelVersion::new(4, 19, 0) {
        assert_matches!(sk_reuseport, Ok(true));
    } else {
        assert_matches!(sk_reuseport, Ok(false));
    }

    let flow_dissector = retry(3, || is_program_supported(ProgramType::FlowDissector));
    if current >= KernelVersion::new(4, 20, 0) {
        assert_matches!(flow_dissector, Ok(true));
    } else {
        assert_matches!(flow_dissector, Ok(false));
    }

    let cgroup_sysctl = retry(3, || is_program_supported(ProgramType::CgroupSysctl));
    let raw_tp_writable = retry(3, || {
        is_program_supported(ProgramType::RawTracePointWritable)
    });
    if current >= KernelVersion::new(5, 2, 0) {
        assert_matches!(cgroup_sysctl, Ok(true));
        assert_matches!(raw_tp_writable, Ok(true));
    } else {
        assert_matches!(cgroup_sysctl, Ok(false));
        assert_matches!(raw_tp_writable, Ok(false));
    }

    let cgroup_sockopt = retry(3, || is_program_supported(ProgramType::CgroupSockopt));
    if current >= KernelVersion::new(5, 3, 0) {
        assert_matches!(cgroup_sockopt, Ok(true));
    } else {
        assert_matches!(cgroup_sockopt, Ok(false));
    }

    // Requires `CONFIG_DEBUG_INFO_BTF=y`
    let tracing = retry(3, || is_program_supported(ProgramType::Tracing));
    if current >= KernelVersion::new(5, 5, 0) && Path::new("/sys/kernel/btf").exists() {
        assert_matches!(tracing, Ok(true));
    } else {
        assert_matches!(tracing, Ok(false));
    }

    let struct_ops = retry(3, || is_program_supported(ProgramType::StructOps));
    let extension = retry(3, || is_program_supported(ProgramType::Extension));
    if current >= KernelVersion::new(5, 6, 0) {
        assert_matches!(struct_ops, Ok(true));
        assert_matches!(extension, Ok(true));
    } else {
        assert_matches!(struct_ops, Ok(false));
        assert_matches!(extension, Ok(false));
    }

    // // Requires `CONFIG_BPF_LSM=y` & `CONFIG_DEBUG_INFO_BTF=y`
    // let lsm = retry(3, || is_program_supported(ProgramType::Lsm));
    // if current >= KernelVersion::new(5, 7, 0) && Path::new("/sys/kernel/btf").exists() {
    //     assert_matches!(lsm, Ok(true));
    // } else {
    //     assert_matches!(lsm, Ok(false));
    // }

    let sk_lookup = retry(3, || is_program_supported(ProgramType::SkLookup));
    if current >= KernelVersion::new(5, 9, 0) {
        assert_matches!(sk_lookup, Ok(true));
    } else {
        assert_matches!(sk_lookup, Ok(false));
    }

    let syscall = retry(3, || is_program_supported(ProgramType::Syscall));
    if current >= KernelVersion::new(5, 14, 0) {
        assert_matches!(syscall, Ok(true));
    } else {
        assert_matches!(syscall, Ok(false));
    }

    let netfilter = retry(3, || is_program_supported(ProgramType::Netfilter));
    if current >= KernelVersion::new(6, 4, 0) {
        assert_matches!(netfilter, Ok(true));
    } else {
        assert_matches!(netfilter, Ok(false));
    }
}

// Back-to-back calls can be flaky and return `EPERM`.
fn retry<T, E>(max_retries: u32, try_func: impl Fn() -> Result<T, E>) -> Result<T, E> {
    let mut res = try_func();
    for i in 1..max_retries {
        if res.is_ok() {
            return res;
        }
        std::thread::sleep(RETRY_DURATION * i);
        res = try_func();
    }
    res
}
