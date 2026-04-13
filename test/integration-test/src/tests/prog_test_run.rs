use aya::{
    Ebpf, TestRunOptions, TestRunResult,
    maps::Array,
    programs::{SchedClassifier, SocketFilter, TestRun as _, Xdp},
};
use integration_common::test_run::{IF_INDEX, XDP_MODIFY_LEN, XDP_MODIFY_VAL};

// https://github.com/torvalds/linux/blob/8fdb05de/tools/testing/selftests/bpf/prog_tests/xdp_context_test_run.c#L48
// `sizeof(pkt_v4)` = Size(Ethernet) + Size(IPv4) + Size(TCP) = 14 + 20 + 20
const PKT_ETH_HDR_SIZE: usize = 14;
const PKT_IP4_HDR_SIZE: usize = 20;
const PKT_TCP_HDR_SIZE: usize = 20;
const PKT_V4_SIZE: usize = PKT_ETH_HDR_SIZE + PKT_IP4_HDR_SIZE + PKT_TCP_HDR_SIZE;

fn bytes_of<T: Sized>(val: &T) -> &[u8] {
    let size = size_of::<T>();
    unsafe { core::slice::from_raw_parts(core::ptr::from_ref::<T>(val).cast::<u8>(), size) }
}

#[test_log::test]
fn test_classifier_test_run() {
    let kernel_version = aya::util::KernelVersion::current().unwrap();
    // BPF_PROG_TEST_RUN was introduced in v4.12 (1cf1cae963c2, "bpf: introduce
    // BPF_PROG_TEST_RUN command") with support for sched_cls (used here) and
    // sched_act program types. On kernels before v4.12 the syscall command does
    // not exist and the bpf(2) call returns EINVAL.
    if kernel_version < aya::util::KernelVersion::new(4, 12, 0) {
        return;
    }

    let mut bpf = Ebpf::load(crate::TEST_RUN).unwrap();
    let prog: &mut SchedClassifier = bpf
        .program_mut("test_classifier")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();

    let data_in = vec![0u8; PKT_V4_SIZE];
    let mut data_out = vec![0u8; PKT_V4_SIZE];

    let opts = TestRunOptions {
        data_in: Some(&data_in),
        data_out: Some(&mut data_out),
        ..TestRunOptions::default()
    };

    let TestRunResult {
        return_value,
        duration,
        data_size_out,
        ctx_size_out,
    } = prog.test_run(opts).unwrap();

    assert_eq!(return_value, 1, "Expected SK_PASS(1)");
    assert!(!duration.is_zero());
    assert_eq!(data_size_out as usize, PKT_V4_SIZE);
    assert_eq!(ctx_size_out, 0);
}

#[test_log::test]
fn test_run_repeat() {
    let kernel_version = aya::util::KernelVersion::current().unwrap();
    // BPF_PROG_TEST_RUN was introduced in v4.12 (1cf1cae963c2, "bpf: introduce
    // BPF_PROG_TEST_RUN command") with support for sched_cls (used here) and
    // sched_act program types.
    // The `repeat` field in the BPF_PROG_TEST_RUN attribute struct was present from v4.12
    if kernel_version < aya::util::KernelVersion::new(4, 12, 0) {
        return;
    }

    let mut bpf = Ebpf::load(crate::TEST_RUN).unwrap();

    let mut exec_count: Array<_, u64> = bpf.take_map("EXEC_COUNT").unwrap().try_into().unwrap();

    exec_count.set(0, 0, 0).unwrap();

    let prog: &mut SchedClassifier = bpf
        .program_mut("test_count_exec")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();

    let data_in = vec![0u8; PKT_V4_SIZE];
    let mut data_out = vec![0u8; PKT_V4_SIZE];

    let opts = TestRunOptions {
        data_in: Some(&data_in),
        data_out: Some(&mut data_out),
        repeat: 50,
        ..TestRunOptions::default()
    };
    let TestRunResult {
        return_value,
        duration,
        data_size_out,
        ctx_size_out,
    } = prog.test_run(opts).unwrap();

    let final_count: u64 = exec_count.get(&0, 0).unwrap();
    assert_eq!(return_value, 1, "Expected SK_PASS(1)");
    assert_eq!(final_count, 50);
    assert!(!duration.is_zero());
    assert_eq!(data_size_out as usize, PKT_V4_SIZE);
    assert_eq!(ctx_size_out, 0);
}

#[test_log::test]
fn test_xdp_modify_packet() {
    let kernel_version = aya::util::KernelVersion::current().unwrap();
    // The test_xdp_modify eBPF program uses a bounded for-loop to overwrite packet
    // bytes. Before v5.3, the BPF verifier rejected all back-edges unconditionally,
    // treating even provably-terminating loops as potential infinite loops. The v5.3
    // merge (94079b64255f, "bpf: bounded loops") taught the verifier to track loop
    // bounds and accept loops with a statically-known iteration count. Without this,
    // prog.load() fails with a verifier error ("back-edge from insn N to M").
    // We require v5.6 rather than v5.3 as a conservative bound validated in CI.
    if kernel_version < aya::util::KernelVersion::new(5, 6, 0) {
        return;
    }

    let mut bpf = Ebpf::load(crate::TEST_RUN).unwrap();
    let prog: &mut Xdp = bpf
        .program_mut("test_xdp_modify")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();

    let data_in = vec![0u8; PKT_V4_SIZE];
    let mut data_out = vec![0u8; PKT_V4_SIZE];

    let opts = TestRunOptions {
        data_in: Some(&data_in),
        data_out: Some(&mut data_out),
        ..TestRunOptions::default()
    };

    let TestRunResult {
        return_value,
        duration,
        data_size_out,
        ctx_size_out,
    } = prog.test_run(opts).unwrap();

    assert_eq!(return_value, 2, "Expected XDP_PASS(2)");
    assert!(!duration.is_zero());
    assert_eq!(data_size_out as usize, PKT_V4_SIZE);
    assert_eq!(ctx_size_out, 0);

    let expected_pattern: Vec<u8> = vec![XDP_MODIFY_VAL; XDP_MODIFY_LEN];
    assert_eq!(&data_out[..XDP_MODIFY_LEN], &*expected_pattern);
    assert_eq!(&data_out[XDP_MODIFY_LEN..], &data_in[XDP_MODIFY_LEN..]);
}

#[test_log::test]
fn test_socket_filter_test_run() {
    let kernel_version = aya::util::KernelVersion::current().unwrap();
    // BPF_PROG_TEST_RUN was introduced in v4.12 but initially only supported
    // sched_cls and sched_act program types. Support for BPF_PROG_TYPE_SOCKET_FILTER
    // was added in v4.16 (61f3c964dfd2, "bpf: allow socket_filter programs to use
    // bpf_prog_test_run"). On earlier kernels, calling BPF_PROG_TEST_RUN on a socket
    // filter program returns EINVAL.
    if kernel_version < aya::util::KernelVersion::new(4, 16, 0) {
        return;
    }

    let mut bpf = Ebpf::load(crate::TEST_RUN).unwrap();
    let prog: &mut SocketFilter = bpf
        .program_mut("test_sock_filter")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();

    let data_in = vec![0u8; PKT_V4_SIZE];
    let mut data_out = vec![0u8; PKT_V4_SIZE];

    let opts = TestRunOptions {
        data_in: Some(&data_in),
        data_out: Some(&mut data_out),
        ..TestRunOptions::default()
    };

    let TestRunResult {
        return_value,
        duration,
        data_size_out,
        ctx_size_out,
    } = prog.test_run(opts).unwrap();

    assert_eq!(return_value as usize, PKT_V4_SIZE - PKT_ETH_HDR_SIZE);
    assert!(!duration.is_zero());
    assert_eq!(data_size_out as usize, PKT_V4_SIZE);
    assert_eq!(ctx_size_out, 0);
}

#[test_log::test]
fn test_xdp_test_run() {
    let kernel_version = aya::util::KernelVersion::current().unwrap();
    // XDP test-run with a writable data_out buffer requires the kernel to properly
    // initialize xdp_buff.frame_sz during test execution. Before v5.8
    // (bc56c919fce7, "bpf: Add xdp.frame_sz in bpf_prog_test_run_xdp"), frame_sz
    // was left as zero. The kernel uses frame_sz to compute available headroom and
    // tailroom; with frame_sz=0 those bounds are wrong and bpf_prog_test_run may
    // return an error or silently produce incorrect data_out contents.
    if kernel_version < aya::util::KernelVersion::new(5, 8, 0) {
        return;
    }

    let mut bpf = Ebpf::load(crate::TEST_RUN).unwrap();
    let prog: &mut Xdp = bpf.program_mut("test_xdp").unwrap().try_into().unwrap();
    prog.load().unwrap();

    let data_in = vec![0u8; PKT_V4_SIZE];
    let mut data_out = vec![0u8; PKT_V4_SIZE];

    let opts = TestRunOptions {
        data_in: Some(&data_in),
        data_out: Some(&mut data_out),
        ..TestRunOptions::default()
    };

    let TestRunResult {
        return_value,
        duration,
        data_size_out,
        ctx_size_out,
    } = prog.test_run(opts).unwrap();

    assert_eq!(return_value, 2, "Expected XDP_PASS(2)");
    assert!(!duration.is_zero());
    assert_eq!(data_size_out as usize, PKT_V4_SIZE);
    assert_eq!(ctx_size_out, 0);
}

#[test_log::test]
fn test_xdp_context() {
    let kernel_version = aya::util::KernelVersion::current().unwrap();
    // BPF_PROG_TEST_RUN gained ctx_in/ctx_out support for XDP programs in v5.15.
    // Two commits together enabled this: 47316f4a3053 ("bpf: Support input xdp_md
    // context in BPF_PROG_TEST_RUN") wired up the ctx_in/ctx_out fields so the
    // test runner populates the XDP metadata (including ingress_ifindex) from the
    // caller-supplied context, and ec94670fcb3b added ingress_ifindex propagation
    // into the live xdp_buff. Before v5.15, passing ctx_in for an XDP program
    // returns EINVAL because the kernel does not recognise or forward the context.
    if kernel_version < aya::util::KernelVersion::new(5, 15, 0) {
        return;
    }

    let mut bpf = Ebpf::load(crate::TEST_RUN).unwrap();
    let prog: &mut Xdp = bpf
        .program_mut("test_xdp_context")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();

    let data_in = vec![0u8; PKT_V4_SIZE];
    let mut data_out = vec![0u8; PKT_V4_SIZE];

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct XdpMd {
        data: u32,
        data_end: u32,
        data_meta: u32,
        ingress_ifindex: u32,
        rx_queue_index: u32,
        egress_ifindex: u32,
    }

    // see: https://github.com/torvalds/linux/blob/63804fed/tools/testing/selftests/bpf/prog_tests/xdp_context_test_run.c#L92
    // for more details.
    let ctx = XdpMd {
        data: 0,
        data_end: data_in.len() as u32,
        data_meta: 0,
        ingress_ifindex: IF_INDEX,
        // RX queue cannot be specified without specifying an ingress
        rx_queue_index: 0,
        // egress cannot be specified
        egress_ifindex: 0,
    };

    let size = size_of::<XdpMd>();
    let ctx_bytes = bytes_of(&ctx);
    let mut ctx_out = vec![0u8; size];

    let opts = TestRunOptions {
        data_in: Some(&data_in),
        data_out: Some(&mut data_out),
        ctx_in: Some(ctx_bytes),
        ctx_out: Some(&mut ctx_out),
        ..TestRunOptions::default()
    };

    let TestRunResult {
        return_value,
        duration,
        data_size_out,
        ctx_size_out,
    } = prog.test_run(opts).unwrap();

    assert_eq!(return_value, 2, "Expected XDP_PASS(2)");
    assert!(!duration.is_zero());
    assert_eq!(data_size_out as usize, PKT_V4_SIZE);
    assert_eq!(ctx_size_out as usize, size_of::<XdpMd>());
}
