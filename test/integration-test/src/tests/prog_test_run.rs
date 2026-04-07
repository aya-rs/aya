use aya::{
    Ebpf, TestRunOptions,
    maps::Array,
    programs::{SchedClassifier, SocketFilter, TestRun as _, Xdp},
};
use integration_common::test_run::{IF_INDEX, XDP_MODIFY_LEN, XDP_MODIFY_VAL};

// https://github.com/torvalds/linux/blob/8fdb05de/tools/testing/selftests/bpf/prog_tests/xdp_context_test_run.c#L48
// `sizeof(pkt_v4)` = Size(Ethernet) + Size(IPv4) + Size(TCP) = 14 + 20 + 20
const PKT_V4_SIZE: usize = 14 + 20 + 20;

#[test_log::test]
fn test_xdp_test_run() {
    let kernel_version = aya::util::KernelVersion::current().unwrap();
    // bc56c919fce7 "bpf: Add xdp.frame_sz in bpf_prog_test_run_xdp()" → v5.8
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

    let result = prog.test_run(opts).unwrap();

    assert_eq!(result.return_value, 2, "Expected XDP_PASS (2)");
    assert!(result.duration > 0, "Expected non-zero duration");
}

#[test_log::test]
fn test_xdp_modify_packet() {
    let kernel_version = aya::util::KernelVersion::current().unwrap();
    // 94079b64255f — "Merge branch 'bpf-bounded-loops'" → v5.3
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

    let result = prog.test_run(opts).unwrap();

    assert_eq!(result.return_value, 2, "Expected XDP_PASS (2)");
    assert!(result.duration > 0, "Expected non-zero duration");

    let expected_pattern: Vec<u8> = vec![XDP_MODIFY_VAL; XDP_MODIFY_LEN];
    assert_eq!(&data_out[..XDP_MODIFY_LEN], &*expected_pattern);
    assert_eq!(&data_out[XDP_MODIFY_LEN..], &data_in[XDP_MODIFY_LEN..]);
}

#[test_log::test]
fn test_socket_filter_test_run() {
    let kernel_version = aya::util::KernelVersion::current().unwrap();
    // 61f3c964dfd2 "bpf: allow socket_filter programs to use bpf_prog_test_run" → v4.16
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

    let result = prog.test_run(opts).unwrap();

    // Ethernet header size = 14 bytes
    let expected_len = PKT_V4_SIZE - 14;
    assert_eq!(
        result.return_value as usize, expected_len,
        "Expected return value to be packet length minus Ethernet header"
    );
    assert!(result.duration > 0, "Expected non-zero duration");
}

#[test_log::test]
fn test_classifier_test_run() {
    let kernel_version = aya::util::KernelVersion::current().unwrap();
    // 1cf1cae963c2 "bpf: introduce BPF_PROG_TEST_RUN command" → v4.12
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

    let result = prog.test_run(opts).unwrap();

    assert_eq!(result.return_value, 1, "Expected SK_PASS(1)");
    assert!(result.duration > 0, "Expected non-zero duration");
}

#[test_log::test]
fn test_run_repeat() {
    let kernel_version = aya::util::KernelVersion::current().unwrap();
    // 61f3c964dfd2 "bpf: allow socket_filter programs to use bpf_prog_test_run" → v4.16
    // since we use `SocketFilter` for test
    if kernel_version < aya::util::KernelVersion::new(4, 16, 0) {
        return;
    }

    let mut bpf = Ebpf::load(crate::TEST_RUN).unwrap();

    let mut exec_count: Array<_, u64> = bpf.take_map("EXEC_COUNT").unwrap().try_into().unwrap();

    exec_count.set(0, 0, 0).unwrap();

    let prog: &mut SocketFilter = bpf
        .program_mut("test_count_exec")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();

    let data_in = vec![0u8; PKT_V4_SIZE];
    let mut data_out = vec![0u8; PKT_V4_SIZE];

    // Run the test 50 times
    let opts = TestRunOptions {
        data_in: Some(&data_in),
        data_out: Some(&mut data_out),
        repeat: 50,
        ..TestRunOptions::default()
    };
    let _result = prog.test_run(opts).unwrap();

    let final_count: u64 = exec_count.get(&0, 0).unwrap();
    assert_eq!(final_count, repeat_count.into());
}

#[test_log::test]
fn test_xdp_context() {
    let kernel_version = aya::util::KernelVersion::current().unwrap();
    // 47316f4a3053 "bpf: Support input xdp_md context in BPF_PROG_TEST_RUN"
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
    let ctx_bytes = unsafe { core::slice::from_raw_parts((&raw const ctx).cast::<u8>(), size) };
    let mut ctx_out = vec![0u8; size];

    let opts = TestRunOptions {
        data_in: Some(&data_in),
        data_out: Some(&mut data_out),
        ctx_in: Some(ctx_bytes),
        ctx_out: Some(&mut ctx_out),
        ..TestRunOptions::default()
    };

    let result = prog.test_run(opts).unwrap();

    // XDP_PASS is 2 - should pass when rx_queue_index matches expected value
    assert_eq!(
        result.return_value, 2,
        "Expected XDP_PASS (2) when rx_queue_index matches"
    );
    assert!(result.duration > 0, "Expected non-zero duration");
}
