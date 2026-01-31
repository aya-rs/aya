use aya::{
    Ebpf, TestRunOptions,
    maps::Array,
    programs::{SchedClassifier, SocketFilter, TestRun as _, Xdp},
    util::KernelVersion,
};

fn require_version(major: u8, minor: u8, patch: u16) -> bool {
    let kernel_version = KernelVersion::current().unwrap();
    if kernel_version < KernelVersion::new(major, minor, patch) {
        eprintln!(
            "skipping test on kernel {kernel_version:?}, requires kernel >= {}.{}.{}",
            major, minor, patch
        );
        return false;
    }
    true
}

#[test_log::test]
fn test_xdp_test_run() {
    if !require_version(5, 18, 0) {
        return;
    }

    let mut bpf = Ebpf::load(crate::TEST_RUN).unwrap();
    let prog: &mut Xdp = bpf.program_mut("test_xdp").unwrap().try_into().unwrap();
    prog.load().unwrap();

    let data_in = vec![0u8; 64];
    let mut data_out = vec![0u8; 64];

    let mut opts = TestRunOptions::default();
    opts.data_in = Some(&data_in);
    opts.data_out = Some(&mut data_out);

    let result = prog.test_run(&mut opts).unwrap();

    assert_eq!(result.return_value, 2, "Expected XDP_PASS (2)");
    assert!(result.duration > 0, "Expected non-zero duration");
}

#[test_log::test]
fn test_xdp_modify_packet() {
    if !require_version(5, 18, 0) {
        return;
    }

    let mut bpf = Ebpf::load(crate::TEST_RUN).unwrap();
    let prog: &mut Xdp = bpf
        .program_mut("test_xdp_modify")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();

    let data_in = vec![0u8; 64];
    let mut data_out = vec![0u8; 64];

    let mut opts = TestRunOptions::default();
    opts.data_in = Some(&data_in);
    opts.data_out = Some(&mut data_out);

    let result = prog.test_run(&mut opts).unwrap();

    assert_eq!(result.return_value, 2, "Expected XDP_PASS (2)");
    assert!(result.duration > 0, "Expected non-zero duration");

    let expected_pattern: Vec<u8> = vec![0xAAu8; 16];
    assert_eq!(&data_out[..16], &expected_pattern[..],);
    assert_eq!(&data_out[16..], &data_in[16..],);
}

#[test_log::test]
fn test_socket_filter_test_run() {
    let mut bpf = Ebpf::load(crate::TEST_RUN).unwrap();
    let prog: &mut SocketFilter = bpf
        .program_mut("test_sock_filter")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();

    let packet_len = 128;
    let data_in = vec![0u8; packet_len];
    let mut data_out = vec![0u8; packet_len];

    let mut opts = TestRunOptions::default();
    opts.data_in = Some(&data_in);
    opts.data_out = Some(&mut data_out);

    let result = prog.test_run(&mut opts).unwrap();

    // Ethernet header size = 14 bytes
    let expected_len = packet_len - 14;
    assert_eq!(
        result.return_value as usize, expected_len,
        "Expected return value to be packet length minus Ethernet header"
    );
    assert!(result.duration > 0, "Expected non-zero duration");
}

#[test_log::test]
fn test_classifier_test_run() {
    if !require_version(4, 14, 0) {
        return;
    }

    let mut bpf = Ebpf::load(crate::TEST_RUN).unwrap();
    let prog: &mut SchedClassifier = bpf
        .program_mut("test_classifier")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();

    let data_in = vec![0u8; 64];
    let mut data_out = vec![0u8; 64];

    let mut opts = TestRunOptions::default();
    opts.data_in = Some(&data_in);
    opts.data_out = Some(&mut data_out);

    let result = prog.test_run(&mut opts).unwrap();

    assert_eq!(result.return_value, 1, "Expected SK_PASS(1)");
    assert!(result.duration > 0, "Expected non-zero duration");
}

#[test_log::test]
fn test_run_repeat() {
    let mut bpf = Ebpf::load(crate::TEST_RUN).unwrap();

    let mut exec_count: Array<_, u64> = bpf.take_map("EXEC_COUNT").unwrap().try_into().unwrap();

    exec_count.set(0, 0, 0).unwrap();

    let prog: &mut SocketFilter = bpf
        .program_mut("test_count_exec")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();

    let data_in = vec![0u8; 64];
    let mut data_out = vec![0u8; 64];

    // Run the test 50 times
    let repeat_count = 50;
    let mut opts = TestRunOptions::default();
    opts.data_in = Some(&data_in);
    opts.data_out = Some(&mut data_out);
    opts.repeat = repeat_count;
    let _result = prog.test_run(&mut opts).unwrap();

    let final_count: u64 = exec_count.get(&0, 0).unwrap();
    assert_eq!(final_count, repeat_count.into());
}

#[test_log::test]
fn test_xdp_context() {
    if !require_version(5, 18, 0) {
        return;
    }

    let mut bpf = Ebpf::load(crate::TEST_RUN).unwrap();
    let prog: &mut Xdp = bpf
        .program_mut("test_xdp_context")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();

    let data_in = vec![0u8; 64];
    let mut data_out = vec![0u8; 64];

    #[repr(C)]
    struct XdpMd {
        data: u32,
        data_end: u32,
        data_meta: u32,
        ingress_ifindex: u32,
        rx_queue_index: u32,
        egress_ifindex: u32,
    }

    // there are several rules must follow for using the xdp_md context correctly,
    // which are extracted from the kernel's selftests:
    //   1. Meta data's size must be a multiple of 4
    //   2. data_meta must reference the start of data
    //   3. Total size of data must be data_end - data_meta or larger
    //   4. RX queue cannot be specified without specifying an ingress
    //   5. Interface 1 is always the loopback interface which always has only
    //   6. The egress cannot be specified
    // see: https://github.com/torvalds/linux/blob/63804fed149a6750ffd28610c5c1c98cce6bd377/tools/testing/selftests/bpf/prog_tests/xdp_context_test_run.c#L92
    // for more details.
    let ctx = XdpMd {
        data: 0,
        data_end: data_in.len() as u32,
        data_meta: 0,
        ingress_ifindex: 1,
        // RX queue cannot be specified without specifying an ingress
        rx_queue_index: 0,
        // egress cannot be specified
        egress_ifindex: 0,
    };

    let size = size_of::<XdpMd>();
    #[allow(clippy::ref_as_ptr, clippy::ptr_as_ptr)]
    let ctx_bytes = unsafe { std::slice::from_raw_parts(&ctx as *const XdpMd as *const u8, size) };
    let mut ctx_out = vec![0u8; size];

    let mut opts = TestRunOptions::default();
    opts.data_in = Some(&data_in);
    opts.data_out = Some(&mut data_out);
    opts.ctx_in = Some(ctx_bytes);
    opts.ctx_out = Some(&mut ctx_out);

    let result = prog.test_run(&mut opts).unwrap();

    // XDP_PASS is 2 - should pass when rx_queue_index matches expected value
    assert_eq!(
        result.return_value, 2,
        "Expected XDP_PASS (2) when rx_queue_index matches"
    );
    assert!(result.duration > 0, "Expected non-zero duration");
}
