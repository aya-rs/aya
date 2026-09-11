use aya::{
    Ebpf, EbpfLoader,
    programs::{Extension, ProgramError, ProgramType, TracePoint, Xdp, XdpMode, tc},
    sys::is_program_supported,
    test_helpers::NetNsGuard,
    util::KernelVersion,
};

#[test_log::test]
fn modprobe() {
    // This very simple looking test is actually quite complex.
    // The call to tc::qdisc_add_clsact() causes the linux kernel to call into
    // `__request_module()`, which via the usermodehelper calls out into the
    // `/sbin/modprobe` to load the required kernel module.
    // In order for this test to pass, all of that machinery must work
    // correctly within the test environment.
    let _netns = NetNsGuard::new().unwrap();

    tc::qdisc_add_clsact("lo").unwrap();
}

#[test_log::test]
fn xdp() {
    let kernel_version = KernelVersion::current().unwrap();
    let mut bpf = Ebpf::load(crate::PASS).unwrap();
    let dispatcher: &mut Xdp = bpf.program_mut("pass").unwrap().try_into().unwrap();
    match dispatcher.load() {
        Ok(()) => {}
        Err(error) => {
            assert!(
                kernel_version < KernelVersion::new(5, 18, 0),
                "failed to load XDP dispatcher on {kernel_version}: {error}"
            );
            assert_matches::assert_matches!(error, ProgramError::LoadError { io_error, verifier_log } => {
                assert_eq!(io_error.raw_os_error(), Some(libc::EINVAL), "{verifier_log}");
                assert!(verifier_log.to_string().is_empty(), "{verifier_log}");
            });
            return;
        }
    }

    let _netns = NetNsGuard::new().unwrap();
    dispatcher.attach("lo", XdpMode::default()).unwrap();
}

#[test_log::test]
fn two_progs() {
    let mut bpf = Ebpf::load(crate::TWO_PROGS).unwrap();

    let prog_one: &mut TracePoint = bpf
        .program_mut("test_tracepoint_one")
        .unwrap()
        .try_into()
        .unwrap();

    prog_one.load().unwrap();
    prog_one.attach("sched", "sched_switch").unwrap();

    let prog_two: &mut TracePoint = bpf
        .program_mut("test_tracepoint_two")
        .unwrap()
        .try_into()
        .unwrap();
    prog_two.load().unwrap();
    prog_two.attach("sched", "sched_switch").unwrap();
}

#[test_log::test]
fn extension() {
    let extension_supported = is_program_supported(ProgramType::Extension).unwrap();
    let _netns = NetNsGuard::new().unwrap();

    let mut bpf = Ebpf::load(crate::MAIN).unwrap();
    let pass: &mut Xdp = bpf.program_mut("xdp_pass").unwrap().try_into().unwrap();
    pass.load().unwrap();
    pass.attach("lo", XdpMode::default()).unwrap();

    let mut bpf = EbpfLoader::new()
        .extension("xdp_drop")
        .load(crate::EXT)
        .unwrap();
    let drop_: &mut Extension = bpf.program_mut("xdp_drop").unwrap().try_into().unwrap();
    let result = drop_.load(pass.fd().unwrap().try_clone().unwrap(), "xdp_pass");
    match result {
        Ok(()) => {}
        Err(error) => {
            assert_matches::assert_matches!(error, ProgramError::LoadError { io_error, verifier_log } => {
                assert_eq!(io_error.raw_os_error(), Some(libc::EINVAL), "{verifier_log}");
                if !extension_supported && KernelVersion::current().unwrap() < KernelVersion::new(5, 6, 0) {
                    // BPF_PROG_TYPE_EXT first appeared in Linux 5.6. Unknown
                    // program types are rejected before the verifier runs.
                    // https://github.com/torvalds/linux/blob/v5.6/include/uapi/linux/bpf.h#L183
                    assert!(verifier_log.to_string().is_empty(), "{verifier_log}");
                } else {
                    assert!(super::vmlinux_btf_missing(), "{verifier_log}");
                    assert!(verifier_log.to_string().contains("Cannot replace static functions"), "{verifier_log}");
                }
            });
        }
    }
}
